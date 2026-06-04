from __future__ import annotations

from collections import Counter
from contextlib import contextmanager
from dataclasses import asdict, dataclass
import os
from pathlib import Path
import sqlite3
import tempfile
from typing import Iterator


COMPANION_XOR_KEY = bytes.fromhex("06685a5efa4b0161f69385b124777a82")
SQLITE_MAGIC = b"SQLite format 3\x00"


SQLITE_TEXT_ENCODINGS = {
    1: "utf-8",
    2: "utf-16le",
    3: "utf-16be",
}


SQLITE_PAGE_TYPES = {
    0x02: "interior_index",
    0x05: "interior_table",
    0x0A: "leaf_index",
    0x0D: "leaf_table",
}


@dataclass(frozen=True)
class CompanionSqliteHeader:
    path: str | None
    size: int | None
    key_hex: str
    sqlite_magic: str
    page_size: int
    write_version: int
    read_version: int
    reserved_space: int
    max_embedded_payload_fraction: int
    min_embedded_payload_fraction: int
    leaf_payload_fraction: int
    file_change_counter: int
    database_size_pages_header: int
    database_size_pages_file: int | None
    first_freelist_trunk_page: int
    freelist_page_count: int
    schema_cookie: int
    schema_format: int
    default_page_cache_size: int
    largest_root_btree_page: int
    text_encoding_code: int
    text_encoding: str | None
    user_version: int
    incremental_vacuum_mode: int
    application_id: int
    version_valid_for: int
    sqlite_version_number: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class CompanionSchemaItem:
    type: str
    name: str
    table_name: str
    sql: str | None
    row_count: int | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def decode_companion_bytes(data: bytes, *, offset: int = 0) -> bytes:
    return bytes(
        byte ^ COMPANION_XOR_KEY[(offset + index) % len(COMPANION_XOR_KEY)]
        for index, byte in enumerate(data)
    )


def parse_companion_header(path_or_file: str | Path) -> CompanionSqliteHeader:
    path = Path(path_or_file)
    size = path.stat().st_size
    with path.open("rb") as handle:
        header = decode_companion_bytes(handle.read(100))
    if len(header) < 100:
        raise ValueError("file is too small to contain an obfuscated SQLite header")
    if not header.startswith(SQLITE_MAGIC):
        raise ValueError("file is not an ATOK companion SQLite file")

    page_size_raw = int.from_bytes(header[16:18], "big")
    page_size = 65536 if page_size_raw == 1 else page_size_raw
    database_size_pages_file = size // page_size if page_size and size % page_size == 0 else None
    text_encoding_code = _u32(header, 56)

    return CompanionSqliteHeader(
        path=str(path),
        size=size,
        key_hex=COMPANION_XOR_KEY.hex(),
        sqlite_magic=SQLITE_MAGIC.rstrip(b"\x00").decode("ascii"),
        page_size=page_size,
        write_version=header[18],
        read_version=header[19],
        reserved_space=header[20],
        max_embedded_payload_fraction=header[21],
        min_embedded_payload_fraction=header[22],
        leaf_payload_fraction=header[23],
        file_change_counter=_u32(header, 24),
        database_size_pages_header=_u32(header, 28),
        database_size_pages_file=database_size_pages_file,
        first_freelist_trunk_page=_u32(header, 32),
        freelist_page_count=_u32(header, 36),
        schema_cookie=_u32(header, 40),
        schema_format=_u32(header, 44),
        default_page_cache_size=_u32(header, 48),
        largest_root_btree_page=_u32(header, 52),
        text_encoding_code=text_encoding_code,
        text_encoding=SQLITE_TEXT_ENCODINGS.get(text_encoding_code),
        user_version=_u32(header, 60),
        incremental_vacuum_mode=_u32(header, 64),
        application_id=_u32(header, 68),
        version_valid_for=_u32(header, 92),
        sqlite_version_number=_u32(header, 96),
    )


def companion_page_type_counts(path_or_file: str | Path) -> dict[str, int]:
    path = Path(path_or_file)
    header = parse_companion_header(path)
    if header.database_size_pages_file is None:
        raise ValueError("file size is not aligned to the decoded SQLite page size")

    counts: Counter[str] = Counter()
    with path.open("rb") as handle:
        for page_index in range(header.database_size_pages_file):
            offset = page_index * header.page_size
            if page_index == 0:
                handle.seek(offset + 100)
                type_offset = offset + 100
            else:
                handle.seek(offset)
                type_offset = offset
            encoded = handle.read(1)
            if not encoded:
                break
            page_type = encoded[0] ^ COMPANION_XOR_KEY[type_offset % len(COMPANION_XOR_KEY)]
            counts[SQLITE_PAGE_TYPES.get(page_type, f"unknown_0x{page_type:02x}")] += 1
    return dict(sorted(counts.items()))


def read_companion_schema(
    path_or_file: str | Path, *, include_counts: bool = False
) -> list[CompanionSchemaItem]:
    with decoded_companion_tempfile(path_or_file) as decoded_path:
        connection = sqlite3.connect(f"file:{decoded_path}?mode=ro", uri=True)
        try:
            rows = connection.execute(
                """
                SELECT type, name, tbl_name, sql
                FROM sqlite_master
                WHERE name NOT LIKE 'sqlite_%'
                ORDER BY type, name
                """
            ).fetchall()
            items: list[CompanionSchemaItem] = []
            for item_type, name, table_name, sql in rows:
                row_count = None
                if include_counts and item_type == "table":
                    row_count = _table_row_count(connection, name)
                items.append(
                    CompanionSchemaItem(
                        type=item_type,
                        name=name,
                        table_name=table_name,
                        sql=sql,
                        row_count=row_count,
                    )
                )
            return items
        finally:
            connection.close()


@contextmanager
def decoded_companion_tempfile(path_or_file: str | Path) -> Iterator[str]:
    source = Path(path_or_file)
    fd, temp_path = tempfile.mkstemp(prefix="atokdict-", suffix=".sqlite")
    os.close(fd)
    try:
        offset = 0
        with source.open("rb") as input_file, open(temp_path, "wb") as output_file:
            while True:
                chunk = input_file.read(1024 * 1024)
                if not chunk:
                    break
                output_file.write(decode_companion_bytes(chunk, offset=offset))
                offset += len(chunk)
        yield temp_path
    finally:
        try:
            os.remove(temp_path)
        except FileNotFoundError:
            pass


def _table_row_count(connection: sqlite3.Connection, table_name: str) -> int:
    escaped = table_name.replace('"', '""')
    return int(connection.execute(f'SELECT COUNT(*) FROM "{escaped}"').fetchone()[0])


def _u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "big")
