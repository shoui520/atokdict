from __future__ import annotations

from collections import Counter
from contextlib import contextmanager
from dataclasses import asdict, dataclass
import os
from pathlib import Path
import sqlite3
import tempfile
from typing import Iterator, Sequence


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


@dataclass(frozen=True)
class DszIdRangeSummary:
    table_name: str
    column_name: str
    row_count: int
    nonnull_count: int
    distinct_count: int
    min_value: int | None
    max_value: int | None
    dense_integer_range: bool | None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class DszTextColumnSummary:
    table_name: str
    column_name: str
    row_count: int
    null_count: int
    empty_text_count: int
    nonempty_text_count: int
    distinct_nonnull_count: int
    min_text_length: int | None
    max_text_length: int | None
    average_text_length: float | None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class DszValueCountSummary:
    table_name: str
    column_name: str
    row_count: int
    null_count: int
    distinct_nonnull_count: int
    counts_returned: int
    value_counts: dict[str, int]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class DszForeignKeySummary:
    relationship_name: str
    child_table_name: str
    child_column_name: str
    parent_table_name: str
    parent_column_name: str
    child_row_count: int
    child_null_key_count: int
    child_zero_key_count: int
    child_nonnull_key_count: int
    distinct_child_key_count: int
    missing_parent_row_count: int
    parent_row_count: int
    parent_referenced_count: int
    parent_unreferenced_count: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class DszDegreeSummary:
    relationship_name: str
    parent_table_name: str
    child_table_name: str
    parent_row_count: int
    child_nonnull_key_count: int
    parent_with_child_count: int
    parent_without_child_count: int
    min_child_count: int | None
    max_child_count: int | None
    average_child_count: float | None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class DszClassTreeSummary:
    class_row_count: int
    null_parent_count: int
    zero_parent_count: int
    missing_nonzero_parent_count: int
    self_parent_count: int
    cycle_node_count: int
    max_depth: int | None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class DszRelationshipSummary:
    path: str
    table_row_counts: dict[str, int]
    id_ranges: list[DszIdRangeSummary]
    class_tree: DszClassTreeSummary
    foreign_keys: list[DszForeignKeySummary]
    degree_summaries: list[DszDegreeSummary]
    text_column_summaries: list[DszTextColumnSummary]
    numeric_value_summaries: list[DszValueCountSummary]

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "table_row_counts": self.table_row_counts,
            "id_ranges": [item.to_dict() for item in self.id_ranges],
            "class_tree": self.class_tree.to_dict(),
            "foreign_keys": [item.to_dict() for item in self.foreign_keys],
            "degree_summaries": [item.to_dict() for item in self.degree_summaries],
            "text_column_summaries": [
                item.to_dict() for item in self.text_column_summaries
            ],
            "numeric_value_summaries": [
                item.to_dict() for item in self.numeric_value_summaries
            ],
        }


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


def summarize_dsz_relationships(path_or_file: str | Path) -> DszRelationshipSummary:
    source = Path(path_or_file)
    with decoded_companion_tempfile(source) as decoded_path:
        connection = sqlite3.connect(f"file:{decoded_path}?mode=ro", uri=True)
        try:
            table_row_counts = {
                table_name: _table_row_count(connection, table_name)
                for table_name in DSZ_TABLE_NAMES
            }
            id_ranges = [
                _summarize_dsz_id_range(connection, table_name, column_name)
                for table_name, column_name in DSZ_ID_COLUMNS
            ]
            class_tree = _summarize_dsz_class_tree(connection)
            foreign_keys = [
                _summarize_dsz_foreign_key(connection, *relationship)
                for relationship in DSZ_RELATIONSHIPS
            ]
            degree_summaries = [
                _summarize_dsz_degree(connection, *relationship)
                for relationship in DSZ_RELATIONSHIPS
            ]
            text_column_summaries = [
                _summarize_dsz_text_column(connection, table_name, column_name)
                for table_name, column_name in DSZ_TEXT_COLUMNS
            ]
            numeric_value_summaries = [
                _summarize_dsz_value_counts(connection, table_name, column_name)
                for table_name, column_name in DSZ_NUMERIC_VALUE_COLUMNS
            ]
        finally:
            connection.close()

    return DszRelationshipSummary(
        path=str(source),
        table_row_counts=table_row_counts,
        id_ranges=id_ranges,
        class_tree=class_tree,
        foreign_keys=foreign_keys,
        degree_summaries=degree_summaries,
        text_column_summaries=text_column_summaries,
        numeric_value_summaries=numeric_value_summaries,
    )


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


DSZ_TABLE_NAMES = (
    "TABLE_HEADER",
    "TABLE_CLASS",
    "TABLE_GROUP",
    "TABLE_WORD",
    "TABLE_WORD_IHYOKI",
)

DSZ_ID_COLUMNS = (
    ("TABLE_CLASS", "CLASS_ID"),
    ("TABLE_GROUP", "GROUP_ID"),
    ("TABLE_WORD", "ID"),
)

DSZ_RELATIONSHIPS = (
    (
        "class_parent",
        "TABLE_CLASS",
        "PARENT_ID",
        "TABLE_CLASS",
        "CLASS_ID",
    ),
    (
        "group_class",
        "TABLE_GROUP",
        "CLASS_ID",
        "TABLE_CLASS",
        "CLASS_ID",
    ),
    (
        "word_class",
        "TABLE_WORD",
        "CLASS_ID",
        "TABLE_CLASS",
        "CLASS_ID",
    ),
    (
        "word_group",
        "TABLE_WORD",
        "GROUP_ID",
        "TABLE_GROUP",
        "GROUP_ID",
    ),
    (
        "ihyoki_word",
        "TABLE_WORD_IHYOKI",
        "WORD_ID",
        "TABLE_WORD",
        "ID",
    ),
    (
        "ihyoki_class",
        "TABLE_WORD_IHYOKI",
        "CLASS_ID",
        "TABLE_CLASS",
        "CLASS_ID",
    ),
)

DSZ_TEXT_COLUMNS = (
    ("TABLE_HEADER", "DSZ_FILENAME"),
    ("TABLE_HEADER", "NAME"),
    ("TABLE_HEADER", "DESCRIPTION"),
    ("TABLE_HEADER", "COPYRIGHT"),
    ("TABLE_HEADER", "LOT"),
    ("TABLE_CLASS", "NAME"),
    ("TABLE_CLASS", "SHORTNAME"),
    ("TABLE_GROUP", "NAME"),
    ("TABLE_WORD", "LABEL"),
    ("TABLE_WORD", "YOMI"),
    ("TABLE_WORD", "HYOKI"),
    ("TABLE_WORD", "HYOKI_GOBI"),
    ("TABLE_WORD", "DESCRIPTION"),
    ("TABLE_WORD_IHYOKI", "HYOKI"),
)

DSZ_NUMERIC_VALUE_COLUMNS = (
    ("TABLE_WORD", "HINSHI"),
    ("TABLE_WORD", "SEARCHABLE"),
    ("TABLE_WORD", "DISPLAYABLE"),
    ("TABLE_WORD", "TORIKOMI"),
    ("TABLE_WORD", "OKURI"),
    ("TABLE_WORD_IHYOKI", "HINSHI"),
)


def _summarize_dsz_id_range(
    connection: sqlite3.Connection,
    table_name: str,
    column_name: str,
) -> DszIdRangeSummary:
    table = _quote_identifier(table_name)
    column = _quote_identifier(column_name)
    row = connection.execute(
        f"""
        SELECT
          COUNT(*),
          COUNT({column}),
          COUNT(DISTINCT {column}),
          MIN({column}),
          MAX({column})
        FROM {table}
        """
    ).fetchone()
    row_count, nonnull_count, distinct_count, min_value, max_value = row
    if min_value is None or max_value is None:
        dense_integer_range = None
    else:
        dense_integer_range = (
            int(distinct_count) == int(nonnull_count)
            and int(distinct_count) == int(max_value) - int(min_value) + 1
        )
    return DszIdRangeSummary(
        table_name=table_name,
        column_name=column_name,
        row_count=int(row_count),
        nonnull_count=int(nonnull_count),
        distinct_count=int(distinct_count),
        min_value=None if min_value is None else int(min_value),
        max_value=None if max_value is None else int(max_value),
        dense_integer_range=dense_integer_range,
    )


def _summarize_dsz_text_column(
    connection: sqlite3.Connection,
    table_name: str,
    column_name: str,
) -> DszTextColumnSummary:
    table = _quote_identifier(table_name)
    column = _quote_identifier(column_name)
    row = connection.execute(
        f"""
        SELECT
          COUNT(*),
          SUM(CASE WHEN {column} IS NULL THEN 1 ELSE 0 END),
          SUM(CASE WHEN {column} = '' THEN 1 ELSE 0 END),
          SUM(CASE WHEN {column} IS NOT NULL AND {column} != '' THEN 1 ELSE 0 END),
          COUNT(DISTINCT {column}),
          MIN(length({column})),
          MAX(length({column})),
          AVG(length({column}))
        FROM {table}
        """
    ).fetchone()
    (
        row_count,
        null_count,
        empty_text_count,
        nonempty_text_count,
        distinct_nonnull_count,
        min_text_length,
        max_text_length,
        average_text_length,
    ) = row
    return DszTextColumnSummary(
        table_name=table_name,
        column_name=column_name,
        row_count=int(row_count),
        null_count=int(null_count or 0),
        empty_text_count=int(empty_text_count or 0),
        nonempty_text_count=int(nonempty_text_count or 0),
        distinct_nonnull_count=int(distinct_nonnull_count),
        min_text_length=None if min_text_length is None else int(min_text_length),
        max_text_length=None if max_text_length is None else int(max_text_length),
        average_text_length=(
            None if average_text_length is None else float(average_text_length)
        ),
    )


def _summarize_dsz_value_counts(
    connection: sqlite3.Connection,
    table_name: str,
    column_name: str,
    *,
    value_limit: int = 64,
) -> DszValueCountSummary:
    table = _quote_identifier(table_name)
    column = _quote_identifier(column_name)
    row_count, null_count, distinct_nonnull_count = connection.execute(
        f"""
        SELECT
          COUNT(*),
          SUM(CASE WHEN {column} IS NULL THEN 1 ELSE 0 END),
          COUNT(DISTINCT {column})
        FROM {table}
        """
    ).fetchone()
    rows = connection.execute(
        f"""
        SELECT {column}, COUNT(*) AS value_count
        FROM {table}
        WHERE {column} IS NOT NULL
        GROUP BY {column}
        ORDER BY value_count DESC, {column}
        LIMIT ?
        """,
        (value_limit,),
    ).fetchall()
    return DszValueCountSummary(
        table_name=table_name,
        column_name=column_name,
        row_count=int(row_count),
        null_count=int(null_count or 0),
        distinct_nonnull_count=int(distinct_nonnull_count),
        counts_returned=len(rows),
        value_counts={str(value): int(count) for value, count in rows},
    )


def _summarize_dsz_foreign_key(
    connection: sqlite3.Connection,
    relationship_name: str,
    child_table_name: str,
    child_column_name: str,
    parent_table_name: str,
    parent_column_name: str,
) -> DszForeignKeySummary:
    child_table = _quote_identifier(child_table_name)
    child_column = _quote_identifier(child_column_name)
    parent_table = _quote_identifier(parent_table_name)
    parent_column = _quote_identifier(parent_column_name)
    row = connection.execute(
        f"""
        SELECT
          COUNT(*),
          SUM(CASE WHEN {child_column} IS NULL THEN 1 ELSE 0 END),
          SUM(CASE WHEN {child_column} = 0 THEN 1 ELSE 0 END),
          COUNT({child_column}),
          COUNT(DISTINCT {child_column})
        FROM {child_table}
        """
    ).fetchone()
    (
        child_row_count,
        child_null_key_count,
        child_zero_key_count,
        child_nonnull_key_count,
        distinct_child_key_count,
    ) = row
    missing_parent_row_count = _scalar_int(
        connection,
        f"""
        SELECT COUNT(*)
        FROM {child_table} AS child
        WHERE child.{child_column} IS NOT NULL
          AND NOT EXISTS (
            SELECT 1
            FROM {parent_table} AS parent
            WHERE parent.{parent_column} = child.{child_column}
          )
        """,
    )
    parent_row_count = _table_row_count(connection, parent_table_name)
    parent_referenced_count = _scalar_int(
        connection,
        f"""
        SELECT COUNT(*)
        FROM {parent_table} AS parent
        WHERE EXISTS (
          SELECT 1
          FROM {child_table} AS child
          WHERE child.{child_column} = parent.{parent_column}
        )
        """,
    )
    return DszForeignKeySummary(
        relationship_name=relationship_name,
        child_table_name=child_table_name,
        child_column_name=child_column_name,
        parent_table_name=parent_table_name,
        parent_column_name=parent_column_name,
        child_row_count=int(child_row_count),
        child_null_key_count=int(child_null_key_count or 0),
        child_zero_key_count=int(child_zero_key_count or 0),
        child_nonnull_key_count=int(child_nonnull_key_count),
        distinct_child_key_count=int(distinct_child_key_count),
        missing_parent_row_count=missing_parent_row_count,
        parent_row_count=parent_row_count,
        parent_referenced_count=parent_referenced_count,
        parent_unreferenced_count=parent_row_count - parent_referenced_count,
    )


def _summarize_dsz_degree(
    connection: sqlite3.Connection,
    relationship_name: str,
    child_table_name: str,
    child_column_name: str,
    parent_table_name: str,
    parent_column_name: str,
) -> DszDegreeSummary:
    child_table = _quote_identifier(child_table_name)
    child_column = _quote_identifier(child_column_name)
    parent_table = _quote_identifier(parent_table_name)
    parent_column = _quote_identifier(parent_column_name)
    row = connection.execute(
        f"""
        SELECT
          COUNT(*),
          SUM(CASE WHEN child_count > 0 THEN 1 ELSE 0 END),
          SUM(CASE WHEN child_count = 0 THEN 1 ELSE 0 END),
          MIN(child_count),
          MAX(child_count),
          AVG(child_count)
        FROM (
          SELECT parent.{parent_column}, COUNT(child.{child_column}) AS child_count
          FROM {parent_table} AS parent
          LEFT JOIN {child_table} AS child
            ON child.{child_column} = parent.{parent_column}
          GROUP BY parent.{parent_column}
        )
        """
    ).fetchone()
    (
        parent_row_count,
        parent_with_child_count,
        parent_without_child_count,
        min_child_count,
        max_child_count,
        average_child_count,
    ) = row
    child_nonnull_key_count = _scalar_int(
        connection,
        f"SELECT COUNT({child_column}) FROM {child_table}",
    )
    return DszDegreeSummary(
        relationship_name=relationship_name,
        parent_table_name=parent_table_name,
        child_table_name=child_table_name,
        parent_row_count=int(parent_row_count),
        child_nonnull_key_count=child_nonnull_key_count,
        parent_with_child_count=int(parent_with_child_count or 0),
        parent_without_child_count=int(parent_without_child_count or 0),
        min_child_count=None if min_child_count is None else int(min_child_count),
        max_child_count=None if max_child_count is None else int(max_child_count),
        average_child_count=(
            None if average_child_count is None else float(average_child_count)
        ),
    )


def _summarize_dsz_class_tree(
    connection: sqlite3.Connection,
) -> DszClassTreeSummary:
    rows = connection.execute(
        "SELECT CLASS_ID, PARENT_ID FROM TABLE_CLASS"
    ).fetchall()
    parents = {int(class_id): _optional_int(parent_id) for class_id, parent_id in rows}
    class_ids = set(parents)
    null_parent_count = sum(1 for parent_id in parents.values() if parent_id is None)
    zero_parent_count = sum(1 for parent_id in parents.values() if parent_id == 0)
    missing_nonzero_parent_count = sum(
        1
        for parent_id in parents.values()
        if parent_id is not None and parent_id != 0 and parent_id not in class_ids
    )
    self_parent_count = sum(
        1 for class_id, parent_id in parents.items() if parent_id == class_id
    )
    depths: list[int] = []
    cycle_nodes: set[int] = set()
    for class_id in class_ids:
        depth, cycle = _dsz_class_depth(class_id, parents)
        depths.append(depth)
        if cycle:
            cycle_nodes.add(class_id)

    return DszClassTreeSummary(
        class_row_count=len(rows),
        null_parent_count=null_parent_count,
        zero_parent_count=zero_parent_count,
        missing_nonzero_parent_count=missing_nonzero_parent_count,
        self_parent_count=self_parent_count,
        cycle_node_count=len(cycle_nodes),
        max_depth=max(depths) if depths else None,
    )


def _dsz_class_depth(
    class_id: int,
    parents: dict[int, int | None],
) -> tuple[int, bool]:
    depth = 0
    seen: set[int] = set()
    current = class_id
    while True:
        if current in seen:
            return depth, True
        seen.add(current)
        parent = parents.get(current)
        if parent is None or parent == 0:
            return depth, False
        depth += 1
        if parent not in parents:
            return depth, False
        current = parent


def _scalar_int(
    connection: sqlite3.Connection,
    sql: str,
    parameters: Sequence[object] = (),
) -> int:
    return int(connection.execute(sql, parameters).fetchone()[0])


def _optional_int(value: object) -> int | None:
    return None if value is None else int(value)


def _quote_identifier(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def _u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "big")
