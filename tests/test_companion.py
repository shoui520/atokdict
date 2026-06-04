from __future__ import annotations

from pathlib import Path
import sqlite3

from atokdict.companion import (
    COMPANION_XOR_KEY,
    companion_page_type_counts,
    decode_companion_bytes,
    parse_companion_header,
    read_companion_schema,
)


def test_decode_companion_bytes_uses_repeating_key() -> None:
    assert decode_companion_bytes(COMPANION_XOR_KEY) == bytes(len(COMPANION_XOR_KEY))
    assert decode_companion_bytes(bytes(len(COMPANION_XOR_KEY))) == COMPANION_XOR_KEY


def test_parse_obfuscated_sqlite_header_and_schema(tmp_path: Path) -> None:
    plain = tmp_path / "plain.sqlite"
    obfuscated = tmp_path / "sample.DRW"
    connection = sqlite3.connect(plain)
    try:
        connection.execute("PRAGMA page_size=1024")
        connection.execute(
            "CREATE TABLE keyword_info (a_id INTEGER PRIMARY KEY, word TEXT NOT NULL)"
        )
        connection.execute("CREATE INDEX keyword_search_index on keyword_info(word)")
        connection.executemany(
            "INSERT INTO keyword_info(word) VALUES (?)",
            [("alpha",), ("beta",)],
        )
        connection.commit()
    finally:
        connection.close()

    data = plain.read_bytes()
    obfuscated.write_bytes(decode_companion_bytes(data))

    header = parse_companion_header(obfuscated)
    assert header.sqlite_magic == "SQLite format 3"
    assert header.page_size == 1024
    assert header.database_size_pages_file == obfuscated.stat().st_size // 1024
    assert header.text_encoding == "utf-8"

    schema = read_companion_schema(obfuscated, include_counts=True)
    tables = [item for item in schema if item.type == "table"]
    indexes = [item for item in schema if item.type == "index"]
    assert tables[0].name == "keyword_info"
    assert tables[0].row_count == 2
    assert indexes[0].name == "keyword_search_index"

    page_counts = companion_page_type_counts(obfuscated)
    assert sum(page_counts.values()) == header.database_size_pages_file
