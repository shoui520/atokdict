from __future__ import annotations

from pathlib import Path
import sqlite3

from atokdict.companion import (
    COMPANION_XOR_KEY,
    companion_page_type_counts,
    decode_companion_bytes,
    parse_companion_header,
    read_companion_schema,
    summarize_dsz_relationships,
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


def test_summarize_synthetic_dsz_relationships(tmp_path: Path) -> None:
    plain = tmp_path / "plain.sqlite"
    obfuscated = tmp_path / "sample.DSZ"
    connection = sqlite3.connect(plain)
    try:
        connection.execute("PRAGMA page_size=1024")
        connection.execute(
            """
            CREATE TABLE TABLE_HEADER(
              DSZ_FILENAME TEXT,
              NAME         TEXT,
              DESCRIPTION  TEXT,
              COPYRIGHT    TEXT,
              LOT          TEXT
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE TABLE_CLASS(
              CLASS_ID  INTEGER PRIMARY KEY,
              NAME      TEXT,
              SHORTNAME TEXT,
              PARENT_ID INTEGER
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE TABLE_GROUP(
              GROUP_ID INTEGER PRIMARY KEY,
              NAME     TEXT,
              CLASS_ID INTEGER
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE TABLE_WORD(
              ID          INTEGER PRIMARY KEY,
              CLASS_ID    INTEGER,
              GROUP_ID    INTEGER,
              LABEL       TEXT,
              YOMI        TEXT,
              HYOKI       TEXT,
              HYOKI_GOBI  TEXT,
              HINSHI      INTEGER,
              SEARCHABLE  INTEGER,
              DISPLAYABLE INTEGER,
              TORIKOMI    INTEGER,
              OKURI       INTEGER,
              DESCRIPTION TEXT
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE TABLE_WORD_IHYOKI(
              WORD_ID     INTEGER,
              CLASS_ID    INTEGER,
              HYOKI       TEXT,
              HINSHI      INTEGER
            )
            """
        )
        connection.execute(
            """
            INSERT INTO TABLE_HEADER
            VALUES ('sample.DSZ', 'Sample', '', 'none', 'test')
            """
        )
        connection.executemany(
            "INSERT INTO TABLE_CLASS VALUES (?, ?, ?, ?)",
            [
                (1, "root", "r", 0),
                (2, "child", "c", 1),
                (3, "orphan", "o", 99),
            ],
        )
        connection.executemany(
            "INSERT INTO TABLE_GROUP VALUES (?, ?, ?)",
            [
                (10, "group-a", 2),
                (11, "group-b", 9),
            ],
        )
        connection.executemany(
            """
            INSERT INTO TABLE_WORD
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (100, 2, 10, None, "a", "A", "", 1, 1, 1, 0, 0, ""),
                (101, 9, 11, "label", "b", "B", "", 1, 1, 0, 0, 0, None),
                (102, 3, 99, "label", "c", "C", "tail", 2, 0, 1, 1, 1, "desc"),
            ],
        )
        connection.executemany(
            "INSERT INTO TABLE_WORD_IHYOKI VALUES (?, ?, ?, ?)",
            [
                (100, 2, "ALT", 1),
                (999, 3, "MISS", 2),
            ],
        )
        connection.commit()
    finally:
        connection.close()

    obfuscated.write_bytes(decode_companion_bytes(plain.read_bytes()))

    summary = summarize_dsz_relationships(obfuscated)
    assert summary.table_row_counts["TABLE_WORD"] == 3
    assert summary.table_row_counts["TABLE_WORD_IHYOKI"] == 2

    id_ranges = {
        (item.table_name, item.column_name): item for item in summary.id_ranges
    }
    assert id_ranges[("TABLE_CLASS", "CLASS_ID")].dense_integer_range is True
    assert id_ranges[("TABLE_WORD", "ID")].min_value == 100
    assert id_ranges[("TABLE_WORD", "ID")].max_value == 102

    assert summary.class_tree.zero_parent_count == 1
    assert summary.class_tree.missing_nonzero_parent_count == 1
    assert summary.class_tree.max_depth == 1

    foreign_keys = {
        item.relationship_name: item for item in summary.foreign_keys
    }
    assert foreign_keys["group_class"].missing_parent_row_count == 1
    assert foreign_keys["word_class"].missing_parent_row_count == 1
    assert foreign_keys["word_group"].missing_parent_row_count == 1
    assert foreign_keys["ihyoki_word"].missing_parent_row_count == 1

    text_columns = {
        (item.table_name, item.column_name): item
        for item in summary.text_column_summaries
    }
    assert text_columns[("TABLE_WORD", "LABEL")].null_count == 1
    assert text_columns[("TABLE_WORD", "DESCRIPTION")].empty_text_count == 1

    value_counts = {
        (item.table_name, item.column_name): item
        for item in summary.numeric_value_summaries
    }
    assert value_counts[("TABLE_WORD", "SEARCHABLE")].value_counts == {
        "0": 1,
        "1": 2,
    }
