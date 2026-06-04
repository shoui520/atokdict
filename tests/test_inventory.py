from __future__ import annotations

from pathlib import Path
import sqlite3

from atokdict.companion import decode_companion_bytes
from atokdict.inventory import scan_inventory


def test_inventory_includes_companion_sqlite_metadata(tmp_path: Path) -> None:
    plain = tmp_path / "plain.sqlite"
    companion = tmp_path / "SAMPLE.DRW"
    connection = sqlite3.connect(plain)
    try:
        connection.execute("CREATE TABLE t (id INTEGER PRIMARY KEY)")
        connection.commit()
    finally:
        connection.close()
    companion.write_bytes(decode_companion_bytes(plain.read_bytes()))

    groups = scan_inventory(tmp_path)

    assert len(groups) == 1
    item = groups[0].files[0]
    assert item.header is None
    assert item.companion_sqlite is not None
    assert item.companion_sqlite["sqlite_magic"] == "SQLite format 3"
    assert item.section_descriptors == []
