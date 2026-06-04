from __future__ import annotations

from pathlib import Path
import sqlite3

from atokdict.companion import decode_companion_bytes
from atokdict.linkage import summarize_drt_keyword_ranges


def test_summarize_drt_keyword_ranges(tmp_path: Path) -> None:
    drt = tmp_path / "sample.DRT"
    drw = tmp_path / "sample.DRW"
    _write_synthetic_drt(drt)
    _write_synthetic_drw(drw)

    summary = summarize_drt_keyword_ranges(drt)

    assert summary.keyword_count == 5
    assert summary.root_entry_count == 3
    assert summary.nonempty_separator_count == 2
    assert summary.exact_separator_count == 2
    assert summary.separator_ranks_monotonic is True
    assert [item.partition_start_rank for item in summary.ranges] == [0, 1, 3]
    assert [item.partition_end_rank for item in summary.ranges] == [1, 3, 5]
    assert [item.partition_keyword_count for item in summary.ranges] == [1, 2, 2]
    assert summary.ranges[0].separator_lower_bound_rank == 1
    assert summary.ranges[0].separator_lower_bound_a_id == 2
    assert summary.ranges[0].separator_exact_a_ids == [2]
    assert summary.ranges[2].separator_is_empty is True
    assert summary.ranges[2].separator_lower_bound_rank is None


def _write_synthetic_drt(path: Path) -> None:
    data = bytearray(0x700)
    data[0:4] = b"DRT\0"
    data[8:12] = b"ATOK"
    data[0x10:0x14] = (0x0F01).to_bytes(4, "big")
    data[0x14:0x18] = bytes([0x01, 0x18, 0x11, 0x16])
    data[0x3C:0x40] = bytes([0x19, 0x89, 0x02, 0x22])
    title = "辞書".encode("cp932")
    data[0x40 : 0x40 + len(title)] = title
    data[0x388:0x390] = (0x500).to_bytes(4, "big") + (0x200).to_bytes(4, "big")

    root = 0x500
    data[root : root + 4] = (3).to_bytes(4, "big")
    entry_1 = root + 14
    data[entry_1 : entry_1 + 16] = _root_entry(0x546)
    data[entry_1 + 16 : entry_1 + 20] = "bb".encode("utf-16be")

    entry_2 = entry_1 + 20
    data[entry_2 : entry_2 + 16] = _root_entry(0x5A0)
    data[entry_2 + 16 : entry_2 + 20] = "dd".encode("utf-16be")

    entry_3 = entry_2 + 20
    data[entry_3 : entry_3 + 16] = _root_entry(0x5C0)
    path.write_bytes(data)


def _root_entry(data_offset: int) -> bytes:
    return (
        data_offset.to_bytes(4, "big")
        + (1).to_bytes(2, "big")
        + (2).to_bytes(2, "big")
        + (0x10).to_bytes(4, "big")
        + (0x20).to_bytes(4, "big")
    )


def _write_synthetic_drw(path: Path) -> None:
    plain = path.with_suffix(".sqlite")
    connection = sqlite3.connect(plain)
    try:
        connection.execute("PRAGMA page_size=1024")
        connection.execute(
            "CREATE TABLE keyword_info (a_id INTEGER PRIMARY KEY, word TEXT NOT NULL)"
        )
        connection.executemany(
            "INSERT INTO keyword_info(a_id, word) VALUES (?, ?)",
            [(1, "aa"), (2, "bb"), (3, "cc"), (4, "dd"), (5, "ee")],
        )
        connection.commit()
    finally:
        connection.close()
    path.write_bytes(decode_companion_bytes(plain.read_bytes()))
