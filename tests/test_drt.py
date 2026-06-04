from __future__ import annotations

from io import BytesIO

import pytest

from atokdict.drt import parse_drt_root_index


def test_parse_synthetic_drt_root_index() -> None:
    data = bytearray(0x600)
    _write_drt_header(data)
    data[0x388:0x390] = (0x500).to_bytes(4, "big") + (0x100).to_bytes(4, "big")

    root = 0x500
    data[root : root + 4] = (2).to_bytes(4, "big")
    entry_1 = root + 14
    data[entry_1 : entry_1 + 16] = (
        (0x536).to_bytes(4, "big")
        + (1).to_bytes(2, "big")
        + (2).to_bytes(2, "big")
        + (0x10).to_bytes(4, "big")
        + (0x20).to_bytes(4, "big")
    )
    data[entry_1 + 16 : entry_1 + 20] = "aa".encode("utf-16be")

    entry_2 = entry_1 + 20
    data[entry_2 : entry_2 + 16] = (
        (0x560).to_bytes(4, "big")
        + (0).to_bytes(2, "big")
        + (3).to_bytes(2, "big")
        + (0x30).to_bytes(4, "big")
        + (0x40).to_bytes(4, "big")
    )
    data[entry_2 + 16 : entry_2 + 20] = "bb".encode("utf-16be")

    root_index = parse_drt_root_index(BytesIO(data))

    assert root_index.entry_count == 2
    assert root_index.root_record_area_length == 0x536 - 0x500 - 14
    assert [entry.key for entry in root_index.entries] == ["aa", "bb"]
    assert root_index.entries[0].record_offset == entry_1
    assert root_index.entries[0].data_offset == 0x536
    assert root_index.entries[0].flag == 1
    assert root_index.entries[0].tag == 2
    assert root_index.entries[0].value_a == 0x10
    assert root_index.entries[0].value_b == 0x20


def test_rejects_non_root_index_final_section() -> None:
    data = bytearray(0x600)
    _write_drt_header(data)
    data[0x388:0x390] = (0x500).to_bytes(4, "big") + (0x100).to_bytes(4, "big")
    data[0x500:0x504] = (0xFF00FF00).to_bytes(4, "big")

    with pytest.raises(ValueError, match="observed root index"):
        parse_drt_root_index(BytesIO(data))


def _write_drt_header(data: bytearray) -> None:
    data[0:4] = b"DRT\0"
    data[8:12] = b"ATOK"
    data[0x10:0x14] = (0x0F01).to_bytes(4, "big")
    data[0x14:0x18] = bytes([0x01, 0x18, 0x11, 0x16])
    data[0x3C:0x40] = bytes([0x19, 0x89, 0x02, 0x22])
    data[0x40:0x46] = "辞書".encode("cp932")
