from __future__ import annotations

from io import BytesIO

import pytest

from atokdict.drt import parse_drt_primary_index, parse_drt_root_index
from atokdict.drt import summarize_drt_root_child_blocks


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


def test_parse_synthetic_drt_primary_index() -> None:
    data = bytearray(0x700)
    _write_drt_header(data)
    data[0x390:0x398] = (0x500).to_bytes(4, "big") + (0x28).to_bytes(4, "big")
    data[0x3A8:0x3B0] = (0x600).to_bytes(4, "big") + (0x100).to_bytes(4, "big")

    data[0x500:0x514] = (
        b"\x00\x00ab"
        + (0x600).to_bytes(4, "big")
        + (1).to_bytes(4, "big")
        + (2).to_bytes(4, "big")
        + (0x3D).to_bytes(4, "big")
    )
    data[0x514:0x528] = (
        bytes.fromhex("30d05e38")
        + (0x640).to_bytes(4, "big")
        + (3).to_bytes(4, "big")
        + (4).to_bytes(4, "big")
        + (0xB9).to_bytes(4, "big")
    )

    primary_index = parse_drt_primary_index(BytesIO(data))

    assert primary_index.record_count == 2
    assert primary_index.entries[0].record_offset == 0x500
    assert primary_index.entries[0].key_encoding_guess == "ascii"
    assert primary_index.entries[0].key_byte_length == 2
    assert primary_index.entries[0].key_char_length == 2
    assert primary_index.entries[0].data_offset == 0x600
    assert primary_index.entries[0].byte_length == 0x40
    assert primary_index.entries[0].field_0x08_byte_length == 1
    assert primary_index.entries[0].field_0x0c_byte_length == 2
    assert primary_index.entries[0].field_0x10_byte_length == 0x3D
    assert primary_index.entries[0].segment_0_offset == 0x600
    assert primary_index.entries[0].segment_0_byte_length == 0x3D
    assert primary_index.entries[0].segment_1_offset == 0x63D
    assert primary_index.entries[0].segment_1_byte_length == 1
    assert primary_index.entries[0].segment_2_offset == 0x63E
    assert primary_index.entries[0].segment_2_byte_length == 2
    assert primary_index.entries[1].key_encoding_guess == "utf-16be"
    assert primary_index.entries[1].key_char_length == 2
    assert primary_index.entries[1].relative_offset == 0x40
    assert primary_index.entries[1].byte_length == 0xC0


def test_rejects_non_root_index_final_section() -> None:
    data = bytearray(0x600)
    _write_drt_header(data)
    data[0x388:0x390] = (0x500).to_bytes(4, "big") + (0x100).to_bytes(4, "big")
    data[0x500:0x504] = (0xFF00FF00).to_bytes(4, "big")

    with pytest.raises(ValueError, match="observed root index"):
        parse_drt_root_index(BytesIO(data))


def test_summarize_synthetic_drt_root_child_blocks() -> None:
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

    data[0x536:0x53E] = (
        (0xFFFF).to_bytes(2, "big")
        + (0xFFFE).to_bytes(2, "big")
        + (0x560).to_bytes(4, "big")
    )

    blocks = summarize_drt_root_child_blocks(BytesIO(data), scan_bytes=32)

    assert len(blocks) == 2
    assert blocks[0].block_offset == 0x536
    assert blocks[0].relative_offset == 0x36
    assert blocks[0].byte_length == 0x2A
    assert blocks[0].root_flag == 1
    assert blocks[0].marker_first_offsets["0xffff"] == 0
    assert blocks[0].marker_first_offsets["0xfffe"] == 2
    assert blocks[0].marker_counts["0xffff"] == 1
    assert blocks[0].possible_absolute_offsets_in_scan == 1
    assert blocks[0].root_key_char_length == 2


def _write_drt_header(data: bytearray) -> None:
    data[0:4] = b"DRT\0"
    data[8:12] = b"ATOK"
    data[0x10:0x14] = (0x0F01).to_bytes(4, "big")
    data[0x14:0x18] = bytes([0x01, 0x18, 0x11, 0x16])
    data[0x3C:0x40] = bytes([0x19, 0x89, 0x02, 0x22])
    data[0x40:0x46] = "辞書".encode("cp932")
