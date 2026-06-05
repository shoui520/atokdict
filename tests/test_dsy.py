from __future__ import annotations

from pathlib import Path

from atokdict.dsy import parse_dsy_map, parse_dsy_region1_index
from atokdict.dsy import summarize_dsy_region1_records, summarize_dsy_regions
from atokdict.dsy import summarize_dsy_region3_first_run
from atokdict.dsy import summarize_dsy_region3_prefix
from atokdict.dsy import summarize_dsy_region3_sentinels


def test_parse_synthetic_dsy_map(tmp_path: Path) -> None:
    path = tmp_path / "sample.DSY"
    data = bytearray(0x760)
    data[0:4] = b"DSY\0"
    data[8:12] = b"ATOK"
    data[0x10:0x14] = (0x0E01).to_bytes(4, "big")
    data[0x14:0x18] = bytes([0x01, 0x24, 0x01, 0x02])
    data[0x3C:0x40] = bytes([0x19, 0x89, 0x02, 0x22])
    title = "辞書".encode("utf-16be")
    data[0x40 : 0x40 + len(title)] = title

    data[0x300:0x304] = (0x004000FF).to_bytes(4, "big")
    data[0x304:0x308] = (1).to_bytes(4, "big")
    data[0x308:0x30C] = (0x00FFFFFF).to_bytes(4, "big")
    data[0x30C:0x310] = (0x12).to_bytes(4, "big")
    data[0x310:0x314] = (0x00200200).to_bytes(4, "big")
    data[0x314:0x318] = (0xFFFF0003).to_bytes(4, "big")
    data[0x318:0x31C] = (0x00080000).to_bytes(4, "big")
    data[0x31C:0x320] = (0x00010000).to_bytes(4, "big")
    data[0x32C:0x330] = (4).to_bytes(4, "big")

    _write_region(data, 0x330, 0x360, 0x200)
    _write_region(data, 0x338, 0x560, 0x100)
    _write_region(data, 0x340, 0x660, 0x20)
    _write_region(data, 0x348, 0x680, 0xE0)
    data[0x360:0x560] = b"".join(
        value.to_bytes(2, "big") for value in range(1, 257)
    )
    data[0x680:0x686] = (
        (0xFFFF).to_bytes(2, "big")
        + (0xFFFE).to_bytes(2, "big")
        + (0xFFFD).to_bytes(2, "big")
    )
    path.write_bytes(data)

    dsy_map = parse_dsy_map(path)
    regions = summarize_dsy_regions(path)

    assert dsy_map.size == 0x760
    assert dsy_map.metadata_words["0x300"] == 0x004000FF
    assert dsy_map.field_0x30c_count_like == 0x12
    assert dsy_map.field_0x314_high == 0xFFFF
    assert dsy_map.field_0x314_low_count_like == 3
    assert dsy_map.regions_cover_from_0x360_to_eof is True
    assert [region.data_offset for region in dsy_map.regions] == [
        0x360,
        0x560,
        0x660,
        0x680,
    ]
    assert [region.byte_length for region in dsy_map.regions] == [
        0x200,
        0x100,
        0x20,
        0xE0,
    ]
    assert regions[0].region0_is_u16_permutation_1_to_256 is True
    assert regions[0].u16_word_count == 256
    assert regions[0].u16_nonzero_count == 256
    assert regions[0].u16_unique_count == 256
    assert regions[3].marker_counts["0xffff"] == 1
    assert regions[3].marker_first_offsets["0xfffe"] == 2


def test_parse_synthetic_dsy_region1_index(tmp_path: Path) -> None:
    path = tmp_path / "sample.DSY"
    data = bytearray(0x760)
    _write_dsy_header(data)
    _write_dsy_metadata(data, region1_record_count=3)
    _write_region(data, 0x330, 0x360, 0x200)
    _write_region(data, 0x338, 0x560, 0x40)
    _write_region(data, 0x340, 0x5A0, 0x20)
    _write_region(data, 0x348, 0x5C0, 0x1A0)

    data[0x560:0x578] = (
        (24).to_bytes(4, "big")
        + (0).to_bytes(4, "big")
        + (10).to_bytes(4, "big")
        + (10).to_bytes(4, "big")
        + (8).to_bytes(4, "big")
        + (18).to_bytes(4, "big")
    )
    path.write_bytes(data)

    index = parse_dsy_region1_index(path)

    assert index.region_offset == 0x560
    assert index.region_byte_length == 0x40
    assert index.metadata_record_count == 3
    assert index.table_byte_length == 24
    assert index.table_record_count == 3
    assert index.table_header_first_field == 24
    assert index.table_header_second_field == 0
    assert index.payload_base_offset == 0x578
    assert index.covered_payload_byte_length == 18
    assert index.trailer_offset == 0x58A
    assert index.trailer_byte_length == 22
    assert [entry.payload_offset for entry in index.entries] == [0x578, 0x582]
    assert [entry.payload_relative_offset for entry in index.entries] == [0, 10]
    assert [entry.byte_length for entry in index.entries] == [10, 8]
    assert [entry.cumulative_payload_end for entry in index.entries] == [10, 18]


def test_summarize_synthetic_dsy_region1_records(tmp_path: Path) -> None:
    path = tmp_path / "sample.DSY"
    data = bytearray(0x760)
    _write_dsy_header(data)
    _write_dsy_metadata(data, region1_record_count=3)
    _write_region(data, 0x330, 0x360, 0x200)
    _write_region(data, 0x338, 0x560, 0x40)
    _write_region(data, 0x340, 0x5A0, 0x20)
    _write_region(data, 0x348, 0x5C0, 0x1A0)

    data[0x560:0x578] = (
        (24).to_bytes(4, "big")
        + (0).to_bytes(4, "big")
        + (10).to_bytes(4, "big")
        + (10).to_bytes(4, "big")
        + (8).to_bytes(4, "big")
        + (18).to_bytes(4, "big")
    )
    data[0x578:0x582] = (
        (0xFFFF).to_bytes(2, "big")
        + (0xFFFE).to_bytes(2, "big")
        + (0x5C0).to_bytes(4, "big")
        + b"\x00\x04"
    )
    data[0x582:0x58A] = (0x5A0).to_bytes(4, "big") + (8).to_bytes(4, "big")
    data[0x58A:0x590] = (0xFFFD).to_bytes(2, "big") + (4).to_bytes(4, "big")
    path.write_bytes(data)

    diagnostics = summarize_dsy_region1_records(path, scan_bytes=16)

    assert diagnostics.payload_record_count == 2
    assert diagnostics.trailer_byte_length == 22
    first = diagnostics.payload_records[0]
    assert first.record_kind == "payload"
    assert first.table_record_index == 1
    assert first.record_offset == 0x578
    assert first.region_relative_offset == 0x18
    assert first.payload_relative_offset == 0
    assert first.marker_first_offsets["0xffff"] == 0
    assert first.marker_first_offsets["0xfffe"] == 2
    assert first.marker_counts["0xffff"] == 1
    assert first.possible_absolute_offsets_by_region["region_3"] == 1
    assert first.possible_region1_payload_relative_offsets == 0

    second = diagnostics.payload_records[1]
    assert second.possible_absolute_offsets_by_region["region_2"] == 1
    assert second.possible_region_relative_offsets["region_1"] == 1

    trailer = diagnostics.trailer_record
    assert trailer.record_kind == "trailer"
    assert trailer.table_record_index is None
    assert trailer.record_offset == 0x58A
    assert trailer.marker_counts["0xfffd"] == 1
    assert trailer.possible_region1_payload_relative_offsets >= 1


def test_summarize_synthetic_dsy_region3_prefix(tmp_path: Path) -> None:
    path = tmp_path / "sample.DSY"
    data = bytearray(0x760)
    _write_dsy_header(data)
    _write_dsy_metadata(data, region1_record_count=2)
    _write_region(data, 0x330, 0x360, 0x200)
    _write_region(data, 0x338, 0x560, 0x40)
    _write_region(data, 0x340, 0x5A0, 0x20)
    _write_region(data, 0x348, 0x5C0, 0x1A0)

    data[0x560:0x570] = (
        (16).to_bytes(4, "big")
        + (0).to_bytes(4, "big")
        + (8).to_bytes(4, "big")
        + (8).to_bytes(4, "big")
    )
    prefix = bytearray(32)
    prefix[0:2] = (32).to_bytes(2, "big")
    prefix[2:4] = (0xFFFF).to_bytes(2, "big")
    prefix[4:8] = (0x570).to_bytes(4, "big")
    prefix[8:12] = (4).to_bytes(4, "big")
    prefix[12:16] = (0x5C0).to_bytes(4, "big")
    data[0x5C0:0x5E0] = prefix
    data[0x5E0:0x5E2] = (0xFFFE).to_bytes(2, "big")
    path.write_bytes(data)

    summary = summarize_dsy_region3_prefix(path, tail_scan_bytes=16)

    assert summary.region_offset == 0x5C0
    assert summary.region_byte_length == 0x1A0
    assert summary.prefix_byte_length == 32
    assert summary.prefix_word_count == 16
    assert summary.prefix_end_offset == 0x5E0
    assert summary.tail_byte_length == 0x180
    assert summary.tail_scan_byte_length == 16
    assert summary.header_u16_words[:2] == [32, 0xFFFF]
    assert summary.prefix_marker_counts["0xffff"] == 1
    assert summary.prefix_marker_first_offsets["0xffff"] == 2
    assert summary.tail_marker_counts["0xfffe"] == 1
    assert summary.tail_marker_first_offsets["0xfffe"] == 0
    assert summary.prefix_high_u16_word_count == 1
    assert summary.prefix_zero_u16_word_count >= 1
    assert summary.possible_absolute_offsets_by_region["region_1"] >= 1
    assert summary.possible_absolute_offsets_by_region["region_3"] >= 1
    assert summary.possible_region1_payload_relative_offsets >= 1


def test_summarize_synthetic_dsy_region3_sentinels(tmp_path: Path) -> None:
    path = tmp_path / "sample.DSY"
    data = bytearray(0x760)
    _write_dsy_header(data)
    _write_dsy_metadata(data, region1_record_count=1)
    _write_region(data, 0x330, 0x360, 0x200)
    _write_region(data, 0x338, 0x560, 0x40)
    _write_region(data, 0x340, 0x5A0, 0x20)
    _write_region(data, 0x348, 0x5C0, 0x1A0)
    data[0x560:0x568] = (8).to_bytes(4, "big") + (0).to_bytes(4, "big")

    prefix_words = [
        24,
        1,
        0xFFFF,
        0xFFFE,
        4,
        0xFFFC,
        0xFFFB,
        0xFFF0,
        8,
        0,
        0,
        0,
    ]
    data[0x5C0:0x5D8] = b"".join(
        word.to_bytes(2, "big") for word in prefix_words
    )
    path.write_bytes(data)

    summary = summarize_dsy_region3_sentinels(path)

    assert summary.prefix_byte_length == 24
    assert summary.prefix_word_count == 12
    assert summary.high_word_count == 5
    assert summary.descending_run_count == 3
    assert summary.first_descending_run_value_count == 2
    assert summary.first_descending_run_start_value == "0xffff"
    assert summary.first_descending_run_end_value == "0xfffe"
    assert summary.longest_descending_run_value_count == 2
    runs = summary.descending_runs
    assert [run.value_count for run in runs] == [2, 2, 1]
    assert [run.start_word_index for run in runs] == [2, 5, 7]
    assert runs[1].start_value == 0xFFFC
    assert runs[1].end_value == 0xFFFB


def test_summarize_synthetic_dsy_region3_first_run(tmp_path: Path) -> None:
    path = tmp_path / "sample.DSY"
    data = bytearray(0x760)
    _write_dsy_header(data)
    _write_dsy_metadata(data, region1_record_count=1)
    _write_region(data, 0x330, 0x360, 0x200)
    _write_region(data, 0x338, 0x560, 0x40)
    _write_region(data, 0x340, 0x5A0, 0x20)
    _write_region(data, 0x348, 0x5C0, 0x1A0)
    data[0x560:0x568] = (8).to_bytes(4, "big") + (0).to_bytes(4, "big")

    prefix_words = [
        28,
        1,
        0xFFFF,
        2,
        0xFFFE,
        4,
        6,
        0xFFFD,
        0xFFF0,
        8,
        0,
        0,
        0,
        0,
    ]
    data[0x5C0:0x5DC] = b"".join(
        word.to_bytes(2, "big") for word in prefix_words
    )
    path.write_bytes(data)

    summary = summarize_dsy_region3_first_run(path)

    assert summary.prefix_byte_length == 28
    assert summary.start_word_index == 2
    assert summary.end_word_index == 7
    assert summary.start_byte_offset == 4
    assert summary.end_byte_offset == 14
    assert summary.start_value == "0xffff"
    assert summary.end_value == "0xfffd"
    assert summary.sentinel_word_count == 3
    assert summary.span_word_count == 6
    assert summary.filler_word_count == 3
    assert summary.gap_counts == {"2": 1, "3": 1}
    assert summary.filler_min_value == 2
    assert summary.filler_max_value == 6
    assert summary.filler_unique_value_count == 3
    assert summary.filler_even_value_count == 3
    assert summary.filler_le_0x0100_count == 3
    assert summary.filler_zero_count == 0


def _write_region(data: bytearray, descriptor_offset: int, offset: int, length: int) -> None:
    data[descriptor_offset : descriptor_offset + 4] = offset.to_bytes(4, "big")
    data[descriptor_offset + 4 : descriptor_offset + 8] = length.to_bytes(4, "big")


def _write_dsy_header(data: bytearray) -> None:
    data[0:4] = b"DSY\0"
    data[8:12] = b"ATOK"
    data[0x10:0x14] = (0x0E01).to_bytes(4, "big")
    data[0x14:0x18] = bytes([0x01, 0x24, 0x01, 0x02])
    data[0x3C:0x40] = bytes([0x19, 0x89, 0x02, 0x22])
    title = "辞書".encode("utf-16be")
    data[0x40 : 0x40 + len(title)] = title


def _write_dsy_metadata(data: bytearray, *, region1_record_count: int) -> None:
    data[0x300:0x304] = (0x004000FF).to_bytes(4, "big")
    data[0x304:0x308] = (1).to_bytes(4, "big")
    data[0x308:0x30C] = (0x00FFFFFF).to_bytes(4, "big")
    data[0x30C:0x310] = region1_record_count.to_bytes(4, "big")
    data[0x310:0x314] = (0x00200200).to_bytes(4, "big")
    data[0x314:0x318] = (0xFFFF0003).to_bytes(4, "big")
    data[0x318:0x31C] = (0x00080000).to_bytes(4, "big")
    data[0x31C:0x320] = (0x00010000).to_bytes(4, "big")
    data[0x32C:0x330] = (4).to_bytes(4, "big")
