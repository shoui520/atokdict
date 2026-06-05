from __future__ import annotations

from pathlib import Path

from atokdict.dsy import parse_dsy_map, parse_dsy_region1_index
from atokdict.dsy import summarize_dsy_region1_records, summarize_dsy_regions
from atokdict.dsy import summarize_dsy_region3_extra_run_links
from atokdict.dsy import summarize_dsy_region3_extra_runs
from atokdict.dsy import summarize_dsy_region3_first_run
from atokdict.dsy import summarize_dsy_region3_first_run_links
from atokdict.dsy import summarize_dsy_region3_first_run_outliers
from atokdict.dsy import summarize_dsy_region3_gap4
from atokdict.dsy import summarize_dsy_region3_gap4_links
from atokdict.dsy import summarize_dsy_region3_prefix
from atokdict.dsy import summarize_dsy_region3_run_index_links
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


def test_summarize_synthetic_dsy_region3_first_run_links(tmp_path: Path) -> None:
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
        44,
        1,
        0,
        0,
        0,
        0,
        0,
        0,
        0xFFFF,
        3,
        3,
        99,
        0xFFFE,
        5,
        7,
        5,
        44,
        55,
        0xFFFD,
        0,
        0xFFF0,
        0,
    ]
    data[0x5C0:0x5EC] = b"".join(
        word.to_bytes(2, "big") for word in prefix_words
    )
    path.write_bytes(data)

    summary = summarize_dsy_region3_first_run_links(path)

    assert summary.first_run_start_word_index == 8
    assert summary.first_run_end_word_index == 18
    assert summary.first_run_sentinel_word_count == 3
    assert summary.interval_count == 2
    assert summary.anchor_match_interval_count == 2
    assert summary.no_anchor_match_interval_count == 0
    assert summary.multiple_anchor_match_interval_count == 2
    assert summary.anchor_match_filler_count == 4
    gap4, gap6 = summary.gap_summaries
    assert gap4.gap_word_count == 4
    assert gap4.interval_count == 1
    assert gap4.filler_word_count == 3
    assert gap4.anchor_match_interval_count == 1
    assert gap4.multiple_anchor_match_interval_count == 1
    assert gap4.anchor_match_filler_count == 2
    assert gap4.first_filler_anchor_match_count == 1
    assert gap4.second_filler_anchor_match_count == 1
    assert gap4.anchor_match_position_counts == {"1": 1, "2": 1}
    assert gap6.gap_word_count == 6
    assert gap6.filler_word_count == 5
    assert gap6.anchor_match_filler_count == 2
    assert gap6.first_filler_anchor_match_count == 1
    assert gap6.second_filler_anchor_match_count == 0
    assert gap6.anchor_match_position_counts == {"1": 1, "3": 1}


def test_summarize_synthetic_dsy_region3_first_run_outliers(tmp_path: Path) -> None:
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
        44,
        1,
        0,
        0,
        0,
        0,
        0,
        0,
        0xFFFF,
        2,
        0xFFFE,
        4,
        4,
        99,
        0xFFFD,
        6,
        55,
        6,
        77,
        88,
        0xFFFC,
        0,
    ]
    data[0x5C0:0x5EC] = b"".join(
        word.to_bytes(2, "big") for word in prefix_words
    )
    path.write_bytes(data)

    summary = summarize_dsy_region3_first_run_outliers(path)

    assert summary.first_run_start_word_index == 8
    assert summary.first_run_end_word_index == 20
    assert summary.first_run_sentinel_word_count == 4
    assert summary.interval_count == 3
    assert summary.no_anchor_match_interval_count == 1
    assert summary.non_first_anchor_match_interval_count == 2
    assert summary.non_first_anchor_match_filler_count == 2
    assert summary.late_after_second_anchor_match_interval_count == 1
    assert summary.late_after_second_anchor_match_filler_count == 1
    no_match = summary.no_anchor_match_gap_summaries[0]
    assert no_match.gap_word_count == 2
    assert no_match.interval_ordinal_min == 0
    assert no_match.interval_ordinal_max == 0
    assert no_match.anchor_word_index_min == 8
    assert no_match.anchor_word_index_max == 8
    assert no_match.filler_word_count == 1
    assert no_match.filler_min_value == 2
    assert no_match.filler_max_value == 2
    assert no_match.filler_le_0x0100_count == 1
    secondary_gap4, secondary_gap6 = summary.non_first_anchor_match_gap_summaries
    assert secondary_gap4.gap_word_count == 4
    assert secondary_gap4.interval_count == 1
    assert secondary_gap4.non_first_match_position_counts == {"2": 1}
    assert secondary_gap4.late_after_second_match_position_counts == {}
    assert secondary_gap6.gap_word_count == 6
    assert secondary_gap6.non_first_match_position_counts == {"3": 1}
    assert secondary_gap6.late_after_second_match_position_counts == {"3": 1}


def test_summarize_synthetic_dsy_region3_run_index_links(tmp_path: Path) -> None:
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
        68,
        1,
        0,
        0,
        0,
        0,
        0,
        0,
        0xFFFF,
        2,
        0xFFFE,
        4,
        4,
        99,
        0xFFFD,
        6,
        55,
        6,
        77,
        88,
        0xFFFC,
        0,
        0xFFF0,
        0,
        0xFFEF,
        0,
        0xFFE0,
        0,
        0xFFDF,
        0,
        0xFFDE,
        0,
        0xFFD0,
        0,
    ]
    data[0x5C0:0x604] = b"".join(
        word.to_bytes(2, "big") for word in prefix_words
    )
    path.write_bytes(data)

    summary = summarize_dsy_region3_run_index_links(path)

    assert summary.first_run_sentinel_word_count == 4
    assert summary.first_run_interval_count == 3
    assert summary.descending_run_count == 4
    assert summary.later_run_count == 3
    assert summary.same_index_later_run_count == 2
    assert summary.missing_later_run_count == 1
    assert summary.later_run_without_first_run_interval_count == 1
    no_match, first_only, second_position, late = summary.category_summaries
    assert no_match.category == "no_anchor_match"
    assert no_match.interval_count == 1
    assert no_match.same_index_later_run_count == 0
    assert no_match.missing_interval_ordinal_min == 0
    assert no_match.first_run_gap_counts == {"2": 1}
    assert first_only.category == "first_only"
    assert first_only.interval_count == 0
    assert second_position.category == "second_position"
    assert second_position.interval_count == 1
    assert second_position.same_index_later_run_count == 1
    assert second_position.first_run_gap_counts == {"4": 1}
    assert second_position.linked_later_run_value_count_counts == {"2": 1}
    assert second_position.linked_later_run_value_ordinal_min == 15
    assert second_position.linked_later_run_value_ordinal_max == 16
    assert late.category == "late_after_second"
    assert late.interval_count == 1
    assert late.same_index_later_run_count == 1
    assert late.first_run_gap_counts == {"6": 1}
    assert late.linked_later_run_value_count_counts == {"3": 1}
    assert late.linked_later_run_value_ordinal_min == 31
    assert late.linked_later_run_value_ordinal_max == 33


def test_summarize_synthetic_dsy_region3_extra_runs(tmp_path: Path) -> None:
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
        68,
        1,
        0,
        0,
        0,
        0,
        0,
        0,
        0xFFFF,
        2,
        0xFFFE,
        4,
        4,
        99,
        0xFFFD,
        6,
        55,
        6,
        77,
        88,
        0xFFFC,
        0,
        0xFFF0,
        0,
        0xFFEF,
        0,
        0xFFE0,
        0,
        0xFFDF,
        0,
        0xFFDE,
        0,
        0xFFD0,
        0,
    ]
    data[0x5C0:0x604] = b"".join(
        word.to_bytes(2, "big") for word in prefix_words
    )
    path.write_bytes(data)

    summary = summarize_dsy_region3_extra_runs(path)

    assert summary.first_run_interval_count == 3
    assert summary.first_run_interval_ordinal_min == 0
    assert summary.first_run_interval_ordinal_max == 2
    assert summary.descending_run_count == 4
    assert summary.later_run_count == 3
    assert summary.extra_later_run_count == 1
    assert summary.extra_run_index_min == 3
    assert summary.extra_run_index_max == 3
    assert summary.extra_run_indexes_are_contiguous is True
    assert summary.extra_runs_after_first_run_interval_range_count == 1
    assert summary.extra_run_index_delta_counts == {}
    assert summary.extra_run_value_count_min == 1
    assert summary.extra_run_value_count_max == 1
    assert summary.extra_run_value_count_counts == {"1": 1}
    assert summary.extra_run_word_span_min == 1
    assert summary.extra_run_word_span_max == 1
    assert summary.extra_run_start_word_index_min == 32
    assert summary.extra_run_start_word_index_max == 32
    assert summary.extra_run_end_word_index_min == 32
    assert summary.extra_run_end_word_index_max == 32
    assert summary.extra_run_value_ordinal_min == 47
    assert summary.extra_run_value_ordinal_max == 47


def test_summarize_synthetic_dsy_region3_extra_run_links(tmp_path: Path) -> None:
    path = tmp_path / "sample.DSY"
    data = bytearray(0x760)
    _write_dsy_header(data)
    _write_dsy_metadata(data, region1_record_count=5)
    _write_region(data, 0x330, 0x360, 0x200)
    _write_region(data, 0x338, 0x560, 0x40)
    _write_region(data, 0x340, 0x5A0, 0x20)
    _write_region(data, 0x348, 0x5C0, 0x1A0)
    region1_records = [
        (40, 0),
        (1, 1),
        (2, 3),
        (3, 6),
        (4, 10),
    ]
    data[0x560:0x588] = b"".join(
        first.to_bytes(4, "big") + second.to_bytes(4, "big")
        for first, second in region1_records
    )

    prefix_words = [
        72,
        1,
        0,
        0,
        0,
        0,
        0,
        0,
        0xFFFF,
        3,
        0xFFFE,
        4,
        47,
        99,
        0xFFFD,
        6,
        55,
        6,
        77,
        88,
        0xFFFC,
        0,
        0xFFF0,
        3,
        0xFFEF,
        47,
        0xFFE0,
        0,
        0xFFDF,
        0,
        0xFFDE,
        0,
        0xFFD0,
        0,
        0,
        0,
    ]
    data[0x5C0:0x608] = b"".join(
        word.to_bytes(2, "big") for word in prefix_words
    )
    path.write_bytes(data)

    summary = summarize_dsy_region3_extra_run_links(path)

    assert summary.region1_record_count == 4
    assert summary.extra_later_run_count == 1
    assert summary.extra_run_index_count == 1
    assert summary.extra_run_index_min == 3
    assert summary.extra_run_index_max == 3
    assert summary.extra_value_ordinal_count == 1
    assert summary.extra_value_ordinal_min == 47
    assert summary.extra_value_ordinal_max == 47
    assert summary.extra_run_indexes_in_region1_record_range_count == 1
    assert summary.extra_value_ordinals_in_region1_record_range_count == 0
    assert summary.region1_extra_index_record_length_min == 3
    assert summary.region1_extra_index_record_length_max == 3
    assert summary.region1_extra_index_record_length_unique_count == 1
    assert summary.region1_extra_ordinal_record_length_min is None
    zones = {zone.zone_name: zone for zone in summary.zone_summaries}
    assert zones["all"].extra_run_index_match_word_count == 2
    assert zones["all"].extra_run_index_unique_match_count == 1
    assert zones["all"].extra_value_ordinal_match_word_count == 2
    assert zones["all"].extra_value_ordinal_unique_match_count == 1
    assert zones["first_run_span"].extra_run_index_match_word_count == 1
    assert zones["first_run_span"].extra_value_ordinal_match_word_count == 1
    assert zones["post_first_run"].extra_run_index_match_word_count == 1
    assert zones["post_first_run"].extra_value_ordinal_match_word_count == 1


def test_summarize_synthetic_dsy_region3_gap4(tmp_path: Path) -> None:
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
        2,
        300,
        0xFFFE,
        4,
        8,
        200,
        0xFFFD,
        123,
        0xFFF0,
        0,
    ]
    data[0x5C0:0x5DC] = b"".join(
        word.to_bytes(2, "big") for word in prefix_words
    )
    path.write_bytes(data)

    summary = summarize_dsy_region3_gap4(path)

    assert summary.first_run_start_word_index == 2
    assert summary.first_run_end_word_index == 10
    assert summary.first_run_sentinel_word_count == 3
    assert summary.gap4_chunk_count == 2
    assert summary.slot_0_equals_slot_1_count == 1
    assert summary.slot_0_le_slot_1_count == 2
    assert summary.slot_0_and_slot_1_even_count == 2
    assert summary.slot_2_le_0x0100_count == 1
    slots = summary.slot_summaries
    assert [slot.value_count for slot in slots] == [2, 2, 2]
    assert [slot.min_value for slot in slots] == [2, 2, 200]
    assert [slot.max_value for slot in slots] == [4, 8, 300]
    assert [slot.unique_value_count for slot in slots] == [2, 2, 2]
    assert [slot.le_0x0100_count for slot in slots] == [2, 2, 1]


def test_summarize_synthetic_dsy_region3_gap4_links(tmp_path: Path) -> None:
    path = tmp_path / "sample.DSY"
    data = bytearray(0x760)
    _write_dsy_header(data)
    _write_dsy_metadata(data, region1_record_count=6)
    _write_region(data, 0x330, 0x360, 0x200)
    _write_region(data, 0x338, 0x560, 0x40)
    _write_region(data, 0x340, 0x5A0, 0x20)
    _write_region(data, 0x348, 0x5C0, 0x1A0)
    region1_records = [
        (48, 0),
        (1, 1),
        (1, 2),
        (1, 3),
        (1, 4),
        (1, 5),
    ]
    data[0x560:0x590] = b"".join(
        first.to_bytes(4, "big") + second.to_bytes(4, "big")
        for first, second in region1_records
    )

    prefix_words = [
        36,
        1,
        0,
        0,
        0,
        0,
        0,
        0,
        0xFFFF,
        3,
        3,
        20,
        0xFFFE,
        4,
        5,
        22,
        0xFFFD,
        0,
    ]
    data[0x5C0:0x5E4] = b"".join(
        word.to_bytes(2, "big") for word in prefix_words
    )
    path.write_bytes(data)

    summary = summarize_dsy_region3_gap4_links(path)

    assert summary.region1_record_count == 5
    assert summary.prefix_word_count == 18
    assert summary.gap4_chunk_count == 2
    assert summary.slot_1_minus_slot_0_counts == {"0": 1, "1": 1}
    slots = summary.slot_summaries
    assert [slot.times2_plus2_anchor_count for slot in slots] == [1, 2, 0]
    assert [slot.times2_plus6_next_count for slot in slots] == [1, 2, 0]
    assert [slot.region1_record_index_range_count for slot in slots] == [2, 2, 0]
    assert [slot.prefix_word_index_range_count for slot in slots] == [2, 2, 0]
    assert [slot.prefix_byte_offset_range_count for slot in slots] == [2, 2, 2]
    assert [slot.adjacent_delta_counts for slot in slots] == [{"1": 1}, {"2": 1}, {"2": 1}]


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
