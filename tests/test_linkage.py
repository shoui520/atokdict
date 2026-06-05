from __future__ import annotations

from pathlib import Path
import sqlite3

from atokdict.companion import decode_companion_bytes
from atokdict.linkage import summarize_drt_primary_keyword_ranges
from atokdict.linkage import summarize_drt_keyword_ranges
from atokdict.linkage import summarize_dsy_dsz_active_class_links
from atokdict.linkage import summarize_dsy_dsz_record_profile


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


def test_summarize_drt_primary_keyword_ranges(tmp_path: Path) -> None:
    drt = tmp_path / "primary.DRT"
    drw = tmp_path / "primary.DRW"
    _write_synthetic_primary_drt(drt)
    _write_synthetic_drw(drw)

    summary = summarize_drt_primary_keyword_ranges(drt)

    assert summary.keyword_count == 5
    assert summary.primary_record_count == 3
    assert summary.decodable_separator_count == 2
    assert summary.exact_separator_count == 2
    assert summary.prefix_separator_count == 2
    assert summary.separator_ranks_monotonic is True
    assert [item.partition_start_rank for item in summary.ranges] == [0, 1, 3]
    assert [item.partition_end_rank for item in summary.ranges] == [1, 3, 5]
    assert [item.partition_keyword_count for item in summary.ranges] == [1, 2, 2]
    assert summary.ranges[0].separator_key_encoding_guess == "ascii"
    assert summary.ranges[0].separator_lower_bound_rank == 1
    assert summary.ranges[0].separator_lower_bound_a_id == 2
    assert summary.ranges[0].separator_exact_match_count == 1
    assert summary.ranges[0].separator_prefix_match_count == 1
    assert summary.ranges[2].separator_is_decodable is False
    assert summary.ranges[2].separator_lower_bound_rank is None


def test_summarize_dsy_dsz_active_class_links(tmp_path: Path) -> None:
    dsy = tmp_path / "sample.DSY"
    dsz = tmp_path / "sample.DSZ"
    _write_synthetic_dsy_region1(dsy, record_lengths=[100, 200, 300])
    _write_synthetic_dsz_active_classes(dsz)

    summary = summarize_dsy_dsz_active_class_links(dsy)

    assert summary.dsy_table_record_count == 4
    assert summary.dsy_payload_record_count == 3
    assert summary.dsz_class_count == 4
    assert summary.dsz_active_class_union_count == 4
    assert summary.dsz_active_class_intersection_count == 4
    assert summary.dsz_group_only_active_class_count == 0
    assert summary.dsz_word_only_active_class_count == 0
    assert summary.dsz_active_class_min == 10
    assert summary.dsz_active_class_max == 40
    assert summary.dsz_active_classes_are_dense is False
    assert summary.active_class_count_matches_dsy_table_count is True
    assert summary.active_class_count_minus_one_matches_dsy_payload_count is True

    assert [model.model_name for model in summary.order_models] == [
        "drop_first_active_class",
        "drop_last_active_class",
    ]
    drop_last = summary.order_models[1]
    assert drop_last.compared_record_count == 3
    assert drop_last.first_active_class_id == 10
    assert drop_last.last_active_class_id == 30
    assert drop_last.length_to_word_count_pearson == 1.0
    assert drop_last.length_to_word_count_spearman == 1.0
    assert drop_last.length_to_group_count_pearson == 1.0


def test_summarize_dsy_dsz_record_profile(tmp_path: Path) -> None:
    dsy = tmp_path / "sample.DSY"
    dsz = tmp_path / "sample.DSZ"
    _write_synthetic_dsy_region1(dsy, record_lengths=[100, 200, 300])
    _write_synthetic_dsz_active_classes(dsz)

    summary = summarize_dsy_dsz_record_profile(dsy)

    assert summary.model_name == "drop_last_active_class"
    assert summary.model_is_compatible is True
    assert summary.compared_record_count == 3
    assert summary.first_active_class_id == 10
    assert summary.last_active_class_id == 30
    assert summary.region1_payload_byte_length == 600
    assert summary.record_byte_length_mod_counts["4"] == {"0": 3}
    assert summary.word_count_linear_fit.x_metric_name == "dsz_word_count"
    assert summary.word_count_linear_fit.y_metric_name == "record_byte_length"
    assert summary.word_count_linear_fit.slope == 100.0
    assert summary.word_count_linear_fit.intercept == 0.0

    metrics = {item.metric_name: item for item in summary.metric_summaries}
    assert metrics["record_byte_length"].value_sum == 600
    assert metrics["record_byte_length"].correlation_to_word_count_pearson == 1.0
    assert metrics["u16_zero_count"].value_sum == 300
    assert metrics["u16_zero_count"].correlation_to_word_count_pearson == 1.0

    incompatible = summarize_dsy_dsz_record_profile(
        dsy,
        model_name="all_active_classes",
    )
    assert incompatible.model_is_compatible is False
    assert incompatible.compared_record_count == 0
    assert incompatible.metric_summaries == []


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


def _write_synthetic_primary_drt(path: Path) -> None:
    data = bytearray(0x700)
    _write_common_drt_header(data)
    data[0x390:0x398] = (0x500).to_bytes(4, "big") + (0x3C).to_bytes(4, "big")
    data[0x3A8:0x3B0] = (0x600).to_bytes(4, "big") + (0x100).to_bytes(4, "big")

    data[0x500:0x514] = (
        b"\x00\x00bb"
        + (0x600).to_bytes(4, "big")
        + (8).to_bytes(4, "big")
        + (8).to_bytes(4, "big")
        + (0x30).to_bytes(4, "big")
    )
    data[0x514:0x528] = (
        b"\x00\x00dd"
        + (0x640).to_bytes(4, "big")
        + (8).to_bytes(4, "big")
        + (8).to_bytes(4, "big")
        + (0x30).to_bytes(4, "big")
    )
    data[0x528:0x53C] = (
        b"\xff\xff\xff\xff"
        + (0x680).to_bytes(4, "big")
        + (8).to_bytes(4, "big")
        + (8).to_bytes(4, "big")
        + (0x70).to_bytes(4, "big")
    )
    path.write_bytes(data)


def _write_synthetic_dsy_region1(path: Path, *, record_lengths: list[int]) -> None:
    table_record_count = len(record_lengths) + 1
    table_byte_length = table_record_count * 8
    payload_byte_length = sum(record_lengths)
    region1_offset = 0x560
    region1_length = table_byte_length + payload_byte_length + 0x20
    region2_offset = region1_offset + region1_length
    region3_offset = region2_offset + 0x20
    data = bytearray(region3_offset + 0x100)
    _write_common_dsy_header(data)
    _write_common_dsy_metadata(data, region1_record_count=table_record_count)
    _write_dsy_region_descriptor(data, 0x330, 0x360, 0x200)
    _write_dsy_region_descriptor(data, 0x338, region1_offset, region1_length)
    _write_dsy_region_descriptor(data, 0x340, region2_offset, 0x20)
    _write_dsy_region_descriptor(data, 0x348, region3_offset, 0x100)

    records = [(table_byte_length, 0)]
    cumulative = 0
    for byte_length in record_lengths:
        cumulative += byte_length
        records.append((byte_length, cumulative))
    data[region1_offset : region1_offset + table_byte_length] = b"".join(
        first.to_bytes(4, "big") + second.to_bytes(4, "big")
        for first, second in records
    )
    path.write_bytes(data)


def _write_synthetic_dsz_active_classes(path: Path) -> None:
    plain = path.with_suffix(".sqlite")
    connection = sqlite3.connect(plain)
    try:
        connection.execute("PRAGMA page_size=1024")
        _create_synthetic_dsz_schema(connection)
        connection.executemany(
            "INSERT INTO TABLE_CLASS VALUES (?, ?, ?, ?)",
            [
                (10, "c10", "", 0),
                (20, "c20", "", 10),
                (30, "c30", "", 20),
                (40, "c40", "", 0),
            ],
        )
        group_id = 1
        word_id = 1
        for class_id, count in [(10, 1), (20, 2), (30, 3), (40, 4)]:
            for _index in range(count):
                connection.execute(
                    "INSERT INTO TABLE_GROUP VALUES (?, ?, ?)",
                    (group_id, "", class_id),
                )
                connection.execute(
                    """
                    INSERT INTO TABLE_WORD
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        word_id,
                        class_id,
                        group_id,
                        "",
                        f"y{word_id}",
                        f"h{word_id}",
                        "",
                        1,
                        1,
                        1,
                        1,
                        0,
                        "",
                    ),
                )
                group_id += 1
                word_id += 1
        connection.commit()
    finally:
        connection.close()
    path.write_bytes(decode_companion_bytes(plain.read_bytes()))


def _create_synthetic_dsz_schema(connection: sqlite3.Connection) -> None:
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
          WORD_ID  INTEGER,
          CLASS_ID INTEGER,
          HYOKI    TEXT,
          HINSHI   INTEGER
        )
        """
    )


def _write_common_dsy_header(data: bytearray) -> None:
    data[0:4] = b"DSY\0"
    data[8:12] = b"ATOK"
    data[0x10:0x14] = (0x0E01).to_bytes(4, "big")
    data[0x14:0x18] = bytes([0x01, 0x24, 0x01, 0x02])
    data[0x3C:0x40] = bytes([0x19, 0x89, 0x02, 0x22])
    title = "辞書".encode("utf-16be")
    data[0x40 : 0x40 + len(title)] = title


def _write_common_dsy_metadata(
    data: bytearray,
    *,
    region1_record_count: int,
) -> None:
    data[0x300:0x304] = (0x004000FF).to_bytes(4, "big")
    data[0x304:0x308] = (1).to_bytes(4, "big")
    data[0x308:0x30C] = (0x00FFFFFF).to_bytes(4, "big")
    data[0x30C:0x310] = region1_record_count.to_bytes(4, "big")
    data[0x310:0x314] = (0x00200200).to_bytes(4, "big")
    data[0x314:0x318] = (0xFFFF0003).to_bytes(4, "big")
    data[0x318:0x31C] = (0x00080000).to_bytes(4, "big")
    data[0x31C:0x320] = (0x00010000).to_bytes(4, "big")
    data[0x32C:0x330] = (4).to_bytes(4, "big")


def _write_dsy_region_descriptor(
    data: bytearray,
    descriptor_offset: int,
    offset: int,
    length: int,
) -> None:
    data[descriptor_offset : descriptor_offset + 4] = offset.to_bytes(4, "big")
    data[descriptor_offset + 4 : descriptor_offset + 8] = length.to_bytes(4, "big")


def _write_common_drt_header(data: bytearray) -> None:
    data[0:4] = b"DRT\0"
    data[8:12] = b"ATOK"
    data[0x10:0x14] = (0x0F01).to_bytes(4, "big")
    data[0x14:0x18] = bytes([0x01, 0x18, 0x11, 0x16])
    data[0x3C:0x40] = bytes([0x19, 0x89, 0x02, 0x22])
    title = "辞書".encode("cp932")
    data[0x40 : 0x40 + len(title)] = title


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
