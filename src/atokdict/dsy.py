from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Callable, Iterable

from atokdict.container import parse_header
from atokdict.drt import CHILD_MARKERS


DSY_METADATA_OFFSET = 0x300
DSY_METADATA_BYTE_LENGTH = 0x30
DSY_REGION_TABLE_OFFSET = 0x330
DSY_REGION_TABLE_END = 0x360
DSY_REGION_RECORD_SIZE = 8
DSY_REGION1_INDEX_RECORD_SIZE = 8
DSY_REGION1_RECORD_SCAN_BYTES = 4096
DSY_REGION1_RECORD_HASH_BYTES = 64
DSY_REGION3_TAIL_SCAN_BYTES = 4096
DSY_REGION3_HASH_BYTES = 64
DSY_REGION3_HIGH_WORD_MINIMUM = 0xFF00
DSY_REGION_HASH_BYTES = 64
DSY_REGION_SCAN_BYTES = 4096


@dataclass(frozen=True)
class DsyRegionDescriptor:
    descriptor_offset: int
    data_offset: int
    byte_length: int
    end_offset: int

    def to_dict(self) -> dict[str, object]:
        return {
            "descriptor_offset": self.descriptor_offset,
            "data_offset": self.data_offset,
            "byte_length": self.byte_length,
            "end_offset": self.end_offset,
        }


@dataclass(frozen=True)
class DsyMap:
    path: str | None
    size: int
    metadata_words: dict[str, int]
    field_0x30c_count_like: int
    field_0x314_high: int
    field_0x314_low_count_like: int
    regions: list[DsyRegionDescriptor]
    regions_cover_from_0x360_to_eof: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "size": self.size,
            "metadata_words": self.metadata_words,
            "field_0x30c_count_like": self.field_0x30c_count_like,
            "field_0x314_high": self.field_0x314_high,
            "field_0x314_low_count_like": self.field_0x314_low_count_like,
            "regions_cover_from_0x360_to_eof": self.regions_cover_from_0x360_to_eof,
            "regions": [region.to_dict() for region in self.regions],
        }


@dataclass(frozen=True)
class DsyRegionSummary:
    region_index: int
    data_offset: int
    byte_length: int
    scan_byte_length: int
    prefix_sha256: str
    nul_byte_ratio: float
    printable_ascii_ratio: float
    unique_byte_count: int
    marker_counts: dict[str, int]
    marker_first_offsets: dict[str, int | None]
    u16_word_count: int
    u16_nonzero_count: int
    u16_unique_count: int
    region0_is_u16_permutation_1_to_256: bool | None

    def to_dict(self) -> dict[str, object]:
        return {
            "region_index": self.region_index,
            "data_offset": self.data_offset,
            "byte_length": self.byte_length,
            "scan_byte_length": self.scan_byte_length,
            "prefix_sha256": self.prefix_sha256,
            "nul_byte_ratio": self.nul_byte_ratio,
            "printable_ascii_ratio": self.printable_ascii_ratio,
            "unique_byte_count": self.unique_byte_count,
            "marker_counts": self.marker_counts,
            "marker_first_offsets": self.marker_first_offsets,
            "u16_word_count": self.u16_word_count,
            "u16_nonzero_count": self.u16_nonzero_count,
            "u16_unique_count": self.u16_unique_count,
            "region0_is_u16_permutation_1_to_256": (
                self.region0_is_u16_permutation_1_to_256
            ),
        }


@dataclass(frozen=True)
class DsyRegion1IndexEntry:
    table_record_index: int
    index_record_offset: int
    payload_offset: int
    payload_relative_offset: int
    byte_length: int
    end_offset: int
    cumulative_payload_end: int

    def to_dict(self) -> dict[str, object]:
        return {
            "table_record_index": self.table_record_index,
            "index_record_offset": self.index_record_offset,
            "payload_offset": self.payload_offset,
            "payload_relative_offset": self.payload_relative_offset,
            "byte_length": self.byte_length,
            "end_offset": self.end_offset,
            "cumulative_payload_end": self.cumulative_payload_end,
        }


@dataclass(frozen=True)
class DsyRegion1Index:
    path: str | None
    region_offset: int
    region_byte_length: int
    metadata_record_count: int
    table_byte_length: int
    table_record_count: int
    table_header_first_field: int
    table_header_second_field: int
    payload_base_offset: int
    covered_payload_byte_length: int
    trailer_offset: int
    trailer_byte_length: int
    entries: list[DsyRegion1IndexEntry]

    def to_dict(self, *, entry_limit: int | None = None) -> dict[str, object]:
        entries = self.entries if entry_limit is None else self.entries[:entry_limit]
        return {
            "path": self.path,
            "region_offset": self.region_offset,
            "region_byte_length": self.region_byte_length,
            "metadata_record_count": self.metadata_record_count,
            "table_byte_length": self.table_byte_length,
            "table_record_count": self.table_record_count,
            "table_header_first_field": self.table_header_first_field,
            "table_header_second_field": self.table_header_second_field,
            "payload_base_offset": self.payload_base_offset,
            "covered_payload_byte_length": self.covered_payload_byte_length,
            "trailer_offset": self.trailer_offset,
            "trailer_byte_length": self.trailer_byte_length,
            "entries_returned": len(entries),
            "entries": [entry.to_dict() for entry in entries],
        }


@dataclass(frozen=True)
class DsyRegion1RecordSummary:
    record_kind: str
    table_record_index: int | None
    record_offset: int
    region_relative_offset: int
    payload_relative_offset: int | None
    byte_length: int
    scan_byte_length: int
    prefix_sha256: str
    nul_byte_ratio: float
    printable_ascii_ratio: float
    unique_byte_count: int
    marker_counts: dict[str, int]
    marker_first_offsets: dict[str, int | None]
    possible_absolute_offsets_by_region: dict[str, int]
    possible_region_relative_offsets: dict[str, int]
    possible_region1_payload_relative_offsets: int

    def to_dict(self) -> dict[str, object]:
        return {
            "record_kind": self.record_kind,
            "table_record_index": self.table_record_index,
            "record_offset": self.record_offset,
            "region_relative_offset": self.region_relative_offset,
            "payload_relative_offset": self.payload_relative_offset,
            "byte_length": self.byte_length,
            "scan_byte_length": self.scan_byte_length,
            "prefix_sha256": self.prefix_sha256,
            "nul_byte_ratio": self.nul_byte_ratio,
            "printable_ascii_ratio": self.printable_ascii_ratio,
            "unique_byte_count": self.unique_byte_count,
            "marker_counts": self.marker_counts,
            "marker_first_offsets": self.marker_first_offsets,
            "possible_absolute_offsets_by_region": self.possible_absolute_offsets_by_region,
            "possible_region_relative_offsets": self.possible_region_relative_offsets,
            "possible_region1_payload_relative_offsets": (
                self.possible_region1_payload_relative_offsets
            ),
        }


@dataclass(frozen=True)
class DsyRegion1RecordDiagnostics:
    path: str | None
    region_offset: int
    region_byte_length: int
    payload_base_offset: int
    covered_payload_byte_length: int
    trailer_offset: int
    trailer_byte_length: int
    payload_record_count: int
    scan_bytes: int
    prefix_hash_bytes: int
    payload_records: list[DsyRegion1RecordSummary]
    trailer_record: DsyRegion1RecordSummary

    def to_dict(self, *, entry_limit: int | None = None) -> dict[str, object]:
        records = (
            self.payload_records
            if entry_limit is None
            else self.payload_records[:entry_limit]
        )
        return {
            "path": self.path,
            "region_offset": self.region_offset,
            "region_byte_length": self.region_byte_length,
            "payload_base_offset": self.payload_base_offset,
            "covered_payload_byte_length": self.covered_payload_byte_length,
            "trailer_offset": self.trailer_offset,
            "trailer_byte_length": self.trailer_byte_length,
            "payload_record_count": self.payload_record_count,
            "scan_bytes": self.scan_bytes,
            "prefix_hash_bytes": self.prefix_hash_bytes,
            "payload_records_returned": len(records),
            "payload_records": [record.to_dict() for record in records],
            "trailer_record": self.trailer_record.to_dict(),
        }


@dataclass(frozen=True)
class DsyRegion3PrefixSummary:
    path: str | None
    region_offset: int
    region_byte_length: int
    prefix_byte_length: int
    prefix_word_count: int
    prefix_end_offset: int
    tail_byte_length: int
    tail_scan_byte_length: int
    prefix_sha256: str
    tail_prefix_sha256: str
    header_u16_words: list[int]
    prefix_marker_counts: dict[str, int]
    prefix_marker_first_offsets: dict[str, int | None]
    tail_marker_counts: dict[str, int]
    tail_marker_first_offsets: dict[str, int | None]
    prefix_high_u16_word_count: int
    prefix_zero_u16_word_count: int
    prefix_unique_u16_word_count: int
    possible_absolute_offsets_by_region: dict[str, int]
    possible_region_relative_offsets: dict[str, int]
    possible_region1_payload_relative_offsets: int

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "region_offset": self.region_offset,
            "region_byte_length": self.region_byte_length,
            "prefix_byte_length": self.prefix_byte_length,
            "prefix_word_count": self.prefix_word_count,
            "prefix_end_offset": self.prefix_end_offset,
            "tail_byte_length": self.tail_byte_length,
            "tail_scan_byte_length": self.tail_scan_byte_length,
            "prefix_sha256": self.prefix_sha256,
            "tail_prefix_sha256": self.tail_prefix_sha256,
            "header_u16_words": self.header_u16_words,
            "prefix_marker_counts": self.prefix_marker_counts,
            "prefix_marker_first_offsets": self.prefix_marker_first_offsets,
            "tail_marker_counts": self.tail_marker_counts,
            "tail_marker_first_offsets": self.tail_marker_first_offsets,
            "prefix_high_u16_word_count": self.prefix_high_u16_word_count,
            "prefix_zero_u16_word_count": self.prefix_zero_u16_word_count,
            "prefix_unique_u16_word_count": self.prefix_unique_u16_word_count,
            "possible_absolute_offsets_by_region": self.possible_absolute_offsets_by_region,
            "possible_region_relative_offsets": self.possible_region_relative_offsets,
            "possible_region1_payload_relative_offsets": (
                self.possible_region1_payload_relative_offsets
            ),
        }


@dataclass(frozen=True)
class DsyRegion3SentinelRun:
    run_index: int
    start_word_index: int
    end_word_index: int
    start_byte_offset: int
    end_byte_offset: int
    start_value: int
    end_value: int
    value_count: int

    def to_dict(self) -> dict[str, object]:
        return {
            "run_index": self.run_index,
            "start_word_index": self.start_word_index,
            "end_word_index": self.end_word_index,
            "start_byte_offset": self.start_byte_offset,
            "end_byte_offset": self.end_byte_offset,
            "start_value": f"0x{self.start_value:04x}",
            "end_value": f"0x{self.end_value:04x}",
            "value_count": self.value_count,
        }


@dataclass(frozen=True)
class DsyRegion3SentinelSummary:
    path: str | None
    region_offset: int
    prefix_byte_length: int
    prefix_word_count: int
    high_word_minimum: str
    high_word_count: int
    descending_run_count: int
    first_descending_run_value_count: int
    first_descending_run_start_value: str | None
    first_descending_run_end_value: str | None
    longest_descending_run_value_count: int
    descending_runs: list[DsyRegion3SentinelRun]

    def to_dict(self, *, run_limit: int | None = None) -> dict[str, object]:
        runs = self.descending_runs if run_limit is None else self.descending_runs[:run_limit]
        return {
            "path": self.path,
            "region_offset": self.region_offset,
            "prefix_byte_length": self.prefix_byte_length,
            "prefix_word_count": self.prefix_word_count,
            "high_word_minimum": self.high_word_minimum,
            "high_word_count": self.high_word_count,
            "descending_run_count": self.descending_run_count,
            "first_descending_run_value_count": self.first_descending_run_value_count,
            "first_descending_run_start_value": self.first_descending_run_start_value,
            "first_descending_run_end_value": self.first_descending_run_end_value,
            "longest_descending_run_value_count": self.longest_descending_run_value_count,
            "descending_runs_returned": len(runs),
            "descending_runs": [run.to_dict() for run in runs],
        }


@dataclass(frozen=True)
class DsyRegion3FirstRunSummary:
    path: str | None
    region_offset: int
    prefix_byte_length: int
    start_word_index: int
    end_word_index: int
    start_byte_offset: int
    end_byte_offset: int
    start_value: str
    end_value: str
    sentinel_word_count: int
    span_word_count: int
    filler_word_count: int
    gap_counts: dict[str, int]
    filler_min_value: int | None
    filler_max_value: int | None
    filler_unique_value_count: int
    filler_even_value_count: int
    filler_le_0x0100_count: int
    filler_zero_count: int

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "region_offset": self.region_offset,
            "prefix_byte_length": self.prefix_byte_length,
            "start_word_index": self.start_word_index,
            "end_word_index": self.end_word_index,
            "start_byte_offset": self.start_byte_offset,
            "end_byte_offset": self.end_byte_offset,
            "start_value": self.start_value,
            "end_value": self.end_value,
            "sentinel_word_count": self.sentinel_word_count,
            "span_word_count": self.span_word_count,
            "filler_word_count": self.filler_word_count,
            "gap_counts": self.gap_counts,
            "filler_min_value": self.filler_min_value,
            "filler_max_value": self.filler_max_value,
            "filler_unique_value_count": self.filler_unique_value_count,
            "filler_even_value_count": self.filler_even_value_count,
            "filler_le_0x0100_count": self.filler_le_0x0100_count,
            "filler_zero_count": self.filler_zero_count,
        }


@dataclass(frozen=True)
class DsyRegion3FirstRunIntervalGapSummary:
    gap_word_count: int
    interval_count: int
    filler_word_count: int
    anchor_match_interval_count: int
    no_anchor_match_interval_count: int
    multiple_anchor_match_interval_count: int
    anchor_match_filler_count: int
    first_filler_anchor_match_count: int
    second_filler_anchor_match_count: int
    anchor_match_position_counts: dict[str, int]

    def to_dict(self) -> dict[str, object]:
        return {
            "gap_word_count": self.gap_word_count,
            "interval_count": self.interval_count,
            "filler_word_count": self.filler_word_count,
            "anchor_match_interval_count": self.anchor_match_interval_count,
            "no_anchor_match_interval_count": self.no_anchor_match_interval_count,
            "multiple_anchor_match_interval_count": (
                self.multiple_anchor_match_interval_count
            ),
            "anchor_match_filler_count": self.anchor_match_filler_count,
            "first_filler_anchor_match_count": self.first_filler_anchor_match_count,
            "second_filler_anchor_match_count": self.second_filler_anchor_match_count,
            "anchor_match_position_counts": self.anchor_match_position_counts,
        }


@dataclass(frozen=True)
class DsyRegion3FirstRunLinkSummary:
    path: str | None
    region_offset: int
    prefix_byte_length: int
    first_run_start_word_index: int
    first_run_end_word_index: int
    first_run_sentinel_word_count: int
    interval_count: int
    anchor_match_interval_count: int
    no_anchor_match_interval_count: int
    multiple_anchor_match_interval_count: int
    anchor_match_filler_count: int
    gap_summaries: list[DsyRegion3FirstRunIntervalGapSummary]

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "region_offset": self.region_offset,
            "prefix_byte_length": self.prefix_byte_length,
            "first_run_start_word_index": self.first_run_start_word_index,
            "first_run_end_word_index": self.first_run_end_word_index,
            "first_run_sentinel_word_count": self.first_run_sentinel_word_count,
            "interval_count": self.interval_count,
            "anchor_match_interval_count": self.anchor_match_interval_count,
            "no_anchor_match_interval_count": self.no_anchor_match_interval_count,
            "multiple_anchor_match_interval_count": (
                self.multiple_anchor_match_interval_count
            ),
            "anchor_match_filler_count": self.anchor_match_filler_count,
            "gap_summaries": [gap.to_dict() for gap in self.gap_summaries],
        }


@dataclass(frozen=True)
class DsyRegion3FirstRunNoMatchGapSummary:
    gap_word_count: int
    interval_count: int
    interval_ordinal_min: int | None
    interval_ordinal_max: int | None
    anchor_word_index_min: int | None
    anchor_word_index_max: int | None
    filler_word_count: int
    filler_min_value: int | None
    filler_max_value: int | None
    filler_unique_value_count: int
    filler_even_value_count: int
    filler_le_0x0100_count: int
    filler_zero_count: int

    def to_dict(self) -> dict[str, object]:
        return {
            "gap_word_count": self.gap_word_count,
            "interval_count": self.interval_count,
            "interval_ordinal_min": self.interval_ordinal_min,
            "interval_ordinal_max": self.interval_ordinal_max,
            "anchor_word_index_min": self.anchor_word_index_min,
            "anchor_word_index_max": self.anchor_word_index_max,
            "filler_word_count": self.filler_word_count,
            "filler_min_value": self.filler_min_value,
            "filler_max_value": self.filler_max_value,
            "filler_unique_value_count": self.filler_unique_value_count,
            "filler_even_value_count": self.filler_even_value_count,
            "filler_le_0x0100_count": self.filler_le_0x0100_count,
            "filler_zero_count": self.filler_zero_count,
        }


@dataclass(frozen=True)
class DsyRegion3FirstRunSecondaryMatchGapSummary:
    gap_word_count: int
    interval_count: int
    interval_ordinal_min: int | None
    interval_ordinal_max: int | None
    anchor_word_index_min: int | None
    anchor_word_index_max: int | None
    non_first_match_filler_count: int
    late_after_second_match_filler_count: int
    non_first_match_position_counts: dict[str, int]
    late_after_second_match_position_counts: dict[str, int]

    def to_dict(self) -> dict[str, object]:
        return {
            "gap_word_count": self.gap_word_count,
            "interval_count": self.interval_count,
            "interval_ordinal_min": self.interval_ordinal_min,
            "interval_ordinal_max": self.interval_ordinal_max,
            "anchor_word_index_min": self.anchor_word_index_min,
            "anchor_word_index_max": self.anchor_word_index_max,
            "non_first_match_filler_count": self.non_first_match_filler_count,
            "late_after_second_match_filler_count": (
                self.late_after_second_match_filler_count
            ),
            "non_first_match_position_counts": self.non_first_match_position_counts,
            "late_after_second_match_position_counts": (
                self.late_after_second_match_position_counts
            ),
        }


@dataclass(frozen=True)
class DsyRegion3FirstRunOutlierSummary:
    path: str | None
    region_offset: int
    prefix_byte_length: int
    first_run_start_word_index: int
    first_run_end_word_index: int
    first_run_sentinel_word_count: int
    interval_count: int
    no_anchor_match_interval_count: int
    non_first_anchor_match_interval_count: int
    non_first_anchor_match_filler_count: int
    late_after_second_anchor_match_interval_count: int
    late_after_second_anchor_match_filler_count: int
    no_anchor_match_gap_summaries: list[DsyRegion3FirstRunNoMatchGapSummary]
    non_first_anchor_match_gap_summaries: list[
        DsyRegion3FirstRunSecondaryMatchGapSummary
    ]

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "region_offset": self.region_offset,
            "prefix_byte_length": self.prefix_byte_length,
            "first_run_start_word_index": self.first_run_start_word_index,
            "first_run_end_word_index": self.first_run_end_word_index,
            "first_run_sentinel_word_count": self.first_run_sentinel_word_count,
            "interval_count": self.interval_count,
            "no_anchor_match_interval_count": self.no_anchor_match_interval_count,
            "non_first_anchor_match_interval_count": (
                self.non_first_anchor_match_interval_count
            ),
            "non_first_anchor_match_filler_count": (
                self.non_first_anchor_match_filler_count
            ),
            "late_after_second_anchor_match_interval_count": (
                self.late_after_second_anchor_match_interval_count
            ),
            "late_after_second_anchor_match_filler_count": (
                self.late_after_second_anchor_match_filler_count
            ),
            "no_anchor_match_gap_summaries": [
                gap.to_dict() for gap in self.no_anchor_match_gap_summaries
            ],
            "non_first_anchor_match_gap_summaries": [
                gap.to_dict() for gap in self.non_first_anchor_match_gap_summaries
            ],
        }


@dataclass(frozen=True)
class DsyRegion3RunIndexLinkCategorySummary:
    category: str
    interval_count: int
    interval_ordinal_min: int | None
    interval_ordinal_max: int | None
    same_index_later_run_count: int
    missing_later_run_count: int
    missing_interval_ordinal_min: int | None
    missing_interval_ordinal_max: int | None
    first_run_gap_counts: dict[str, int]
    linked_later_run_value_count_min: int | None
    linked_later_run_value_count_max: int | None
    linked_later_run_value_count_counts: dict[str, int]
    linked_later_run_word_span_min: int | None
    linked_later_run_word_span_max: int | None
    linked_later_run_value_ordinal_min: int | None
    linked_later_run_value_ordinal_max: int | None

    def to_dict(self) -> dict[str, object]:
        return {
            "category": self.category,
            "interval_count": self.interval_count,
            "interval_ordinal_min": self.interval_ordinal_min,
            "interval_ordinal_max": self.interval_ordinal_max,
            "same_index_later_run_count": self.same_index_later_run_count,
            "missing_later_run_count": self.missing_later_run_count,
            "missing_interval_ordinal_min": self.missing_interval_ordinal_min,
            "missing_interval_ordinal_max": self.missing_interval_ordinal_max,
            "first_run_gap_counts": self.first_run_gap_counts,
            "linked_later_run_value_count_min": (
                self.linked_later_run_value_count_min
            ),
            "linked_later_run_value_count_max": (
                self.linked_later_run_value_count_max
            ),
            "linked_later_run_value_count_counts": (
                self.linked_later_run_value_count_counts
            ),
            "linked_later_run_word_span_min": self.linked_later_run_word_span_min,
            "linked_later_run_word_span_max": self.linked_later_run_word_span_max,
            "linked_later_run_value_ordinal_min": (
                self.linked_later_run_value_ordinal_min
            ),
            "linked_later_run_value_ordinal_max": (
                self.linked_later_run_value_ordinal_max
            ),
        }


@dataclass(frozen=True)
class DsyRegion3RunIndexLinkSummary:
    path: str | None
    region_offset: int
    prefix_byte_length: int
    first_run_sentinel_word_count: int
    first_run_interval_count: int
    descending_run_count: int
    later_run_count: int
    same_index_later_run_count: int
    missing_later_run_count: int
    later_run_without_first_run_interval_count: int
    category_summaries: list[DsyRegion3RunIndexLinkCategorySummary]

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "region_offset": self.region_offset,
            "prefix_byte_length": self.prefix_byte_length,
            "first_run_sentinel_word_count": self.first_run_sentinel_word_count,
            "first_run_interval_count": self.first_run_interval_count,
            "descending_run_count": self.descending_run_count,
            "later_run_count": self.later_run_count,
            "same_index_later_run_count": self.same_index_later_run_count,
            "missing_later_run_count": self.missing_later_run_count,
            "later_run_without_first_run_interval_count": (
                self.later_run_without_first_run_interval_count
            ),
            "category_summaries": [
                category.to_dict() for category in self.category_summaries
            ],
        }


@dataclass(frozen=True)
class DsyRegion3Gap4SlotSummary:
    slot_index: int
    value_count: int
    min_value: int | None
    max_value: int | None
    unique_value_count: int
    even_value_count: int
    le_0x0100_count: int
    zero_count: int

    def to_dict(self) -> dict[str, object]:
        return {
            "slot_index": self.slot_index,
            "value_count": self.value_count,
            "min_value": self.min_value,
            "max_value": self.max_value,
            "unique_value_count": self.unique_value_count,
            "even_value_count": self.even_value_count,
            "le_0x0100_count": self.le_0x0100_count,
            "zero_count": self.zero_count,
        }


@dataclass(frozen=True)
class DsyRegion3Gap4Summary:
    path: str | None
    region_offset: int
    prefix_byte_length: int
    first_run_start_word_index: int
    first_run_end_word_index: int
    first_run_sentinel_word_count: int
    gap4_chunk_count: int
    slot_summaries: list[DsyRegion3Gap4SlotSummary]
    slot_0_equals_slot_1_count: int
    slot_0_le_slot_1_count: int
    slot_0_and_slot_1_even_count: int
    slot_2_le_0x0100_count: int

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "region_offset": self.region_offset,
            "prefix_byte_length": self.prefix_byte_length,
            "first_run_start_word_index": self.first_run_start_word_index,
            "first_run_end_word_index": self.first_run_end_word_index,
            "first_run_sentinel_word_count": self.first_run_sentinel_word_count,
            "gap4_chunk_count": self.gap4_chunk_count,
            "slot_summaries": [slot.to_dict() for slot in self.slot_summaries],
            "slot_0_equals_slot_1_count": self.slot_0_equals_slot_1_count,
            "slot_0_le_slot_1_count": self.slot_0_le_slot_1_count,
            "slot_0_and_slot_1_even_count": self.slot_0_and_slot_1_even_count,
            "slot_2_le_0x0100_count": self.slot_2_le_0x0100_count,
        }


@dataclass(frozen=True)
class DsyRegion3Gap4LinkSlotSummary:
    slot_index: int
    value_count: int
    region1_record_index_range_count: int
    prefix_word_index_range_count: int
    prefix_byte_offset_range_count: int
    first_run_word_index_range_count: int
    equals_anchor_word_index_count: int
    equals_next_word_index_count: int
    times2_plus2_anchor_count: int
    times2_plus6_next_count: int
    adjacent_increase_count: int
    adjacent_non_decrease_count: int
    adjacent_decrease_count: int
    adjacent_delta_counts: dict[str, int]

    def to_dict(self) -> dict[str, object]:
        return {
            "slot_index": self.slot_index,
            "value_count": self.value_count,
            "region1_record_index_range_count": (
                self.region1_record_index_range_count
            ),
            "prefix_word_index_range_count": self.prefix_word_index_range_count,
            "prefix_byte_offset_range_count": self.prefix_byte_offset_range_count,
            "first_run_word_index_range_count": self.first_run_word_index_range_count,
            "equals_anchor_word_index_count": self.equals_anchor_word_index_count,
            "equals_next_word_index_count": self.equals_next_word_index_count,
            "times2_plus2_anchor_count": self.times2_plus2_anchor_count,
            "times2_plus6_next_count": self.times2_plus6_next_count,
            "adjacent_increase_count": self.adjacent_increase_count,
            "adjacent_non_decrease_count": self.adjacent_non_decrease_count,
            "adjacent_decrease_count": self.adjacent_decrease_count,
            "adjacent_delta_counts": self.adjacent_delta_counts,
        }


@dataclass(frozen=True)
class DsyRegion3Gap4LinkSummary:
    path: str | None
    region_offset: int
    prefix_byte_length: int
    prefix_word_count: int
    region1_record_count: int
    first_run_start_word_index: int
    first_run_end_word_index: int
    gap4_chunk_count: int
    slot_summaries: list[DsyRegion3Gap4LinkSlotSummary]
    slot_1_minus_slot_0_counts: dict[str, int]

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "region_offset": self.region_offset,
            "prefix_byte_length": self.prefix_byte_length,
            "prefix_word_count": self.prefix_word_count,
            "region1_record_count": self.region1_record_count,
            "first_run_start_word_index": self.first_run_start_word_index,
            "first_run_end_word_index": self.first_run_end_word_index,
            "gap4_chunk_count": self.gap4_chunk_count,
            "slot_summaries": [slot.to_dict() for slot in self.slot_summaries],
            "slot_1_minus_slot_0_counts": self.slot_1_minus_slot_0_counts,
        }


@dataclass(frozen=True)
class _DsyRegion3Gap4Chunk:
    ordinal: int
    anchor_word_index: int
    next_word_index: int
    values: tuple[int, int, int]


@dataclass(frozen=True)
class _DsyRegion3FirstRunInterval:
    ordinal: int
    anchor_word_index: int
    next_word_index: int
    gap_word_count: int
    filler_values: list[int]


def parse_dsy_map(path_or_file: str | Path) -> DsyMap:
    path = Path(path_or_file)
    header = parse_header(path)
    if header.container_magic != "DSY":
        raise ValueError("DSY map parsing requires a DSY container")
    if header.size is None:
        raise ValueError("DSY map parsing requires a filesystem path")
    if header.size < DSY_REGION_TABLE_END:
        raise ValueError("DSY container is too small to contain the observed map")

    with path.open("rb") as handle:
        data = handle.read(DSY_REGION_TABLE_END)
    metadata_words = {
        f"0x{offset:03x}": int.from_bytes(data[offset : offset + 4], "big")
        for offset in range(
            DSY_METADATA_OFFSET,
            DSY_METADATA_OFFSET + DSY_METADATA_BYTE_LENGTH,
            4,
        )
    }

    regions: list[DsyRegionDescriptor] = []
    for descriptor_offset in range(
        DSY_REGION_TABLE_OFFSET,
        DSY_REGION_TABLE_END,
        DSY_REGION_RECORD_SIZE,
    ):
        data_offset = int.from_bytes(data[descriptor_offset : descriptor_offset + 4], "big")
        byte_length = int.from_bytes(
            data[descriptor_offset + 4 : descriptor_offset + 8], "big"
        )
        if data_offset == 0 and byte_length == 0:
            continue
        end_offset = data_offset + byte_length
        if data_offset > header.size or end_offset > header.size:
            raise ValueError("DSY region descriptor points outside the file")
        regions.append(
            DsyRegionDescriptor(
                descriptor_offset=descriptor_offset,
                data_offset=data_offset,
                byte_length=byte_length,
                end_offset=end_offset,
            )
        )

    regions_cover = bool(regions) and regions[0].data_offset == DSY_REGION_TABLE_END
    regions_cover = regions_cover and regions[-1].end_offset == header.size
    regions_cover = regions_cover and all(
        earlier.end_offset == later.data_offset
        for earlier, later in zip(regions, regions[1:])
    )

    field_0x314 = metadata_words["0x314"]
    return DsyMap(
        path=str(path),
        size=header.size,
        metadata_words=metadata_words,
        field_0x30c_count_like=metadata_words["0x30c"],
        field_0x314_high=field_0x314 >> 16,
        field_0x314_low_count_like=field_0x314 & 0xFFFF,
        regions=regions,
        regions_cover_from_0x360_to_eof=regions_cover,
    )


def parse_dsy_region1_index(path_or_file: str | Path) -> DsyRegion1Index:
    path = Path(path_or_file)
    dsy_map = parse_dsy_map(path)
    if len(dsy_map.regions) < 2:
        raise ValueError("DSY region 1 index requires at least two mapped regions")

    region = dsy_map.regions[1]
    record_count = dsy_map.field_0x30c_count_like
    if record_count <= 0:
        raise ValueError("DSY region 1 index requires a positive metadata record count")

    table_byte_length = record_count * DSY_REGION1_INDEX_RECORD_SIZE
    if table_byte_length > region.byte_length:
        raise ValueError("DSY region 1 index table exceeds region 1 length")

    with path.open("rb") as handle:
        handle.seek(region.data_offset)
        table = handle.read(table_byte_length)
    if len(table) != table_byte_length:
        raise ValueError("DSY region 1 index table is truncated")

    records = [
        (
            int.from_bytes(
                table[offset : offset + 4],
                "big",
            ),
            int.from_bytes(
                table[offset + 4 : offset + DSY_REGION1_INDEX_RECORD_SIZE],
                "big",
            ),
        )
        for offset in range(0, table_byte_length, DSY_REGION1_INDEX_RECORD_SIZE)
    ]
    table_header_first_field, table_header_second_field = records[0]
    if table_header_first_field != table_byte_length:
        raise ValueError("DSY region 1 table header does not match metadata count")
    if table_header_second_field != 0:
        raise ValueError("DSY region 1 table header second field is not zero")

    payload_base_offset = region.data_offset + table_byte_length
    entries: list[DsyRegion1IndexEntry] = []
    previous_end = 0
    for index, (byte_length, cumulative_end) in enumerate(records[1:], start=1):
        if cumulative_end != previous_end + byte_length:
            raise ValueError("DSY region 1 table entries are not cumulative")
        payload_offset = payload_base_offset + previous_end
        entries.append(
            DsyRegion1IndexEntry(
                table_record_index=index,
                index_record_offset=region.data_offset
                + index * DSY_REGION1_INDEX_RECORD_SIZE,
                payload_offset=payload_offset,
                payload_relative_offset=previous_end,
                byte_length=byte_length,
                end_offset=payload_offset + byte_length,
                cumulative_payload_end=cumulative_end,
            )
        )
        previous_end = cumulative_end

    covered_payload_byte_length = previous_end
    trailer_offset = payload_base_offset + covered_payload_byte_length
    trailer_byte_length = region.end_offset - trailer_offset
    if trailer_byte_length < 0:
        raise ValueError("DSY region 1 index entries exceed region 1 length")

    return DsyRegion1Index(
        path=str(path),
        region_offset=region.data_offset,
        region_byte_length=region.byte_length,
        metadata_record_count=record_count,
        table_byte_length=table_byte_length,
        table_record_count=len(records),
        table_header_first_field=table_header_first_field,
        table_header_second_field=table_header_second_field,
        payload_base_offset=payload_base_offset,
        covered_payload_byte_length=covered_payload_byte_length,
        trailer_offset=trailer_offset,
        trailer_byte_length=trailer_byte_length,
        entries=entries,
    )


def summarize_dsy_region1_records(
    path_or_file: str | Path,
    *,
    scan_bytes: int = DSY_REGION1_RECORD_SCAN_BYTES,
    prefix_hash_bytes: int = DSY_REGION1_RECORD_HASH_BYTES,
) -> DsyRegion1RecordDiagnostics:
    path = Path(path_or_file)
    dsy_map = parse_dsy_map(path)
    index = parse_dsy_region1_index(path)
    region = dsy_map.regions[1]
    payload_records: list[DsyRegion1RecordSummary] = []

    with path.open("rb") as handle:
        for entry in index.entries:
            handle.seek(entry.payload_offset)
            scan = handle.read(min(entry.byte_length, scan_bytes))
            payload_records.append(
                _summarize_dsy_region1_record_scan(
                    scan=scan,
                    dsy_map=dsy_map,
                    index=index,
                    record_kind="payload",
                    table_record_index=entry.table_record_index,
                    record_offset=entry.payload_offset,
                    region_relative_offset=entry.payload_offset - region.data_offset,
                    payload_relative_offset=entry.payload_relative_offset,
                    byte_length=entry.byte_length,
                    prefix_hash_bytes=prefix_hash_bytes,
                )
            )

        handle.seek(index.trailer_offset)
        trailer_scan = handle.read(min(index.trailer_byte_length, scan_bytes))
        trailer_record = _summarize_dsy_region1_record_scan(
            scan=trailer_scan,
            dsy_map=dsy_map,
            index=index,
            record_kind="trailer",
            table_record_index=None,
            record_offset=index.trailer_offset,
            region_relative_offset=index.trailer_offset - region.data_offset,
            payload_relative_offset=None,
            byte_length=index.trailer_byte_length,
            prefix_hash_bytes=prefix_hash_bytes,
        )

    return DsyRegion1RecordDiagnostics(
        path=index.path,
        region_offset=index.region_offset,
        region_byte_length=index.region_byte_length,
        payload_base_offset=index.payload_base_offset,
        covered_payload_byte_length=index.covered_payload_byte_length,
        trailer_offset=index.trailer_offset,
        trailer_byte_length=index.trailer_byte_length,
        payload_record_count=len(index.entries),
        scan_bytes=scan_bytes,
        prefix_hash_bytes=prefix_hash_bytes,
        payload_records=payload_records,
        trailer_record=trailer_record,
    )


def summarize_dsy_region3_prefix(
    path_or_file: str | Path,
    *,
    tail_scan_bytes: int = DSY_REGION3_TAIL_SCAN_BYTES,
    prefix_hash_bytes: int = DSY_REGION3_HASH_BYTES,
) -> DsyRegion3PrefixSummary:
    path = Path(path_or_file)
    dsy_map = parse_dsy_map(path)
    index = parse_dsy_region1_index(path)
    if len(dsy_map.regions) < 4:
        raise ValueError("DSY region 3 prefix diagnostics require four mapped regions")

    region = dsy_map.regions[3]
    prefix = _read_dsy_region3_prefix(path, dsy_map)
    prefix_byte_length = len(prefix)
    tail_byte_length = region.byte_length - prefix_byte_length
    with path.open("rb") as handle:
        handle.seek(region.data_offset + prefix_byte_length)
        tail_scan = handle.read(min(tail_byte_length, tail_scan_bytes))

    prefix_words = _u16_words(prefix)
    return DsyRegion3PrefixSummary(
        path=str(path),
        region_offset=region.data_offset,
        region_byte_length=region.byte_length,
        prefix_byte_length=prefix_byte_length,
        prefix_word_count=len(prefix_words),
        prefix_end_offset=region.data_offset + prefix_byte_length,
        tail_byte_length=tail_byte_length,
        tail_scan_byte_length=len(tail_scan),
        prefix_sha256=hashlib.sha256(prefix[:prefix_hash_bytes]).hexdigest(),
        tail_prefix_sha256=hashlib.sha256(tail_scan[:prefix_hash_bytes]).hexdigest(),
        header_u16_words=prefix_words[:16],
        prefix_marker_counts=_marker_counts(prefix),
        prefix_marker_first_offsets=_marker_first_offsets(prefix),
        tail_marker_counts=_marker_counts(tail_scan),
        tail_marker_first_offsets=_marker_first_offsets(tail_scan),
        prefix_high_u16_word_count=sum(1 for word in prefix_words if word >= 0xFF00),
        prefix_zero_u16_word_count=sum(1 for word in prefix_words if word == 0),
        prefix_unique_u16_word_count=len(set(prefix_words)),
        possible_absolute_offsets_by_region=_possible_absolute_offsets_by_region(
            prefix,
            dsy_map,
        ),
        possible_region_relative_offsets=_possible_region_relative_offsets(
            prefix,
            dsy_map,
        ),
        possible_region1_payload_relative_offsets=_possible_relative_offset_count(
            prefix,
            index.covered_payload_byte_length,
        ),
    )


def summarize_dsy_region3_sentinels(
    path_or_file: str | Path,
    *,
    high_word_minimum: int = DSY_REGION3_HIGH_WORD_MINIMUM,
) -> DsyRegion3SentinelSummary:
    path = Path(path_or_file)
    dsy_map = parse_dsy_map(path)
    prefix = _read_dsy_region3_prefix(path, dsy_map)
    words = _u16_words(prefix)
    high_words = [
        (word_index, value)
        for word_index, value in enumerate(words)
        if value >= high_word_minimum
    ]
    runs = _descending_high_word_runs(high_words)
    first_run = runs[0] if runs else None
    longest_run_length = max((run.value_count for run in runs), default=0)
    return DsyRegion3SentinelSummary(
        path=str(path),
        region_offset=dsy_map.regions[3].data_offset,
        prefix_byte_length=len(prefix),
        prefix_word_count=len(words),
        high_word_minimum=f"0x{high_word_minimum:04x}",
        high_word_count=len(high_words),
        descending_run_count=len(runs),
        first_descending_run_value_count=first_run.value_count if first_run else 0,
        first_descending_run_start_value=(
            f"0x{first_run.start_value:04x}" if first_run else None
        ),
        first_descending_run_end_value=(
            f"0x{first_run.end_value:04x}" if first_run else None
        ),
        longest_descending_run_value_count=longest_run_length,
        descending_runs=runs,
    )


def summarize_dsy_region3_first_run(
    path_or_file: str | Path,
    *,
    high_word_minimum: int = DSY_REGION3_HIGH_WORD_MINIMUM,
) -> DsyRegion3FirstRunSummary:
    path = Path(path_or_file)
    dsy_map = parse_dsy_map(path)
    prefix = _read_dsy_region3_prefix(path, dsy_map)
    words = _u16_words(prefix)
    high_words = [
        (word_index, value)
        for word_index, value in enumerate(words)
        if value >= high_word_minimum
    ]
    runs = _descending_high_word_runs(high_words)
    if not runs:
        raise ValueError("DSY region 3 prefix has no high-word sentinel runs")

    first_run = runs[0]
    sentinel_positions = [
        word_index
        for word_index in range(first_run.start_word_index, first_run.end_word_index + 1)
        if words[word_index] >= high_word_minimum
    ]
    gaps = [
        later - earlier
        for earlier, later in zip(sentinel_positions, sentinel_positions[1:])
    ]
    filler_values = [
        words[word_index]
        for word_index in range(first_run.start_word_index, first_run.end_word_index + 1)
        if words[word_index] < high_word_minimum
    ]
    gap_counts = {
        str(gap): count
        for gap, count in sorted(Counter(gaps).items(), key=lambda item: item[0])
    }
    return DsyRegion3FirstRunSummary(
        path=str(path),
        region_offset=dsy_map.regions[3].data_offset,
        prefix_byte_length=len(prefix),
        start_word_index=first_run.start_word_index,
        end_word_index=first_run.end_word_index,
        start_byte_offset=first_run.start_byte_offset,
        end_byte_offset=first_run.end_byte_offset,
        start_value=f"0x{first_run.start_value:04x}",
        end_value=f"0x{first_run.end_value:04x}",
        sentinel_word_count=first_run.value_count,
        span_word_count=first_run.end_word_index - first_run.start_word_index + 1,
        filler_word_count=len(filler_values),
        gap_counts=gap_counts,
        filler_min_value=min(filler_values) if filler_values else None,
        filler_max_value=max(filler_values) if filler_values else None,
        filler_unique_value_count=len(set(filler_values)),
        filler_even_value_count=sum(1 for value in filler_values if value % 2 == 0),
        filler_le_0x0100_count=sum(1 for value in filler_values if value <= 0x0100),
        filler_zero_count=sum(1 for value in filler_values if value == 0),
    )


def summarize_dsy_region3_first_run_links(
    path_or_file: str | Path,
    *,
    high_word_minimum: int = DSY_REGION3_HIGH_WORD_MINIMUM,
) -> DsyRegion3FirstRunLinkSummary:
    path = Path(path_or_file)
    dsy_map = parse_dsy_map(path)
    prefix = _read_dsy_region3_prefix(path, dsy_map)
    words = _u16_words(prefix)
    first_run = _first_dsy_region3_sentinel_run(words, high_word_minimum)
    intervals = _dsy_region3_first_run_intervals(
        words,
        first_run,
        high_word_minimum,
    )
    anchor_match_positions_by_gap: dict[int, list[int]] = {}
    match_counts_by_interval: list[int] = []
    interval_count_by_gap: Counter[int] = Counter()
    no_match_count_by_gap: Counter[int] = Counter()
    multi_match_count_by_gap: Counter[int] = Counter()
    first_position_count_by_gap: Counter[int] = Counter()
    second_position_count_by_gap: Counter[int] = Counter()
    for interval in intervals:
        gap = interval.gap_word_count
        interval_count_by_gap[gap] += 1
        positions = _dsy_region3_anchor_match_positions(interval)
        anchor_match_positions_by_gap.setdefault(gap, []).extend(positions)
        match_counts_by_interval.append(len(positions))
        if not positions:
            no_match_count_by_gap[gap] += 1
        if len(positions) > 1:
            multi_match_count_by_gap[gap] += 1
        if 1 in positions:
            first_position_count_by_gap[gap] += 1
        if 2 in positions:
            second_position_count_by_gap[gap] += 1

    return DsyRegion3FirstRunLinkSummary(
        path=str(path),
        region_offset=dsy_map.regions[3].data_offset,
        prefix_byte_length=len(prefix),
        first_run_start_word_index=first_run.start_word_index,
        first_run_end_word_index=first_run.end_word_index,
        first_run_sentinel_word_count=first_run.value_count,
        interval_count=len(intervals),
        anchor_match_interval_count=sum(1 for count in match_counts_by_interval if count),
        no_anchor_match_interval_count=sum(
            1 for count in match_counts_by_interval if not count
        ),
        multiple_anchor_match_interval_count=sum(
            1 for count in match_counts_by_interval if count > 1
        ),
        anchor_match_filler_count=sum(match_counts_by_interval),
        gap_summaries=[
            DsyRegion3FirstRunIntervalGapSummary(
                gap_word_count=gap,
                interval_count=interval_count_by_gap[gap],
                filler_word_count=interval_count_by_gap[gap] * (gap - 1),
                anchor_match_interval_count=(
                    interval_count_by_gap[gap] - no_match_count_by_gap[gap]
                ),
                no_anchor_match_interval_count=no_match_count_by_gap[gap],
                multiple_anchor_match_interval_count=multi_match_count_by_gap[gap],
                anchor_match_filler_count=len(anchor_match_positions_by_gap.get(gap, [])),
                first_filler_anchor_match_count=first_position_count_by_gap[gap],
                second_filler_anchor_match_count=second_position_count_by_gap[gap],
                anchor_match_position_counts=_string_key_counts(
                    anchor_match_positions_by_gap.get(gap, [])
                ),
            )
            for gap in sorted(interval_count_by_gap)
        ],
    )


def summarize_dsy_region3_first_run_outliers(
    path_or_file: str | Path,
    *,
    high_word_minimum: int = DSY_REGION3_HIGH_WORD_MINIMUM,
) -> DsyRegion3FirstRunOutlierSummary:
    path = Path(path_or_file)
    dsy_map = parse_dsy_map(path)
    prefix = _read_dsy_region3_prefix(path, dsy_map)
    words = _u16_words(prefix)
    first_run = _first_dsy_region3_sentinel_run(words, high_word_minimum)
    intervals = _dsy_region3_first_run_intervals(
        words,
        first_run,
        high_word_minimum,
    )
    no_match_by_gap: dict[int, list[_DsyRegion3FirstRunInterval]] = {}
    non_first_by_gap: dict[int, list[tuple[_DsyRegion3FirstRunInterval, list[int]]]] = {}
    for interval in intervals:
        positions = _dsy_region3_anchor_match_positions(interval)
        if not positions:
            no_match_by_gap.setdefault(interval.gap_word_count, []).append(interval)
        non_first_positions = [position for position in positions if position > 1]
        if non_first_positions:
            non_first_by_gap.setdefault(interval.gap_word_count, []).append(
                (interval, non_first_positions)
            )

    non_first_pairs = [
        pair for pairs in non_first_by_gap.values() for pair in pairs
    ]
    late_pairs = [
        (interval, [position for position in positions if position > 2])
        for interval, positions in non_first_pairs
        if any(position > 2 for position in positions)
    ]
    return DsyRegion3FirstRunOutlierSummary(
        path=str(path),
        region_offset=dsy_map.regions[3].data_offset,
        prefix_byte_length=len(prefix),
        first_run_start_word_index=first_run.start_word_index,
        first_run_end_word_index=first_run.end_word_index,
        first_run_sentinel_word_count=first_run.value_count,
        interval_count=len(intervals),
        no_anchor_match_interval_count=sum(
            len(intervals_for_gap) for intervals_for_gap in no_match_by_gap.values()
        ),
        non_first_anchor_match_interval_count=len(non_first_pairs),
        non_first_anchor_match_filler_count=sum(
            len(positions) for _, positions in non_first_pairs
        ),
        late_after_second_anchor_match_interval_count=len(late_pairs),
        late_after_second_anchor_match_filler_count=sum(
            len(positions) for _, positions in late_pairs
        ),
        no_anchor_match_gap_summaries=[
            _summarize_dsy_region3_no_match_gap(gap, intervals_for_gap)
            for gap, intervals_for_gap in sorted(no_match_by_gap.items())
        ],
        non_first_anchor_match_gap_summaries=[
            _summarize_dsy_region3_secondary_match_gap(gap, pairs)
            for gap, pairs in sorted(non_first_by_gap.items())
        ],
    )


def summarize_dsy_region3_run_index_links(
    path_or_file: str | Path,
    *,
    high_word_minimum: int = DSY_REGION3_HIGH_WORD_MINIMUM,
) -> DsyRegion3RunIndexLinkSummary:
    path = Path(path_or_file)
    dsy_map = parse_dsy_map(path)
    prefix = _read_dsy_region3_prefix(path, dsy_map)
    words = _u16_words(prefix)
    high_words = [
        (word_index, value)
        for word_index, value in enumerate(words)
        if value >= high_word_minimum
    ]
    runs = _descending_high_word_runs(high_words)
    if not runs:
        raise ValueError("DSY region 3 prefix has no high-word sentinel runs")

    first_run = runs[0]
    later_runs_by_index = {run.run_index: run for run in runs[1:]}
    intervals = _dsy_region3_first_run_intervals(
        words,
        first_run,
        high_word_minimum,
    )
    interval_ordinals = {interval.ordinal for interval in intervals}
    pairs_by_category: dict[
        str,
        list[tuple[_DsyRegion3FirstRunInterval, DsyRegion3SentinelRun | None]],
    ] = {
        "no_anchor_match": [],
        "first_only": [],
        "second_position": [],
        "late_after_second": [],
    }
    same_index_later_run_count = 0
    for interval in intervals:
        later_run = later_runs_by_index.get(interval.ordinal)
        if later_run is not None:
            same_index_later_run_count += 1
        category = _dsy_region3_interval_anchor_category(interval)
        pairs_by_category[category].append((interval, later_run))

    return DsyRegion3RunIndexLinkSummary(
        path=str(path),
        region_offset=dsy_map.regions[3].data_offset,
        prefix_byte_length=len(prefix),
        first_run_sentinel_word_count=first_run.value_count,
        first_run_interval_count=len(intervals),
        descending_run_count=len(runs),
        later_run_count=len(runs) - 1,
        same_index_later_run_count=same_index_later_run_count,
        missing_later_run_count=len(intervals) - same_index_later_run_count,
        later_run_without_first_run_interval_count=sum(
            1 for run_index in later_runs_by_index if run_index not in interval_ordinals
        ),
        category_summaries=[
            _summarize_dsy_region3_run_index_category(category, pairs)
            for category, pairs in pairs_by_category.items()
        ],
    )


def summarize_dsy_region3_gap4(
    path_or_file: str | Path,
    *,
    high_word_minimum: int = DSY_REGION3_HIGH_WORD_MINIMUM,
) -> DsyRegion3Gap4Summary:
    path = Path(path_or_file)
    dsy_map = parse_dsy_map(path)
    prefix = _read_dsy_region3_prefix(path, dsy_map)
    words = _u16_words(prefix)
    first_run = _first_dsy_region3_sentinel_run(words, high_word_minimum)
    chunks = _dsy_region3_gap4_chunks(words, first_run, high_word_minimum)
    slots = [
        [chunk.values[slot_index] for chunk in chunks]
        for slot_index in range(3)
    ]
    return DsyRegion3Gap4Summary(
        path=str(path),
        region_offset=dsy_map.regions[3].data_offset,
        prefix_byte_length=len(prefix),
        first_run_start_word_index=first_run.start_word_index,
        first_run_end_word_index=first_run.end_word_index,
        first_run_sentinel_word_count=first_run.value_count,
        gap4_chunk_count=len(chunks),
        slot_summaries=[
            _summarize_dsy_region3_gap4_slot(index, values)
            for index, values in enumerate(slots)
        ],
        slot_0_equals_slot_1_count=sum(
            1 for chunk in chunks if chunk.values[0] == chunk.values[1]
        ),
        slot_0_le_slot_1_count=sum(
            1 for chunk in chunks if chunk.values[0] <= chunk.values[1]
        ),
        slot_0_and_slot_1_even_count=sum(
            1
            for chunk in chunks
            if chunk.values[0] % 2 == 0 and chunk.values[1] % 2 == 0
        ),
        slot_2_le_0x0100_count=sum(
            1 for chunk in chunks if chunk.values[2] <= 0x0100
        ),
    )


def summarize_dsy_region3_gap4_links(
    path_or_file: str | Path,
    *,
    high_word_minimum: int = DSY_REGION3_HIGH_WORD_MINIMUM,
) -> DsyRegion3Gap4LinkSummary:
    path = Path(path_or_file)
    dsy_map = parse_dsy_map(path)
    region1_index = parse_dsy_region1_index(path)
    prefix = _read_dsy_region3_prefix(path, dsy_map)
    words = _u16_words(prefix)
    first_run = _first_dsy_region3_sentinel_run(words, high_word_minimum)
    chunks = _dsy_region3_gap4_chunks(words, first_run, high_word_minimum)
    return DsyRegion3Gap4LinkSummary(
        path=str(path),
        region_offset=dsy_map.regions[3].data_offset,
        prefix_byte_length=len(prefix),
        prefix_word_count=len(words),
        region1_record_count=len(region1_index.entries),
        first_run_start_word_index=first_run.start_word_index,
        first_run_end_word_index=first_run.end_word_index,
        gap4_chunk_count=len(chunks),
        slot_summaries=[
            _summarize_dsy_region3_gap4_link_slot(
                slot_index=slot_index,
                chunks=chunks,
                region1_record_count=len(region1_index.entries),
                prefix_word_count=len(words),
                prefix_byte_length=len(prefix),
                first_run=first_run,
            )
            for slot_index in range(3)
        ],
        slot_1_minus_slot_0_counts=_string_key_counts(
            chunk.values[1] - chunk.values[0] for chunk in chunks
        ),
    )


def summarize_dsy_regions(
    path_or_file: str | Path,
    *,
    scan_bytes: int = DSY_REGION_SCAN_BYTES,
    prefix_hash_bytes: int = DSY_REGION_HASH_BYTES,
) -> list[DsyRegionSummary]:
    path = Path(path_or_file)
    dsy_map = parse_dsy_map(path)
    summaries: list[DsyRegionSummary] = []
    with path.open("rb") as handle:
        for index, region in enumerate(dsy_map.regions):
            handle.seek(region.data_offset)
            scan = handle.read(min(region.byte_length, scan_bytes))
            region0_permutation = None
            if index == 0 and region.byte_length <= scan_bytes:
                region0_permutation = _is_u16_permutation_1_to_256(scan)
            u16_words = [
                int.from_bytes(scan[offset : offset + 2], "big")
                for offset in range(0, len(scan) - 1, 2)
            ]
            summaries.append(
                DsyRegionSummary(
                    region_index=index,
                    data_offset=region.data_offset,
                    byte_length=region.byte_length,
                    scan_byte_length=len(scan),
                    prefix_sha256=hashlib.sha256(
                        scan[:prefix_hash_bytes]
                    ).hexdigest(),
                    nul_byte_ratio=_byte_ratio(scan, lambda value: value == 0),
                    printable_ascii_ratio=_byte_ratio(
                        scan, lambda value: 0x20 <= value <= 0x7E
                    ),
                    unique_byte_count=len(set(scan)),
                    marker_counts=_marker_counts(scan),
                    marker_first_offsets=_marker_first_offsets(scan),
                    u16_word_count=len(u16_words),
                    u16_nonzero_count=sum(1 for value in u16_words if value),
                    u16_unique_count=len(set(u16_words)),
                    region0_is_u16_permutation_1_to_256=region0_permutation,
                )
            )
    return summaries


def _is_u16_permutation_1_to_256(data: bytes) -> bool:
    if len(data) != 512:
        return False
    values = [
        int.from_bytes(data[offset : offset + 2], "big")
        for offset in range(0, 512, 2)
    ]
    return sorted(values) == list(range(1, 257))


def _marker_first_offsets(data: bytes) -> dict[str, int | None]:
    found: dict[str, int | None] = {f"0x{marker:04x}": None for marker in CHILD_MARKERS}
    for offset in range(0, len(data) - 1, 2):
        value = int.from_bytes(data[offset : offset + 2], "big")
        key = f"0x{value:04x}"
        if key in found and found[key] is None:
            found[key] = offset
    return found


def _marker_counts(data: bytes) -> dict[str, int]:
    counts = {f"0x{marker:04x}": 0 for marker in CHILD_MARKERS}
    for offset in range(0, len(data) - 1, 2):
        value = int.from_bytes(data[offset : offset + 2], "big")
        key = f"0x{value:04x}"
        if key in counts:
            counts[key] += 1
    return counts


def _read_dsy_region3_prefix(path: Path, dsy_map: DsyMap) -> bytes:
    if len(dsy_map.regions) < 4:
        raise ValueError("DSY region 3 diagnostics require four mapped regions")
    region = dsy_map.regions[3]
    with path.open("rb") as handle:
        handle.seek(region.data_offset)
        prefix_length_bytes = handle.read(2)
        if len(prefix_length_bytes) != 2:
            raise ValueError("DSY region 3 is too small to contain a prefix length")
        prefix_byte_length = int.from_bytes(prefix_length_bytes, "big")
        if prefix_byte_length % 2:
            raise ValueError("DSY region 3 prefix length is not 16-bit aligned")
        if prefix_byte_length > region.byte_length:
            raise ValueError("DSY region 3 prefix length exceeds region length")

        handle.seek(region.data_offset)
        prefix = handle.read(prefix_byte_length)
        if len(prefix) != prefix_byte_length:
            raise ValueError("DSY region 3 prefix is truncated")
        return prefix


def _descending_high_word_runs(
    high_words: list[tuple[int, int]],
) -> list[DsyRegion3SentinelRun]:
    if not high_words:
        return []

    raw_runs: list[tuple[int, int, int, int]] = []
    start_word_index, start_value = high_words[0]
    end_word_index, end_value = high_words[0]
    for word_index, value in high_words[1:]:
        if value == end_value - 1:
            end_word_index = word_index
            end_value = value
            continue
        raw_runs.append((start_word_index, end_word_index, start_value, end_value))
        start_word_index = word_index
        start_value = value
        end_word_index = word_index
        end_value = value
    raw_runs.append((start_word_index, end_word_index, start_value, end_value))

    return [
        DsyRegion3SentinelRun(
            run_index=index,
            start_word_index=start_word_index,
            end_word_index=end_word_index,
            start_byte_offset=start_word_index * 2,
            end_byte_offset=end_word_index * 2,
            start_value=start_value,
            end_value=end_value,
            value_count=start_value - end_value + 1,
        )
        for index, (start_word_index, end_word_index, start_value, end_value) in enumerate(
            raw_runs
        )
    ]


def _first_dsy_region3_sentinel_run(
    words: list[int],
    high_word_minimum: int,
) -> DsyRegion3SentinelRun:
    high_words = [
        (word_index, value)
        for word_index, value in enumerate(words)
        if value >= high_word_minimum
    ]
    runs = _descending_high_word_runs(high_words)
    if not runs:
        raise ValueError("DSY region 3 prefix has no high-word sentinel runs")
    return runs[0]


def _dsy_region3_first_run_intervals(
    words: list[int],
    first_run: DsyRegion3SentinelRun,
    high_word_minimum: int,
) -> list[_DsyRegion3FirstRunInterval]:
    sentinel_positions = [
        word_index
        for word_index in range(first_run.start_word_index, first_run.end_word_index + 1)
        if words[word_index] >= high_word_minimum
    ]
    return [
        _DsyRegion3FirstRunInterval(
            ordinal=ordinal,
            anchor_word_index=earlier,
            next_word_index=later,
            gap_word_count=later - earlier,
            filler_values=words[earlier + 1 : later],
        )
        for ordinal, (earlier, later) in enumerate(
            zip(sentinel_positions, sentinel_positions[1:])
        )
    ]


def _dsy_region3_anchor_match_positions(
    interval: _DsyRegion3FirstRunInterval,
) -> list[int]:
    return [
        relative_position
        for relative_position, value in enumerate(interval.filler_values, start=1)
        if value * 2 + 2 == interval.anchor_word_index
    ]


def _dsy_region3_interval_anchor_category(
    interval: _DsyRegion3FirstRunInterval,
) -> str:
    positions = _dsy_region3_anchor_match_positions(interval)
    if not positions:
        return "no_anchor_match"
    if any(position > 2 for position in positions):
        return "late_after_second"
    if any(position > 1 for position in positions):
        return "second_position"
    return "first_only"


def _summarize_dsy_region3_no_match_gap(
    gap_word_count: int,
    intervals: list[_DsyRegion3FirstRunInterval],
) -> DsyRegion3FirstRunNoMatchGapSummary:
    ordinals = [interval.ordinal for interval in intervals]
    anchor_word_indexes = [interval.anchor_word_index for interval in intervals]
    filler_values = [value for interval in intervals for value in interval.filler_values]
    return DsyRegion3FirstRunNoMatchGapSummary(
        gap_word_count=gap_word_count,
        interval_count=len(intervals),
        interval_ordinal_min=min(ordinals) if ordinals else None,
        interval_ordinal_max=max(ordinals) if ordinals else None,
        anchor_word_index_min=min(anchor_word_indexes) if anchor_word_indexes else None,
        anchor_word_index_max=max(anchor_word_indexes) if anchor_word_indexes else None,
        filler_word_count=len(filler_values),
        filler_min_value=min(filler_values) if filler_values else None,
        filler_max_value=max(filler_values) if filler_values else None,
        filler_unique_value_count=len(set(filler_values)),
        filler_even_value_count=sum(1 for value in filler_values if value % 2 == 0),
        filler_le_0x0100_count=sum(1 for value in filler_values if value <= 0x0100),
        filler_zero_count=sum(1 for value in filler_values if value == 0),
    )


def _summarize_dsy_region3_run_index_category(
    category: str,
    pairs: list[tuple[_DsyRegion3FirstRunInterval, DsyRegion3SentinelRun | None]],
) -> DsyRegion3RunIndexLinkCategorySummary:
    intervals = [interval for interval, _ in pairs]
    linked_runs = [run for _, run in pairs if run is not None]
    missing_ordinals = [
        interval.ordinal for interval, run in pairs if run is None
    ]
    interval_ordinals = [interval.ordinal for interval in intervals]
    later_run_value_counts = [run.value_count for run in linked_runs]
    later_run_word_spans = [
        run.end_word_index - run.start_word_index + 1 for run in linked_runs
    ]
    later_run_value_ordinals = [
        ordinal
        for run in linked_runs
        for ordinal in (0xFFFF - run.start_value, 0xFFFF - run.end_value)
    ]
    return DsyRegion3RunIndexLinkCategorySummary(
        category=category,
        interval_count=len(intervals),
        interval_ordinal_min=min(interval_ordinals) if interval_ordinals else None,
        interval_ordinal_max=max(interval_ordinals) if interval_ordinals else None,
        same_index_later_run_count=len(linked_runs),
        missing_later_run_count=len(missing_ordinals),
        missing_interval_ordinal_min=(
            min(missing_ordinals) if missing_ordinals else None
        ),
        missing_interval_ordinal_max=(
            max(missing_ordinals) if missing_ordinals else None
        ),
        first_run_gap_counts=_string_key_counts(
            interval.gap_word_count for interval in intervals
        ),
        linked_later_run_value_count_min=(
            min(later_run_value_counts) if later_run_value_counts else None
        ),
        linked_later_run_value_count_max=(
            max(later_run_value_counts) if later_run_value_counts else None
        ),
        linked_later_run_value_count_counts=_string_key_counts(
            later_run_value_counts
        ),
        linked_later_run_word_span_min=(
            min(later_run_word_spans) if later_run_word_spans else None
        ),
        linked_later_run_word_span_max=(
            max(later_run_word_spans) if later_run_word_spans else None
        ),
        linked_later_run_value_ordinal_min=(
            min(later_run_value_ordinals) if later_run_value_ordinals else None
        ),
        linked_later_run_value_ordinal_max=(
            max(later_run_value_ordinals) if later_run_value_ordinals else None
        ),
    )


def _summarize_dsy_region3_secondary_match_gap(
    gap_word_count: int,
    pairs: list[tuple[_DsyRegion3FirstRunInterval, list[int]]],
) -> DsyRegion3FirstRunSecondaryMatchGapSummary:
    intervals = [interval for interval, _ in pairs]
    ordinals = [interval.ordinal for interval in intervals]
    anchor_word_indexes = [interval.anchor_word_index for interval in intervals]
    non_first_positions = [position for _, positions in pairs for position in positions]
    late_positions = [
        position for position in non_first_positions if position > 2
    ]
    return DsyRegion3FirstRunSecondaryMatchGapSummary(
        gap_word_count=gap_word_count,
        interval_count=len(intervals),
        interval_ordinal_min=min(ordinals) if ordinals else None,
        interval_ordinal_max=max(ordinals) if ordinals else None,
        anchor_word_index_min=min(anchor_word_indexes) if anchor_word_indexes else None,
        anchor_word_index_max=max(anchor_word_indexes) if anchor_word_indexes else None,
        non_first_match_filler_count=len(non_first_positions),
        late_after_second_match_filler_count=len(late_positions),
        non_first_match_position_counts=_string_key_counts(non_first_positions),
        late_after_second_match_position_counts=_string_key_counts(late_positions),
    )


def _dsy_region3_gap4_chunks(
    words: list[int],
    first_run: DsyRegion3SentinelRun,
    high_word_minimum: int,
) -> list[_DsyRegion3Gap4Chunk]:
    sentinel_positions = [
        word_index
        for word_index in range(first_run.start_word_index, first_run.end_word_index + 1)
        if words[word_index] >= high_word_minimum
    ]
    return [
        _DsyRegion3Gap4Chunk(
            ordinal=ordinal,
            anchor_word_index=earlier,
            next_word_index=later,
            values=(
                words[earlier + 1],
                words[earlier + 2],
                words[earlier + 3],
            ),
        )
        for ordinal, (earlier, later) in enumerate(
            zip(sentinel_positions, sentinel_positions[1:])
        )
        if later - earlier == 4
    ]


def _summarize_dsy_region3_gap4_slot(
    slot_index: int,
    values: list[int],
) -> DsyRegion3Gap4SlotSummary:
    return DsyRegion3Gap4SlotSummary(
        slot_index=slot_index,
        value_count=len(values),
        min_value=min(values) if values else None,
        max_value=max(values) if values else None,
        unique_value_count=len(set(values)),
        even_value_count=sum(1 for value in values if value % 2 == 0),
        le_0x0100_count=sum(1 for value in values if value <= 0x0100),
        zero_count=sum(1 for value in values if value == 0),
    )


def _summarize_dsy_region3_gap4_link_slot(
    *,
    slot_index: int,
    chunks: list[_DsyRegion3Gap4Chunk],
    region1_record_count: int,
    prefix_word_count: int,
    prefix_byte_length: int,
    first_run: DsyRegion3SentinelRun,
) -> DsyRegion3Gap4LinkSlotSummary:
    values = [chunk.values[slot_index] for chunk in chunks]
    adjacent_deltas = [later - earlier for earlier, later in zip(values, values[1:])]
    return DsyRegion3Gap4LinkSlotSummary(
        slot_index=slot_index,
        value_count=len(values),
        region1_record_index_range_count=sum(
            1 for value in values if 1 <= value <= region1_record_count
        ),
        prefix_word_index_range_count=sum(
            1 for value in values if 0 <= value < prefix_word_count
        ),
        prefix_byte_offset_range_count=sum(
            1 for value in values if 0 <= value < prefix_byte_length
        ),
        first_run_word_index_range_count=sum(
            1
            for value in values
            if first_run.start_word_index <= value <= first_run.end_word_index
        ),
        equals_anchor_word_index_count=sum(
            1
            for chunk in chunks
            if chunk.values[slot_index] == chunk.anchor_word_index
        ),
        equals_next_word_index_count=sum(
            1 for chunk in chunks if chunk.values[slot_index] == chunk.next_word_index
        ),
        times2_plus2_anchor_count=sum(
            1
            for chunk in chunks
            if chunk.values[slot_index] * 2 + 2 == chunk.anchor_word_index
        ),
        times2_plus6_next_count=sum(
            1
            for chunk in chunks
            if chunk.values[slot_index] * 2 + 6 == chunk.next_word_index
        ),
        adjacent_increase_count=sum(1 for delta in adjacent_deltas if delta > 0),
        adjacent_non_decrease_count=sum(1 for delta in adjacent_deltas if delta >= 0),
        adjacent_decrease_count=sum(1 for delta in adjacent_deltas if delta < 0),
        adjacent_delta_counts=_string_key_counts(adjacent_deltas),
    )


def _string_key_counts(values: Iterable[int]) -> dict[str, int]:
    return {
        str(value): count
        for value, count in sorted(Counter(values).items(), key=lambda item: item[0])
    }


def _u16_words(data: bytes) -> list[int]:
    return [
        int.from_bytes(data[offset : offset + 2], "big")
        for offset in range(0, len(data) - 1, 2)
    ]


def _summarize_dsy_region1_record_scan(
    *,
    scan: bytes,
    dsy_map: DsyMap,
    index: DsyRegion1Index,
    record_kind: str,
    table_record_index: int | None,
    record_offset: int,
    region_relative_offset: int,
    payload_relative_offset: int | None,
    byte_length: int,
    prefix_hash_bytes: int,
) -> DsyRegion1RecordSummary:
    return DsyRegion1RecordSummary(
        record_kind=record_kind,
        table_record_index=table_record_index,
        record_offset=record_offset,
        region_relative_offset=region_relative_offset,
        payload_relative_offset=payload_relative_offset,
        byte_length=byte_length,
        scan_byte_length=len(scan),
        prefix_sha256=hashlib.sha256(scan[:prefix_hash_bytes]).hexdigest(),
        nul_byte_ratio=_byte_ratio(scan, lambda value: value == 0),
        printable_ascii_ratio=_byte_ratio(scan, lambda value: 0x20 <= value <= 0x7E),
        unique_byte_count=len(set(scan)),
        marker_counts=_marker_counts(scan),
        marker_first_offsets=_marker_first_offsets(scan),
        possible_absolute_offsets_by_region=_possible_absolute_offsets_by_region(
            scan,
            dsy_map,
        ),
        possible_region_relative_offsets=_possible_region_relative_offsets(
            scan,
            dsy_map,
        ),
        possible_region1_payload_relative_offsets=_possible_relative_offset_count(
            scan,
            index.covered_payload_byte_length,
        ),
    )


def _possible_absolute_offsets_by_region(data: bytes, dsy_map: DsyMap) -> dict[str, int]:
    return {
        f"region_{index}": _possible_absolute_offset_count(data, region)
        for index, region in enumerate(dsy_map.regions)
    }


def _possible_absolute_offset_count(
    data: bytes,
    region: DsyRegionDescriptor,
) -> int:
    count = 0
    for offset in range(0, len(data) - 3, 2):
        value = int.from_bytes(data[offset : offset + 4], "big")
        if region.data_offset <= value < region.end_offset:
            count += 1
    return count


def _possible_region_relative_offsets(data: bytes, dsy_map: DsyMap) -> dict[str, int]:
    return {
        f"region_{index}": _possible_relative_offset_count(data, region.byte_length)
        for index, region in enumerate(dsy_map.regions)
    }


def _possible_relative_offset_count(data: bytes, byte_length: int) -> int:
    count = 0
    for offset in range(0, len(data) - 3, 2):
        value = int.from_bytes(data[offset : offset + 4], "big")
        if 0 <= value < byte_length:
            count += 1
    return count


def _byte_ratio(data: bytes, predicate: Callable[[int], bool]) -> float:
    if not data:
        return 0.0
    count = sum(1 for value in data if predicate(value))
    return round(count / len(data), 6)
