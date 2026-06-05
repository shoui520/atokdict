from __future__ import annotations

from bisect import bisect_left, bisect_right
from dataclasses import dataclass
import hashlib
import math
from pathlib import Path
import sqlite3

from atokdict.companion import decoded_companion_tempfile
from atokdict.drt import DrtPrimaryIndex
from atokdict.drt import PRIMARY_INDEX_RECORD_SIZE
from atokdict.drt import parse_drt_primary_index, parse_drt_root_index
from atokdict.dsy import parse_dsy_map, parse_dsy_region1_index


DSY_DSZ_ACTIVE_CLASS_ORDER_MODELS = {
    "all_active_classes",
    "drop_first_active_class",
    "drop_last_active_class",
}
DSY_DSZ_RECORD_HEADER_BYTE_LENGTH = 64
DSY_DSZ_RECORD_HEADER_U32_SLOT_COUNT = DSY_DSZ_RECORD_HEADER_BYTE_LENGTH // 4
DSY_DSZ_RECORD_BODY_PREFIX_U16_SLOT_COUNT = 16
DSY_DSZ_RECORD_PROFILE_MODULI = (4, 8, 16, 32, 64)


@dataclass(frozen=True)
class DrtKeywordRange:
    root_entry_index: int
    block_offset: int
    block_byte_length: int
    separator_key_sha256_utf16be: str
    separator_key_byte_length: int
    separator_key_char_length: int
    separator_is_empty: bool
    separator_lower_bound_rank: int | None
    separator_lower_bound_a_id: int | None
    separator_exact_match_count: int
    separator_exact_a_ids: list[int]
    partition_start_rank: int
    partition_end_rank: int
    partition_keyword_count: int

    def to_dict(self) -> dict[str, object]:
        return {
            "root_entry_index": self.root_entry_index,
            "block_offset": self.block_offset,
            "block_byte_length": self.block_byte_length,
            "separator_key_sha256_utf16be": self.separator_key_sha256_utf16be,
            "separator_key_byte_length": self.separator_key_byte_length,
            "separator_key_char_length": self.separator_key_char_length,
            "separator_is_empty": self.separator_is_empty,
            "separator_lower_bound_rank": self.separator_lower_bound_rank,
            "separator_lower_bound_a_id": self.separator_lower_bound_a_id,
            "separator_exact_match_count": self.separator_exact_match_count,
            "separator_exact_a_ids": self.separator_exact_a_ids,
            "partition_start_rank": self.partition_start_rank,
            "partition_end_rank": self.partition_end_rank,
            "partition_keyword_count": self.partition_keyword_count,
        }


@dataclass(frozen=True)
class DrtKeywordRangeSummary:
    drt_path: str
    drw_path: str
    keyword_count: int
    root_entry_count: int
    nonempty_separator_count: int
    exact_separator_count: int
    separator_ranks_monotonic: bool
    ranges: list[DrtKeywordRange]

    def to_dict(self, *, entry_limit: int | None = None) -> dict[str, object]:
        ranges = self.ranges if entry_limit is None else self.ranges[:entry_limit]
        return {
            "drt_path": self.drt_path,
            "drw_path": self.drw_path,
            "keyword_count": self.keyword_count,
            "root_entry_count": self.root_entry_count,
            "nonempty_separator_count": self.nonempty_separator_count,
            "exact_separator_count": self.exact_separator_count,
            "separator_ranks_monotonic": self.separator_ranks_monotonic,
            "ranges_returned": len(ranges),
            "ranges": [item.to_dict() for item in ranges],
        }


@dataclass(frozen=True)
class DrtPrimaryKeywordRange:
    primary_record_index: int
    block_offset: int
    block_byte_length: int
    segment_0_byte_length: int
    segment_1_byte_length: int
    segment_2_byte_length: int
    separator_key_raw_sha256: str
    separator_key_encoding_guess: str
    separator_key_byte_length: int
    separator_key_char_length: int | None
    separator_is_decodable: bool
    separator_lower_bound_rank: int | None
    separator_lower_bound_a_id: int | None
    separator_exact_match_count: int
    separator_prefix_match_count: int
    partition_start_rank: int | None
    partition_end_rank: int | None
    partition_keyword_count: int | None

    def to_dict(self) -> dict[str, object]:
        return {
            "primary_record_index": self.primary_record_index,
            "block_offset": self.block_offset,
            "block_byte_length": self.block_byte_length,
            "segment_0_byte_length": self.segment_0_byte_length,
            "segment_1_byte_length": self.segment_1_byte_length,
            "segment_2_byte_length": self.segment_2_byte_length,
            "separator_key_raw_sha256": self.separator_key_raw_sha256,
            "separator_key_encoding_guess": self.separator_key_encoding_guess,
            "separator_key_byte_length": self.separator_key_byte_length,
            "separator_key_char_length": self.separator_key_char_length,
            "separator_is_decodable": self.separator_is_decodable,
            "separator_lower_bound_rank": self.separator_lower_bound_rank,
            "separator_lower_bound_a_id": self.separator_lower_bound_a_id,
            "separator_exact_match_count": self.separator_exact_match_count,
            "separator_prefix_match_count": self.separator_prefix_match_count,
            "partition_start_rank": self.partition_start_rank,
            "partition_end_rank": self.partition_end_rank,
            "partition_keyword_count": self.partition_keyword_count,
        }


@dataclass(frozen=True)
class DrtPrimaryKeywordRangeSummary:
    drt_path: str
    drw_path: str
    keyword_count: int
    primary_record_count: int
    decodable_separator_count: int
    exact_separator_count: int
    prefix_separator_count: int
    separator_ranks_monotonic: bool
    ranges: list[DrtPrimaryKeywordRange]

    def to_dict(self, *, entry_limit: int | None = None) -> dict[str, object]:
        ranges = self.ranges if entry_limit is None else self.ranges[:entry_limit]
        return {
            "drt_path": self.drt_path,
            "drw_path": self.drw_path,
            "keyword_count": self.keyword_count,
            "primary_record_count": self.primary_record_count,
            "decodable_separator_count": self.decodable_separator_count,
            "exact_separator_count": self.exact_separator_count,
            "prefix_separator_count": self.prefix_separator_count,
            "separator_ranks_monotonic": self.separator_ranks_monotonic,
            "ranges_returned": len(ranges),
            "ranges": [item.to_dict() for item in ranges],
        }


@dataclass(frozen=True)
class DsyDszActiveClassOrderModel:
    model_name: str
    compared_record_count: int
    first_active_class_id: int | None
    last_active_class_id: int | None
    record_byte_length_min: int | None
    record_byte_length_max: int | None
    dsz_group_count_min: int | None
    dsz_group_count_max: int | None
    dsz_word_count_min: int | None
    dsz_word_count_max: int | None
    length_to_group_count_pearson: float | None
    length_to_group_count_spearman: float | None
    length_to_word_count_pearson: float | None
    length_to_word_count_spearman: float | None

    def to_dict(self) -> dict[str, object]:
        return {
            "model_name": self.model_name,
            "compared_record_count": self.compared_record_count,
            "first_active_class_id": self.first_active_class_id,
            "last_active_class_id": self.last_active_class_id,
            "record_byte_length_min": self.record_byte_length_min,
            "record_byte_length_max": self.record_byte_length_max,
            "dsz_group_count_min": self.dsz_group_count_min,
            "dsz_group_count_max": self.dsz_group_count_max,
            "dsz_word_count_min": self.dsz_word_count_min,
            "dsz_word_count_max": self.dsz_word_count_max,
            "length_to_group_count_pearson": self.length_to_group_count_pearson,
            "length_to_group_count_spearman": self.length_to_group_count_spearman,
            "length_to_word_count_pearson": self.length_to_word_count_pearson,
            "length_to_word_count_spearman": self.length_to_word_count_spearman,
        }


@dataclass(frozen=True)
class DsyDszActiveClassLinkSummary:
    dsy_path: str
    dsz_path: str
    dsy_table_record_count: int
    dsy_payload_record_count: int
    dsz_class_count: int
    dsz_group_count: int
    dsz_word_count: int
    dsz_group_active_class_count: int
    dsz_word_active_class_count: int
    dsz_active_class_union_count: int
    dsz_active_class_intersection_count: int
    dsz_group_only_active_class_count: int
    dsz_word_only_active_class_count: int
    dsz_active_class_min: int | None
    dsz_active_class_max: int | None
    dsz_active_classes_are_dense: bool | None
    active_class_count_matches_dsy_table_count: bool
    active_class_count_minus_one_matches_dsy_payload_count: bool
    order_models: list[DsyDszActiveClassOrderModel]

    def to_dict(self) -> dict[str, object]:
        return {
            "dsy_path": self.dsy_path,
            "dsz_path": self.dsz_path,
            "dsy_table_record_count": self.dsy_table_record_count,
            "dsy_payload_record_count": self.dsy_payload_record_count,
            "dsz_class_count": self.dsz_class_count,
            "dsz_group_count": self.dsz_group_count,
            "dsz_word_count": self.dsz_word_count,
            "dsz_group_active_class_count": self.dsz_group_active_class_count,
            "dsz_word_active_class_count": self.dsz_word_active_class_count,
            "dsz_active_class_union_count": self.dsz_active_class_union_count,
            "dsz_active_class_intersection_count": (
                self.dsz_active_class_intersection_count
            ),
            "dsz_group_only_active_class_count": (
                self.dsz_group_only_active_class_count
            ),
            "dsz_word_only_active_class_count": self.dsz_word_only_active_class_count,
            "dsz_active_class_min": self.dsz_active_class_min,
            "dsz_active_class_max": self.dsz_active_class_max,
            "dsz_active_classes_are_dense": self.dsz_active_classes_are_dense,
            "active_class_count_matches_dsy_table_count": (
                self.active_class_count_matches_dsy_table_count
            ),
            "active_class_count_minus_one_matches_dsy_payload_count": (
                self.active_class_count_minus_one_matches_dsy_payload_count
            ),
            "order_models": [item.to_dict() for item in self.order_models],
        }


@dataclass(frozen=True)
class DsyDszRecordProfileMetricSummary:
    metric_name: str
    value_sum: int
    min_value: int | None
    max_value: int | None
    nonzero_record_count: int
    correlation_to_group_count_pearson: float | None
    correlation_to_group_count_spearman: float | None
    correlation_to_word_count_pearson: float | None
    correlation_to_word_count_spearman: float | None
    correlation_to_alt_form_count_pearson: float | None
    correlation_to_alt_form_count_spearman: float | None

    def to_dict(self) -> dict[str, object]:
        return {
            "metric_name": self.metric_name,
            "value_sum": self.value_sum,
            "min_value": self.min_value,
            "max_value": self.max_value,
            "nonzero_record_count": self.nonzero_record_count,
            "correlation_to_group_count_pearson": (
                self.correlation_to_group_count_pearson
            ),
            "correlation_to_group_count_spearman": (
                self.correlation_to_group_count_spearman
            ),
            "correlation_to_word_count_pearson": (
                self.correlation_to_word_count_pearson
            ),
            "correlation_to_word_count_spearman": (
                self.correlation_to_word_count_spearman
            ),
            "correlation_to_alt_form_count_pearson": (
                self.correlation_to_alt_form_count_pearson
            ),
            "correlation_to_alt_form_count_spearman": (
                self.correlation_to_alt_form_count_spearman
            ),
        }


@dataclass(frozen=True)
class DsyDszRecordProfileLinearFit:
    x_metric_name: str
    y_metric_name: str
    slope: float | None
    intercept: float | None
    residual_min: float | None
    residual_max: float | None
    residual_average_absolute: float | None

    def to_dict(self) -> dict[str, object]:
        return {
            "x_metric_name": self.x_metric_name,
            "y_metric_name": self.y_metric_name,
            "slope": self.slope,
            "intercept": self.intercept,
            "residual_min": self.residual_min,
            "residual_max": self.residual_max,
            "residual_average_absolute": self.residual_average_absolute,
        }


@dataclass(frozen=True)
class DsyDszRecordSlotSummary:
    slot_kind: str
    slot_index: int
    byte_offset: int
    value_width_bits: int
    observed_count: int
    zero_count: int
    unique_value_count: int
    fixed_value: int | None
    min_value: int | None
    max_value: int | None
    candidate_header_length_match_count: int
    local_record_offset_range_count: int
    region1_payload_relative_offset_range_count: int
    correlation_to_word_count_pearson: float | None
    correlation_to_word_count_spearman: float | None

    def to_dict(self) -> dict[str, object]:
        return {
            "slot_kind": self.slot_kind,
            "slot_index": self.slot_index,
            "byte_offset": self.byte_offset,
            "value_width_bits": self.value_width_bits,
            "observed_count": self.observed_count,
            "zero_count": self.zero_count,
            "unique_value_count": self.unique_value_count,
            "fixed_value": self.fixed_value,
            "min_value": self.min_value,
            "max_value": self.max_value,
            "candidate_header_length_match_count": (
                self.candidate_header_length_match_count
            ),
            "local_record_offset_range_count": self.local_record_offset_range_count,
            "region1_payload_relative_offset_range_count": (
                self.region1_payload_relative_offset_range_count
            ),
            "correlation_to_word_count_pearson": (
                self.correlation_to_word_count_pearson
            ),
            "correlation_to_word_count_spearman": (
                self.correlation_to_word_count_spearman
            ),
        }


@dataclass(frozen=True)
class DsyDszRecordProfileSummary:
    dsy_path: str
    dsz_path: str
    model_name: str
    model_is_compatible: bool
    dsy_payload_record_count: int
    candidate_active_class_count: int
    compared_record_count: int
    first_active_class_id: int | None
    last_active_class_id: int | None
    region1_payload_byte_length: int
    candidate_header_byte_length: int
    candidate_header_length_match_count: int
    record_byte_length_mod_counts: dict[str, dict[str, int]]
    word_count_linear_fit: DsyDszRecordProfileLinearFit
    body_byte_length_linear_fit: DsyDszRecordProfileLinearFit
    header_u32_slot_summaries: list[DsyDszRecordSlotSummary]
    body_prefix_u16_slot_summaries: list[DsyDszRecordSlotSummary]
    metric_summaries: list[DsyDszRecordProfileMetricSummary]

    def to_dict(self) -> dict[str, object]:
        return {
            "dsy_path": self.dsy_path,
            "dsz_path": self.dsz_path,
            "model_name": self.model_name,
            "model_is_compatible": self.model_is_compatible,
            "dsy_payload_record_count": self.dsy_payload_record_count,
            "candidate_active_class_count": self.candidate_active_class_count,
            "compared_record_count": self.compared_record_count,
            "first_active_class_id": self.first_active_class_id,
            "last_active_class_id": self.last_active_class_id,
            "region1_payload_byte_length": self.region1_payload_byte_length,
            "candidate_header_byte_length": self.candidate_header_byte_length,
            "candidate_header_length_match_count": (
                self.candidate_header_length_match_count
            ),
            "record_byte_length_mod_counts": self.record_byte_length_mod_counts,
            "word_count_linear_fit": self.word_count_linear_fit.to_dict(),
            "body_byte_length_linear_fit": self.body_byte_length_linear_fit.to_dict(),
            "header_u32_slot_summaries": [
                item.to_dict() for item in self.header_u32_slot_summaries
            ],
            "body_prefix_u16_slot_summaries": [
                item.to_dict() for item in self.body_prefix_u16_slot_summaries
            ],
            "metric_summaries": [item.to_dict() for item in self.metric_summaries],
        }


def summarize_drt_keyword_ranges(
    drt_path: str | Path,
    drw_path: str | Path | None = None,
) -> DrtKeywordRangeSummary:
    drt = Path(drt_path)
    drw = Path(drw_path) if drw_path is not None else drt.with_suffix(".DRW")
    if not drw.exists():
        raise ValueError(f"companion DRW file does not exist: {drw}")

    root_index = parse_drt_root_index(drt)
    keyword_rows = _read_keyword_rows(drw)
    words = [word for word, _a_id in keyword_rows]
    a_ids = [a_id for _word, a_id in keyword_rows]
    keyword_count = len(words)

    child_starts = [entry.data_offset for entry in root_index.entries]
    child_ends = child_starts[1:] + [root_index.section_descriptor.end_offset]

    ranges: list[DrtKeywordRange] = []
    separator_ranks: list[int] = []
    previous_rank = 0
    exact_separator_count = 0

    for index, (entry, child_end) in enumerate(
        zip(root_index.entries, child_ends, strict=True)
    ):
        key_hash = hashlib.sha256(entry.key.encode("utf-16be")).hexdigest()
        if entry.key:
            lower_bound_rank = bisect_left(words, entry.key)
            separator_ranks.append(lower_bound_rank)
            lower_bound_a_id = a_ids[lower_bound_rank] if lower_bound_rank < keyword_count else None
            exact_end = bisect_right(words, entry.key, lo=lower_bound_rank)
            exact_a_ids = a_ids[lower_bound_rank:exact_end]
            exact_match_count = len(exact_a_ids)
            if exact_match_count:
                exact_separator_count += 1
            partition_end_rank = lower_bound_rank
        else:
            lower_bound_rank = None
            lower_bound_a_id = None
            exact_a_ids = []
            exact_match_count = 0
            partition_end_rank = keyword_count

        ranges.append(
            DrtKeywordRange(
                root_entry_index=index,
                block_offset=entry.data_offset,
                block_byte_length=child_end - entry.data_offset,
                separator_key_sha256_utf16be=key_hash,
                separator_key_byte_length=entry.key_byte_length,
                separator_key_char_length=entry.key_char_length,
                separator_is_empty=entry.key == "",
                separator_lower_bound_rank=lower_bound_rank,
                separator_lower_bound_a_id=lower_bound_a_id,
                separator_exact_match_count=exact_match_count,
                separator_exact_a_ids=exact_a_ids,
                partition_start_rank=previous_rank,
                partition_end_rank=partition_end_rank,
                partition_keyword_count=partition_end_rank - previous_rank,
            )
        )
        previous_rank = partition_end_rank

    return DrtKeywordRangeSummary(
        drt_path=str(drt),
        drw_path=str(drw),
        keyword_count=keyword_count,
        root_entry_count=len(root_index.entries),
        nonempty_separator_count=len(separator_ranks),
        exact_separator_count=exact_separator_count,
        separator_ranks_monotonic=all(
            earlier <= later for earlier, later in zip(separator_ranks, separator_ranks[1:])
        ),
        ranges=ranges,
    )


def summarize_dsy_dsz_active_class_links(
    dsy_path: str | Path,
    dsz_path: str | Path | None = None,
) -> DsyDszActiveClassLinkSummary:
    dsy = Path(dsy_path)
    dsz = Path(dsz_path) if dsz_path is not None else dsy.with_suffix(".DSZ")
    if not dsz.exists():
        raise ValueError(f"companion DSZ file does not exist: {dsz}")

    dsy_index = parse_dsy_region1_index(dsy)
    dsy_record_lengths = [entry.byte_length for entry in dsy_index.entries]
    dsz_stats = _read_dsz_active_class_stats(dsz)
    active_classes = dsz_stats.active_class_ids
    active_class_min = min(active_classes) if active_classes else None
    active_class_max = max(active_classes) if active_classes else None
    active_classes_are_dense = (
        None
        if active_class_min is None or active_class_max is None
        else len(active_classes) == active_class_max - active_class_min + 1
    )

    order_models = [
        model
        for model in (
            _dsy_dsz_active_class_order_model(
                "all_active_classes",
                dsy_record_lengths,
                active_classes,
                dsz_stats.group_counts_by_class,
                dsz_stats.word_counts_by_class,
            ),
            _dsy_dsz_active_class_order_model(
                "drop_first_active_class",
                dsy_record_lengths,
                active_classes[1:],
                dsz_stats.group_counts_by_class,
                dsz_stats.word_counts_by_class,
            ),
            _dsy_dsz_active_class_order_model(
                "drop_last_active_class",
                dsy_record_lengths,
                active_classes[:-1],
                dsz_stats.group_counts_by_class,
                dsz_stats.word_counts_by_class,
            ),
        )
        if model is not None
    ]

    return DsyDszActiveClassLinkSummary(
        dsy_path=str(dsy),
        dsz_path=str(dsz),
        dsy_table_record_count=dsy_index.table_record_count,
        dsy_payload_record_count=len(dsy_index.entries),
        dsz_class_count=dsz_stats.class_count,
        dsz_group_count=dsz_stats.group_count,
        dsz_word_count=dsz_stats.word_count,
        dsz_group_active_class_count=len(dsz_stats.group_active_class_ids),
        dsz_word_active_class_count=len(dsz_stats.word_active_class_ids),
        dsz_active_class_union_count=len(active_classes),
        dsz_active_class_intersection_count=len(dsz_stats.active_class_intersection),
        dsz_group_only_active_class_count=len(dsz_stats.group_only_active_class_ids),
        dsz_word_only_active_class_count=len(dsz_stats.word_only_active_class_ids),
        dsz_active_class_min=active_class_min,
        dsz_active_class_max=active_class_max,
        dsz_active_classes_are_dense=active_classes_are_dense,
        active_class_count_matches_dsy_table_count=(
            len(active_classes) == dsy_index.table_record_count
        ),
        active_class_count_minus_one_matches_dsy_payload_count=(
            len(active_classes) - 1 == len(dsy_index.entries)
        ),
        order_models=order_models,
    )


def summarize_dsy_dsz_record_profile(
    dsy_path: str | Path,
    dsz_path: str | Path | None = None,
    *,
    model_name: str = "drop_last_active_class",
) -> DsyDszRecordProfileSummary:
    if model_name not in DSY_DSZ_ACTIVE_CLASS_ORDER_MODELS:
        raise ValueError(f"unsupported active-class order model: {model_name}")

    dsy = Path(dsy_path)
    dsz = Path(dsz_path) if dsz_path is not None else dsy.with_suffix(".DSZ")
    if not dsz.exists():
        raise ValueError(f"companion DSZ file does not exist: {dsz}")

    dsy_index = parse_dsy_region1_index(dsy)
    dsy_map = parse_dsy_map(dsy)
    dsz_stats = _read_dsz_active_class_stats(dsz)
    active_class_ids = _select_active_class_model(
        dsz_stats.active_class_ids,
        model_name,
    )
    model_is_compatible = len(active_class_ids) == len(dsy_index.entries)
    if not model_is_compatible:
        return DsyDszRecordProfileSummary(
            dsy_path=str(dsy),
            dsz_path=str(dsz),
            model_name=model_name,
            model_is_compatible=False,
            dsy_payload_record_count=len(dsy_index.entries),
            candidate_active_class_count=len(active_class_ids),
            compared_record_count=0,
            first_active_class_id=active_class_ids[0] if active_class_ids else None,
            last_active_class_id=active_class_ids[-1] if active_class_ids else None,
            region1_payload_byte_length=dsy_index.covered_payload_byte_length,
            candidate_header_byte_length=DSY_DSZ_RECORD_HEADER_BYTE_LENGTH,
            candidate_header_length_match_count=0,
            record_byte_length_mod_counts={},
            word_count_linear_fit=_linear_fit([], [], "dsz_word_count", "record_byte_length"),
            body_byte_length_linear_fit=_linear_fit(
                [],
                [],
                "dsz_word_count",
                "body_byte_length",
            ),
            header_u32_slot_summaries=[],
            body_prefix_u16_slot_summaries=[],
            metric_summaries=[],
        )

    group_counts = [
        dsz_stats.group_counts_by_class.get(class_id, 0)
        for class_id in active_class_ids
    ]
    word_counts = [
        dsz_stats.word_counts_by_class.get(class_id, 0)
        for class_id in active_class_ids
    ]
    alt_counts = [
        dsz_stats.alt_form_counts_by_class.get(class_id, 0)
        for class_id in active_class_ids
    ]
    metric_values = _dsy_region1_record_profile_metrics(
        dsy,
        dsy_index,
        dsy_map,
        dsz_stats,
    )

    metric_summaries = [
        _summarize_record_profile_metric(
            metric_name,
            values,
            group_counts,
            word_counts,
            alt_counts,
        )
        for metric_name, values in metric_values.items()
    ]
    header_slot_summaries, body_slot_summaries = _dsy_region1_record_slot_summaries(
        dsy,
        dsy_index,
        word_counts,
    )
    candidate_header_length_match_count = (
        header_slot_summaries[1].candidate_header_length_match_count
        if len(header_slot_summaries) > 1
        else 0
    )
    record_lengths = metric_values["record_byte_length"]
    body_lengths = [
        max(0, record_length - DSY_DSZ_RECORD_HEADER_BYTE_LENGTH)
        for record_length in record_lengths
    ]

    return DsyDszRecordProfileSummary(
        dsy_path=str(dsy),
        dsz_path=str(dsz),
        model_name=model_name,
        model_is_compatible=True,
        dsy_payload_record_count=len(dsy_index.entries),
        candidate_active_class_count=len(active_class_ids),
        compared_record_count=len(active_class_ids),
        first_active_class_id=active_class_ids[0] if active_class_ids else None,
        last_active_class_id=active_class_ids[-1] if active_class_ids else None,
        region1_payload_byte_length=dsy_index.covered_payload_byte_length,
        candidate_header_byte_length=DSY_DSZ_RECORD_HEADER_BYTE_LENGTH,
        candidate_header_length_match_count=candidate_header_length_match_count,
        record_byte_length_mod_counts=_record_length_mod_counts(
            record_lengths
        ),
        word_count_linear_fit=_linear_fit(
            word_counts,
            record_lengths,
            "dsz_word_count",
            "record_byte_length",
        ),
        body_byte_length_linear_fit=_linear_fit(
            word_counts,
            body_lengths,
            "dsz_word_count",
            "body_byte_length",
        ),
        header_u32_slot_summaries=header_slot_summaries,
        body_prefix_u16_slot_summaries=body_slot_summaries,
        metric_summaries=metric_summaries,
    )


def summarize_drt_primary_keyword_ranges(
    drt_path: str | Path,
    drw_path: str | Path | None = None,
) -> DrtPrimaryKeywordRangeSummary:
    drt = Path(drt_path)
    drw = Path(drw_path) if drw_path is not None else drt.with_suffix(".DRW")
    if not drw.exists():
        raise ValueError(f"companion DRW file does not exist: {drw}")

    primary_index = parse_drt_primary_index(drt)
    raw_keys = _read_primary_key_raws(drt, primary_index)
    keyword_rows = _read_keyword_rows(drw)
    words = [word for word, _a_id in keyword_rows]
    a_ids = [a_id for _word, a_id in keyword_rows]
    keyword_count = len(words)

    key_summaries: list[_PrimaryKeyRank] = []
    ranks: list[int] = []
    exact_separator_count = 0
    prefix_separator_count = 0
    for raw_key in raw_keys:
        decoded = _decode_primary_separator_key(raw_key)
        if decoded.key is None:
            rank = None
            lower_bound_a_id = None
            exact_match_count = 0
            prefix_match_count = 0
        else:
            rank = bisect_left(words, decoded.key)
            ranks.append(rank)
            lower_bound_a_id = a_ids[rank] if rank < keyword_count else None
            exact_end = bisect_right(words, decoded.key, lo=rank)
            exact_match_count = exact_end - rank
            prefix_match_count = _prefix_match_count(words, decoded.key, rank)
            if exact_match_count:
                exact_separator_count += 1
            if prefix_match_count:
                prefix_separator_count += 1
        key_summaries.append(
            _PrimaryKeyRank(
                decoded=decoded,
                lower_bound_rank=rank,
                lower_bound_a_id=lower_bound_a_id,
                exact_match_count=exact_match_count,
                prefix_match_count=prefix_match_count,
            )
        )

    separator_ranks_monotonic = all(
        earlier <= later for earlier, later in zip(ranks, ranks[1:])
    )
    partition_bounds = _primary_partition_bounds(
        key_summaries, keyword_count, enabled=separator_ranks_monotonic
    )

    ranges: list[DrtPrimaryKeywordRange] = []
    for entry, summary, partition in zip(
        primary_index.entries, key_summaries, partition_bounds, strict=True
    ):
        decoded = summary.decoded
        ranges.append(
            DrtPrimaryKeywordRange(
                primary_record_index=entry.record_index,
                block_offset=entry.data_offset,
                block_byte_length=entry.byte_length,
                segment_0_byte_length=entry.segment_0_byte_length,
                segment_1_byte_length=entry.segment_1_byte_length,
                segment_2_byte_length=entry.segment_2_byte_length,
                separator_key_raw_sha256=hashlib.sha256(decoded.raw).hexdigest(),
                separator_key_encoding_guess=decoded.encoding_guess,
                separator_key_byte_length=decoded.byte_length,
                separator_key_char_length=decoded.char_length,
                separator_is_decodable=decoded.key is not None,
                separator_lower_bound_rank=summary.lower_bound_rank,
                separator_lower_bound_a_id=summary.lower_bound_a_id,
                separator_exact_match_count=summary.exact_match_count,
                separator_prefix_match_count=summary.prefix_match_count,
                partition_start_rank=partition[0],
                partition_end_rank=partition[1],
                partition_keyword_count=(
                    None if partition[0] is None else partition[1] - partition[0]
                ),
            )
        )

    return DrtPrimaryKeywordRangeSummary(
        drt_path=str(drt),
        drw_path=str(drw),
        keyword_count=keyword_count,
        primary_record_count=primary_index.record_count,
        decodable_separator_count=sum(1 for item in key_summaries if item.decoded.key),
        exact_separator_count=exact_separator_count,
        prefix_separator_count=prefix_separator_count,
        separator_ranks_monotonic=separator_ranks_monotonic,
        ranges=ranges,
    )


def _read_keyword_rows(drw_path: Path) -> list[tuple[str, int]]:
    with decoded_companion_tempfile(drw_path) as decoded_path:
        connection = sqlite3.connect(f"file:{decoded_path}?mode=ro", uri=True)
        try:
            rows = connection.execute("SELECT word, a_id FROM keyword_info").fetchall()
        finally:
            connection.close()
    return sorted((str(word), int(a_id)) for word, a_id in rows)


@dataclass(frozen=True)
class _DszActiveClassStats:
    class_count: int
    group_count: int
    word_count: int
    alt_form_count: int
    class_id_min: int | None
    class_id_max: int | None
    group_id_min: int | None
    group_id_max: int | None
    word_id_min: int | None
    word_id_max: int | None
    group_counts_by_class: dict[int, int]
    word_counts_by_class: dict[int, int]
    alt_form_counts_by_class: dict[int, int]
    group_active_class_ids: set[int]
    word_active_class_ids: set[int]
    active_class_ids: list[int]
    active_class_intersection: set[int]
    group_only_active_class_ids: set[int]
    word_only_active_class_ids: set[int]


def _read_dsz_active_class_stats(dsz_path: Path) -> _DszActiveClassStats:
    with decoded_companion_tempfile(dsz_path) as decoded_path:
        connection = sqlite3.connect(f"file:{decoded_path}?mode=ro", uri=True)
        try:
            class_count = _sqlite_scalar_int(connection, "SELECT COUNT(*) FROM TABLE_CLASS")
            group_count = _sqlite_scalar_int(connection, "SELECT COUNT(*) FROM TABLE_GROUP")
            word_count = _sqlite_scalar_int(connection, "SELECT COUNT(*) FROM TABLE_WORD")
            alt_form_count = _sqlite_scalar_int(
                connection,
                "SELECT COUNT(*) FROM TABLE_WORD_IHYOKI",
            )
            class_id_min, class_id_max = _read_min_max_id(connection, "TABLE_CLASS", "CLASS_ID")
            group_id_min, group_id_max = _read_min_max_id(connection, "TABLE_GROUP", "GROUP_ID")
            word_id_min, word_id_max = _read_min_max_id(connection, "TABLE_WORD", "ID")
            group_counts_by_class = _read_count_by_class(
                connection,
                "SELECT CLASS_ID, COUNT(*) FROM TABLE_GROUP GROUP BY CLASS_ID",
            )
            word_counts_by_class = _read_count_by_class(
                connection,
                "SELECT CLASS_ID, COUNT(*) FROM TABLE_WORD GROUP BY CLASS_ID",
            )
            alt_form_counts_by_class = _read_count_by_class(
                connection,
                "SELECT CLASS_ID, COUNT(*) FROM TABLE_WORD_IHYOKI GROUP BY CLASS_ID",
            )
        finally:
            connection.close()

    group_active_class_ids = set(group_counts_by_class)
    word_active_class_ids = set(word_counts_by_class)
    active_class_intersection = group_active_class_ids & word_active_class_ids
    return _DszActiveClassStats(
        class_count=class_count,
        group_count=group_count,
        word_count=word_count,
        alt_form_count=alt_form_count,
        class_id_min=class_id_min,
        class_id_max=class_id_max,
        group_id_min=group_id_min,
        group_id_max=group_id_max,
        word_id_min=word_id_min,
        word_id_max=word_id_max,
        group_counts_by_class=group_counts_by_class,
        word_counts_by_class=word_counts_by_class,
        alt_form_counts_by_class=alt_form_counts_by_class,
        group_active_class_ids=group_active_class_ids,
        word_active_class_ids=word_active_class_ids,
        active_class_ids=sorted(group_active_class_ids | word_active_class_ids),
        active_class_intersection=active_class_intersection,
        group_only_active_class_ids=group_active_class_ids - word_active_class_ids,
        word_only_active_class_ids=word_active_class_ids - group_active_class_ids,
    )


def _select_active_class_model(
    active_class_ids: list[int],
    model_name: str,
) -> list[int]:
    if model_name == "all_active_classes":
        return active_class_ids
    if model_name == "drop_first_active_class":
        return active_class_ids[1:]
    if model_name == "drop_last_active_class":
        return active_class_ids[:-1]
    raise ValueError(f"unsupported active-class order model: {model_name}")


def _dsy_region1_record_profile_metrics(
    dsy_path: Path,
    dsy_index,
    dsy_map,
    dsz_stats: _DszActiveClassStats,
) -> dict[str, list[int]]:
    metrics = {
        "record_byte_length": [],
        "u16_zero_count": [],
        "u16_high_ffxx_count": [],
        "u16_marker_count": [],
        "u16_region1_record_index_range_count": [],
        "u32_absolute_region1_offset_count": [],
        "u32_absolute_region3_offset_count": [],
        "u32_region1_payload_relative_offset_count": [],
        "u32_class_id_range_count": [],
        "u32_group_id_range_count": [],
        "u32_word_id_range_count": [],
    }
    region1 = dsy_map.regions[1]
    region3 = dsy_map.regions[3]
    with dsy_path.open("rb") as handle:
        for entry in dsy_index.entries:
            handle.seek(entry.payload_offset)
            data = handle.read(entry.byte_length)
            record_metrics = _profile_dsy_region1_record(
                data,
                dsy_index,
                region1.data_offset,
                region1.end_offset,
                region3.data_offset,
                region3.end_offset,
                dsz_stats,
            )
            for metric_name, value in record_metrics.items():
                metrics[metric_name].append(value)
    return metrics


def _profile_dsy_region1_record(
    data: bytes,
    dsy_index,
    region1_offset: int,
    region1_end_offset: int,
    region3_offset: int,
    region3_end_offset: int,
    dsz_stats: _DszActiveClassStats,
) -> dict[str, int]:
    u16_zero_count = 0
    u16_high_ffxx_count = 0
    u16_marker_count = 0
    u16_region1_record_index_range_count = 0
    for offset in range(0, len(data) - 1, 2):
        value = int.from_bytes(data[offset : offset + 2], "big")
        if value == 0:
            u16_zero_count += 1
        if value >= 0xFF00:
            u16_high_ffxx_count += 1
        if value in (0xFFFF, 0xFFFE, 0xFFFD):
            u16_marker_count += 1
        if 0 <= value <= len(dsy_index.entries):
            u16_region1_record_index_range_count += 1

    u32_absolute_region1_offset_count = 0
    u32_absolute_region3_offset_count = 0
    u32_region1_payload_relative_offset_count = 0
    u32_class_id_range_count = 0
    u32_group_id_range_count = 0
    u32_word_id_range_count = 0
    for offset in range(0, len(data) - 3, 4):
        value = int.from_bytes(data[offset : offset + 4], "big")
        if region1_offset <= value < region1_end_offset:
            u32_absolute_region1_offset_count += 1
        if region3_offset <= value < region3_end_offset:
            u32_absolute_region3_offset_count += 1
        if 0 <= value < dsy_index.covered_payload_byte_length:
            u32_region1_payload_relative_offset_count += 1
        if _in_optional_range(value, dsz_stats.class_id_min, dsz_stats.class_id_max):
            u32_class_id_range_count += 1
        if _in_optional_range(value, dsz_stats.group_id_min, dsz_stats.group_id_max):
            u32_group_id_range_count += 1
        if _in_optional_range(value, dsz_stats.word_id_min, dsz_stats.word_id_max):
            u32_word_id_range_count += 1

    return {
        "record_byte_length": len(data),
        "u16_zero_count": u16_zero_count,
        "u16_high_ffxx_count": u16_high_ffxx_count,
        "u16_marker_count": u16_marker_count,
        "u16_region1_record_index_range_count": (
            u16_region1_record_index_range_count
        ),
        "u32_absolute_region1_offset_count": u32_absolute_region1_offset_count,
        "u32_absolute_region3_offset_count": u32_absolute_region3_offset_count,
        "u32_region1_payload_relative_offset_count": (
            u32_region1_payload_relative_offset_count
        ),
        "u32_class_id_range_count": u32_class_id_range_count,
        "u32_group_id_range_count": u32_group_id_range_count,
        "u32_word_id_range_count": u32_word_id_range_count,
    }


def _dsy_region1_record_slot_summaries(
    dsy_path: Path,
    dsy_index,
    word_counts: list[int],
) -> tuple[list[DsyDszRecordSlotSummary], list[DsyDszRecordSlotSummary]]:
    header_slot_values: list[list[int | None]] = [
        [] for _index in range(DSY_DSZ_RECORD_HEADER_U32_SLOT_COUNT)
    ]
    body_slot_values: list[list[int | None]] = [
        [] for _index in range(DSY_DSZ_RECORD_BODY_PREFIX_U16_SLOT_COUNT)
    ]
    record_lengths: list[int] = []

    with dsy_path.open("rb") as handle:
        for entry in dsy_index.entries:
            handle.seek(entry.payload_offset)
            prefix = handle.read(
                DSY_DSZ_RECORD_HEADER_BYTE_LENGTH
                + DSY_DSZ_RECORD_BODY_PREFIX_U16_SLOT_COUNT * 2
            )
            record_lengths.append(entry.byte_length)
            for slot_index, values in enumerate(header_slot_values):
                offset = slot_index * 4
                if len(prefix) >= offset + 4:
                    values.append(int.from_bytes(prefix[offset : offset + 4], "big"))
                else:
                    values.append(None)
            for slot_index, values in enumerate(body_slot_values):
                offset = DSY_DSZ_RECORD_HEADER_BYTE_LENGTH + slot_index * 2
                if len(prefix) >= offset + 2:
                    values.append(int.from_bytes(prefix[offset : offset + 2], "big"))
                else:
                    values.append(None)

    header_summaries = [
        _summarize_record_slot_values(
            slot_kind="header_u32",
            slot_index=slot_index,
            byte_offset=slot_index * 4,
            value_width_bits=32,
            values=values,
            record_lengths=record_lengths,
            region1_payload_byte_length=dsy_index.covered_payload_byte_length,
            word_counts=word_counts,
        )
        for slot_index, values in enumerate(header_slot_values)
    ]
    body_summaries = [
        _summarize_record_slot_values(
            slot_kind="body_prefix_u16",
            slot_index=slot_index,
            byte_offset=DSY_DSZ_RECORD_HEADER_BYTE_LENGTH + slot_index * 2,
            value_width_bits=16,
            values=values,
            record_lengths=record_lengths,
            region1_payload_byte_length=dsy_index.covered_payload_byte_length,
            word_counts=word_counts,
        )
        for slot_index, values in enumerate(body_slot_values)
    ]
    return header_summaries, body_summaries


def _summarize_record_slot_values(
    *,
    slot_kind: str,
    slot_index: int,
    byte_offset: int,
    value_width_bits: int,
    values: list[int | None],
    record_lengths: list[int],
    region1_payload_byte_length: int,
    word_counts: list[int],
) -> DsyDszRecordSlotSummary:
    observed_pairs = [
        (value, record_length, word_count)
        for value, record_length, word_count in zip(
            values,
            record_lengths,
            word_counts,
            strict=True,
        )
        if value is not None
    ]
    observed_values = [value for value, _record_length, _word_count in observed_pairs]
    observed_word_counts = [
        word_count for _value, _record_length, word_count in observed_pairs
    ]
    unique_values = set(observed_values)
    fixed_value = (
        next(iter(unique_values)) if len(unique_values) == 1 and observed_values else None
    )
    return DsyDszRecordSlotSummary(
        slot_kind=slot_kind,
        slot_index=slot_index,
        byte_offset=byte_offset,
        value_width_bits=value_width_bits,
        observed_count=len(observed_values),
        zero_count=sum(1 for value in observed_values if value == 0),
        unique_value_count=len(unique_values),
        fixed_value=fixed_value,
        min_value=min(observed_values) if observed_values else None,
        max_value=max(observed_values) if observed_values else None,
        candidate_header_length_match_count=sum(
            1 for value in observed_values if value == DSY_DSZ_RECORD_HEADER_BYTE_LENGTH
        ),
        local_record_offset_range_count=sum(
            1
            for value, record_length, _word_count in observed_pairs
            if 0 <= value < record_length
        ),
        region1_payload_relative_offset_range_count=sum(
            1 for value in observed_values if 0 <= value < region1_payload_byte_length
        ),
        correlation_to_word_count_pearson=_pearson(
            observed_values,
            observed_word_counts,
        ),
        correlation_to_word_count_spearman=_spearman(
            observed_values,
            observed_word_counts,
        ),
    )


def _read_count_by_class(
    connection: sqlite3.Connection,
    sql: str,
) -> dict[int, int]:
    return {
        int(class_id): int(row_count)
        for class_id, row_count in connection.execute(sql).fetchall()
    }


def _read_min_max_id(
    connection: sqlite3.Connection,
    table_name: str,
    column_name: str,
) -> tuple[int | None, int | None]:
    table = _quote_identifier(table_name)
    column = _quote_identifier(column_name)
    minimum, maximum = connection.execute(
        f"SELECT MIN({column}), MAX({column}) FROM {table}"
    ).fetchone()
    return (
        None if minimum is None else int(minimum),
        None if maximum is None else int(maximum),
    )


def _summarize_record_profile_metric(
    metric_name: str,
    values: list[int],
    group_counts: list[int],
    word_counts: list[int],
    alt_counts: list[int],
) -> DsyDszRecordProfileMetricSummary:
    return DsyDszRecordProfileMetricSummary(
        metric_name=metric_name,
        value_sum=sum(values),
        min_value=min(values) if values else None,
        max_value=max(values) if values else None,
        nonzero_record_count=sum(1 for value in values if value),
        correlation_to_group_count_pearson=_pearson(values, group_counts),
        correlation_to_group_count_spearman=_spearman(values, group_counts),
        correlation_to_word_count_pearson=_pearson(values, word_counts),
        correlation_to_word_count_spearman=_spearman(values, word_counts),
        correlation_to_alt_form_count_pearson=_pearson(values, alt_counts),
        correlation_to_alt_form_count_spearman=_spearman(values, alt_counts),
    )


def _record_length_mod_counts(record_lengths: list[int]) -> dict[str, dict[str, int]]:
    return {
        str(modulus): _count_strings(length % modulus for length in record_lengths)
        for modulus in DSY_DSZ_RECORD_PROFILE_MODULI
    }


def _linear_fit(
    xs: list[int] | list[float],
    ys: list[int] | list[float],
    x_metric_name: str,
    y_metric_name: str,
) -> DsyDszRecordProfileLinearFit:
    if len(xs) != len(ys) or len(xs) < 2:
        return DsyDszRecordProfileLinearFit(
            x_metric_name=x_metric_name,
            y_metric_name=y_metric_name,
            slope=None,
            intercept=None,
            residual_min=None,
            residual_max=None,
            residual_average_absolute=None,
        )
    x_mean = sum(xs) / len(xs)
    y_mean = sum(ys) / len(ys)
    x_variance = sum((value - x_mean) ** 2 for value in xs)
    if x_variance == 0:
        return DsyDszRecordProfileLinearFit(
            x_metric_name=x_metric_name,
            y_metric_name=y_metric_name,
            slope=None,
            intercept=None,
            residual_min=None,
            residual_max=None,
            residual_average_absolute=None,
        )
    slope = sum(
        (x_value - x_mean) * (y_value - y_mean)
        for x_value, y_value in zip(xs, ys, strict=True)
    ) / x_variance
    intercept = y_mean - slope * x_mean
    residuals = [
        y_value - (intercept + slope * x_value)
        for x_value, y_value in zip(xs, ys, strict=True)
    ]
    return DsyDszRecordProfileLinearFit(
        x_metric_name=x_metric_name,
        y_metric_name=y_metric_name,
        slope=slope,
        intercept=intercept,
        residual_min=min(residuals),
        residual_max=max(residuals),
        residual_average_absolute=sum(abs(value) for value in residuals)
        / len(residuals),
    )


def _count_strings(values) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        key = str(value)
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items(), key=lambda item: int(item[0])))


def _in_optional_range(
    value: int,
    minimum: int | None,
    maximum: int | None,
) -> bool:
    return minimum is not None and maximum is not None and minimum <= value <= maximum


def _quote_identifier(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def _dsy_dsz_active_class_order_model(
    model_name: str,
    record_lengths: list[int],
    active_class_ids: list[int],
    group_counts_by_class: dict[int, int],
    word_counts_by_class: dict[int, int],
) -> DsyDszActiveClassOrderModel | None:
    if len(record_lengths) != len(active_class_ids):
        return None
    group_counts = [group_counts_by_class.get(class_id, 0) for class_id in active_class_ids]
    word_counts = [word_counts_by_class.get(class_id, 0) for class_id in active_class_ids]
    return DsyDszActiveClassOrderModel(
        model_name=model_name,
        compared_record_count=len(record_lengths),
        first_active_class_id=active_class_ids[0] if active_class_ids else None,
        last_active_class_id=active_class_ids[-1] if active_class_ids else None,
        record_byte_length_min=min(record_lengths) if record_lengths else None,
        record_byte_length_max=max(record_lengths) if record_lengths else None,
        dsz_group_count_min=min(group_counts) if group_counts else None,
        dsz_group_count_max=max(group_counts) if group_counts else None,
        dsz_word_count_min=min(word_counts) if word_counts else None,
        dsz_word_count_max=max(word_counts) if word_counts else None,
        length_to_group_count_pearson=_pearson(record_lengths, group_counts),
        length_to_group_count_spearman=_spearman(record_lengths, group_counts),
        length_to_word_count_pearson=_pearson(record_lengths, word_counts),
        length_to_word_count_spearman=_spearman(record_lengths, word_counts),
    )


def _pearson(xs: list[int] | list[float], ys: list[int] | list[float]) -> float | None:
    if len(xs) != len(ys) or len(xs) < 2:
        return None
    x_mean = sum(xs) / len(xs)
    y_mean = sum(ys) / len(ys)
    x_variance = sum((value - x_mean) ** 2 for value in xs)
    y_variance = sum((value - y_mean) ** 2 for value in ys)
    if x_variance == 0 or y_variance == 0:
        return None
    covariance = sum(
        (x_value - x_mean) * (y_value - y_mean)
        for x_value, y_value in zip(xs, ys, strict=True)
    )
    return covariance / math.sqrt(x_variance * y_variance)


def _spearman(xs: list[int] | list[float], ys: list[int] | list[float]) -> float | None:
    if len(xs) != len(ys) or len(xs) < 2:
        return None
    return _pearson(_average_ranks(xs), _average_ranks(ys))


def _average_ranks(values: list[int] | list[float]) -> list[float]:
    order = sorted(range(len(values)), key=values.__getitem__)
    ranks = [0.0] * len(values)
    index = 0
    while index < len(order):
        end = index + 1
        while end < len(order) and values[order[end]] == values[order[index]]:
            end += 1
        rank = (index + end - 1) / 2
        for tied_index in range(index, end):
            ranks[order[tied_index]] = rank
        index = end
    return ranks


def _sqlite_scalar_int(connection: sqlite3.Connection, sql: str) -> int:
    return int(connection.execute(sql).fetchone()[0])


@dataclass(frozen=True)
class _DecodedPrimaryKey:
    raw: bytes
    key: str | None
    encoding_guess: str
    byte_length: int
    char_length: int | None


@dataclass(frozen=True)
class _PrimaryKeyRank:
    decoded: _DecodedPrimaryKey
    lower_bound_rank: int | None
    lower_bound_a_id: int | None
    exact_match_count: int
    prefix_match_count: int


def _read_primary_key_raws(drt_path: Path, primary_index: DrtPrimaryIndex) -> list[bytes]:
    with drt_path.open("rb") as handle:
        handle.seek(primary_index.index_descriptor.data_offset)
        data = handle.read(primary_index.index_descriptor.byte_length)
    return [
        data[offset : offset + 4]
        for offset in range(0, len(data), PRIMARY_INDEX_RECORD_SIZE)
    ]


def _decode_primary_separator_key(raw: bytes) -> _DecodedPrimaryKey:
    key = raw.lstrip(b"\x00")
    if not key:
        return _DecodedPrimaryKey(
            raw=raw,
            key=None,
            encoding_guess="empty",
            byte_length=0,
            char_length=0,
        )
    if all(0x20 <= byte <= 0x7E for byte in key):
        decoded = key.decode("ascii")
        return _DecodedPrimaryKey(
            raw=raw,
            key=decoded,
            encoding_guess="ascii",
            byte_length=len(key),
            char_length=len(decoded),
        )
    if len(key) % 2 == 0:
        try:
            decoded = key.decode("utf-16be")
        except UnicodeDecodeError:
            pass
        else:
            if decoded.isprintable():
                return _DecodedPrimaryKey(
                    raw=raw,
                    key=decoded,
                    encoding_guess="utf-16be",
                    byte_length=len(key),
                    char_length=len(decoded),
                )
    return _DecodedPrimaryKey(
        raw=raw,
        key=None,
        encoding_guess="binary",
        byte_length=len(key),
        char_length=None,
    )


def _prefix_match_count(words: list[str], key: str, rank: int) -> int:
    count = 0
    for word in words[rank:]:
        if not word.startswith(key):
            break
        count += 1
    return count


def _primary_partition_bounds(
    key_summaries: list[_PrimaryKeyRank], keyword_count: int, *, enabled: bool
) -> list[tuple[int | None, int | None]]:
    if not enabled:
        return [(None, None) for _item in key_summaries]
    bounds: list[tuple[int | None, int | None]] = []
    previous_rank = 0
    for item in key_summaries:
        if item.lower_bound_rank is None:
            partition_end_rank = keyword_count
        else:
            partition_end_rank = item.lower_bound_rank
        bounds.append((previous_rank, partition_end_rank))
        previous_rank = partition_end_rank
    return bounds
