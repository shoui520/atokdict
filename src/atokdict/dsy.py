from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Callable

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
