from __future__ import annotations

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


def _byte_ratio(data: bytes, predicate: Callable[[int], bool]) -> float:
    if not data:
        return 0.0
    count = sum(1 for value in data if predicate(value))
    return round(count / len(data), 6)
