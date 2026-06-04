from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from atokdict.container import parse_header


DSY_METADATA_OFFSET = 0x300
DSY_METADATA_BYTE_LENGTH = 0x30
DSY_REGION_TABLE_OFFSET = 0x330
DSY_REGION_TABLE_END = 0x360
DSY_REGION_RECORD_SIZE = 8


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
