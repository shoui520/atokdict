from __future__ import annotations

from pathlib import Path

from atokdict.dsy import parse_dsy_map


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
    path.write_bytes(data)

    dsy_map = parse_dsy_map(path)

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


def _write_region(data: bytearray, descriptor_offset: int, offset: int, length: int) -> None:
    data[descriptor_offset : descriptor_offset + 4] = offset.to_bytes(4, "big")
    data[descriptor_offset + 4 : descriptor_offset + 8] = length.to_bytes(4, "big")
