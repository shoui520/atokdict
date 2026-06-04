from __future__ import annotations

from io import BytesIO

from atokdict.container import parse_header, parse_section_descriptors


def test_parse_synthetic_dic_header() -> None:
    data = bytearray(0x100)
    data[0:4] = b"DIC\0"
    data[8:12] = b"ATOK"
    data[0x10:0x14] = (0xA0).to_bytes(4, "big")
    data[0x14:0x18] = bytes([0x0B, 0x16, 0x10, 0x24])
    data[0x1C:0x20] = (1).to_bytes(4, "big")
    data[0x3C:0x40] = bytes([0x19, 0x89, 0x02, 0x22])
    data[0x40:0x46] = "辞書".encode("cp932")

    header = parse_header(BytesIO(data))

    assert header.container_magic == "DIC"
    assert header.subtype == "ATOK"
    assert header.format_code == 0xA0
    assert header.variant_code == 0x0B
    assert header.build_year == 2016
    assert header.build_month == 10
    assert header.build_day == 24
    assert header.flag_0x1c == 1
    assert header.epoch_bcd == "1989-02-22"
    assert header.title == "辞書"
    assert header.title_encoding == "cp932"


def test_parse_synthetic_dsy_title_as_utf16be() -> None:
    data = bytearray(0x100)
    data[0:4] = b"DSY\0"
    data[8:12] = b"ATOK"
    data[0x10:0x14] = (0x0E01).to_bytes(4, "big")
    data[0x14:0x18] = bytes([0x01, 0x18, 0x11, 0x16])
    data[0x3C:0x40] = bytes([0x19, 0x89, 0x02, 0x22])
    data[0x40:0x40 + len("類語".encode("utf-16be"))] = "類語".encode("utf-16be")

    header = parse_header(BytesIO(data))

    assert header.container_magic == "DSY"
    assert header.format_code == 0x0E01
    assert header.title == "類語"
    assert header.title_encoding == "utf-16be"


def test_parse_synthetic_section_descriptors() -> None:
    data = bytearray(0x500)
    data[0:4] = b"DRT\0"
    data[8:12] = b"ATOK"
    data[0x10:0x14] = (0x0F01).to_bytes(4, "big")
    data[0x14:0x18] = bytes([0x01, 0x18, 0x11, 0x16])
    data[0x3C:0x40] = bytes([0x19, 0x89, 0x02, 0x22])
    data[0x40:0x46] = "辞書".encode("cp932")
    data[0x388:0x390] = (0x400).to_bytes(4, "big") + (0x80).to_bytes(4, "big")
    data[0x390:0x398] = (0x480).to_bytes(4, "big") + (0x40).to_bytes(4, "big")

    sections = parse_section_descriptors(BytesIO(data))

    assert [section.descriptor_offset for section in sections] == [0x388, 0x390]
    assert sections[0].data_offset == 0x400
    assert sections[0].byte_length == 0x80
    assert sections[0].end_offset == 0x480
