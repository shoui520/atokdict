from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import BinaryIO


HEADER_SIZE = 0x100
TITLE_OFFSET = 0x40
TITLE_SIZE = 0x40
EPOCH_OFFSET = 0x3C
KNOWN_CONTAINER_MAGICS = {"DIC", "DRT", "DSY"}


@dataclass(frozen=True)
class AtokHeader:
    path: str | None
    size: int | None
    container_magic: str
    subtype: str
    format_code: int
    variant_code: int
    build_year: int | None
    build_month: int | None
    build_day: int | None
    flag_0x1c: int
    epoch_bcd: str | None
    title: str
    title_encoding: str
    raw_title_hex: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def parse_header(path_or_file: str | Path | BinaryIO) -> AtokHeader:
    path: Path | None
    size: int | None
    if hasattr(path_or_file, "read"):
        path = None
        size = None
        data = path_or_file.read(HEADER_SIZE)  # type: ignore[union-attr]
    else:
        path = Path(path_or_file)
        size = path.stat().st_size
        with path.open("rb") as handle:
            data = handle.read(HEADER_SIZE)

    if len(data) < 0x80:
        raise ValueError("file is too small to contain an ATOK-style header")

    magic = _decode_ascii_token(data[0:4])
    if magic not in KNOWN_CONTAINER_MAGICS:
        raise ValueError(f"unknown ATOK container magic: {magic!r}")

    subtype = _decode_ascii_token(data[8:12])
    format_code = int.from_bytes(data[0x10:0x14], "big")
    variant_code = data[0x14]
    build_year = _decode_bcd_year(data[0x15])
    build_month = _decode_bcd_byte(data[0x16])
    build_day = _decode_bcd_byte(data[0x17])
    flag_0x1c = int.from_bytes(data[0x1C:0x20], "big")
    epoch_bcd = _decode_epoch(data[EPOCH_OFFSET : EPOCH_OFFSET + 4])
    raw_title = data[TITLE_OFFSET : TITLE_OFFSET + TITLE_SIZE]
    title, title_encoding = _decode_title(magic, raw_title)

    return AtokHeader(
        path=str(path) if path else None,
        size=size,
        container_magic=magic,
        subtype=subtype,
        format_code=format_code,
        variant_code=variant_code,
        build_year=build_year,
        build_month=build_month,
        build_day=build_day,
        flag_0x1c=flag_0x1c,
        epoch_bcd=epoch_bcd,
        title=title,
        title_encoding=title_encoding,
        raw_title_hex=raw_title.rstrip(b"\x00").hex(),
    )


def _decode_ascii_token(data: bytes) -> str:
    return data.rstrip(b"\x00").decode("ascii", errors="replace")


def _decode_cp932_c_string(data: bytes) -> str:
    return data.split(b"\x00", 1)[0].decode("cp932", errors="replace")


def _decode_title(container_magic: str, data: bytes) -> tuple[str, str]:
    if container_magic == "DSY":
        return _decode_utf16be_c_string(data), "utf-16be"
    return _decode_cp932_c_string(data), "cp932"


def _decode_utf16be_c_string(data: bytes) -> str:
    end = len(data)
    for index in range(0, len(data) - 1, 2):
        if data[index : index + 2] == b"\x00\x00":
            end = index
            break
    if end % 2:
        end -= 1
    return data[:end].decode("utf-16be", errors="replace")


def _decode_bcd_byte(value: int) -> int | None:
    hi, lo = divmod(value, 16)
    if hi > 9 or lo > 9:
        return None
    return hi * 10 + lo


def _decode_bcd_year(value: int) -> int | None:
    year = _decode_bcd_byte(value)
    if year is None:
        return None
    return 2000 + year if year < 80 else 1900 + year


def _decode_epoch(data: bytes) -> str | None:
    if len(data) != 4:
        return None
    year_hi = _decode_bcd_byte(data[0])
    year_lo = _decode_bcd_byte(data[1])
    month = _decode_bcd_byte(data[2])
    day = _decode_bcd_byte(data[3])
    if None in (year_hi, year_lo, month, day):
        return None
    return f"{year_hi:02d}{year_lo:02d}-{month:02d}-{day:02d}"
