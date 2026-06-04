from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class TextRun:
    offset: int
    byte_length: int
    char_count: int
    non_ascii_chars: int

    def to_dict(self) -> dict[str, int]:
        return asdict(self)


def scan_cp932_runs(
    path: str | Path,
    *,
    min_chars: int = 12,
    limit: int = 100,
    max_bytes: int | None = None,
) -> list[TextRun]:
    with Path(path).open("rb") as handle:
        data = handle.read(max_bytes or -1)

    runs: list[TextRun] = []
    index = 0
    while index < len(data):
        start = index
        char_count = 0
        non_ascii = 0
        while index < len(data):
            consumed = _cp932_char_length(data, index)
            if consumed == 0:
                break
            if data[index] >= 0x80:
                non_ascii += 1
            char_count += 1
            index += consumed

        if char_count >= min_chars and non_ascii:
            runs.append(
                TextRun(
                    offset=start,
                    byte_length=index - start,
                    char_count=char_count,
                    non_ascii_chars=non_ascii,
                )
            )
            if len(runs) >= limit:
                return runs

        index = max(index + 1, start + 1)
    return runs


def _cp932_char_length(data: bytes, index: int) -> int:
    byte = data[index]
    if byte in (0x09, 0x0A, 0x0D) or 0x20 <= byte <= 0x7E:
        return 1
    if 0xA1 <= byte <= 0xDF:
        return 1
    if 0x81 <= byte <= 0x9F or 0xE0 <= byte <= 0xFC:
        if index + 1 >= len(data):
            return 0
        trail = data[index + 1]
        if 0x40 <= trail <= 0x7E or 0x80 <= trail <= 0xFC:
            return 2
    return 0
