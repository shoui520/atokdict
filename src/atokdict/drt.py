from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import BinaryIO

from atokdict.container import AtokSectionDescriptor, parse_header, parse_section_descriptors


ROOT_HEADER_SIZE = 14
ROOT_RECORD_FIXED_SIZE = 16
DEFAULT_MAX_ROOT_ENTRIES = 4096
DEFAULT_MAX_ROOT_BYTES = 4 * 1024 * 1024
DEFAULT_MAX_KEY_BYTES = 1024


@dataclass(frozen=True)
class DrtRootIndexEntry:
    record_offset: int
    data_offset: int
    flag: int
    tag: int
    value_a: int
    value_b: int
    key: str
    key_encoding: str
    key_byte_length: int

    @property
    def key_char_length(self) -> int:
        return len(self.key)

    def to_dict(self, *, include_key: bool = False) -> dict[str, object]:
        output: dict[str, object] = {
            "record_offset": self.record_offset,
            "data_offset": self.data_offset,
            "flag": self.flag,
            "tag": self.tag,
            "value_a": self.value_a,
            "value_b": self.value_b,
            "key_encoding": self.key_encoding,
            "key_byte_length": self.key_byte_length,
            "key_char_length": self.key_char_length,
        }
        if include_key:
            output["key"] = self.key
        else:
            output["key_sha256_utf16be"] = hashlib.sha256(
                self.key.encode("utf-16be")
            ).hexdigest()
        return output


@dataclass(frozen=True)
class DrtRootIndex:
    path: str | None
    section_descriptor: AtokSectionDescriptor
    entry_count: int
    root_header_unknown_hex: str
    root_record_area_length: int
    entries: list[DrtRootIndexEntry]

    def to_dict(
        self, *, include_keys: bool = False, entry_limit: int | None = None
    ) -> dict[str, object]:
        entries = self.entries if entry_limit is None else self.entries[:entry_limit]
        return {
            "path": self.path,
            "section_descriptor": self.section_descriptor.to_dict(),
            "entry_count": self.entry_count,
            "root_header_unknown_hex": self.root_header_unknown_hex,
            "root_record_area_length": self.root_record_area_length,
            "entries_returned": len(entries),
            "entries": [entry.to_dict(include_key=include_keys) for entry in entries],
        }


def parse_drt_root_index(
    path_or_file: str | Path | BinaryIO,
    *,
    max_entries: int = DEFAULT_MAX_ROOT_ENTRIES,
    max_root_bytes: int = DEFAULT_MAX_ROOT_BYTES,
) -> DrtRootIndex:
    header = parse_header(path_or_file)
    if header.container_magic != "DRT":
        raise ValueError("DRT root index parsing requires a DRT container")

    sections = parse_section_descriptors(path_or_file)
    if not sections:
        raise ValueError("DRT container has no parsed section descriptors")

    section = next((item for item in reversed(sections) if item.byte_length > 0), None)
    if section is None:
        raise ValueError("DRT container has no non-empty parsed section descriptors")

    data = _read_section_prefix(path_or_file, section, max_root_bytes=max_root_bytes)
    if len(data) < ROOT_HEADER_SIZE:
        raise ValueError("DRT final section is too small to contain a root index header")

    entry_count = int.from_bytes(data[0:4], "big")
    unknown_header = data[4:ROOT_HEADER_SIZE]
    if entry_count <= 0 or entry_count > max_entries:
        raise ValueError("DRT final section does not look like the observed root index layout")
    if unknown_header != b"\x00" * len(unknown_header):
        raise ValueError("DRT root index header does not match the observed zero-filled layout")

    position = ROOT_HEADER_SIZE
    entries: list[DrtRootIndexEntry] = []
    pending_last_entry: tuple[int, int, int, int, int, int] | None = None

    for entry_index in range(entry_count):
        fields = _read_record_fields(data, position, section)
        data_offset, flag, tag, value_a, value_b = fields
        if entry_index == entry_count - 1:
            pending_last_entry = (position, data_offset, flag, tag, value_a, value_b)
            break

        next_position = _find_next_record_position(data, position, section)
        if next_position is None:
            raise ValueError("could not infer the next DRT root index record boundary")

        key_bytes = data[position + ROOT_RECORD_FIXED_SIZE : next_position]
        key = _decode_key(key_bytes)
        entries.append(
            DrtRootIndexEntry(
                record_offset=section.data_offset + position,
                data_offset=data_offset,
                flag=flag,
                tag=tag,
                value_a=value_a,
                value_b=value_b,
                key=key,
                key_encoding="utf-16be",
                key_byte_length=len(key_bytes),
            )
        )
        position = next_position

    if pending_last_entry is None:
        raise ValueError("DRT root index did not contain a final entry")

    position, data_offset, flag, tag, value_a, value_b = pending_last_entry
    root_entry_area_end = min([entry.data_offset for entry in entries] + [data_offset])
    key_end = root_entry_area_end - section.data_offset
    if key_end < position + ROOT_RECORD_FIXED_SIZE:
        raise ValueError("DRT root index pointer area overlaps the final root record")
    if key_end > len(data):
        raise ValueError("DRT root index entry area exceeds the bytes read for parsing")

    key_bytes = data[position + ROOT_RECORD_FIXED_SIZE : key_end]
    key = _decode_key(key_bytes)
    entries.append(
        DrtRootIndexEntry(
            record_offset=section.data_offset + position,
            data_offset=data_offset,
            flag=flag,
            tag=tag,
            value_a=value_a,
            value_b=value_b,
            key=key,
            key_encoding="utf-16be",
            key_byte_length=len(key_bytes),
        )
    )

    return DrtRootIndex(
        path=header.path,
        section_descriptor=section,
        entry_count=entry_count,
        root_header_unknown_hex=unknown_header.hex(),
        root_record_area_length=key_end - ROOT_HEADER_SIZE,
        entries=entries,
    )


def _read_section_prefix(
    path_or_file: str | Path | BinaryIO,
    section: AtokSectionDescriptor,
    *,
    max_root_bytes: int,
) -> bytes:
    bytes_to_read = min(section.byte_length, max_root_bytes)
    if hasattr(path_or_file, "read"):
        current = (
            path_or_file.tell()  # type: ignore[union-attr]
            if hasattr(path_or_file, "tell")
            else None
        )
        if hasattr(path_or_file, "seek"):
            path_or_file.seek(section.data_offset)  # type: ignore[union-attr]
        data = path_or_file.read(bytes_to_read)  # type: ignore[union-attr]
        if current is not None and hasattr(path_or_file, "seek"):
            path_or_file.seek(current)  # type: ignore[union-attr]
        return data

    path = Path(path_or_file)
    with path.open("rb") as handle:
        handle.seek(section.data_offset)
        return handle.read(bytes_to_read)


def _read_record_fields(
    data: bytes, position: int, section: AtokSectionDescriptor
) -> tuple[int, int, int, int, int]:
    if position + ROOT_RECORD_FIXED_SIZE > len(data):
        raise ValueError("DRT root index record is truncated")
    data_offset = int.from_bytes(data[position : position + 4], "big")
    if not section.data_offset <= data_offset < section.end_offset:
        raise ValueError("DRT root index record points outside the final section")
    flag = int.from_bytes(data[position + 4 : position + 6], "big")
    tag = int.from_bytes(data[position + 6 : position + 8], "big")
    value_a = int.from_bytes(data[position + 8 : position + 12], "big")
    value_b = int.from_bytes(data[position + 12 : position + 16], "big")
    return data_offset, flag, tag, value_a, value_b


def _find_next_record_position(
    data: bytes, position: int, section: AtokSectionDescriptor
) -> int | None:
    search_start = position + ROOT_RECORD_FIXED_SIZE
    search_end = min(len(data) - 8, search_start + DEFAULT_MAX_KEY_BYTES)
    for candidate in range(search_start, search_end + 1, 2):
        candidate_offset = int.from_bytes(data[candidate : candidate + 4], "big")
        if not section.data_offset <= candidate_offset < section.end_offset:
            continue
        try:
            _decode_key(data[search_start:candidate])
        except ValueError:
            continue
        return candidate
    return None


def _decode_key(data: bytes) -> str:
    if len(data) % 2:
        raise ValueError("DRT root index key has odd UTF-16BE byte length")
    return data.decode("utf-16be")
