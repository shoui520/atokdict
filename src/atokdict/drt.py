from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import BinaryIO

from atokdict.container import AtokSectionDescriptor, parse_header, parse_section_descriptors


ROOT_HEADER_SIZE = 14
ROOT_RECORD_FIXED_SIZE = 16
PRIMARY_INDEX_DESCRIPTOR_OFFSET = 0x390
PRIMARY_PAYLOAD_DESCRIPTOR_OFFSET = 0x3A8
PRIMARY_INDEX_RECORD_SIZE = 20
DEFAULT_MAX_ROOT_ENTRIES = 4096
DEFAULT_MAX_ROOT_BYTES = 4 * 1024 * 1024
DEFAULT_MAX_KEY_BYTES = 1024
DEFAULT_CHILD_SCAN_BYTES = 16 * 1024
DEFAULT_CHILD_HASH_BYTES = 64
CHILD_MARKERS = (0xFFFF, 0xFFFE, 0xFFFD)


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


@dataclass(frozen=True)
class DrtRootChildBlock:
    root_entry_index: int
    block_offset: int
    relative_offset: int
    byte_length: int
    root_flag: int
    root_tag: int
    root_value_a: int
    root_value_b: int
    root_key_byte_length: int
    root_key_char_length: int
    root_key_sha256_utf16be: str
    scan_byte_length: int
    prefix_sha256: str
    marker_first_offsets: dict[str, int | None]
    marker_counts: dict[str, int]
    possible_absolute_offsets_in_scan: int

    def to_dict(self) -> dict[str, object]:
        return {
            "root_entry_index": self.root_entry_index,
            "block_offset": self.block_offset,
            "relative_offset": self.relative_offset,
            "byte_length": self.byte_length,
            "root_flag": self.root_flag,
            "root_tag": self.root_tag,
            "root_value_a": self.root_value_a,
            "root_value_b": self.root_value_b,
            "root_key_byte_length": self.root_key_byte_length,
            "root_key_char_length": self.root_key_char_length,
            "root_key_sha256_utf16be": self.root_key_sha256_utf16be,
            "scan_byte_length": self.scan_byte_length,
            "prefix_sha256": self.prefix_sha256,
            "marker_first_offsets": self.marker_first_offsets,
            "marker_counts": self.marker_counts,
            "possible_absolute_offsets_in_scan": self.possible_absolute_offsets_in_scan,
        }


@dataclass(frozen=True)
class DrtPrimaryIndexEntry:
    record_index: int
    record_offset: int
    key_raw_sha256: str
    key_byte_length: int
    key_encoding_guess: str
    key_char_length: int | None
    data_offset: int
    relative_offset: int
    byte_length: int
    unknown_0x08: int
    unknown_0x0c: int
    unknown_0x10: int

    def to_dict(self) -> dict[str, object]:
        return {
            "record_index": self.record_index,
            "record_offset": self.record_offset,
            "key_raw_sha256": self.key_raw_sha256,
            "key_byte_length": self.key_byte_length,
            "key_encoding_guess": self.key_encoding_guess,
            "key_char_length": self.key_char_length,
            "data_offset": self.data_offset,
            "relative_offset": self.relative_offset,
            "byte_length": self.byte_length,
            "unknown_0x08": self.unknown_0x08,
            "unknown_0x0c": self.unknown_0x0c,
            "unknown_0x10": self.unknown_0x10,
        }


@dataclass(frozen=True)
class DrtPrimaryIndex:
    path: str | None
    index_descriptor: AtokSectionDescriptor
    payload_descriptor: AtokSectionDescriptor
    record_count: int
    entries: list[DrtPrimaryIndexEntry]

    def to_dict(self, *, entry_limit: int | None = None) -> dict[str, object]:
        entries = self.entries if entry_limit is None else self.entries[:entry_limit]
        return {
            "path": self.path,
            "index_descriptor": self.index_descriptor.to_dict(),
            "payload_descriptor": self.payload_descriptor.to_dict(),
            "record_count": self.record_count,
            "entries_returned": len(entries),
            "entries": [entry.to_dict() for entry in entries],
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


def parse_drt_primary_index(path_or_file: str | Path | BinaryIO) -> DrtPrimaryIndex:
    header = parse_header(path_or_file)
    if header.container_magic != "DRT":
        raise ValueError("DRT primary index parsing requires a DRT container")

    descriptors = {
        item.descriptor_offset: item for item in parse_section_descriptors(path_or_file)
    }
    index_descriptor = descriptors.get(PRIMARY_INDEX_DESCRIPTOR_OFFSET)
    payload_descriptor = descriptors.get(PRIMARY_PAYLOAD_DESCRIPTOR_OFFSET)
    if index_descriptor is None or payload_descriptor is None:
        raise ValueError("DRT primary index requires descriptors at 0x390 and 0x3a8")
    if index_descriptor.byte_length % PRIMARY_INDEX_RECORD_SIZE:
        raise ValueError("DRT primary index byte length is not a multiple of 20")

    data = _read_absolute_prefix(
        path_or_file,
        offset=index_descriptor.data_offset,
        byte_length=index_descriptor.byte_length,
    )
    record_count = len(data) // PRIMARY_INDEX_RECORD_SIZE
    pointers: list[int] = []
    raw_records: list[tuple[bytes, int, int, int, int]] = []
    for index in range(record_count):
        position = index * PRIMARY_INDEX_RECORD_SIZE
        key_raw = data[position : position + 4]
        data_offset = int.from_bytes(data[position + 4 : position + 8], "big")
        unknown_0x08 = int.from_bytes(data[position + 8 : position + 12], "big")
        unknown_0x0c = int.from_bytes(data[position + 12 : position + 16], "big")
        unknown_0x10 = int.from_bytes(data[position + 16 : position + 20], "big")
        if not payload_descriptor.data_offset <= data_offset < payload_descriptor.end_offset:
            raise ValueError("DRT primary index record points outside descriptor 0x3a8")
        pointers.append(data_offset)
        raw_records.append((key_raw, data_offset, unknown_0x08, unknown_0x0c, unknown_0x10))

    if not all(earlier <= later for earlier, later in zip(pointers, pointers[1:])):
        raise ValueError("DRT primary index data offsets are not monotonic")

    ends = pointers[1:] + [payload_descriptor.end_offset]
    entries: list[DrtPrimaryIndexEntry] = []
    for index, ((key_raw, data_offset, unknown_0x08, unknown_0x0c, unknown_0x10), end) in enumerate(
        zip(raw_records, ends, strict=True)
    ):
        key_info = _guess_primary_key_encoding(key_raw)
        entries.append(
            DrtPrimaryIndexEntry(
                record_index=index,
                record_offset=index_descriptor.data_offset
                + index * PRIMARY_INDEX_RECORD_SIZE,
                key_raw_sha256=hashlib.sha256(key_raw).hexdigest(),
                key_byte_length=key_info[0],
                key_encoding_guess=key_info[1],
                key_char_length=key_info[2],
                data_offset=data_offset,
                relative_offset=data_offset - payload_descriptor.data_offset,
                byte_length=end - data_offset,
                unknown_0x08=unknown_0x08,
                unknown_0x0c=unknown_0x0c,
                unknown_0x10=unknown_0x10,
            )
        )

    return DrtPrimaryIndex(
        path=header.path,
        index_descriptor=index_descriptor,
        payload_descriptor=payload_descriptor,
        record_count=record_count,
        entries=entries,
    )


def summarize_drt_root_child_blocks(
    path_or_file: str | Path | BinaryIO,
    *,
    scan_bytes: int = DEFAULT_CHILD_SCAN_BYTES,
    prefix_hash_bytes: int = DEFAULT_CHILD_HASH_BYTES,
) -> list[DrtRootChildBlock]:
    root_index = parse_drt_root_index(path_or_file)
    starts = [entry.data_offset for entry in root_index.entries]
    ends = starts[1:] + [root_index.section_descriptor.end_offset]
    summaries: list[DrtRootChildBlock] = []

    for index, (entry, end_offset) in enumerate(zip(root_index.entries, ends, strict=True)):
        byte_length = end_offset - entry.data_offset
        if byte_length < 0:
            raise ValueError("DRT root child block pointers are not monotonic")
        scan = _read_absolute_prefix(
            path_or_file,
            offset=entry.data_offset,
            byte_length=min(byte_length, scan_bytes),
        )
        summaries.append(
            DrtRootChildBlock(
                root_entry_index=index,
                block_offset=entry.data_offset,
                relative_offset=entry.data_offset - root_index.section_descriptor.data_offset,
                byte_length=byte_length,
                root_flag=entry.flag,
                root_tag=entry.tag,
                root_value_a=entry.value_a,
                root_value_b=entry.value_b,
                root_key_byte_length=entry.key_byte_length,
                root_key_char_length=entry.key_char_length,
                root_key_sha256_utf16be=hashlib.sha256(
                    entry.key.encode("utf-16be")
                ).hexdigest(),
                scan_byte_length=len(scan),
                prefix_sha256=hashlib.sha256(scan[:prefix_hash_bytes]).hexdigest(),
                marker_first_offsets=_marker_first_offsets(scan),
                marker_counts=_marker_counts(scan),
                possible_absolute_offsets_in_scan=_possible_absolute_offset_count(
                    scan, root_index.section_descriptor
                ),
            )
        )
    return summaries


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


def _read_absolute_prefix(
    path_or_file: str | Path | BinaryIO,
    *,
    offset: int,
    byte_length: int,
) -> bytes:
    if hasattr(path_or_file, "read"):
        current = (
            path_or_file.tell()  # type: ignore[union-attr]
            if hasattr(path_or_file, "tell")
            else None
        )
        if hasattr(path_or_file, "seek"):
            path_or_file.seek(offset)  # type: ignore[union-attr]
        data = path_or_file.read(byte_length)  # type: ignore[union-attr]
        if current is not None and hasattr(path_or_file, "seek"):
            path_or_file.seek(current)  # type: ignore[union-attr]
        return data

    path = Path(path_or_file)
    with path.open("rb") as handle:
        handle.seek(offset)
        return handle.read(byte_length)


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


def _possible_absolute_offset_count(data: bytes, section: AtokSectionDescriptor) -> int:
    count = 0
    for offset in range(0, len(data) - 3, 2):
        value = int.from_bytes(data[offset : offset + 4], "big")
        if section.data_offset <= value < section.end_offset:
            count += 1
    return count


def _guess_primary_key_encoding(key_raw: bytes) -> tuple[int, str, int | None]:
    key = key_raw.lstrip(b"\x00")
    if not key:
        return 0, "empty", 0
    if all(0x20 <= byte <= 0x7E for byte in key):
        return len(key), "ascii", len(key)
    if len(key) % 2 == 0:
        try:
            decoded = key.decode("utf-16be")
        except UnicodeDecodeError:
            pass
        else:
            if decoded.isprintable():
                return len(key), "utf-16be", len(decoded)
    return len(key), "binary", None
