from __future__ import annotations

from bisect import bisect_left, bisect_right
from dataclasses import dataclass
import hashlib
from pathlib import Path
import sqlite3

from atokdict.companion import decoded_companion_tempfile
from atokdict.drt import DrtPrimaryIndex
from atokdict.drt import PRIMARY_INDEX_RECORD_SIZE
from atokdict.drt import parse_drt_primary_index, parse_drt_root_index


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
