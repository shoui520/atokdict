from __future__ import annotations

from bisect import bisect_left, bisect_right
from dataclasses import dataclass
import hashlib
from pathlib import Path
import sqlite3

from atokdict.companion import decoded_companion_tempfile
from atokdict.drt import parse_drt_root_index


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


def _read_keyword_rows(drw_path: Path) -> list[tuple[str, int]]:
    with decoded_companion_tempfile(drw_path) as decoded_path:
        connection = sqlite3.connect(f"file:{decoded_path}?mode=ro", uri=True)
        try:
            rows = connection.execute("SELECT word, a_id FROM keyword_info").fetchall()
        finally:
            connection.close()
    return sorted((str(word), int(a_id)) for word, a_id in rows)
