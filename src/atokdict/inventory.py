from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path

from atokdict.companion import CompanionSqliteHeader, parse_companion_header
from atokdict.container import AtokHeader, parse_header
from atokdict.container import parse_section_descriptors


KNOWN_EXTENSIONS = {".DIC", ".DRT", ".DRW", ".DAR", ".DSY", ".DSZ"}


@dataclass(frozen=True)
class InventoryFile:
    path: str
    name: str
    stem: str
    extension: str
    size: int
    header: dict[str, object] | None
    companion_sqlite: dict[str, object] | None
    section_descriptors: list[dict[str, int]]


@dataclass(frozen=True)
class InventoryGroup:
    stem: str
    files: list[InventoryFile]


def scan_inventory(root: str | Path) -> list[InventoryGroup]:
    root_path = Path(root)
    grouped: dict[str, list[InventoryFile]] = defaultdict(list)
    for path in sorted(root_path.rglob("*")):
        if not path.is_file() or path.suffix.upper() not in KNOWN_EXTENSIONS:
            continue
        header = _try_parse_header(path)
        companion = _try_parse_companion_header(path) if header is None else None
        sections = _try_parse_section_descriptors(path) if header is not None else []
        item = InventoryFile(
            path=str(path),
            name=path.name,
            stem=path.stem,
            extension=path.suffix.upper().lstrip("."),
            size=path.stat().st_size,
            header=header.to_dict() if header else None,
            companion_sqlite=companion.to_dict() if companion else None,
            section_descriptors=sections,
        )
        grouped[path.stem].append(item)
    return [
        InventoryGroup(stem=stem, files=sorted(files, key=lambda item: item.extension))
        for stem, files in sorted(grouped.items())
    ]


def inventory_to_dict(groups: list[InventoryGroup]) -> list[dict[str, object]]:
    return [
        {"stem": group.stem, "files": [asdict(item) for item in group.files]}
        for group in groups
    ]


def _try_parse_header(path: Path) -> AtokHeader | None:
    try:
        return parse_header(path)
    except ValueError:
        return None


def _try_parse_companion_header(path: Path) -> CompanionSqliteHeader | None:
    if path.suffix.upper() not in {".DRW", ".DSZ"}:
        return None
    try:
        return parse_companion_header(path)
    except ValueError:
        return None


def _try_parse_section_descriptors(path: Path) -> list[dict[str, int]]:
    try:
        return [descriptor.to_dict() for descriptor in parse_section_descriptors(path)]
    except ValueError:
        return []
