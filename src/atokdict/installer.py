from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path


DICTIONARY_KEYS = {"SetDic", "SetAbbDic", "SetDrtDic", "SetAcsDic"}


@dataclass(frozen=True)
class SetupDictionaryRef:
    role: str
    filename: str
    priority: int | None = None


@dataclass(frozen=True)
class SetupVersionBlock:
    selector: str
    folder: str | None = None
    dictionaries: list[SetupDictionaryRef] = field(default_factory=list)


@dataclass(frozen=True)
class SetupMetadata:
    path: str
    encoding: str
    product_name: str | None
    product_id: str | None
    license_file: str | None
    manual_file: str | None
    version_blocks: list[SetupVersionBlock]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def parse_setup_ini(path: str | Path) -> SetupMetadata:
    setup_path = Path(path)
    text, encoding = _decode_setup(setup_path.read_bytes())
    product_name: str | None = None
    product_id: str | None = None
    license_file: str | None = None
    manual_file: str | None = None
    blocks: list[SetupVersionBlock] = []
    current_selector: str | None = None
    current_folder: str | None = None
    current_refs: list[SetupDictionaryRef] = []

    def finish_block() -> None:
        nonlocal current_selector, current_folder, current_refs
        if current_selector is not None:
            blocks.append(
                SetupVersionBlock(
                    selector=current_selector,
                    folder=current_folder,
                    dictionaries=current_refs,
                )
            )
        current_selector = None
        current_folder = None
        current_refs = []

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("<Version=") and line.endswith(">"):
            finish_block()
            current_selector = line[len("<Version=") : -1]
            continue
        if line == "</Version>":
            finish_block()
            continue
        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        if key == "ProductName":
            product_name = value
        elif key == "ProductID":
            product_id = value
        elif key == "License":
            license_file = value
        elif key == "Manual":
            manual_file = value
        elif key == "Folder" and current_selector is not None:
            current_folder = value
        elif key in DICTIONARY_KEYS and current_selector is not None:
            current_refs.append(_parse_dictionary_ref(key, value))

    finish_block()

    return SetupMetadata(
        path=str(setup_path),
        encoding=encoding,
        product_name=product_name,
        product_id=product_id,
        license_file=license_file,
        manual_file=manual_file,
        version_blocks=blocks,
    )


def _decode_setup(data: bytes) -> tuple[str, str]:
    if data.startswith(b"\xff\xfe"):
        return data[2:].decode("utf-16le"), "utf-16le"
    if data.startswith(b"\xfe\xff"):
        return data[2:].decode("utf-16be"), "utf-16be"
    return data.decode("cp932"), "cp932"


def _parse_dictionary_ref(role: str, value: str) -> SetupDictionaryRef:
    parts = [part.strip() for part in value.split(",", 1)]
    priority: int | None = None
    if len(parts) == 2 and parts[1]:
        try:
            priority = int(parts[1])
        except ValueError:
            priority = None
    return SetupDictionaryRef(role=role, filename=parts[0], priority=priority)
