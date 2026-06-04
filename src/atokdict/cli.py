from __future__ import annotations

import argparse
import json
from pathlib import Path

from atokdict.companion import (
    companion_page_type_counts,
    parse_companion_header,
    read_companion_schema,
)
from atokdict.container import parse_header
from atokdict.container import parse_section_descriptors
from atokdict.drt import parse_drt_root_index
from atokdict.drt import summarize_drt_root_child_blocks
from atokdict.installer import parse_setup_ini
from atokdict.inventory import inventory_to_dict, scan_inventory
from atokdict.textscan import scan_cp932_runs, scan_utf16be_runs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="atokdict")
    subparsers = parser.add_subparsers(dest="command", required=True)

    header_parser = subparsers.add_parser("header", help="parse an ATOK container header")
    header_parser.add_argument("path", type=Path)

    sections_parser = subparsers.add_parser(
        "sections", help="parse structural ATOK offset/length descriptors"
    )
    sections_parser.add_argument("path", type=Path)

    drt_root_parser = subparsers.add_parser(
        "drt-root-index", help="parse the observed DRT final-section root index"
    )
    drt_root_parser.add_argument("path", type=Path)
    drt_root_parser.add_argument("--limit", type=int, default=20)
    drt_root_parser.add_argument(
        "--show-keys",
        action="store_true",
        help="include decoded root separator keys in output",
    )

    drt_child_parser = subparsers.add_parser(
        "drt-root-children", help="summarize blocks pointed to by DRT root entries"
    )
    drt_child_parser.add_argument("path", type=Path)
    drt_child_parser.add_argument("--limit", type=int, default=20)
    drt_child_parser.add_argument("--scan-bytes", type=int, default=16 * 1024)
    drt_child_parser.add_argument("--prefix-hash-bytes", type=int, default=64)

    inventory_parser = subparsers.add_parser("inventory", help="inventory dictionary sidecars")
    inventory_parser.add_argument("root", type=Path)
    inventory_parser.add_argument("--json", action="store_true", help="emit JSON")

    scan_parser = subparsers.add_parser(
        "scan-text-runs", help="find redacted CP932-like text runs"
    )
    scan_parser.add_argument("path", type=Path)
    scan_parser.add_argument("--min-chars", type=int, default=12)
    scan_parser.add_argument("--limit", type=int, default=100)
    scan_parser.add_argument("--max-bytes", type=int, default=None)
    scan_parser.add_argument(
        "--encoding",
        choices=["cp932", "utf-16be"],
        default="cp932",
        help="text encoding heuristic to scan for",
    )

    setup_parser = subparsers.add_parser("setup", help="parse an ATOK SETUP.INI file")
    setup_parser.add_argument("path", type=Path)

    companion_header_parser = subparsers.add_parser(
        "companion-header", help="parse a DRW/DSZ XOR-obfuscated SQLite header"
    )
    companion_header_parser.add_argument("path", type=Path)

    companion_schema_parser = subparsers.add_parser(
        "companion-schema", help="show DRW/DSZ SQLite schema without dumping table data"
    )
    companion_schema_parser.add_argument("path", type=Path)
    companion_schema_parser.add_argument(
        "--counts", action="store_true", help="include table row counts"
    )
    companion_schema_parser.add_argument(
        "--page-types", action="store_true", help="include decoded SQLite page type counts"
    )

    args = parser.parse_args(argv)

    if args.command == "header":
        print(json.dumps(parse_header(args.path).to_dict(), ensure_ascii=False, indent=2))
        return 0

    if args.command == "sections":
        descriptors = parse_section_descriptors(args.path)
        print(json.dumps([item.to_dict() for item in descriptors], ensure_ascii=False, indent=2))
        return 0

    if args.command == "drt-root-index":
        root_index = parse_drt_root_index(args.path)
        print(
            json.dumps(
                root_index.to_dict(include_keys=args.show_keys, entry_limit=args.limit),
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0

    if args.command == "drt-root-children":
        blocks = summarize_drt_root_child_blocks(
            args.path,
            scan_bytes=args.scan_bytes,
            prefix_hash_bytes=args.prefix_hash_bytes,
        )
        entries = blocks if args.limit is None else blocks[: args.limit]
        print(json.dumps([item.to_dict() for item in entries], ensure_ascii=False, indent=2))
        return 0

    if args.command == "inventory":
        groups = scan_inventory(args.root)
        if args.json:
            print(json.dumps(inventory_to_dict(groups), ensure_ascii=False, indent=2))
        else:
            for group in groups:
                extensions = ", ".join(item.extension for item in group.files)
                print(f"{group.stem}: {extensions}")
        return 0

    if args.command == "scan-text-runs":
        scanner = scan_utf16be_runs if args.encoding == "utf-16be" else scan_cp932_runs
        runs = scanner(
            args.path,
            min_chars=args.min_chars,
            limit=args.limit,
            max_bytes=args.max_bytes,
        )
        print(json.dumps([run.to_dict() for run in runs], ensure_ascii=False, indent=2))
        return 0

    if args.command == "setup":
        print(json.dumps(parse_setup_ini(args.path).to_dict(), ensure_ascii=False, indent=2))
        return 0

    if args.command == "companion-header":
        print(json.dumps(parse_companion_header(args.path).to_dict(), ensure_ascii=False, indent=2))
        return 0

    if args.command == "companion-schema":
        output: dict[str, object] = {
            "schema": [
                item.to_dict()
                for item in read_companion_schema(args.path, include_counts=args.counts)
            ]
        }
        if args.page_types:
            output["page_types"] = companion_page_type_counts(args.path)
        print(json.dumps(output, ensure_ascii=False, indent=2))
        return 0

    parser.error(f"unsupported command: {args.command}")
    return 2
