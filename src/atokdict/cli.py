from __future__ import annotations

import argparse
import json
from pathlib import Path

from atokdict.container import parse_header
from atokdict.installer import parse_setup_ini
from atokdict.inventory import inventory_to_dict, scan_inventory
from atokdict.textscan import scan_cp932_runs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="atokdict")
    subparsers = parser.add_subparsers(dest="command", required=True)

    header_parser = subparsers.add_parser("header", help="parse an ATOK container header")
    header_parser.add_argument("path", type=Path)

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

    setup_parser = subparsers.add_parser("setup", help="parse an ATOK SETUP.INI file")
    setup_parser.add_argument("path", type=Path)

    args = parser.parse_args(argv)

    if args.command == "header":
        print(json.dumps(parse_header(args.path).to_dict(), ensure_ascii=False, indent=2))
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
        runs = scan_cp932_runs(
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

    parser.error(f"unsupported command: {args.command}")
    return 2
