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
from atokdict.drt import parse_drt_primary_index
from atokdict.drt import parse_drt_root_index
from atokdict.drt import summarize_drt_primary_blocks
from atokdict.drt import summarize_drt_primary_segments
from atokdict.drt import summarize_drt_root_child_blocks
from atokdict.dsy import parse_dsy_map, parse_dsy_region1_index, summarize_dsy_regions
from atokdict.dsy import summarize_dsy_region1_records
from atokdict.dsy import summarize_dsy_region3_first_run
from atokdict.dsy import summarize_dsy_region3_gap4
from atokdict.dsy import summarize_dsy_region3_prefix
from atokdict.dsy import summarize_dsy_region3_sentinels
from atokdict.installer import parse_setup_ini
from atokdict.inventory import inventory_to_dict, scan_inventory
from atokdict.linkage import summarize_drt_primary_keyword_ranges
from atokdict.linkage import summarize_drt_keyword_ranges
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

    drt_primary_parser = subparsers.add_parser(
        "drt-primary-index", help="parse the common DRT descriptor-0x390 index table"
    )
    drt_primary_parser.add_argument("path", type=Path)
    drt_primary_parser.add_argument("--limit", type=int, default=20)

    drt_primary_blocks_parser = subparsers.add_parser(
        "drt-primary-blocks",
        help="summarize DRT primary block unit counts and segment-0 headers",
    )
    drt_primary_blocks_parser.add_argument("path", type=Path)
    drt_primary_blocks_parser.add_argument("--limit", type=int, default=20)

    drt_primary_segments_parser = subparsers.add_parser(
        "drt-primary-segments",
        help="summarize bounded prefixes of DRT primary block segments",
    )
    drt_primary_segments_parser.add_argument("path", type=Path)
    drt_primary_segments_parser.add_argument("--limit", type=int, default=20)
    drt_primary_segments_parser.add_argument("--scan-bytes", type=int, default=4 * 1024)
    drt_primary_segments_parser.add_argument("--prefix-hash-bytes", type=int, default=64)

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

    drt_keyword_parser = subparsers.add_parser(
        "drt-keyword-ranges",
        help="link DRT root child blocks to DRW keyword sort-order ranges",
    )
    drt_keyword_parser.add_argument("drt_path", type=Path)
    drt_keyword_parser.add_argument("drw_path", type=Path, nargs="?")
    drt_keyword_parser.add_argument("--limit", type=int, default=20)

    drt_primary_keyword_parser = subparsers.add_parser(
        "drt-primary-keyword-ranges",
        help="link DRT primary separators to DRW keyword sort-order ranges",
    )
    drt_primary_keyword_parser.add_argument("drt_path", type=Path)
    drt_primary_keyword_parser.add_argument("drw_path", type=Path, nargs="?")
    drt_primary_keyword_parser.add_argument("--limit", type=int, default=20)

    dsy_map_parser = subparsers.add_parser(
        "dsy-map", help="parse the observed DSY metadata and region map"
    )
    dsy_map_parser.add_argument("path", type=Path)

    dsy_regions_parser = subparsers.add_parser(
        "dsy-regions", help="summarize bounded DSY region diagnostics"
    )
    dsy_regions_parser.add_argument("path", type=Path)
    dsy_regions_parser.add_argument("--scan-bytes", type=int, default=4096)
    dsy_regions_parser.add_argument("--prefix-hash-bytes", type=int, default=64)

    dsy_region1_parser = subparsers.add_parser(
        "dsy-region1-index", help="parse the observed DSY region-1 boundary table"
    )
    dsy_region1_parser.add_argument("path", type=Path)
    dsy_region1_parser.add_argument("--limit", type=int, default=20)

    dsy_region1_records_parser = subparsers.add_parser(
        "dsy-region1-records",
        help="summarize bounded DSY region-1 payload records and trailer",
    )
    dsy_region1_records_parser.add_argument("path", type=Path)
    dsy_region1_records_parser.add_argument("--limit", type=int, default=20)
    dsy_region1_records_parser.add_argument("--scan-bytes", type=int, default=4096)
    dsy_region1_records_parser.add_argument("--prefix-hash-bytes", type=int, default=64)

    dsy_region3_parser = subparsers.add_parser(
        "dsy-region3-prefix",
        help="summarize the observed DSY region-3 prefix split",
    )
    dsy_region3_parser.add_argument("path", type=Path)
    dsy_region3_parser.add_argument("--tail-scan-bytes", type=int, default=4096)
    dsy_region3_parser.add_argument("--prefix-hash-bytes", type=int, default=64)

    dsy_region3_sentinels_parser = subparsers.add_parser(
        "dsy-region3-sentinels",
        help="summarize high-word sentinel runs in the DSY region-3 prefix",
    )
    dsy_region3_sentinels_parser.add_argument("path", type=Path)
    dsy_region3_sentinels_parser.add_argument("--limit", type=int, default=20)

    dsy_region3_first_run_parser = subparsers.add_parser(
        "dsy-region3-first-run",
        help="summarize the first high-word run in the DSY region-3 prefix",
    )
    dsy_region3_first_run_parser.add_argument("path", type=Path)

    dsy_region3_gap4_parser = subparsers.add_parser(
        "dsy-region3-gap4",
        help="summarize gap-4 chunks in the DSY region-3 first sentinel run",
    )
    dsy_region3_gap4_parser.add_argument("path", type=Path)

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

    if args.command == "drt-primary-index":
        primary_index = parse_drt_primary_index(args.path)
        print(
            json.dumps(
                primary_index.to_dict(entry_limit=args.limit),
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0

    if args.command == "drt-primary-segments":
        segments = summarize_drt_primary_segments(
            args.path,
            scan_bytes=args.scan_bytes,
            prefix_hash_bytes=args.prefix_hash_bytes,
        )
        entries = segments if args.limit is None else segments[: args.limit]
        print(json.dumps([item.to_dict() for item in entries], ensure_ascii=False, indent=2))
        return 0

    if args.command == "drt-primary-blocks":
        blocks = summarize_drt_primary_blocks(args.path)
        entries = blocks if args.limit is None else blocks[: args.limit]
        print(json.dumps([item.to_dict() for item in entries], ensure_ascii=False, indent=2))
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

    if args.command == "drt-keyword-ranges":
        summary = summarize_drt_keyword_ranges(args.drt_path, args.drw_path)
        print(json.dumps(summary.to_dict(entry_limit=args.limit), ensure_ascii=False, indent=2))
        return 0

    if args.command == "drt-primary-keyword-ranges":
        summary = summarize_drt_primary_keyword_ranges(args.drt_path, args.drw_path)
        print(json.dumps(summary.to_dict(entry_limit=args.limit), ensure_ascii=False, indent=2))
        return 0

    if args.command == "dsy-map":
        print(json.dumps(parse_dsy_map(args.path).to_dict(), ensure_ascii=False, indent=2))
        return 0

    if args.command == "dsy-regions":
        regions = summarize_dsy_regions(
            args.path,
            scan_bytes=args.scan_bytes,
            prefix_hash_bytes=args.prefix_hash_bytes,
        )
        print(json.dumps([region.to_dict() for region in regions], ensure_ascii=False, indent=2))
        return 0

    if args.command == "dsy-region1-index":
        index = parse_dsy_region1_index(args.path)
        print(json.dumps(index.to_dict(entry_limit=args.limit), ensure_ascii=False, indent=2))
        return 0

    if args.command == "dsy-region1-records":
        records = summarize_dsy_region1_records(
            args.path,
            scan_bytes=args.scan_bytes,
            prefix_hash_bytes=args.prefix_hash_bytes,
        )
        print(json.dumps(records.to_dict(entry_limit=args.limit), ensure_ascii=False, indent=2))
        return 0

    if args.command == "dsy-region3-prefix":
        prefix = summarize_dsy_region3_prefix(
            args.path,
            tail_scan_bytes=args.tail_scan_bytes,
            prefix_hash_bytes=args.prefix_hash_bytes,
        )
        print(json.dumps(prefix.to_dict(), ensure_ascii=False, indent=2))
        return 0

    if args.command == "dsy-region3-sentinels":
        sentinels = summarize_dsy_region3_sentinels(args.path)
        print(json.dumps(sentinels.to_dict(run_limit=args.limit), ensure_ascii=False, indent=2))
        return 0

    if args.command == "dsy-region3-first-run":
        first_run = summarize_dsy_region3_first_run(args.path)
        print(json.dumps(first_run.to_dict(), ensure_ascii=False, indent=2))
        return 0

    if args.command == "dsy-region3-gap4":
        gap4 = summarize_dsy_region3_gap4(args.path)
        print(json.dumps(gap4.to_dict(), ensure_ascii=False, indent=2))
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
