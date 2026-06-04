#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


FORBIDDEN_SUFFIXES = {
    ".7z",
    ".dar",
    ".dic",
    ".dll",
    ".drt",
    ".drw",
    ".dsy",
    ".dsz",
    ".exe",
    ".pdf",
    ".rar",
    ".zip",
}


def main() -> int:
    result = subprocess.run(
        ["git", "ls-files"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    offenders = [
        path for path in result.stdout.splitlines() if Path(path).suffix.lower() in FORBIDDEN_SUFFIXES
    ]
    if offenders:
        print("Forbidden dictionary/archive/binary payload files are tracked:", file=sys.stderr)
        for offender in offenders:
            print(f"  {offender}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
