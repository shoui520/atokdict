from __future__ import annotations

from pathlib import Path

from atokdict.textscan import scan_cp932_runs, scan_utf16be_runs


def test_scan_cp932_runs_reports_offsets_without_content(tmp_path: Path) -> None:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"\x00\xff" + "会社四季報".encode("cp932") + b"\x00")

    runs = scan_cp932_runs(path, min_chars=4)

    assert runs[0].offset == 2
    assert runs[0].byte_length == len("会社四季報".encode("cp932"))


def test_scan_utf16be_runs_reports_offsets_without_content(tmp_path: Path) -> None:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"\xff" + "辞書検索".encode("utf-16be") + b"\x00")

    runs = scan_utf16be_runs(path, min_chars=4)

    assert runs[0].offset == 1
    assert runs[0].byte_length == len("辞書検索".encode("utf-16be"))
