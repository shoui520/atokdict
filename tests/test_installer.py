from __future__ import annotations

from pathlib import Path

from atokdict.installer import parse_setup_ini


def test_parse_setup_ini_cp932(tmp_path: Path) -> None:
    path = tmp_path / "SETUP.INI"
    path.write_bytes(
        "\n".join(
            [
                "ProductName=テスト辞典",
                "ProductID=テスト",
                "License=LICENSE.TXT",
                "Manual=README.TXT",
                "",
                "<Version=31->",
                "Folder=DATA",
                "SetDic=MAIN.DIC,5",
                "SetAbbDic=MAIN.DAR",
                "SetDrtDic=MAIN.DRT",
                "SetAcsDic=MAIN.DSY",
                "</Version>",
            ]
        ).encode("cp932")
    )

    setup = parse_setup_ini(path)

    assert setup.encoding == "cp932"
    assert setup.product_name == "テスト辞典"
    assert len(setup.version_blocks) == 1
    block = setup.version_blocks[0]
    assert block.selector == "31-"
    assert block.folder == "DATA"
    assert [item.role for item in block.dictionaries] == [
        "SetDic",
        "SetAbbDic",
        "SetDrtDic",
        "SetAcsDic",
    ]
    assert block.dictionaries[0].filename == "MAIN.DIC"
    assert block.dictionaries[0].priority == 5
