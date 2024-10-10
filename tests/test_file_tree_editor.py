import re

import pytest

from mercury_engine_data_structures.file_tree_editor import FileTreeEditor
from mercury_engine_data_structures.game_check import Game
from mercury_engine_data_structures.romfs import PackedRomFs


def test_add_new_file_exists_romfs(dread_tree_100):
    with pytest.raises(ValueError, match=re.escape("Asset already exists in:\nIn the RomFS")):
        dread_tree_100.add_new_asset("config.ini", b"boo", [])


def test_add_new_file_exists_pkg(dread_tree_100):
    with pytest.raises(ValueError, match=re.escape("Asset already exists in:\npacks/maps/s010_cave/s010_cave.pkg")):
        dread_tree_100.add_new_asset("maps/levels/c10_samus/s010_cave/s010_cave.brfld", b"boo", [])


def test_file_tree_editor_with_packed_romfs(samus_returns_roms_path):
    tree = FileTreeEditor(PackedRomFs(samus_returns_roms_path.joinpath("MSR.3ds")), Game.SAMUS_RETURNS)
    assert tree.does_asset_exists("actors/characters/alpha/charclasses/alpha.bmsad")
