import re

import pytest


def test_add_new_file_exists_romfs(dread_file_tree):
    with pytest.raises(ValueError, match=re.escape("Asset already exists in:\nIn the RomFS")):
        dread_file_tree.add_new_asset("config.ini", b"boo", [])


def test_add_new_file_exists_pkg(dread_file_tree):
    with pytest.raises(ValueError, match=re.escape("Asset already exists in:\npacks/maps/s010_cave/s010_cave.pkg")):
        dread_file_tree.add_new_asset("maps/levels/c10_samus/s010_cave/s010_cave.brfld", b"boo", [])
