from __future__ import annotations

import re

import pytest


def test_add_new_file_exists_romfs(dread_tree_100):
    with pytest.raises(ValueError, match=re.escape("Asset already exists in:\nIn the RomFS")):
        dread_tree_100.add_new_asset("config.ini", b"boo", [])


def test_add_new_file_exists_pkg(dread_tree_100):
    with pytest.raises(ValueError, match=re.escape("Asset already exists in:\npacks/maps/s010_cave/s010_cave.pkg")):
        dread_tree_100.add_new_asset("maps/levels/c10_samus/s010_cave/s010_cave.brfld", b"boo", [])


def test_all_asset_ids_in_folder(dread_tree_100):
    doorshieldmissile_assets = dread_tree_100.all_asset_names_in_folder("actors/props/doorshieldmissile")
    expected_doorshieldmissile_assets = [
        "actors/props/doorshieldmissile/charclasses/doorshieldmissile.bmsad",
        "actors/props/doorshieldmissile/charclasses/doorshieldmissile.bmsas",
        "actors/props/doorshieldmissile/charclasses/timeline.bmsas",
        "actors/props/doorshieldmissile/collisions/doorshieldmissile.bmscd",
        "actors/props/doorshieldmissile/fx/explosion_shieldparticle.bcptl",
        "actors/props/doorshieldmissile/fx/imats/shieldmissile_shieldfx.bsmat",
        "actors/props/doorshieldmissile/fx/shieldmissilefx.bcmdl",
        "actors/props/doorshieldmissile/models/doorshieldmissile.bcmdl",
        "actors/props/doorshieldmissile/models/imats/doorshieldmissile_mp_opaque_01.bsmat",
    ]

    assert set(doorshieldmissile_assets) == set(expected_doorshieldmissile_assets)
