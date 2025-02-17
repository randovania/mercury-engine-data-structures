from __future__ import annotations

import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import samus_returns_data
from mercury_engine_data_structures.formats.bmsbk import BlockType, Bmsbk

sr_missing = [
    "maps/levels/c10_samus/s908_manicminerbotrun/s908_manicminerbotrun.bmsbk",
    "maps/levels/c10_samus/s910_gym/s910_gym.bmsbk",
    "maps/levels/c10_samus/s911_swarmgym/s911_swarmgym.bmsbk",
    "maps/levels/c10_samus/s920_traininggallery/s920_traininggallery.bmsbk",
]


@pytest.mark.parametrize("bmsbk_path", samus_returns_data.all_files_ending_with(".bmsbk", sr_missing))
def test_bmsbk(samus_returns_tree, bmsbk_path):
    parse_build_compare_editor(Bmsbk, samus_returns_tree, bmsbk_path)


@pytest.fixture()
def surface_bmsbk(samus_returns_tree) -> Bmsbk:
    return samus_returns_tree.get_parsed_asset("maps/levels/c10_samus/s000_surface/s000_surface.bmsbk", type_hint=Bmsbk)


def test_get_block(surface_bmsbk: Bmsbk):
    block = surface_bmsbk.get_block(0, 1)
    assert block.respawn_time == 0.0


def test_changing_weakness(surface_bmsbk: Bmsbk):
    surface_bmsbk.set_block_type(1, BlockType.BOMB)
    assert surface_bmsbk.get_block_group(1).types[0].block_type == BlockType.BOMB


def test_respawn_time(surface_bmsbk: Bmsbk):
    surface_bmsbk.set_respawn_time(0, 0, 5.0)
    assert surface_bmsbk.get_block(0, 0).respawn_time == 5.0
