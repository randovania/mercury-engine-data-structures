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
    block = surface_bmsbk.get_block_group(0).get_block(0)
    assert block.position == [-23100.0, 10700.0, 0.0]
    assert block.respawn_time == 0.0
    assert block.model_name == "sg_casca80"
    assert block.vignette_name == ""


def test_changing_weakness(surface_bmsbk: Bmsbk):
    block_group = surface_bmsbk.get_block_group(0)
    original_type = block_group.block_type
    assert original_type == BlockType.POWER_BOMB
    block_group.block_type = BlockType.BOMB
    assert original_type != BlockType.BOMB


def test_respawn_time(surface_bmsbk: Bmsbk):
    block = surface_bmsbk.get_block_group(0).get_block(0)
    original_time = block.respawn_time
    assert original_time == 0.0
    block.respawn_time = 5.0
    assert original_time != block.respawn_time


def test_modify_visuals(surface_bmsbk: Bmsbk):
    block = surface_bmsbk.get_block_group(0).get_block(0)
    block.model_name = "sg_real_model"
    assert block.model_name != "sg_casca80"

    block.vignette_name = "sg_real_vignette"
    assert block.vignette_name != ""
