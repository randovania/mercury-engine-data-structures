from __future__ import annotations

import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import samus_returns_data
from mercury_engine_data_structures.common_types import Vec3
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
    assert block.respawn_time == 0.0
    assert block.model_name == "sg_casca80"
    assert block.vignette_name == ""


def test_move_block(surface_bmsbk: Bmsbk):
    block = surface_bmsbk.get_block_group(0).get_block(0)

    assert block.position == [-23100.0, 10700.0, 0.0]
    block.position = Vec3(100.0, 200.0, 0.0)
    assert block.position == [100.0, 200.0, 0.0]


def test_changing_weakness(surface_bmsbk: Bmsbk):
    block_group = surface_bmsbk.get_block_group(0)
    assert block_group.block_type is BlockType.POWER_BOMB
    block_group.block_type = BlockType.BOMB
    assert block_group.block_type is BlockType.BOMB


def test_respawn_time(surface_bmsbk: Bmsbk):
    block = surface_bmsbk.get_block_group(0).get_block(0)
    assert block.respawn_time == 0.0
    block.respawn_time = 5.0
    assert block.respawn_time == 5.0


def test_modify_visuals(surface_bmsbk: Bmsbk):
    block = surface_bmsbk.get_block_group(0).get_block(0)

    assert block.model_name == "sg_casca80"
    block.model_name = "sg_real_model"
    assert block.model_name == "sg_real_model"

    assert block.vignette_name == ""
    block.vignette_name = "sg_real_vignette"
    assert block.vignette_name == "sg_real_vignette"


def test_collision_cameras(surface_bmsbk: Bmsbk):
    all_collision_cameras = surface_bmsbk.collision_cameras
    assert len(all_collision_cameras) == 15


def test_add_block(surface_bmsbk: Bmsbk):
    # Add a new block group and add the group to the collision camera
    surface_bmsbk.add_block_group("bg_SubArea_collision_camera_000", BlockType.BOMB)
    block_group = surface_bmsbk.get_block_group(43)
    assert block_group is not None
    assert block_group.block_type is BlockType.BOMB
    assert surface_bmsbk.collision_cameras["bg_SubArea_collision_camera_000"] == [0, 17, 33, 43]

    # Add a new block to the group
    block_group.add_block(Vec3(100.0, 500.0, 0.0), 1.0, "sg_casca_model", "sg_vignette_model")
    new_block = block_group.get_block(0)
    assert new_block is not None
    assert new_block.position == Vec3(100.0, 500.0, 0.0)
    assert new_block.respawn_time == 1.0
    assert new_block.model_name == "sg_casca_model"
    assert new_block.vignette_name == "sg_vignette_model"


def test_remove_block(surface_bmsbk: Bmsbk):
    block_group = surface_bmsbk.get_block_group(0)
    assert block_group.get_block(0).model_name == "sg_casca80"
    block_group.remove_block(0)
    assert block_group.get_block(0).model_name == "sg_casca79"


def test_remove_block_group(surface_bmsbk: Bmsbk):
    # Check the original group
    assert surface_bmsbk.get_block_group(0).block_type == BlockType.POWER_BOMB
    assert surface_bmsbk.collision_cameras["bg_SubArea_collision_camera_000"] == [0, 17, 33]

    # Remove a group
    surface_bmsbk.remove_block_group("bg_SubArea_collision_camera_000", 0)
    assert surface_bmsbk.get_block_group(0).block_type == BlockType.MISSILE
    assert surface_bmsbk.collision_cameras["bg_SubArea_collision_camera_000"] == [17, 33]


def test_remove_collision_camera(surface_bmsbk: Bmsbk):
    assert len(surface_bmsbk.collision_cameras) == 15
    surface_bmsbk.remove_collision_camera("bg_SubArea_collision_camera_000")
    assert len(surface_bmsbk.collision_cameras) == 14
