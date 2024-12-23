from __future__ import annotations

import pytest
from tests.test_lib import parse_build_compare_editor_parsed

from mercury_engine_data_structures import dread_data, samus_returns_data
from mercury_engine_data_structures.formats.bmssd import Bmssd, ItemType
from mercury_engine_data_structures.game_check import Game

bossrush_assets = [
    "maps/levels/c10_samus/s201_bossrush_scorpius/s201_bossrush_scorpius.bmssd",
    "maps/levels/c10_samus/s202_bossrush_kraid/s202_bossrush_kraid.bmssd",
    "maps/levels/c10_samus/s203_bossrush_cu_artaria/s203_bossrush_cu_artaria.bmssd",
    "maps/levels/c10_samus/s204_bossrush_drogyga/s204_bossrush_drogyga.bmssd",
    "maps/levels/c10_samus/s205_bossrush_strong_rcs/s205_bossrush_strong_rcs.bmssd",
    "maps/levels/c10_samus/s206_bossrush_escue/s206_bossrush_escue.bmssd",
    "maps/levels/c10_samus/s207_bossrush_cooldownx/s207_bossrush_cooldownx.bmssd",
    "maps/levels/c10_samus/s208_bossrush_strong_rcs_x2/s208_bossrush_strong_rcs_x2.bmssd",
    "maps/levels/c10_samus/s209_bossrush_golzuna/s209_bossrush_golzuna.bmssd",
    "maps/levels/c10_samus/s210_bossrush_elite_cwx/s210_bossrush_elite_cwx.bmssd",
    "maps/levels/c10_samus/s211_bossrush_cu_ferenia/s211_bossrush_cu_ferenia.bmssd",
    "maps/levels/c10_samus/s212_bossrush_commander/s212_bossrush_commander.bmssd",
]


@pytest.mark.parametrize("bmssd_path", dread_data.all_files_ending_with(".bmssd", bossrush_assets))
def test_compare_bmssd_dread_100(dread_tree_100, bmssd_path):
    parse_build_compare_editor_parsed(Bmssd, dread_tree_100, bmssd_path)


@pytest.mark.parametrize("bmssd_path", bossrush_assets)
def test_compare_dread_210(dread_tree_210, bmssd_path):
    parse_build_compare_editor_parsed(Bmssd, dread_tree_210, bmssd_path)


@pytest.mark.parametrize("bmssd_path", samus_returns_data.all_files_ending_with(".bmssd"))
def test_compare_bmssd_msr(samus_returns_tree, bmssd_path):
    parse_build_compare_editor_parsed(Bmssd, samus_returns_tree, bmssd_path)


def test_bmssd_dread_functions(dread_tree_100):
    bmssd = dread_tree_100.get_parsed_asset("maps/levels/c10_samus/s090_skybase/s090_skybase.bmssd", type_hint=Bmssd)

    # PART 1: Ensure getting an item and accessing scene group for item works

    lshaft03 = bmssd.get_item("part001_jp6_lshaft03", ItemType.SCENE_BLOCK)

    # check get_item returned the correct data
    assert lshaft03.transform.position[0] == 640.7750244140625
    # check the scene groups are correct
    assert bmssd.scene_groups_for_item(lshaft03, ItemType.SCENE_BLOCK) == [
        f"sg_SubArea_collision_camera_00{x}" for x in [3, 2, 1]
    ]
    # check using the name and object to find scene groups works
    assert bmssd.scene_groups_for_item("part001_jp6_lshaft03", ItemType.SCENE_BLOCK) == bmssd.scene_groups_for_item(
        lshaft03, ItemType.SCENE_BLOCK
    )

    # check objects work right
    cc3 = bmssd.get_scene_group("sg_SubArea_collision_camera_003")
    map_object = cc3[ItemType.OBJECT][0]
    assert map_object.model_name == "chozoskypathroofx1"
    assert bmssd.scene_groups_for_item(map_object, ItemType.OBJECT) == [
        f"sg_SubArea_collision_camera_00{x}" for x in [3, 2]
    ]

    # PART 2: Add new items to sg (created as new dicts)

    # scene_blocks
    new_sb = {
        "model_name": "part420_rdv_newblock",
        "byte0": 1,
        "byte1": 1,
        "byte2": 1,
        "int3": 1,
        "byte4": 1,
        "transform": {"position": [100.0, 200.0, 300.0], "rotation": [0.0, 0.0, 0.0], "scale": [1.0, 1.0, 1.0]},
    }
    new_sb_groups = [f"sg_casca100{x}" for x in [0, 1, 2]]
    bmssd.add_item(new_sb, ItemType.SCENE_BLOCK, new_sb_groups)
    assert bmssd.get_item("part420_rdv_newblock", ItemType.SCENE_BLOCK) == new_sb
    assert bmssd.scene_groups_for_item("part420_rdv_newblock", ItemType.SCENE_BLOCK) == new_sb_groups

    # objects
    new_obj = {
        "model_name": "theoreticalplandoobj",
        "transform": {"position": [1000.0, 800.0, 202100.0], "rotation": [0.0, 0.0, 0.0], "scale": [0.0, 0.0, 0.0]},
    }
    new_obj_groups = ["sg_SubArea_collision_camera_005"]
    bmssd.add_item(new_obj, ItemType.OBJECT, new_obj_groups)
    assert bmssd.scene_groups_for_item(new_obj, ItemType.OBJECT) == new_obj_groups
    assert new_obj in bmssd.get_scene_group(new_obj_groups[0])[ItemType.OBJECT]

    # PART 3: break things and ensure it acts right :)

    # can't get object by name
    with pytest.raises(ValueError):
        bmssd.get_item("theoreticalplandoobj", ItemType.OBJECT)

    # can get object by index
    obj = bmssd.get_item(69, ItemType.OBJECT)
    assert obj.model_name == "chozoskypathroofx1" and obj.transform.position[1] == -2650.0

    # non-existant object
    assert bmssd.get_item("isweariaddedthis", ItemType.SCENE_BLOCK) is None

    # actually we changed our mind on where the newblock goes
    bmssd.remove_item_from_group(new_sb, ItemType.SCENE_BLOCK, "sg_casca1002")
    assert "sg_casca1002" not in bmssd.scene_groups_for_item("part420_rdv_newblock", ItemType.SCENE_BLOCK)

    # lets get rid of a part of the roof and see what happens
    roof = bmssd.get_scene_group("sg_SubArea_collision_camera_003")[ItemType.OBJECT][0]
    bmssd.remove_item(roof, ItemType.OBJECT)
    assert bmssd.scene_groups_for_item(roof, ItemType.OBJECT) == []
    assert roof not in bmssd.get_scene_group("sg_SubArea_collision_camera_003")[ItemType.OBJECT]
    assert roof not in bmssd.get_scene_group("sg_SubArea_collision_camera_002")[ItemType.OBJECT]

    # remove from an ItemType which uses a dict
    random_obj = bmssd.get_item("part001_jp6_mapmodel04", ItemType.SCENE_BLOCK)
    assert bmssd.scene_groups_for_item(random_obj, ItemType.SCENE_BLOCK) == ["sg_SubArea_collision_camera_002"]
    bmssd.remove_item(random_obj, ItemType.SCENE_BLOCK)
    assert bmssd.scene_groups_for_item(random_obj, ItemType.SCENE_BLOCK) == []

    # try to get a non-existent object
    assert bmssd.scene_groups_for_item("foo", ItemType.LIGHT) == []

    # PART 4: make sure it can actually build and parse lol
    con = Bmssd.construct_class(target_game=Game.DREAD)
    built = con.build(bmssd.raw, target_game=Game.DREAD)
    reparsed = con.parse(built, target_game=Game.DREAD)
    assert reparsed == bmssd.raw
