from __future__ import annotations

import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data
from mercury_engine_data_structures.formats.brfld import ActorLayer, Brfld

bossrush_assets = [
    "maps/levels/c10_samus/s201_bossrush_scorpius/s201_bossrush_scorpius.brfld",
    "maps/levels/c10_samus/s202_bossrush_kraid/s202_bossrush_kraid.brfld",
    "maps/levels/c10_samus/s203_bossrush_cu_artaria/s203_bossrush_cu_artaria.brfld",
    "maps/levels/c10_samus/s204_bossrush_drogyga/s204_bossrush_drogyga.brfld",
    "maps/levels/c10_samus/s205_bossrush_strong_rcs/s205_bossrush_strong_rcs.brfld",
    "maps/levels/c10_samus/s206_bossrush_escue/s206_bossrush_escue.brfld",
    "maps/levels/c10_samus/s207_bossrush_cooldownx/s207_bossrush_cooldownx.brfld",
    "maps/levels/c10_samus/s208_bossrush_strong_rcs_x2/s208_bossrush_strong_rcs_x2.brfld",
    "maps/levels/c10_samus/s209_bossrush_golzuna/s209_bossrush_golzuna.brfld",
    "maps/levels/c10_samus/s210_bossrush_elite_cwx/s210_bossrush_elite_cwx.brfld",
    "maps/levels/c10_samus/s211_bossrush_cu_ferenia/s211_bossrush_cu_ferenia.brfld",
    "maps/levels/c10_samus/s212_bossrush_commander/s212_bossrush_commander.brfld",
]


@pytest.mark.parametrize("brfld_path", dread_data.all_files_ending_with(".brfld", bossrush_assets))
def test_dread_brfld_100(dread_tree_100, brfld_path):
    parse_build_compare_editor(Brfld, dread_tree_100, brfld_path)


@pytest.mark.parametrize("brfld_path", bossrush_assets)
def test_dread_brfld_210(dread_tree_210, brfld_path):
    parse_build_compare_editor(Brfld, dread_tree_210, brfld_path)


def test_get_actors_methods(dread_tree_100):
    scenario = dread_tree_100.get_file("maps/levels/c10_samus/s010_cave/s010_cave.brfld", Brfld)

    actors_for_sublayer_names = []

    for sublayer in scenario.sublayers_for_actor_layer():
        actors_for_sublayer_names += scenario.actors_for_sublayer(sublayer).keys()

    all_actors_in_actor_layer_names = [
        actor_name for sublayer_name, actor_name, actor in scenario.all_actors_in_actor_layer()
    ]

    assert actors_for_sublayer_names == all_actors_in_actor_layer_names


def test_follow_link(dread_tree_100):
    scenario = dread_tree_100.get_file("maps/levels/c10_samus/s010_cave/s010_cave.brfld", Brfld)

    actor_link = scenario.link_for_actor("cubemap_fr.2_cave_ini", "cubes", ActorLayer.LIGHTS)

    assert scenario.follow_link(actor_link).sName == "cubemap_fr.2_cave_ini"


to_remove_from_actor_groups = [
    ["eg_collision_camera_000_Default", "breakabletilegroup_052", "breakables", ActorLayer.ENTITIES],
    ["ssg_collision_camera_000_Default", "Pos_C_Trees_R", "default", ActorLayer.SOUNDS],
    ["lg_collision_camera_000", "spot_000_1", "cave_000_light", ActorLayer.LIGHTS],
]


@pytest.mark.parametrize(["actor_group", "actor_name", "sublayer_name", "actor_layer"], to_remove_from_actor_groups)
def test_remove_actor_from_actor_group(dread_tree_100, actor_group, actor_name, sublayer_name, actor_layer):
    scenario = dread_tree_100.get_file("maps/levels/c10_samus/s010_cave/s010_cave.brfld", Brfld)

    scenario.remove_actor_from_group(actor_group, actor_name, sublayer_name, actor_layer)
    assert not scenario.is_actor_in_group(actor_group, actor_name, sublayer_name, actor_layer)


def test_remove_actor_from_actor_group_raises_exception(dread_tree_100):
    scenario = dread_tree_100.get_file("maps/levels/c10_samus/s010_cave/s010_cave.brfld", Brfld)

    with pytest.raises(ValueError, match=r"Actor .+ is not in actor group .+"):
        scenario.remove_actor_from_group("eg_collision_camera_000_Default", "StartPoint0")


to_add_to_actor_groups = [
    ["eg_collision_camera_000_Default", "breakabletilegroup_000", "breakables", ActorLayer.ENTITIES],
    ["ssg_collision_camera_000_Default", "Pos_C_LavaWindow_06", "default", ActorLayer.SOUNDS],
    ["lg_collision_camera_000", "cubemap_006_1_bake", "emmy_006_light", ActorLayer.LIGHTS],
]


@pytest.mark.parametrize(["actor_group", "actor_name", "sublayer_name", "actor_layer"], to_add_to_actor_groups)
def test_add_actor_to_actor_group(dread_tree_100, actor_group, actor_name, sublayer_name, actor_layer):
    scenario = dread_tree_100.get_file("maps/levels/c10_samus/s010_cave/s010_cave.brfld", Brfld)

    scenario.add_actor_to_actor_groups(actor_group, actor_name, sublayer_name, actor_layer)
    assert scenario.is_actor_in_group(actor_group, actor_name, sublayer_name, actor_layer)


def test_add_actor_to_actor_group_raises_exception(dread_tree_100):
    scenario = dread_tree_100.get_file("maps/levels/c10_samus/s010_cave/s010_cave.brfld", Brfld)

    with pytest.raises(ValueError, match=r"Actor .+ is already in actor group .+"):
        scenario.add_actor_to_group("eg_collision_camera_000_Default", "PRP_DB_CV_006")
