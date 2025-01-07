from __future__ import annotations

import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import samus_returns_data
from mercury_engine_data_structures.formats.bmsld import ActorLayer, Bmsld

sr_missing = [
    "maps/levels/c10_samus/s901_alpha/s901_alpha.bmsld",
    "maps/levels/c10_samus/s902_gamma/s902_gamma.bmsld",
    "maps/levels/c10_samus/s903_zeta/s903_zeta.bmsld",
    "maps/levels/c10_samus/s904_omega/s904_omega.bmsld",
    "maps/levels/c10_samus/s905_arachnus/s905_arachnus.bmsld",
    "maps/levels/c10_samus/s905_queen/s905_queen.bmsld",
    "maps/levels/c10_samus/s906_metroid/s906_metroid.bmsld",
    "maps/levels/c10_samus/s907_manicminerbot/s907_manicminerbot.bmsld",
    "maps/levels/c10_samus/s908_manicminerbotrun/s908_manicminerbotrun.bmsld",
    "maps/levels/c10_samus/s909_ridley/s909_ridley.bmsld",
    "maps/levels/c10_samus/s910_gym/s910_gym.bmsld",
    "maps/levels/c10_samus/s911_swarmgym/s911_swarmgym.bmsld",
    "maps/levels/c10_samus/s920_traininggallery/s920_traininggallery.bmsld",
]


@pytest.fixture()
def surface_bmsld(samus_returns_tree) -> Bmsld:
    return samus_returns_tree.get_parsed_asset("maps/levels/c10_samus/s000_surface/s000_surface.bmsld", type_hint=Bmsld)


@pytest.mark.parametrize("bmsld_path", samus_returns_data.all_files_ending_with(".bmsld", sr_missing))
def test_bmsld(samus_returns_tree, bmsld_path):
    parse_build_compare_editor(Bmsld, samus_returns_tree, bmsld_path)


def test_all_actor_groups(surface_bmsld: Bmsld):
    all_groups = surface_bmsld.actor_groups
    assert len(list(all_groups)) == 32


@pytest.mark.parametrize(
    ("cc_name", "actor_name", "should_be_present"),
    [
        ("eg_SubArea_collision_camera_008", "LE_PowerUP_ChargeBeam", True),
        ("eg_SubArea_collision_camera_012", "LE_PowerUP_ChargeBeam", False),
        ("eg_SubArea_collision_camera_010", "SG_Alpha_001", True),
        ("eg_SubArea_collision_camera_020", "SG_Alpha_001", False),
        ("eg_SubArea_collision_camera_010", "LE_Item_001", True),
        ("eg_SubArea_collision_camera_012", "LE_Item_001", False),
    ],
)
def test_is_actor_in_group(surface_bmsld: Bmsld, cc_name, actor_name, should_be_present):
    in_group = surface_bmsld.is_actor_in_group(cc_name, actor_name)
    assert in_group is should_be_present


def test_get_actor_group(surface_bmsld: Bmsld):
    group = surface_bmsld.get_actor_group("eg_SubArea_collision_camera_008")
    assert group is not None

    with pytest.raises(KeyError):
        surface_bmsld.get_actor_group("blabla")


def test_all_actors(surface_bmsld: Bmsld):
    all_actors = list(surface_bmsld.all_actors())
    assert len(all_actors) == 232


def test_all_actor_group_names_for_actor(surface_bmsld: Bmsld):
    groups = surface_bmsld.all_actor_group_names_for_actor("LE_EnergyRecharge")
    assert groups == [
        "eg_SubArea_collision_camera_010",
        "eg_SubArea_collision_camera_023",
        "eg_SubArea_PostAlpha_001",
    ]


def test_add_actor_to_entity_groups(surface_bmsld: Bmsld):
    groups = surface_bmsld.all_actor_group_names_for_actor("LE_AmmoRecharge")
    assert len(groups) == 2

    surface_bmsld.add_actor_to_entity_groups("collision_camera_007", "LE_AmmoRecharge", False)
    groups = surface_bmsld.all_actor_group_names_for_actor("LE_AmmoRecharge")
    assert len(groups) == 3

    surface_bmsld.add_actor_to_entity_groups("collision_camera_011", "LE_AmmoRecharge", True)
    groups = surface_bmsld.all_actor_group_names_for_actor("LE_AmmoRecharge")
    assert len(groups) == 5


def test_remove_actor_from_all_groups(surface_bmsld: Bmsld):
    groups = surface_bmsld.all_actor_group_names_for_actor("Moheek_026")
    assert len(groups) == 4

    surface_bmsld.remove_actor_from_group("eg_SubArea_collision_camera_010", "Moheek_026")
    groups = surface_bmsld.all_actor_group_names_for_actor("Moheek_026")
    assert len(groups) == 3

    surface_bmsld.remove_actor_from_all_groups("Moheek_026")
    groups = surface_bmsld.all_actor_group_names_for_actor("Moheek_026")
    assert len(groups) == 0


def test_get_layer(surface_bmsld: Bmsld):
    layer = surface_bmsld._get_layer(ActorLayer.HIDDEN_POWERUP)
    assert len(layer) == 1


def test_get_actor(surface_bmsld: Bmsld):
    layer = ActorLayer.PASSIVE
    actor = surface_bmsld.get_actor(layer, "LE_Item_001")
    assert actor is not None

    actor.actor_type = "powerup_plasmabeam"
    actor.position.x = -6000.0
    actor_by_layer = surface_bmsld._get_layer(layer)["LE_Item_001"]
    assert actor_by_layer["type"] == "powerup_plasmabeam"
    assert actor_by_layer["position"][0] == -6000.0

    with pytest.raises(KeyError):
        surface_bmsld.get_actor(layer, "FakeActor")


def test_copy_actor(surface_bmsld: Bmsld):
    actor = surface_bmsld.get_actor(ActorLayer.PASSIVE, "LE_Item_001")
    surface_bmsld.copy_actor([1000.0, 340.0, 0.0], actor, "CopiedActor", ActorLayer.PASSIVE)
    surface_bmsld.add_actor_to_entity_groups("collision_camera_000", "CopiedActor")
    assert surface_bmsld.is_actor_in_group("eg_SubArea_collision_camera_000", "CopiedActor") is True


def test_remove_actor(surface_bmsld: Bmsld):
    actor = "SP_Moheekwall_B_006"
    surface_bmsld.remove_actor(ActorLayer.SPAWNPOINT, actor)
    assert surface_bmsld.is_actor_in_group("eg_SubArea_collision_camera_000", actor) is False

    with pytest.raises(KeyError):
        surface_bmsld.remove_actor(ActorLayer.SPAWNPOINT, "SP_Kraid")


def test_get_logic_shape(surface_bmsld: Bmsld):
    logic_shape = surface_bmsld.get_logic_shape("LS_Spikes_001")
    assert logic_shape is not None

    poly = logic_shape.get_poly(0)
    assert poly["num_points"] == 4

    point = logic_shape.get_point(0, 0)
    assert point["x"] != point["y"]
