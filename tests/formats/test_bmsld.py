import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures.formats.bmsld import Bmsld

all_bmsld = [
    "maps/levels/c10_samus/s000_surface/s000_surface.bmsld",
    "maps/levels/c10_samus/s010_area1/s010_area1.bmsld",
    "maps/levels/c10_samus/s020_area2/s020_area2.bmsld",
    "maps/levels/c10_samus/s025_area2b/s025_area2b.bmsld",
    "maps/levels/c10_samus/s028_area2c/s028_area2c.bmsld",
    "maps/levels/c10_samus/s030_area3/s030_area3.bmsld",
    "maps/levels/c10_samus/s033_area3b/s033_area3b.bmsld",
    "maps/levels/c10_samus/s036_area3c/s036_area3c.bmsld",
    "maps/levels/c10_samus/s040_area4/s040_area4.bmsld",
    "maps/levels/c10_samus/s050_area5/s050_area5.bmsld",
    "maps/levels/c10_samus/s060_area6/s060_area6.bmsld",
    "maps/levels/c10_samus/s065_area6b/s065_area6b.bmsld",
    "maps/levels/c10_samus/s067_area6c/s067_area6c.bmsld",
    "maps/levels/c10_samus/s070_area7/s070_area7.bmsld",
    "maps/levels/c10_samus/s090_area9/s090_area9.bmsld",
    "maps/levels/c10_samus/s090_area9/s090_area9.bmsld",
    "maps/levels/c10_samus/s100_area10/s100_area10.bmsld",
    "maps/levels/c10_samus/s110_surfaceb/s110_surfaceb.bmsld",

]


@pytest.fixture()
def surface_bmsld(samus_returns_tree) -> Bmsld:
    return samus_returns_tree.get_parsed_asset(all_bmsld[0], type_hint=Bmsld)

@pytest.mark.parametrize("bmsld_path", all_bmsld)
def test_bmsld(samus_returns_tree, bmsld_path):
    parse_build_compare_editor(Bmsld, samus_returns_tree, bmsld_path)

def test_all_actor_groups(surface_bmsld: Bmsld):
    all_groups = surface_bmsld.all_actor_groups()
    assert len(list(all_groups)) == 32

@pytest.mark.parametrize(("cc_name", "actor_name", "should_be_present"),
                            [
                                ("eg_SubArea_collision_camera_008", "LE_PowerUP_ChargeBeam", True),
                                ("eg_SubArea_collision_camera_012", "LE_PowerUP_ChargeBeam", False),
                                ("eg_SubArea_collision_camera_010", "SG_Alpha_001", True),
                                ("eg_SubArea_collision_camera_020", "SG_Alpha_001", False),
                                ("eg_SubArea_collision_camera_010", "LE_Item_001", True),
                                ("eg_SubArea_collision_camera_012", "LE_Item_001", False),
                            ]
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
        'eg_SubArea_collision_camera_010',
        'eg_SubArea_collision_camera_023',
        'eg_SubArea_PostAlpha_001',
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
