from __future__ import annotations

import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data
from mercury_engine_data_structures.formats.brsa import Brsa

bossrush_assets = [
    "maps/levels/c10_samus/s201_bossrush_scorpius/s201_bossrush_scorpius.brsa",
    "maps/levels/c10_samus/s202_bossrush_kraid/s202_bossrush_kraid.brsa",
    "maps/levels/c10_samus/s203_bossrush_cu_artaria/s203_bossrush_cu_artaria.brsa",
    "maps/levels/c10_samus/s204_bossrush_drogyga/s204_bossrush_drogyga.brsa",
    "maps/levels/c10_samus/s205_bossrush_strong_rcs/s205_bossrush_strong_rcs.brsa",
    "maps/levels/c10_samus/s206_bossrush_escue/s206_bossrush_escue.brsa",
    "maps/levels/c10_samus/s207_bossrush_cooldownx/s207_bossrush_cooldownx.brsa",
    "maps/levels/c10_samus/s208_bossrush_strong_rcs_x2/s208_bossrush_strong_rcs_x2.brsa",
    "maps/levels/c10_samus/s209_bossrush_golzuna/s209_bossrush_golzuna.brsa",
    "maps/levels/c10_samus/s210_bossrush_elite_cwx/s210_bossrush_elite_cwx.brsa",
    "maps/levels/c10_samus/s211_bossrush_cu_ferenia/s211_bossrush_cu_ferenia.brsa",
    "maps/levels/c10_samus/s212_bossrush_commander/s212_bossrush_commander.brsa",
]


@pytest.mark.parametrize("brsa_path", dread_data.all_files_ending_with(".brsa", bossrush_assets))
def test_dread_brsa_100(dread_tree_100, brsa_path):
    parse_build_compare_editor(Brsa, dread_tree_100, brsa_path)


@pytest.mark.parametrize("brsa_path", bossrush_assets)
def test_dread_brsa_210(dread_tree_210, brsa_path):
    parse_build_compare_editor(Brsa, dread_tree_210, brsa_path)


def test_add_setup(dread_tree_100):
    subareas = dread_tree_100.get_file("maps/levels/c10_samus/s010_cave/s010_cave.brsa", Brsa)
    subareas.add_setup("Test")

    assert len(list(subareas.subarea_setups)) == 18

    with pytest.raises(ValueError, match=r"Setup .+? is already present"):
        subareas.add_setup("Default")


def test_add_subarea_config(dread_tree_100):
    subareas = dread_tree_100.get_file("maps/levels/c10_samus/s010_cave/s010_cave.brsa", Brsa)
    new_config = subareas.add_subarea_config("camera_test")

    assert len(subareas.get_subarea_setup("Default").vSubareaConfigs) == 79

    with pytest.raises(ValueError, match=r"Config for .+? is already present in .+?"):
        subareas.add_subarea_config("collision_camera_000")

    subareas.set_scenario_collider("camera_test", "collider_test")
    subareas.set_light_group("camera_test", "lg_test")
    subareas.set_sound_group("camera_test", "ssg_test")
    subareas.set_scene_group("camera_test", "sg_test")
    subareas.set_entity_group("camera_test", "eg_test")
    subareas.set_tilegroup_group("camera_test", "bg_test")
    subareas.set_visual_preset("camera_test", "visual_test")
    subareas.set_sound_preset("camera_test", "sound_test")
    subareas.set_music_preset("camera_test", "music_test")

    for index, to_check in enumerate(
        [
            "collider_test",
            "lg_test",
            "ssg_test",
            "sg_test",
            "eg_test",
            "bg_test",
            "visual_test",
            "sound_test",
            "music_test",
        ]
    ):
        assert new_config.asItemsIds[index] == to_check


def test_charclasses(dread_tree_100):
    subareas = dread_tree_100.get_file("maps/levels/c10_samus/s010_cave/s010_cave.brsa", Brsa)
    subareas.add_charclass_group("Test", ["klaida"])

    assert len(subareas.get_charclass_group("Test").vsCharClassesIds) == 1

    with pytest.raises(ValueError, match=r"Charclass .+? is already present"):
        subareas.add_charclass_group("No Enemies")
