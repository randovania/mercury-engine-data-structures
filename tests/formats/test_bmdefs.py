from __future__ import annotations

import copy

import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures.formats.bmdefs import Bmdefs, InnerStateType, StateType


def test_bmdefs_dread(dread_tree_100):
    parse_build_compare_editor(Bmdefs, dread_tree_100, "system/snd/scenariomusicdefs.bmdefs")


def test_bmdefs_sr(samus_returns_tree):
    parse_build_compare_editor(Bmdefs, samus_returns_tree, "system/snd/scenariomusicdefs.bmdefs")


@pytest.fixture()
def bmdefs(samus_returns_tree) -> Bmdefs:
    return samus_returns_tree.get_parsed_asset("system/snd/scenariomusicdefs.bmdefs", type_hint=Bmdefs)


def test_get_sound(bmdefs: Bmdefs):
    sound = bmdefs.get_sound(0)
    assert sound.sound_name == "matad_jintojo_32728k"
    assert sound.volume == 1.0


def test_set_sound_properties(bmdefs: Bmdefs):
    sound = bmdefs.get_sound(3)
    assert sound is not None

    original_properties = copy.deepcopy(sound)

    sound.sound_name = "m_new_sound"
    sound.priority = 1
    sound.file_path = "a/real/file/path.wav"
    sound.fade_in = 0.1
    sound.fade_out = 4.0
    sound.volume = 0.5
    sound.environment_sfx_volume = 0.79

    assert sound != original_properties


def test_get_enemy(bmdefs: Bmdefs):
    enemy = bmdefs.get_enemy(0)
    assert enemy.enemy_name == "alphanewborn"

    area = enemy.get_area(0)
    assert area.area_name == "s000_surface"

    layer = area.get_layer(0)
    assert layer.layer_name == "default"

    state = layer.get_state(0)
    assert state.state_type == "COMBAT"
    assert state.start_delay == 0.0
    assert state.inner_states == {"RELAX": 3.0, "DEATH": 5.0}


def test_set_enemy_properties(bmdefs: Bmdefs):
    enemy = bmdefs.get_enemy(9)
    assert enemy is not None

    assert enemy.enemy_name == "queen"
    enemy.enemy_name = "kraid"
    assert enemy.enemy_name == "kraid"

    area = enemy.get_area(0)
    assert area.area_name == "s100_area10"
    area.area_name = "s050_area5"
    assert area.area_name == "s050_area5"

    layer = area.get_layer(0)
    assert layer.layer_name == "default"
    layer.layer_name = "not_default"
    assert layer.layer_name == "not_default"

    state = layer.get_state(1)
    assert state.state_type == StateType.DEATH
    state.state_type = StateType.COMBAT
    assert state.state_type == StateType.COMBAT

    assert state.start_delay == 2.0
    state.start_delay = 0.4
    assert state.start_delay == 0.4

    assert state.inner_states == {}
    state.inner_states = {InnerStateType.RELAX: 1.0, InnerStateType.DEATH: 45.0}
    assert state.inner_states == {InnerStateType.RELAX: 1.0, InnerStateType.DEATH: 45.0}

    sound_properties = state.get_sound_properties()
    assert sound_properties.fade_out == 3.0
    sound_properties.fade_out = 10.0
    assert sound_properties.fade_out == 10.0
