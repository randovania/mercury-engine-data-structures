import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures.formats.btunda import Btunda

BTUNDA_PATH = "system/tunables/tunables.btunda"


def test_btunda_100(dread_tree_100):
    parse_build_compare_editor(Btunda, dread_tree_100, BTUNDA_PATH)


def test_btunda_210(dread_tree_210):
    parse_build_compare_editor(Btunda, dread_tree_210, BTUNDA_PATH)


def test_btunda_get_tunable(dread_tree_100):
    btunda = dread_tree_100.get_parsed_asset(BTUNDA_PATH, type_hint=Btunda)

    assert btunda.get_tunable(["ShotManager|CTunableShotManager", "rPlasmaBeamDiffusionExplosion", "uAmount"]) == 3


def test_btunda_set_tunable(dread_tree_100):
    btunda = dread_tree_100.get_parsed_asset(BTUNDA_PATH, type_hint=Btunda)

    tunable_path = ["SubAreaManager|CTunableSubAreaManager", "bKillPlayerOutsideScenario"]
    assert btunda.get_tunable(tunable_path) is True
    btunda.set_tunable(tunable_path, False)
    assert btunda.get_tunable(tunable_path) is False


def test_btunda_set_tunable_100(dread_tree_100):
    btunda = dread_tree_100.get_parsed_asset(BTUNDA_PATH, type_hint=Btunda)

    tunable_path = ["SubAreaManager|CTunableSubAreaManager", "bKillPlayerOutsideScenario"]
    assert btunda.get_tunable(tunable_path) is True
    btunda.set_tunable(tunable_path, False)
    assert btunda.get_tunable(tunable_path) is False

    with pytest.raises(ValueError):
        btunda.set_tunable(["CTunableBossRushManager", "fDeathAddedTime"], 420.0)


def test_btunda_set_tunable_210(dread_tree_210):
    btunda = dread_tree_210.get_parsed_asset(BTUNDA_PATH, type_hint=Btunda)

    tunable_path = ["CTunableBossRushManager", "fDeathAddedTime"]
    assert btunda.get_tunable(tunable_path) == 15.0
    btunda.set_tunable(tunable_path, 420.0)
    assert btunda.get_tunable(tunable_path) == 420.0

    with pytest.raises(ValueError):
        btunda.set_tunable(["CTunableGameManager", "bForceHardMode"], True)
