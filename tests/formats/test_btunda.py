import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures.formats.btunda import Btunda

BTUNDA_PATH = "system/tunables/tunables.btunda"


def test_btunda(dread_file_tree):
    parse_build_compare_editor(Btunda, dread_file_tree, BTUNDA_PATH)


def test_btunda_get_tunable(dread_file_tree):
    btunda = dread_file_tree.get_parsed_asset(BTUNDA_PATH, type_hint=Btunda)

    assert btunda.get_tunable(["ShotManager|CTunableShotManager", "rPlasmaBeamDiffusionExplosion", "uAmount"]) == 3


def test_btunda_set_tunable(dread_file_tree):
    btunda = dread_file_tree.get_parsed_asset(BTUNDA_PATH, type_hint=Btunda)

    tunable_path = ["SubAreaManager|CTunableSubAreaManager", "bKillPlayerOutsideScenario"]
    assert btunda.get_tunable(tunable_path) is True
    btunda.set_tunable(tunable_path, False)
    assert btunda.get_tunable(tunable_path) is False


def test_btunda_invalid_tunable(dread_file_tree):
    btunda = dread_file_tree.get_parsed_asset(BTUNDA_PATH, type_hint=Btunda)

    if btunda.raw.version == "119.0.2":
        with pytest.raises(ValueError):
            btunda.set_tunable(["CTunableBossRushManager", "fDeathAddedTime"], 420.0)

    else:
        with pytest.raises(ValueError):
            btunda.set_tunable(["CTunableGameManager", "bForceHardMode"], True)
