from __future__ import annotations

import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import samus_returns_data
from mercury_engine_data_structures.formats.bmtun import Bmtun


@pytest.mark.parametrize("bmtun_path", samus_returns_data.all_files_ending_with(".bmtun"))
def test_bmtun(samus_returns_tree, bmtun_path):
    parse_build_compare_editor(Bmtun, samus_returns_tree, bmtun_path)


@pytest.fixture()
def bmtun(samus_returns_tree) -> Bmtun:
    return samus_returns_tree.get_parsed_asset("system/tunables/tunables.bmtun", type_hint=Bmtun)


def test_get_tunable(bmtun):
    assert bmtun.get_tunable("Amiibo|CTunableReserveTanks", "fLifeTankSize") == 299.0


def test_set_tunable(bmtun):
    bmtun.set_tunable("Amiibo|CTunableReserveTanks", "fLifeTankSize", 199.0)
    assert bmtun.get_tunable("Amiibo|CTunableReserveTanks", "fLifeTankSize") == 199.0

    bmtun.set_tunable("CTunableMissile", "sDamageSource", "BOMB")
    assert bmtun.get_tunable("CTunableMissile", "sDamageSource") == "BOMB"
