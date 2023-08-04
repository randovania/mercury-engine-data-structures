import contextlib

import construct
import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data, samus_returns_data
from mercury_engine_data_structures.formats.bmsad import Bmsad

all_sr_bmsad = [name for name in samus_returns_data.all_name_to_asset_id().keys()
                if name.endswith(".bmsad")]

all_dread_bmsad = [name for name in dread_data.all_name_to_asset_id().keys()
                   if name.endswith(".bmsad")]

expected_dread_failures = {
    "actors/props/pf_mushr_fr/charclasses/pf_mushr_fr.bmsad",
}
expected_sr_failures = {
    "actors/items/adn/charclasses/adn.bmsad",
    "actors/props/ridleystorm/charclasses/ridleystorm.bmsad",
}


@pytest.mark.parametrize("bmsad_path", all_dread_bmsad)
def test_compare_dread_all(dread_file_tree, bmsad_path):
    if bmsad_path in expected_dread_failures:
        expectation = pytest.raises(construct.ConstructError)
    else:
        expectation = contextlib.nullcontext()

    with expectation:
        parse_build_compare_editor(
            Bmsad, dread_file_tree, bmsad_path
        )


@pytest.mark.parametrize("bmsad_path", all_sr_bmsad)
def test_compare_sr_all(samus_returns_tree, bmsad_path):
    if not samus_returns_tree.does_asset_exists(bmsad_path):
        return pytest.skip()

    if bmsad_path in expected_sr_failures:
        expectation = pytest.raises(construct.core.ConstError)
    else:
        expectation = contextlib.nullcontext()

    with expectation:
        parse_build_compare_editor(
            Bmsad, samus_returns_tree, bmsad_path
        )
