import contextlib

import construct
import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data
from mercury_engine_data_structures.formats.bmsad import Bmsad

all_dread_bmsad = [name for name in dread_data.all_name_to_asset_id().keys()
                   if name.endswith(".bmsad")]

expected_failures = {
    "actors/props/pf_mushr_fr/charclasses/pf_mushr_fr.bmsad",
}


@pytest.mark.parametrize("bmsad_path", all_dread_bmsad)
def test_compare_dread_all(dread_file_tree, bmsad_path):
    if bmsad_path in expected_failures:
        expectation = pytest.raises(construct.ConstructError)
    else:
        expectation = contextlib.nullcontext()

    with expectation:
        parse_build_compare_editor(
            Bmsad.construct_class(dread_file_tree.target_game), dread_file_tree, bmsad_path
        )
