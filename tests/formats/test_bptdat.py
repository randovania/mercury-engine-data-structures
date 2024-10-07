import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data
from mercury_engine_data_structures.formats.bptdat import Bptdat, Bptdef


@pytest.mark.parametrize("bptdat_path", dread_data.all_files_ending_with(".bptdat"))
def test_bptdat(dread_tree_100, bptdat_path):
    parse_build_compare_editor(Bptdat, dread_tree_100, bptdat_path)


@pytest.mark.parametrize("bptdef_path", dread_data.all_files_ending_with(".bptdef"))
def test_bptdef(dread_tree_100, bptdef_path):
    parse_build_compare_editor(Bptdef, dread_tree_100, bptdef_path)
