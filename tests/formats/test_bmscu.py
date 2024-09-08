import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data
from mercury_engine_data_structures.formats.bmscu import Bmscu


@pytest.mark.parametrize("bmscu_path", dread_data.all_files_ending_with(".bmscu"))
def test_compare_dread(dread_tree_100, bmscu_path):
    parse_build_compare_editor(Bmscu, dread_tree_100, bmscu_path)
