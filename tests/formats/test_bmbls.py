import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data
from mercury_engine_data_structures.formats.bmbls import Bmbls


@pytest.mark.parametrize("bmbls_path", dread_data.all_files_ending_with(".bmbls"))
def test_compare_bmbls_dread(dread_tree_100, bmbls_path):
    parse_build_compare_editor(Bmbls, dread_tree_100, bmbls_path)
