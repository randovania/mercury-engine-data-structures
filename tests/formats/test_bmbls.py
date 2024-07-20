import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data
from mercury_engine_data_structures.formats.bmbls import Bmbls
from mercury_engine_data_structures.game_check import Game


@pytest.mark.parametrize("bmbls_path", dread_data.all_files_ending_with(".bmbls"))
def test_compare_dread(dread_file_tree, bmbls_path):
    parse_build_compare_editor(Bmbls, dread_file_tree, bmbls_path)
