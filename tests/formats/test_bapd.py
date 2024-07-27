import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data
from mercury_engine_data_structures.formats.bapd import Bapd


@pytest.mark.parametrize("bapd_path", dread_data.all_files_ending_with(".bapd"))
def test_bapd(dread_file_tree, bapd_path):
    parse_build_compare_editor(Bapd, dread_file_tree, bapd_path)
