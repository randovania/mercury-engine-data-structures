import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data
from mercury_engine_data_structures.formats.blut import Blut


@pytest.mark.parametrize("blut_path", dread_data.all_files_ending_with(".blut"))
def test_all_blut(dread_file_tree, blut_path):
    parse_build_compare_editor(Blut, dread_file_tree, blut_path)
