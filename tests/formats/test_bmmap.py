import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data
from mercury_engine_data_structures.formats.bmmap import Bmmap


@pytest.mark.parametrize("bmmap_path", dread_data.all_files_ending_with(".bmmap"))
def test_dread_bmmap(dread_file_tree, bmmap_path):
    parse_build_compare_editor(Bmmap, dread_file_tree, bmmap_path)
