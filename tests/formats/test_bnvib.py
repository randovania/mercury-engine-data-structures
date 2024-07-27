import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data
from mercury_engine_data_structures.formats.bnvib import Bnvib


@pytest.mark.parametrize("bnvib_path", dread_data.all_files_ending_with(".bnvib"))
def test_bnvib(dread_file_tree, bnvib_path):
    parse_build_compare_editor(Bnvib, dread_file_tree, bnvib_path)
