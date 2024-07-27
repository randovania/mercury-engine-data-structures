import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data
from mercury_engine_data_structures.formats.brspd import Brspd


@pytest.mark.parametrize("brspd_path", dread_data.all_files_ending_with(".brspd"))
def test_brspd(dread_file_tree, brspd_path):
    parse_build_compare_editor(Brspd, dread_file_tree, brspd_path)
