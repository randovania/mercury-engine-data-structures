import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data
from mercury_engine_data_structures.formats.brfld import Brfld


@pytest.mark.parametrize("brfld_path", dread_data.all_files_ending_with(".brfld"))
def test_brfld(dread_file_tree, brfld_path):
    parse_build_compare_editor(Brfld, dread_file_tree, brfld_path)
