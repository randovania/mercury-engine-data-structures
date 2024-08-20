import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data, samus_returns_data
from mercury_engine_data_structures.formats.buct import Buct


@pytest.mark.parametrize("buct_path", dread_data.all_files_ending_with(".buct"))
def test_buct_dread(dread_file_tree, buct_path):
    parse_build_compare_editor(Buct, dread_file_tree, buct_path)


@pytest.mark.parametrize("buct_path", samus_returns_data.all_files_ending_with(".buct"))
def test_buct_sr(samus_returns_tree, buct_path):
    parse_build_compare_editor(Buct, samus_returns_tree, buct_path)
