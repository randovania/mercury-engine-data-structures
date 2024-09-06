import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data, samus_returns_data
from mercury_engine_data_structures.formats.bfont import Bfont


@pytest.mark.parametrize("bfont_path", dread_data.all_files_ending_with(".bfont"))
def test_buct_dread(dread_file_tree, bfont_path):
    parse_build_compare_editor(Bfont, dread_file_tree, bfont_path)


@pytest.mark.parametrize("bfont_path", samus_returns_data.all_files_ending_with(".bfont"))
def test_buct_sr(samus_returns_tree, bfont_path):
    parse_build_compare_editor(Bfont, samus_returns_tree, bfont_path)
