import pytest
from tests.test_lib import parse_build_compare_editor_parsed

from mercury_engine_data_structures import dread_data, samus_returns_data
from mercury_engine_data_structures.formats.bctex import Bctex


@pytest.mark.parametrize("bctex_path", dread_data.all_files_ending_with(".bctex"))
def test_compare_dread(dread_file_tree, bctex_path):
    parse_build_compare_editor_parsed(Bctex, dread_file_tree, bctex_path)

@pytest.mark.parametrize("bctex_path", samus_returns_data.all_files_ending_with(".bctex"))
def test_compare_sr(samus_returns_tree, bctex_path):
    if not samus_returns_tree.does_asset_exists(bctex_path):
        pytest.skip(f"{bctex_path} does not exist!")
    parse_build_compare_editor_parsed(Bctex, samus_returns_tree, bctex_path)
