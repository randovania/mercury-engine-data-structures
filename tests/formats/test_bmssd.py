import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data, samus_returns_data
from mercury_engine_data_structures.formats.bmssd import Bmssd


@pytest.mark.parametrize("bmssd_path", dread_data.all_files_ending_with(".bmssd"))
def test_compare_dread(dread_file_tree, bmssd_path):
    parse_build_compare_editor(Bmssd, dread_file_tree, bmssd_path)

@pytest.mark.parametrize("bmssd_path", samus_returns_data.all_files_ending_with(".bmssd"))
def test_compare_msr(samus_returns_tree, bmssd_path):
    if not samus_returns_tree.does_asset_exists(bmssd_path):
        pytest.skip(f"{bmssd_path} does not exist!")

    parse_build_compare_editor(Bmssd, samus_returns_tree, bmssd_path)
