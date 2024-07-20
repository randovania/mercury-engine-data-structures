import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data, samus_returns_data
from mercury_engine_data_structures.formats.bmsnav import Bmsnav


@pytest.mark.parametrize("bmsnav_path", dread_data.all_files_ending_with(".bmsnav"))
def test_dread_bmsnav(dread_file_tree, bmsnav_path):
    parse_build_compare_editor(Bmsnav, dread_file_tree, bmsnav_path)

@pytest.mark.parametrize("bmsnav_path", samus_returns_data.all_files_ending_with(".bmsnav"))
def test_sr_bmsnav(samus_returns_tree, bmsnav_path):
    if not samus_returns_tree.does_asset_exists(bmsnav_path):
        pytest.skip(f"{bmsnav_path} does not exist!")

    parse_build_compare_editor(Bmsnav, samus_returns_tree, bmsnav_path)
