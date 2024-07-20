import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import samus_returns_data
from mercury_engine_data_structures.formats.bmsbk import Bmsbk


@pytest.mark.parametrize("bmsbk_path", samus_returns_data.all_files_ending_with(".bmsbk"))
def test_bmsbk(samus_returns_tree, bmsbk_path):
    try:
        parse_build_compare_editor(Bmsbk, samus_returns_tree, bmsbk_path)
    except FileNotFoundError:
        pytest.skip(f"{bmsbk_path} does not exist")
