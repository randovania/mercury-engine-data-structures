import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import samus_returns_data
from mercury_engine_data_structures.formats.bmsem import Bmsem


@pytest.mark.parametrize("bmsem_path", samus_returns_data.all_files_ending_with(".bmsem"))
def test_bmsem(samus_returns_tree, bmsem_path):
    parse_build_compare_editor(Bmsem, samus_returns_tree, bmsem_path, print_data=True)
