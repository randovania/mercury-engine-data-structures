import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import samus_returns_data
from mercury_engine_data_structures.formats.bmsmsd import Bmsmsd


@pytest.mark.parametrize("bmsmsd_path", samus_returns_data.all_files_ending_with(".bmsmsd"))
def test_bmsmsd(samus_returns_tree, bmsmsd_path):
    parse_build_compare_editor(Bmsmsd, samus_returns_tree, bmsmsd_path)
