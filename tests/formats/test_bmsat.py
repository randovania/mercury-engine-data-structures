from __future__ import annotations

import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data
from mercury_engine_data_structures.formats.bmsat import Bmsat


@pytest.mark.parametrize("bmsat_path", dread_data.all_files_ending_with(".bmsat"))
def test_bmsat(dread_tree_100, bmsat_path):
    parse_build_compare_editor(Bmsat, dread_tree_100, bmsat_path)
