from __future__ import annotations

import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data
from mercury_engine_data_structures.formats.bmsas import Bmsas


@pytest.mark.parametrize("bmsas_path", dread_data.all_files_ending_with(".bmsas"))
def test_bmsas(dread_tree_100, bmsas_path):
    parse_build_compare_editor(Bmsas, dread_tree_100, bmsas_path)
