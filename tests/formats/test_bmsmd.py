from __future__ import annotations

import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import samus_returns_data
from mercury_engine_data_structures.formats.bmsmd import Bmsmd


@pytest.mark.parametrize("bmsmd_path", samus_returns_data.all_files_ending_with(".bmsmd"))
def test_bmsmd(samus_returns_tree, bmsmd_path):
    parse_build_compare_editor(Bmsmd, samus_returns_tree, bmsmd_path)
