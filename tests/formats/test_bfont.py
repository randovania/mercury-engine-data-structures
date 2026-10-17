from __future__ import annotations

import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data, samus_returns_data
from mercury_engine_data_structures.formats.msapi.bfont import Bfont


@pytest.mark.parametrize("bfont_path", dread_data.all_files_ending_with(".bfont"))
def test_compare_bcmdl_dread(dread_tree_100, bfont_path):
    parse_build_compare_editor(Bfont, dread_tree_100, bfont_path)


@pytest.mark.parametrize("bfont_path", samus_returns_data.all_files_ending_with(".bfont"))
def test_compare_bcmdl_msr(samus_returns_tree, bfont_path):
    parse_build_compare_editor(Bfont, samus_returns_tree, bfont_path)
