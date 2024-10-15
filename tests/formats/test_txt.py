from __future__ import annotations

import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data, samus_returns_data
from mercury_engine_data_structures.formats.txt import Txt


@pytest.mark.parametrize("txt_path", dread_data.all_files_ending_with(".txt"))
def test_compare_txt_dread_100(dread_tree_100, txt_path):
    parse_build_compare_editor(Txt, dread_tree_100, txt_path)


@pytest.mark.parametrize("txt_path", dread_data.all_files_ending_with(".txt"))
def test_compare_dread_210(dread_tree_210, txt_path):
    parse_build_compare_editor(Txt, dread_tree_210, txt_path)


@pytest.mark.parametrize("txt_path", samus_returns_data.all_files_ending_with(".txt"))
def test_compare_txt_sr(samus_returns_tree, txt_path):
    parse_build_compare_editor(Txt, samus_returns_tree, txt_path)
