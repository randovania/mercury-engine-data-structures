import pytest
from tests.test_lib import parse_build_compare_editor, parse_build_compare_editor_parsed

from mercury_engine_data_structures import dread_data
from mercury_engine_data_structures.formats.gui_files import Bmscp, Bmssk, Bmsss
from mercury_engine_data_structures.game_check import Game


@pytest.mark.parametrize("bmscp_path", dread_data.all_files_ending_with(".bmscp"))
def test_compare_bmscp_dread(dread_file_tree, bmscp_path):
    parse_build_compare_editor_parsed(Bmscp, dread_file_tree, bmscp_path)

@pytest.mark.parametrize("bmssk_path", dread_data.all_files_ending_with(".bmssk"))
def test_compare_bmssk_dread(dread_file_tree, bmssk_path):
    parse_build_compare_editor(Bmssk, dread_file_tree, bmssk_path)

@pytest.mark.parametrize("bmsss_path", dread_data.all_files_ending_with(".bmsss"))
def test_compare_bmsss_dread(dread_file_tree, bmsss_path):
    parse_build_compare_editor(Bmsss, dread_file_tree, bmsss_path)
