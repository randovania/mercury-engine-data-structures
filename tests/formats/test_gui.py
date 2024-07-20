import pytest
from tests.test_lib import parse_and_build_compare, parse_and_build_compare_parsed, parse_build_compare_editor

from mercury_engine_data_structures import dread_data
from mercury_engine_data_structures.formats.gui_files import BMSCP, BMSSK, BMSSS
from mercury_engine_data_structures.game_check import Game


@pytest.mark.parametrize("bmscp_path", dread_data.all_files_ending_with(".bmscp"))
def test_compare_bmscp_dread(dread_path, bmscp_path):
    parse_and_build_compare_parsed(
        BMSCP, Game.DREAD, dread_path.joinpath(bmscp_path),
    )

@pytest.mark.parametrize("bmssk_path", dread_data.all_files_ending_with(".bmssk"))
def test_compare_bmssk_dread(dread_path, bmssk_path):
    parse_and_build_compare(
        BMSSK, Game.DREAD, dread_path.joinpath(bmssk_path),
    )

@pytest.mark.parametrize("bmsss_path", dread_data.all_files_ending_with(".bmsss"))
def test_compare_bmsss_dread(dread_path, bmsss_path):
    parse_and_build_compare(
        BMSSS, Game.DREAD, dread_path.joinpath(bmsss_path),
    )
