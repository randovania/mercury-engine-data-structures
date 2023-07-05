from mercury_engine_data_structures.formats.gui_files import BMSCP, BMSSK, BMSSS
from mercury_engine_data_structures.game_check import Game
from test.test_lib import parse_and_build_compare, parse_and_build_compare_parsed


def test_compare_bmscp_dread(dread_path):
    parse_and_build_compare_parsed(
        BMSCP, Game.DREAD, dread_path.joinpath("gui/scripts/samusmenucomposition.bmscp"),
    )

def test_compare_bmssk_dread(dread_path):
    parse_and_build_compare(
        BMSSK, Game.DREAD, dread_path.joinpath("gui/scripts/samusmenucomposition.bmssk"),
    )

def test_compare_bmsss_dread(dread_path):
    parse_and_build_compare(
        BMSSS, Game.DREAD, dread_path.joinpath("gui/scripts/sprites_companylogo.bmsss")
    )
