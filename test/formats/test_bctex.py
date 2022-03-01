from mercury_engine_data_structures.formats.bctex import BCTEX
from mercury_engine_data_structures.game_check import Game
from test.test_lib import parse_and_build_compare_parsed


def test_compare_dread(dread_path):
    parse_and_build_compare_parsed(
        BCTEX, Game.DREAD, dread_path.joinpath("textures/system/minimap/icons/icons.bctex"),
        print_data=True,
    )
