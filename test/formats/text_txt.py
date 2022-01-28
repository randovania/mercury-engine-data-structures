import pytest
from mercury_engine_data_structures.formats.txt import TXT
from mercury_engine_data_structures.game_check import Game
from test.test_lib import parse_and_build_compare

def test_compare_dread(dread_path):
    file_path = dread_path.joinpath("system/localization/us_english.txt")
    parse_and_build_compare(
        TXT, Game.DREAD, file_path
    )
