from mercury_engine_data_structures.formats.bmssd import BMSSD
from mercury_engine_data_structures.game_check import Game
from test.test_lib import parse_and_build_compare


def test_compare_dread(dread_path):
    parse_and_build_compare(
        BMSSD, Game.DREAD, dread_path.joinpath("packs/maps/s060_quarantine/s060_quarantine.bmssd")
    )
