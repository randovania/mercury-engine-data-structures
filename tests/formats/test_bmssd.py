from tests.test_lib import parse_and_build_compare

from mercury_engine_data_structures.formats.bmssd import BMSSD
from mercury_engine_data_structures.game_check import Game


def test_compare_dread(dread_path):
    parse_and_build_compare(
        BMSSD, Game.DREAD, dread_path.joinpath("packs/maps/s060_quarantine/s060_quarantine.bmssd")
    )

def test_compare_msr(samus_returns_path):
    parse_and_build_compare(
        BMSSD, Game.SAMUS_RETURNS, samus_returns_path.joinpath("packs/maps/s050_area5/s050_area5.bmssd")
    )
