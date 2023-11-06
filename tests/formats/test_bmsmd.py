from tests.test_lib import parse_and_build_compare

from mercury_engine_data_structures.formats.bmsmd import Bmsmd
from mercury_engine_data_structures.game_check import Game


def test_bmsmd(samus_returns_path):
    file_path = samus_returns_path.joinpath("gui\minimaps\c10_samus.bmsmd")
    parse_and_build_compare(
        Bmsmd, Game.SAMUS_RETURNS, file_path
    )
