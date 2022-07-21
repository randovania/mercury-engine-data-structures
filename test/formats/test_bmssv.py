import pytest
from mercury_engine_data_structures.formats.bmssv import BMSSV
from mercury_engine_data_structures.game_check import Game
from test.test_lib import parse_and_build_compare


@pytest.mark.parametrize("path", ["common.bmssv", "pkprfl.bmssv", "samus.bmssv"])
def test_compare_dread(dread_save_path, path):
    parse_and_build_compare(
        BMSSV, Game.DREAD, dread_save_path.joinpath(path), True
    )
