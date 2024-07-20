import pytest
from tests.test_lib import parse_and_build_compare_parsed

from mercury_engine_data_structures import samus_returns_data
from mercury_engine_data_structures.formats.bctex import BCTEX_SR, BCTEX_Dread
from mercury_engine_data_structures.game_check import Game


def test_compare_dread(dread_path):
    parse_and_build_compare_parsed(
        BCTEX_Dread, Game.DREAD, dread_path.joinpath("textures/system/minimap/icons/icons.bctex"),
        print_data=True,
    )

#all_sr_bctex = samus_returns_data.all_files_ending_with(".bctex")

@pytest.mark.parametrize("bctex_path", samus_returns_data.all_files_ending_with(".bctex"))
def test_compare_sr(samus_returns_path, bctex_path):
    parse_and_build_compare_parsed(
        BCTEX_SR, Game.SAMUS_RETURNS, samus_returns_path.joinpath(bctex_path),
        print_data=True,
    )
