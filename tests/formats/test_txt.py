import pytest
from tests.test_lib import parse_and_build_compare

from mercury_engine_data_structures import dread_data, samus_returns_data
from mercury_engine_data_structures.formats.txt import TXT
from mercury_engine_data_structures.game_check import Game


@pytest.mark.parametrize("txt_path", dread_data.all_files_ending_with(".txt"))
def test_compare_dread(dread_path, txt_path):
    file_path = dread_path.joinpath(txt_path)
    parse_and_build_compare(
        TXT, Game.DREAD, file_path
    )

@pytest.mark.parametrize("txt_path", samus_returns_data.all_files_ending_with(".txt"))
def test_compare_sr(samus_returns_path, txt_path):
    file_path = samus_returns_path.joinpath(txt_path)
    parse_and_build_compare(
        TXT, Game.SAMUS_RETURNS, file_path
    )
