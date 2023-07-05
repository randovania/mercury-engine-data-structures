from mercury_engine_data_structures.formats.bmmap import BMMAP
from mercury_engine_data_structures.formats.bmmdef import BMMDEF
from mercury_engine_data_structures.game_check import Game
from test.test_lib import parse_and_build_compare


def test_compare_bmmap_dread(dread_path):
    parse_and_build_compare(
        BMMAP, Game.DREAD, dread_path.joinpath("maps/levels/c10_samus/s010_cave/s010_cave.bmmap"), True
    )

def test_compare_bmmdef_dread(dread_path):
    parse_and_build_compare(
        BMMDEF, Game.DREAD, dread_path.joinpath("system/minimap/minimap.bmmdef"), True
    )
