from mercury_engine_data_structures.formats.bmbls import BMBLS
from mercury_engine_data_structures.game_check import Game
from test.test_lib import parse_and_build_compare


def test_compare_dread(dread_path):
    parse_and_build_compare(
        BMBLS, Game.DREAD, dread_path.joinpath("packs/maps/s010_cave/subareas/subareapack_scorpius/actors/characters/scorpius/animations/blendspaces/walktailinit.bmbls")
    )