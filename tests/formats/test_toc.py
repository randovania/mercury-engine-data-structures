from mercury_engine_data_structures.formats.toc import Toc
from mercury_engine_data_structures.game_check import Game


def test_compare_dread(dread_path):
    game = Game.DREAD
    toc_class = Toc.construct_class(game)
    toc_path = dread_path.joinpath("system/files.toc")

    raw = toc_path.read_bytes()
    data = toc_class.parse(raw, target_game=game)
    encoded = toc_class.build(data, target_game=game)

    assert encoded == raw
    assert len(data.files) == 84408
