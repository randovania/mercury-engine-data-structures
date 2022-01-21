from mercury_engine_data_structures.formats.toc import TOC
from mercury_engine_data_structures.game_check import Game


def test_compare_dread(dread_path):
    game = Game.DREAD
    toc_path = dread_path.joinpath("system/files.toc")

    raw = toc_path.read_bytes()
    data = TOC.parse(raw, target_game=game)
    encoded = TOC.build(data, target_game=game)

    assert encoded == raw
    assert len(data.files) == 84408
