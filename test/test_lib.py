from pathlib import Path

import pytest
from construct.lib.containers import Container

from mercury_engine_data_structures.file_tree_editor import FileTreeEditor
from mercury_engine_data_structures.game_check import Game


def _parse_and_build_compare(module, game: Game, file_path: Path, print_data=False, save_file=None):
    if not file_path.is_file():
        return pytest.skip(f"missing {file_path}")

    raw = file_path.read_bytes()

    data = module.parse(raw, target_game=game)
    if print_data:
        print(data)
    encoded = module.build(data, target_game=game)

    if save_file:
        file_path.parent.joinpath(save_file).write_bytes(encoded)

    return raw, encoded, data


def parse_and_build_compare(module, game: Game, file_path: Path, print_data=False, save_file=None):
    raw, encoded, _ = _parse_and_build_compare(module, game, file_path, print_data, save_file)
    assert encoded == raw


def parse_and_build_compare_parsed(module, game: Game, file_path: Path, print_data=False, save_file=None):
    _, encoded, data = _parse_and_build_compare(module, game, file_path, print_data, save_file)

    data2 = module.parse(encoded, target_game=game)
    if print_data:
        print(data2)

    assert purge_hidden(data) == purge_hidden(data2)


def purge_hidden(data: Container) -> Container:
    data = {k: v for k, v in data.items() if not k.startswith("_")}
    return {k: purge_hidden(v) if isinstance(v, Container) else v for k, v in data.items()}


def parse_build_compare_editor(module, editor: FileTreeEditor, file_name: str, print_data=False):
    raw = editor.get_raw_asset(file_name)

    data = module.parse(raw, target_game=editor.target_game)
    if print_data:
        print(data)
    encoded = module.build(data, target_game=editor.target_game)

    assert encoded == raw
