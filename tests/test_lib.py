import typing
from pathlib import Path

import construct
import pytest

from mercury_engine_data_structures.file_tree_editor import FileTreeEditor
from mercury_engine_data_structures.formats import BaseResource
from mercury_engine_data_structures.game_check import Game, GameSpecificStruct


def parse_and_build_compare(module, game: Game, file_path: Path, print_data=False, save_file=None):
    if not file_path.is_file():
        return pytest.skip(f"missing {file_path}")

    raw = file_path.read_bytes()

    data = module.parse(raw, target_game=game)
    if print_data:
        print(data)
    encoded = module.build(data, target_game=game)

    if save_file:
        file_path.parent.joinpath(save_file).write_bytes(encoded)

    assert encoded == raw

def _parse_build_compare(module: typing.Type[BaseResource],
                         editor: FileTreeEditor, file_name: str, print_data=False):
    construct_class = module.construct_class(editor.target_game)
    raw = editor.get_raw_asset(file_name)

    data = construct_class.parse(raw, target_game=editor.target_game)
    if print_data:
        print(data)
    encoded = construct_class.build(data, target_game=editor.target_game)

    return raw, encoded, data

def parse_build_compare_editor(module: typing.Type[BaseResource],
                               editor: FileTreeEditor, file_name: str, print_data=False):
    raw, encoded, _ = _parse_build_compare(module, editor, file_name, print_data)

    assert encoded == raw

def parse_build_compare_editor_parsed(module: typing.Type[BaseResource],
                                      editor: FileTreeEditor, file_name: str, print_data=False):
    _, encoded, data = _parse_build_compare(module, editor, file_name, print_data)

    construct_class = module.construct_class(editor.target_game)
    data2 = construct_class.parse(encoded, target_game=editor.target_game)

    if print_data:
        print(data2)

    assert data == data2


def game_compile_build(con: construct.Construct, data: construct.Container, target_game: Game) -> bytes:
    return GameSpecificStruct(con, target_game).compile().build(data, target_game=target_game)


def game_compile_parse(con: construct.Construct, data: bytes, target_game: Game) -> construct.Container:
    return GameSpecificStruct(con, target_game).compile().parse(data, target_game=target_game)
