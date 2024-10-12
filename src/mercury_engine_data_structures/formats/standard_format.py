import functools
import typing

import construct

from mercury_engine_data_structures.common_types import VersionAdapter
from mercury_engine_data_structures.formats.property_enum import PropertyEnum
from mercury_engine_data_structures.game_check import Game, GameSpecificStruct
from mercury_engine_data_structures.type_lib import get_type_lib_dread


def _const_if_present(con: construct.Construct, value: typing.Any | None) -> construct.Construct:
    return construct.Const(value, con) if value is not None else con


def create(
    name: str | None,
    version: int | str | tuple[int, int, int] | None,
    root_name: str | None = None,
    explicit_root: bool = False,
):
    # this maybe needs to change in the future if SR and Dread have different formats for type using this
    type_lib = get_type_lib_dread()
    if root_name is None:
        root_name = name

    if explicit_root:
        root = construct.FocusedSeq(
            "root",
            "type" / construct.Rebuild(PropertyEnum, name),
            "root" / type_lib.GetTypeConstruct(lambda this: this._.type),
        )
    else:
        root = type_lib.get_type(root_name).construct

    result = GameSpecificStruct(
        construct.Struct(
            _class_crc=_const_if_present(PropertyEnum, name),
            _version=VersionAdapter(version),
            root_type=construct.Const("Root", PropertyEnum),
            Root=root,
            _end=construct.Terminated,
        ),
        Game.DREAD,
    )
    result.name = name
    return result


@functools.lru_cache
def _cached_game_model(name: str | None, version: int | str | tuple[int, int, int] | None):
    return create(name, version, "gameeditor::CGameModelRoot").compile()


def game_model(name: str | None, version: int | str | tuple[int, int, int] | None):
    return _cached_game_model(name, version)
