import functools
import typing
from typing import Optional

import construct

from mercury_engine_data_structures.formats.property_enum import PropertyEnum
from mercury_engine_data_structures.game_check import Game, GameSpecificStruct
from mercury_engine_data_structures.type_lib import get_type_lib_dread


def _const_if_present(con: construct.Construct, value: typing.Any | None) -> construct.Construct:
    return construct.Const(value, con) if value is not None else con


def create(name: Optional[str], version: Optional[int], root_name: Optional[str] = None, explicit_root: bool = False):
    # this maybe needs to change in the future if SR and Dread have different formats for type using this
    type_lib = get_type_lib_dread()
    if root_name is None:
        root_name = name

    if explicit_root:
        root = construct.FocusedSeq(
            "root",
            "type" / construct.Rebuild(PropertyEnum, name),
            "root" / type_lib.GetTypeConstruct(lambda this: this._.type)
        )
    else:
        root = type_lib.get_type(root_name).construct

    result = GameSpecificStruct(construct.Struct(
        _class_crc=_const_if_present(PropertyEnum, name),
        _version=_const_if_present(construct.Hex(construct.Int32ul), version),

        root_type=construct.Const('Root', PropertyEnum),
        Root=root,

        _end=construct.Terminated,
    ), Game.DREAD)
    result.name = name
    return result


@functools.lru_cache
def _cached_game_model():
    return create(None, None, "gameeditor::CGameModelRoot").compile()


def game_model(name: str, version: int):
    return _cached_game_model()
