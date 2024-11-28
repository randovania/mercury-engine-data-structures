from __future__ import annotations

from typing import TYPE_CHECKING

import construct
from construct import Construct
from construct.core import (
    Byte,
    Const,
    Flag,
    Int32ul,
    LazyBound,
    PrefixedArray,
    Struct,
)

from mercury_engine_data_structures.base_resource import BaseResource
from mercury_engine_data_structures.common_types import Float, StrId, VersionAdapter

if TYPE_CHECKING:
    from mercury_engine_data_structures.game_check import Game

UnkStruct = Struct(
    dir=StrId,  # 16 directions (i.e. RIGHT, RIGHT_UP_27, RIGHT_UP_45, RIGHT_UP_63, UP, ...)
    unk2=Flag,
    distance=Float,
    func=StrId,  # empty string, Min or Equals
    edge_type=StrId,  # Portal, Forbidden, Solid, Stitched or Any
    unk6=Float,  # 0 or 51?
    unk7=Flag,
    other_dir=construct.core.If(
        construct.this.edge_type != "Portal",
        StrId,  # right or left, usually opposite of dir
    ),
    children=PrefixedArray(Int32ul, LazyBound(lambda: UnkStruct)),
)

Item = Struct(
    name=StrId,
    type=StrId,
    unk1=Const("", StrId),  # possibly empty string?
    unk2=Float,  # 0-300
    unk3=StrId,  # empty or 'tunnel'
    unk4=Float,  # 0-300
    unk5=StrId,  # empty or 'tunnel'
    unk6=Flag,
    unk7=Flag,
    unk8=StrId,  # name of action?
    unk9=Flag,
    unk10=Flag,
    unk11=Flag,
    unk12=Float,  # 0 or 50
    actions=UnkStruct,
)

LocationStruct = Struct(name=StrId, items=PrefixedArray(Int32ul, Item))

BMSLINK = Struct(
    _magic=Const(b"LINK"),
    version=VersionAdapter("1.31.0"),
    unk_bool=Byte,
    location=LocationStruct,
)


class Bmslink(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BMSLINK
