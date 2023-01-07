import construct

from construct import Construct, Container, ListContainer
from construct.core import (PrefixedArray, Byte, Const, Flag, Hex, If, Int32ul, LazyBound, Struct, )

from mercury_engine_data_structures.formats import BaseResource
from mercury_engine_data_structures.common_types import StrId, Float
from mercury_engine_data_structures.game_check import Game

UnkStruct = Struct(
    unk1 = StrId,
    unk2 = Byte,
    unk3 = Float,
    unk4 = StrId,
    unk5 = StrId,
    unk6 = Float,
    unk7 = Byte,
    unk8 = construct.core.If(
        construct.this.unk5 != "Portal",
        StrId,
    ),
    children = PrefixedArray(Int32ul, LazyBound(lambda: UnkStruct))
)

Item = Struct(
    name = StrId,
    type = StrId,
    unk1 = StrId,
    unk2 = Float,
    unk3 = StrId,   
    unk4 = Float,
    unk5 = StrId,
    unk6 = Byte,
    unk7 = Byte,
    unk8 = StrId,
    unk9 = Byte,
    unk10 = Byte,
    unk11 = Byte,
    unk12 = Float,
    unk13 = UnkStruct,
)

LocationStruct = Struct(
    name = StrId,
    items = PrefixedArray(Int32ul, Item)
)

BMSLINK = Struct(
    _magic = Const(b"LINK"),
    version = Const(0x001F0001, Hex(Int32ul)),

    unk_bool = Byte,
    location = LocationStruct,
)

class Bmslink(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BMSLINK