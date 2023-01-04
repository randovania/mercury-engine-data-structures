import construct
from construct.core import (
    Array, Byte, Const, Construct, Flag, Float32l, Hex, If, Int16ul, Int32ul, Int32sl, Int64ul, LazyBound, PrefixedArray, Select, Struct, Switch, IfThenElse
)

from mercury_engine_data_structures import common_types, type_lib
from mercury_engine_data_structures import game_check
from mercury_engine_data_structures.common_types import Float, StrId, make_dict, make_vector
from mercury_engine_data_structures.construct_extensions.alignment import PrefixedAllowZeroLen
from mercury_engine_data_structures.construct_extensions.misc import ErrorWithMessage
from mercury_engine_data_structures.formats import BaseResource, dread_types
from mercury_engine_data_structures.formats.property_enum import PropertyEnum
from mercury_engine_data_structures.game_check import Game

StrKeyArgument = Struct(
    key = StrId,
    val = Switch(
        construct.this.key[0],
        {
            'b': Flag,
            's': StrId,
            'f': Float,
            'u': Int32ul,
            'i': Int32sl,
            'e': Int32ul,
            'o': Int32ul,
            'v': Array(3, Float)
        },
        default = construct.Error
    )
)

CrcKeyArgument = Struct(
    key = PropertyEnum,
    val = Switch(
        construct.this.key[0],
        {
            'b': Flag,
            's': StrId,
            'f': Float,
            'u': Int32ul,
            'i': Int32sl,
            'e': StrId,
            'o': Int32ul,
            'v': Array(3, Float)
        },
        default = construct.Error
    )
)

Behavior = Struct(
    type = Select(PropertyEnum, Hex(Int64ul)),
    args = PrefixedArray(Int32ul, CrcKeyArgument),
    children = PrefixedArray(Int32ul, LazyBound(lambda: Behavior)),
)

BMTRE = Struct(
    _magic = Const(b"BTRE"),
    version = Const(0x00050001, Hex(Int32ul)), # for dread, unsure if it exists in SR
    args = PrefixedArray(Int32ul, StrKeyArgument),
    behavior = Behavior,
)

class Bmtre(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BMTRE