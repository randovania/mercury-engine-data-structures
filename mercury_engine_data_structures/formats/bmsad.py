import construct
from construct import (
    Struct, Construct, Const, Int32ul, Hex, CString, Switch, Int16ul,
    PrefixedArray, Byte, Array, Float32l, Probe,
)

from mercury_engine_data_structures.construct_extensions.misc import ErrorWithMessage
from mercury_engine_data_structures.formats import BaseResource
from mercury_engine_data_structures.game_check import Game

Pickable = Struct(
    unknown=Int32ul,
)

component_types = {
    "PICKABLE": Pickable,
}

CCharClass = Struct(
    model_name=CString("utf-8"),
    unk_1=Int16ul,
    unk_2=Int32ul,
    unk_3=Int16ul,
    sub_actors=PrefixedArray(Int32ul, CString("utf-8")),
    unk_4=Array(9, Float32l),
    magic=Const(0xFFFFFFFF, Hex(Int32ul)),
    unk_5=Int16ul,
    unk_6=Byte,
    _=Probe(),
    components=PrefixedArray(
        Int32ul,
        Struct(
            type=CString("utf-8"),
            _=Probe(),
            component=Switch(
                construct.this.type,
                component_types,
                ErrorWithMessage("Unknown component type"),
            )
        ),
    ),
)

property_types = {
    "CCharClass": CCharClass,
}

BMSAD = Struct(
    magic_a=Const(b"MSAD"),
    magic_b=Const(0x0200000F, Hex(Int32ul)),
    name=CString("utf-8"),
    type=CString("utf-8"),
    property=Switch(
        construct.this.type,
        property_types,
        ErrorWithMessage("Unknown property type"),
    )
)


class Bmsad(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BMSAD
