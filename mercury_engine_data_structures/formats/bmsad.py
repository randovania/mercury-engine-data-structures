import construct
from construct import (
    Struct, Construct, Const, Int32ul, Hex, CString, Switch, Int16ul,
    PrefixedArray, Byte, Array, Float32l, Bytes, Tell, PascalString, Flag,
)

from mercury_engine_data_structures.common_types import make_dict, StrId, Float
from mercury_engine_data_structures.construct_extensions.misc import ErrorWithMessage
from mercury_engine_data_structures.formats import BaseResource
from mercury_engine_data_structures.formats.property_enum import PropertyEnum
from mercury_engine_data_structures.game_check import Game
from mercury_engine_data_structures.object import Object

Char = construct.PaddedString(1, 'ascii')

FunctionArgument = Struct(
    prop=PropertyEnum,
    type=Char,
    value=Switch(
        construct.this.type,
        {
            's': StrId,
            'f': Float,
            'b': Flag,
        },
        ErrorWithMessage(lambda ctx: f"Unknown argument type: {ctx.type}")
    )
)

CPickableItemComponent = Struct(
    unk_1=Array(3, Hex(Int32ul)),
    empty_string=PropertyEnum,
    root=PropertyEnum,

    fields=Object({
        "sOnPickCaption": StrId,
    }),

    unk_2=Int32ul,

    functions=make_dict(Struct(
        unk=Int16ul,
        params=PrefixedArray(Int32ul, FunctionArgument),
    )),
)

CScriptComponent = Struct(
    unk_1=Array(3, Hex(Int32ul)),
    unk_2=Int32ul,
    functions=make_dict(Struct(
        unk=Int16ul,
        params=PrefixedArray(Int32ul, FunctionArgument),
    )),
)

CModelUpdaterComponent = Struct(
    tell=Tell,
    unk=Bytes(0xA6),
)

CAnimationComponent = Struct(
    unk_1a=Array(3, Hex(Int32ul)),
    empty_string=PropertyEnum,
    root=PropertyEnum,

    fields=Object({
        "sInitialAction": StrId,
        "sAnimTree": StrId,
    }),
    unk_2=Int32ul,

    functions=make_dict(Struct(
        unk=Int16ul,
        params=PrefixedArray(Int32ul, FunctionArgument),
    )),
)

CAudioComponent = Struct(
    tell=Tell,
    unk=Bytes(0x61),
)

component_types = {
    "CPickableItemComponent": CPickableItemComponent,
    "CScriptComponent": CScriptComponent,
    "CModelUpdaterComponent": CModelUpdaterComponent,
    "CAnimationComponent": CAnimationComponent,
    "CAudioComponent": CAudioComponent,
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

    components=make_dict(
        Struct(
            component_type=CString("utf-8"),
            component=Switch(
                construct.this.component_type,
                component_types,
                ErrorWithMessage(lambda ctx: f"Unknown component type: {ctx.component_type}"),
            )
        )
    )

    # components=PrefixedArray(
    #     Int32ul,
    #     Struct(
    #         type=CString("utf-8"),
    #         component=Switch(
    #             construct.this.type,
    #             component_types,
    #             ErrorWithMessage(lambda ctx: f"Unknown component type: {ctx.type}"),
    #         )
    #     ),
    # ),
)

property_types = {
    "CCharClass": CCharClass,
}
#
BMSAD = Struct(
    magic_a=Const(b"MSAD"),
    magic_b=Const(0x0200000F, Hex(Int32ul)),

    # # gameeditor::CGameModelRoot
    # root_type=construct.Const('Root', PropertyEnum),
    # Root=gameeditor_CGameModelRoot,

    name=CString("utf-8"),
    type=CString("utf-8"),

    property=Switch(
        construct.this.type,
        property_types,
        ErrorWithMessage("Unknown property type"),
    )
)


# BMSAD = game_model_root.create('CActorDef', 0x02000031)


class Bmsad(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BMSAD
