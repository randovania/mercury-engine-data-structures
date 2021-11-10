import construct
from construct import (
    Struct, Construct, Const, Int32ul, Hex, CString, Switch, Int16ul,
    PrefixedArray, Byte, Array, Float32l, Flag, Probe, Tell, )

from mercury_engine_data_structures import common_types
from mercury_engine_data_structures.common_types import make_dict, StrId, Float
from mercury_engine_data_structures.construct_extensions.misc import ErrorWithMessage, ForceQuit
from mercury_engine_data_structures.formats import BaseResource
from mercury_engine_data_structures.formats.dread_types import CCharClassCollisionComponent, \
    CCharClassPickableComponent, CCharClassAnimationComponent, CCharClassBasicLifeComponent
from mercury_engine_data_structures.formats.property_enum import PropertyEnum
from mercury_engine_data_structures.game_check import Game

Char = construct.PaddedString(1, 'ascii')

FunctionArgument = Struct(
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
Functions = make_dict(Struct(
    unk=Int16ul,
    params=common_types.DictAdapter(common_types.make_vector(
        construct.Sequence(PropertyEnum, FunctionArgument)
    )),
))

CPickableItemComponent = Struct(
    unk_1=Array(3, Hex(Int32ul)),

    empty_string=PropertyEnum,
    root=PropertyEnum,
    fields=CCharClassPickableComponent,

    unk_2=Int32ul,
    functions=Functions,
)

CScriptComponent = Struct(
    unk_1=Array(3, Hex(Int32ul)),

    unk_2=Int32ul,
    functions=Functions,
)

CModelUpdaterComponent = Struct(
    unk_1=Array(3, Hex(Int32ul)),

    unk_2=Int32ul,
    functions=Functions,
)

CAnimationComponent = Struct(
    unk_1=Array(3, Hex(Int32ul)),

    empty_string=PropertyEnum,
    root=PropertyEnum,
    fields=CCharClassAnimationComponent,

    unk_2=Int32ul,
    functions=Functions,
)

CAudioComponent = Struct(
    unk_1=Array(3, Hex(Int32ul)),
    # unk_2=Int32ul,
    # unk_3=Int32ul,

    count=common_types.make_vector(StrId),
    unk_4=Int32ul,
)

# CAudioComponent = Struct(
#     unk_1=Array(3, Hex(Int32ul)),
#     unk_2=Int32ul,
#     unk_3=Int32ul,
#
#     count=Int32ul,
#     bmsas=StrId,
#     unk_4=Int32ul,
# )

CCollisionComponent = Struct(
    unk_1=Array(3, Hex(Int32ul)),

    empty_string=PropertyEnum,
    root=PropertyEnum,
    fields=CCharClassCollisionComponent,

    unk_2=Int32ul,
    unk_3=Int32ul,
    s=StrId,
    k=Int16ul,
)
CPowerUpLifeComponent = Struct(
    unk_1=Array(3, Hex(Int32ul)),

    empty_string=PropertyEnum,
    root=PropertyEnum,
    fields=CCharClassBasicLifeComponent,

    unk_2=Int32ul,
    functions=Functions,
)
CTimelineComponent = Struct(
    unk_1=Array(3, Hex(Int32ul)),
    unk_2=Int32ul,
    functions=Functions,
)
CMaterialFXComponent = Struct(
    unk_1=Array(3, Hex(Int32ul)),
    unk_2=Int32ul,
    functions=Functions,
)
CFXComponent = Struct(
    unk_1=Array(3, Hex(Int32ul)),
    unk_2=Int32ul,
    unk_3=Int32ul,

    unk_4=PrefixedArray(
        Int32ul,
        Struct(
            s1=StrId,
            a1=Int32ul,
            a2=Int32ul,
            a3=Flag,
        )
    ),
    bmsas=PrefixedArray(Int32ul, StrId),
    other=PrefixedArray(Int32ul, StrId),
    unk_5=Flag,
)

component_types = {
    "CPickableItemComponent": CPickableItemComponent,
    "CScriptComponent": CScriptComponent,
    "CModelUpdaterComponent": CModelUpdaterComponent,
    "CAnimationComponent": CAnimationComponent,
    "CAudioComponent": CAudioComponent,
    "CCollisionComponent": CCollisionComponent,
    "CPowerUpLifeComponent": CPowerUpLifeComponent,
    "CTimelineComponent": CTimelineComponent,
    "CMaterialFXComponent": CMaterialFXComponent,
    "CFXComponent": CFXComponent,
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
    ),
    rest=construct.GreedyBytes,
    # _end=construct.Terminated,
)


# BMSAD = game_model_root.create('CActorDef', 0x02000031)


class Bmsad(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BMSAD
