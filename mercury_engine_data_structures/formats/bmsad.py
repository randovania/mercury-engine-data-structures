import construct
from construct import (
    Struct, Construct, Const, Int32ul, Hex, CString, Switch, Int16ul,
    PrefixedArray, Byte, Array, Float32l, Probe, Int64ul, Flag,
)

from mercury_engine_data_structures.common_types import CVector3D
from mercury_engine_data_structures.construct_extensions.misc import ErrorWithMessage
from mercury_engine_data_structures.formats import BaseResource, game_model_root
from mercury_engine_data_structures.game_check import Game

CPickableItemComponent = Struct(
    unknown=Int32ul,
)

CCollisionComponent = Struct(
    k=Hex(Int64ul),
)

CActorComponentDef = {
    "parent": "base::core::CBaseObject",
    "fields": {
        "bStartEnabled": "bool",
        "bDisabledInEditor": "bool",
        "bPrePhysicsUpdateInEditor": "bool",
        "bPostPhysicsUpdateInEditor": "bool"
    }
}

CCharClassCollisionComponent = {
    "parent": "CCharClassComponent",
    "fields": {
        "v3SpawnPointCollisionSizeInc": "base::math::CVector3D",
        "eDefaultCollisionMaterial": "game::logic::collision::EColMat",
        "bShouldIgnoreSlopeSupport": "bool",
        "bForceSlopeDirectionOnFloorHit": "bool",
        "mExplicitCollisionMaterials": "base::global::CRntSmallDictionary<base::global::CStrId, game::logic::collision::EColMat>"
    },
}


component_types = {
    "CPickableItemComponent": CPickableItemComponent,
    "CCollisionComponent": Struct(
        "bStartEnabled" / Flag,
        "bDisabledInEditor" / Flag,
        "bPrePhysicsUpdateInEditor" / Flag,
        "bPostPhysicsUpdateInEditor" / Flag,
        "v3SpawnPointCollisionSizeInc" / CVector3D,
    ),
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


    some_count=Int32ul,
    key_name=CString("utf-8"),
    component_type=CString("utf-8"),
    component=Switch(
        construct.this.component_type,
        component_types,
        ErrorWithMessage(lambda ctx: f"Unknown component type: {ctx.component_type}"),
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
