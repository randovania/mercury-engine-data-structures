from typing import Dict, Union, Type, Iterable

import construct
from construct import (
    Struct, Construct, Const, Bytes, CString, Array, GreedyBytes, Int32ul, PrefixedArray, Int16ul,
    Switch, Int64ul, Hex, HexDisplayedInteger, Computed, Float32l, Flag, Probe, Int32sl, Pass, )

from mercury_engine_data_structures import resource_names
from mercury_engine_data_structures.construct_extensions.misc import ErrorWithMessage
from mercury_engine_data_structures.formats import BaseResource
from mercury_engine_data_structures.game_check import Game


def force_quit(ctx):
    raise SystemExit(1)


properties = {}

StrId = CString("utf-8")


def add_prop(name: str, value: Construct):
    prop_id = resource_names.all_name_to_property_id()[name]
    if prop_id in properties:
        raise ValueError(f"Attempting to add {name}, but already present.")
    properties[prop_id] = value


PropertyEnum = construct.Enum(Hex(Int64ul), **{
    name: HexDisplayedInteger.new(property_id, "0%sX" % (2 * 8))
    for property_id, name in resource_names.all_property_id_to_name().items()
})

PropertyElement = Struct(
    type=Hex(Int64ul),
    type_name=Computed(lambda ctx: resource_names.all_property_id_to_name().get(ctx.type)),
    element=Switch(
        construct.this.type,
        properties,
        ErrorWithMessage(lambda ctx: f"Property {ctx.type} ({resource_names.all_property_id_to_name().get(ctx.type)}) "
                                     "without assigned type"),
    )
)


def ConfirmType(name: str):
    def check(ctx):
        return ctx[f"{name}_type"] != name

    return construct.If(
        check,
        ErrorWithMessage(
            lambda ctx: f"Expected {name}, got {ctx[f'{name}_type']} ("
                        f"{resource_names.all_property_id_to_name().get(ctx[f'{name}_type'])}) "
                        "without assigned type"
        ),
    )


def create_struct(fields: Dict[str, Union[Construct, Type[Construct]]],
                  extra_before_fields: Iterable[Construct] = (), debug=False):
    r = [
        "field_count" / Int32ul,
    ]
    r.extend(extra_before_fields)
    for name, subcon in fields.items():
        r.extend([
            f"{name}_type" / PropertyEnum,
            f"_{name}_check" / ConfirmType(name),
            name / subcon,
        ])

    if debug:
        r.extend([
            "next_enum" / PropertyEnum,
            "probe" / Probe(lookahead=0x8),
            "check_field_count" / construct.If(
                lambda ctx: ctx.field_count != len(fields),
                ErrorWithMessage(lambda ctx: f"Expected {len(fields)} fields, got {ctx.field_count}"),
            ),
            "quit" / ErrorWithMessage(force_quit),
        ])

    return Struct(*r)


CComponentFields: Dict[str, Union[Construct, Type[Construct]]] = {
    "bWantsEnabled": Flag,
    "bUseDefaultValues": Flag,
}

add_prop("sLevelID", StrId)
add_prop("sScenarioID", StrId)
add_prop("vLayerFiles", PrefixedArray(Int32ul, StrId))
add_prop("rEntitiesLayer", PrefixedArray(Int32ul, PropertyElement))
add_prop("sName", StrId)

component_types = {
    'AUDIO': Struct(
        unk=Array(15, Int16ul),
    ),
    'STARTPOINT': Struct(
        unk=Bytes(0x5d),
    ),
    'SCRIPT': Struct(
        unk=Bytes(0x27),
    ),
    'LOGICCAMERA': Struct(
        unk=Bytes(0x9a),
    ),
}

Component = Struct(
    type=StrId,
    data=Switch(
        construct.this.type,
        component_types,
    )
)


def make_dict(value: Construct, single=True):
    if single:
        return Struct(
            count=Int32ul,
            value=Struct(
                key=StrId,
                value=value,
            )
        )
    return PrefixedArray(
        Int32ul,
        Struct(
            key=StrId,
            value=value,
        )
    )


def make_vector(value: Construct):
    return PrefixedArray(Int32ul, value)


CVector2D = Array(2, Float32l)
CVector3D = Array(3, Float32l)
CVector4D = Array(4, Float32l)

add_prop("dctSublayers", make_dict(Struct(
    # Sublayer
    field_count=Int32ul,
    sName=PropertyElement,
    dctActors=PropertyElement,
)))

add_prop("oActorDefLink", StrId)
add_prop("vPos", CVector3D)
add_prop("vAng", CVector3D)
add_prop("bEnabled", Flag)

add_prop("CLogicCamera", create_struct({
    "sControllerID": StrId,
    "bStatic": Flag,
    "v3Position": CVector3D,
    "v3Dir": CVector3D,
    "fFovX": Float32l,
    "fMinExtraZDist": Float32l,
    "fMaxExtraZDist": Float32l,
    "fDefaultInterp": Float32l,
}))

add_prop("CLogicCameraComponent", Struct(
    count=Int32ul,
    c2=PropertyEnum,
    rLogicCamera=PropertyElement,
))

add_prop("CAudioComponent", create_struct({
    "bWantsEnabled": Flag,
    "bUseDefaultValues": Flag,
}))

add_prop("CStartPointComponent", create_struct({
    "bWantsEnabled": Flag,
    "bUseDefaultValues": Flag,

    "sOnTeleport": StrId,
    "sOnTeleportLogicCamera": StrId,
    "bOnTeleportLogicCameraRaw": Flag,

    "bProjectOnFloor": Flag,
    "bMorphballMode": Flag,
    "bSaveGameToCheckpoint": Flag,
    "bIsBossStartPoint": Flag,
}))

add_prop("CScriptComponent", create_struct({
    "bWantsEnabled": Flag,
    "bUseDefaultValues": Flag,
}))

add_prop("CWeightActivableMovablePlatformComponent", create_struct({
    "bWantsEnabled": Flag,
    "bUseDefaultValues": Flag,
    "sOnActivatedLuaCallback": StrId,
}))

add_prop("CRumbleComponent", create_struct({
    "bWantsEnabled": Flag,
    "bUseDefaultValues": Flag,
}))

add_prop("CFXComponent", create_struct({
    **CComponentFields,
    "fSelectedHighRadius": Float32l,
    "fSelectedLowRadius": Float32l,
}))

add_prop("CCollisionComponent", create_struct({
    **CComponentFields,
}))

add_prop("CAnimationNavMeshItemComponent", create_struct({
    **CComponentFields,
    "tForbiddenEdgesSpawnPoints": make_dict(Struct(
        x=ErrorWithMessage("Not implemented"),
    ), single=False),
}))

add_prop("CAnimationComponent", create_struct({
    **CComponentFields,
}))

add_prop("CModelUpdaterComponent", create_struct({
    **CComponentFields,
    "sDefaultModelPath": StrId,
}))

# CTriggerLogicAction
add_prop("CCameraToRailLogicAction", create_struct({
    "bCameraToRail": Flag,
}))
add_prop("CLuaCallsLogicAction", create_struct({
    "sCallbackEntityName": StrId,  # CRntString, but still a string
    "sCallback": StrId,
    "bCallbackEntity": Flag,
    "bCallbackPersistent": Flag,
}))
add_prop("CSetActorEnabledLogicAction", create_struct({
    "wpActor": StrId,
    "bEnabled": Flag,
}))

add_prop("CColliderTriggerComponent", create_struct({
    **CComponentFields,
    # CTriggerComponent
    "bCallEntityLuaCallback": Flag,
    "iReverb": Int32sl,
    "iLowPassFilter": Int32sl,
    "sOnEnable": StrId,
    "sOnDisable": StrId,
    "bOnEnableAlways": Flag,
    "bOnDisableAlways": Flag,
    "bStartEnabled": Flag,
    "bCheckAllEntities": Flag,
    "bPersistentState": Flag,
    "sSfxType": StrId,
    "lstActivationConditions": make_vector(Struct(
        "type" / PropertyEnum,
        "item" / create_struct({
            "sID": StrId,
            "sCharclasses": StrId,
            "bEnabled": Flag,
            "bAlways": Flag,
            "bDone": Flag,
            "fExecutesEvery": Float32l,
            "fExecutesEveryRandomRange": Float32l,
            "eEvent": make_vector(Struct(
                # TODO empty?
            )),
            "vLogicActions": make_vector(PropertyElement),
        }),
    )),

    # CColliderTriggerComponent
    "lnkShape": StrId,  # TODO: confirm
}))

add_prop("CLogicShapeComponent", create_struct({
    "pLogicShape": PropertyElement,
    "bWantsToGenerateNavMeshEdges": Flag,
}))

# Logic Shapes
add_prop("game::logic::collision::CPolygonCollectionShape", create_struct({
    # CShape
    "vPos": CVector3D,
    "bIsSolid": Flag,

    # CPolygonCollectionShape
    "oPolyCollection": PrefixedArray(Int32ul, Struct(
        # "base::global::CRntVector<base::spatial::CPolygon2D>"
        vPolys_type=PropertyEnum,
        vPolys=PrefixedArray(Int32ul, create_struct({
            "bClosed": Flag,
            # "base::global::CRntVector<base::spatial::SSegmentData>"
            "oSegmentData": PrefixedArray(Int32ul, create_struct({
                "vPos": CVector3D,
            })),
            "bOutwardsNormal": Flag,
        })),
    )),
}))
add_prop("game::logic::collision::COBoxShape2D", create_struct({
    # CShape
    "vPos": CVector3D,
    "bIsSolid": Flag,

    # CPolygonCollectionShape
    "v2Extent": CVector2D,
    "fDegrees": Float32l,
    "bOutwardsNormal": Flag,
}))

add_prop("CCameraRailComponent", create_struct({
    # base::global::CRntVector<SCameraSubRail>
    "oCameraRail": create_struct({
        # SCameraRail
        "tSubRails": make_vector(create_struct({
            # SCameraSubRail
            "tNodes": make_vector(create_struct({
                "vPos": CVector3D,
                "wpLogicCamera": StrId,
            })),
        })),
        "fMaxRailSpeed": Float32l,
        "fMinRailSpeed": Float32l,
        "fMaxRailDistance": Float32l,
    }),
}))

add_prop("CDoorLifeComponent", create_struct({
    "bWantsEnabled": Flag,
    "bUseDefaultValues": Flag,

    # door life
    "fMaxDistanceOpened": Float32l,
    "wpLeftDoorShieldEntity": StrId,
    "wpRightDoorShieldEntity": StrId,
    "fMinTimeOpened": Float32l,
    "bStayOpen": Flag,
    "bStartOpened": Flag,
    "bOnBlackOutOpened": Flag,
    "bDoorIsWet": Flag,
    "bFrozenDuringColdown": Flag,
    "iAreaLeft": Int32ul,
    "iAreaRight": Int32ul,
    "aVignettes": Int32ul,
}))

# add_prop("____debug", create_struct({
#     **CComponentFields,
# }, debug=True))

# bEnabled_ = PropertyEnum,
# bEnabled = Flag,
#
# sOnTeleport_ = PropertyEnum,
#
# x = Probe(),
# z = ErrorWithMessage(force_quit),

add_prop("pComponents", PropertyElement)
add_prop("base::global::CRntSmallDictionary<base::global::CStrId, CActorComponent*>",
         make_dict(PropertyElement, single=False))

add_prop("dctActors", make_dict(Struct(
    # Actor
    field_count=Int32ul,
    f1=Int32ul,
    f2=Int32ul,
    sName=PropertyElement,
    oActorDefLink=PropertyElement,
    vPos=PropertyElement,
    vAng=PropertyElement,
    pComponents=PropertyElement,
    bEnabled=PropertyElement,
), single=False))

BRFLD = Struct(
    intro_a=Const(0x42824DE0BB09EF20, Int64ul),
    intro_b=Hex(Int64ul),
    intro_c=Hex(Int64ul),

    intro_d=PropertyEnum,
    intro_e=PropertyEnum,

    count_for_stuff=Int32ul,

    f1=PropertyElement,
    f2=PropertyElement,
    f3=PropertyElement,

    # Should be PropertyElement!
    f4_type=PropertyEnum,
    f4=Int32ul,

    # dctSublayers
    dctSublayers=PropertyElement,

    raw=GreedyBytes,
)


class Brfld(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BRFLD
