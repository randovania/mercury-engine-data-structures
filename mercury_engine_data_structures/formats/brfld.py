import typing
from typing import Dict, Union, Type, Iterable

import construct
from construct import (
    Struct, Construct, Const, CString, Array, GreedyBytes, Int32ul, PrefixedArray, Switch, Int64ul, Hex,
    HexDisplayedInteger, Computed, Float32l, Flag, Probe, Int32sl,
)

from mercury_engine_data_structures import resource_names
from mercury_engine_data_structures.construct_extensions.misc import ErrorWithMessage
from mercury_engine_data_structures.formats import BaseResource
from mercury_engine_data_structures.game_check import Game


def force_quit(ctx):
    raise SystemExit(1)


PropertyEnum = construct.Enum(Hex(Int64ul), **{
    name: HexDisplayedInteger.new(property_id, "0%sX" % (2 * 8))
    for property_id, name in resource_names.all_property_id_to_name().items()
})


class PointerSet:
    types: Dict[int, Union[Construct, Type[Construct]]]

    def __init__(self, category: str, *, allow_null: bool = False):
        self.category = category
        self.types = {}

    @classmethod
    def construct_pointer_for(cls, name: str, conn: Union[Construct, Type[Construct]]) -> Struct:
        ret = cls(name, allow_null=True)
        ret.add_option(name, conn)
        return ret.create_construct()

    def add_option(self, name: str, value: Union[Construct, Type[Construct]]) -> None:
        prop_id = resource_names.all_name_to_property_id()[name]
        if prop_id in self.types:
            raise ValueError(f"Attempting to add {name} to {self.category}, but already present.")
        self.types[prop_id] = value

    def create_construct(self) -> Struct:
        return Struct(
            type=Hex(Int64ul),
            type_name=Computed(lambda ctx: resource_names.all_property_id_to_name().get(ctx.type)),
            element=Switch(
                construct.this.type,
                self.types,
                ErrorWithMessage(
                    lambda ctx: f"Property {ctx.type} ({resource_names.all_property_id_to_name().get(ctx.type)}) "
                                "without assigned type"),
            )
        )


StrId = CString("utf-8")
Float: construct.FormatField = typing.cast(construct.FormatField, Float32l)
CVector2D = Array(2, Float)
CVector3D = Array(3, Float)
CVector4D = Array(4, Float)


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


def make_dict(value: Construct):
    return PrefixedArray(
        Int32ul,
        Struct(
            key=StrId,
            value=value,
        )
    )


def make_vector(value: Construct):
    return PrefixedArray(Int32ul, value)


# Other Types
CLogicCamera = create_struct({
    "sControllerID": StrId,
    "bStatic": Flag,
    "v3Position": CVector3D,
    "v3Dir": CVector3D,
    "fFovX": Float,
    "fMinExtraZDist": Float,
    "fMaxExtraZDist": Float,
    "fDefaultInterp": Float,
})

# CTriggerLogicAction
TriggerLogicActions = PointerSet("CTriggerLogicAction")
TriggerLogicActions.add_option("CCameraToRailLogicAction", create_struct({
    "bCameraToRail": Flag,
}))
TriggerLogicActions.add_option("CLuaCallsLogicAction", create_struct({
    "sCallbackEntityName": StrId,  # CRntString, but still a string
    "sCallback": StrId,
    "bCallbackEntity": Flag,
    "bCallbackPersistent": Flag,
}))
TriggerLogicActions.add_option("CSetActorEnabledLogicAction", create_struct({
    "wpActor": StrId,
    "bEnabled": Flag,
}))

# Shapes
Shapes = PointerSet("game::logic::collision::CShape")
Shapes.add_option("game::logic::collision::CPolygonCollectionShape", create_struct({
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
Shapes.add_option("game::logic::collision::COBoxShape2D", create_struct({
    # CShape
    "vPos": CVector3D,
    "bIsSolid": Flag,

    # CPolygonCollectionShape
    "v2Extent": CVector2D,
    "fDegrees": Float32l,
    "bOutwardsNormal": Flag,
}))

# CActorComponents
CComponentFields: Dict[str, Union[Construct, Type[Construct]]] = {
    "bWantsEnabled": Flag,
    "bUseDefaultValues": Flag,
}
ActorComponents = PointerSet("CActorComponent")

ActorComponents.add_option("CLogicCameraComponent", create_struct({
    "rLogicCamera": PointerSet.construct_pointer_for("CLogicCamera", CLogicCamera),
}))

ActorComponents.add_option("CAudioComponent", create_struct({
    "bWantsEnabled": Flag,
    "bUseDefaultValues": Flag,
}))

ActorComponents.add_option("CStartPointComponent", create_struct({
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

ActorComponents.add_option("CScriptComponent", create_struct({
    "bWantsEnabled": Flag,
    "bUseDefaultValues": Flag,
}))

ActorComponents.add_option("CWeightActivableMovablePlatformComponent", create_struct({
    "bWantsEnabled": Flag,
    "bUseDefaultValues": Flag,
    "sOnActivatedLuaCallback": StrId,
}))

ActorComponents.add_option("CRumbleComponent", create_struct({
    "bWantsEnabled": Flag,
    "bUseDefaultValues": Flag,
}))

ActorComponents.add_option("CFXComponent", create_struct({
    **CComponentFields,
    "fSelectedHighRadius": Float,
    "fSelectedLowRadius": Float,
}))

ActorComponents.add_option("CCollisionComponent", create_struct({
    **CComponentFields,
}))

ActorComponents.add_option("CAnimationNavMeshItemComponent", create_struct({
    **CComponentFields,
    "tForbiddenEdgesSpawnPoints": make_dict(Struct(
        x=ErrorWithMessage("Not implemented"),
    )),
}))

ActorComponents.add_option("CAnimationComponent", create_struct({
    **CComponentFields,
}))

ActorComponents.add_option("CModelUpdaterComponent", create_struct({
    **CComponentFields,
    "sDefaultModelPath": StrId,
}))

ActorComponents.add_option("CColliderTriggerComponent", create_struct({
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
            "fExecutesEvery": Float,
            "fExecutesEveryRandomRange": Float,
            "eEvent": make_vector(Struct(
                # TODO empty?
            )),
            "vLogicActions": make_vector(TriggerLogicActions.create_construct()),
        }),
    )),

    # CColliderTriggerComponent
    "lnkShape": StrId,  # TODO: confirm
}))

ActorComponents.add_option("CLogicShapeComponent", create_struct({
    "pLogicShape": Shapes.create_construct(),
    "bWantsToGenerateNavMeshEdges": Flag,
}))

ActorComponents.add_option("CCameraRailComponent", create_struct({
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
        "fMaxRailSpeed": Float,
        "fMinRailSpeed": Float,
        "fMaxRailDistance": Float,
    }),
}))

ActorComponents.add_option("CDoorLifeComponent", create_struct({
    "bWantsEnabled": Flag,
    "bUseDefaultValues": Flag,

    # door life
    "fMaxDistanceOpened": Float,
    "wpLeftDoorShieldEntity": StrId,
    "wpRightDoorShieldEntity": StrId,
    "fMinTimeOpened": Float,
    "bStayOpen": Flag,
    "bStartOpened": Flag,
    "bOnBlackOutOpened": Flag,
    "bDoorIsWet": Flag,
    "bFrozenDuringColdown": Flag,
    "iAreaLeft": Int32ul,
    "iAreaRight": Int32ul,
    "aVignettes": Int32ul,
}))

# Actors
CActorFields = {
    "sName": StrId,
    "oActorDefLink": StrId,
    "vPos": CVector3D,
    "vAng": CVector3D,
    "pComponents": PointerSet.construct_pointer_for(
        "base::global::CRntSmallDictionary<base::global::CStrId, CActorComponent*>",
        make_dict(ActorComponents.create_construct())
    ),
    "bEnabled": Flag,
}

Actors = PointerSet("CActor")
Actors.add_option("CActor", create_struct({
    **CActorFields
}))
Actors.add_option("CEntity", create_struct({
    **CActorFields
}))

# Root stuff

CActorSublayer = create_struct({
    # Sublayer
    "sName": StrId,
    "dctActors": make_dict(Actors.create_construct()),
})

CScenario = create_struct({
    "sLevelID": StrId,
    "sScenarioID": StrId,
    "vLayerFiles": PrefixedArray(Int32ul, StrId),
    "rEntitiesLayer": Int32ul,
    "dctSublayers": make_dict(CActorSublayer),
}, debug=True)

BRFLD = Struct(
    intro_a=Const(0x42824DE0BB09EF20, Int64ul),
    intro_b=Hex(Int64ul),
    intro_c=Hex(Int64ul),

    pScenario_t=PropertyEnum,
    pScenario=PointerSet.construct_pointer_for("CScenario", CScenario),

    raw=GreedyBytes,
)


class Brfld(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BRFLD
