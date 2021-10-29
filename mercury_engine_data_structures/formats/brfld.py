from typing import Dict, Union, Type

from construct import (
    Struct, Construct, Const, GreedyBytes, Int32ul, PrefixedArray, Hex,
    Float32l, Flag, Int32sl,
)

from mercury_engine_data_structures.common_types import StrId, Float, CVector2D, CVector3D, make_dict, make_vector
from mercury_engine_data_structures.construct_extensions.misc import ErrorWithMessage
from mercury_engine_data_structures.formats import BaseResource
from mercury_engine_data_structures.game_check import Game
from mercury_engine_data_structures.hashed_names import PropertyEnum
from mercury_engine_data_structures.object import Object
from mercury_engine_data_structures.pointer_set import PointerSet

# Other Types
CLogicCamera = Object({
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
TriggerLogicActions.add_option("CCameraToRailLogicAction", Object({
    "bCameraToRail": Flag,
}))
TriggerLogicActions.add_option("CLuaCallsLogicAction", Object({
    "sCallbackEntityName": StrId,  # CRntString, but still a string
    "sCallback": StrId,
    "bCallbackEntity": Flag,
    "bCallbackPersistent": Flag,
}))
TriggerLogicActions.add_option("CSetActorEnabledLogicAction", Object({
    "wpActor": StrId,
    "bEnabled": Flag,
}))

# Shapes
Shapes = PointerSet("game::logic::collision::CShape")
Shapes.add_option("game::logic::collision::CPolygonCollectionShape", Object({
    # CShape
    "vPos": CVector3D,
    "bIsSolid": Flag,

    # CPolygonCollectionShape
    "oPolyCollection": PrefixedArray(Int32ul, Struct(
        # "base::global::CRntVector<base::spatial::CPolygon2D>"
        vPolys_type=PropertyEnum,
        vPolys=PrefixedArray(Int32ul, Object({
            "bClosed": Flag,
            # "base::global::CRntVector<base::spatial::SSegmentData>"
            "oSegmentData": PrefixedArray(Int32ul, Object({
                "vPos": CVector3D,
            })),
            "bOutwardsNormal": Flag,
        })),
    )),
}))
Shapes.add_option("game::logic::collision::COBoxShape2D", Object({
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

ActorComponents.add_option("CLogicCameraComponent", Object({
    "rLogicCamera": PointerSet.construct_pointer_for("CLogicCamera", CLogicCamera),
}))

ActorComponents.add_option("CAudioComponent", Object({
    "bWantsEnabled": Flag,
    "bUseDefaultValues": Flag,
}))

ActorComponents.add_option("CStartPointComponent", Object({
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

ActorComponents.add_option("CScriptComponent", Object({
    "bWantsEnabled": Flag,
    "bUseDefaultValues": Flag,
}))

ActorComponents.add_option("CWeightActivableMovablePlatformComponent", Object({
    "bWantsEnabled": Flag,
    "bUseDefaultValues": Flag,
    "sOnActivatedLuaCallback": StrId,
}))

ActorComponents.add_option("CRumbleComponent", Object({
    "bWantsEnabled": Flag,
    "bUseDefaultValues": Flag,
}))

ActorComponents.add_option("CFXComponent", Object({
    **CComponentFields,
    "fSelectedHighRadius": Float,
    "fSelectedLowRadius": Float,
}))

ActorComponents.add_option("CCollisionComponent", Object({
    **CComponentFields,
}))

ActorComponents.add_option("CAnimationNavMeshItemComponent", Object({
    **CComponentFields,
    "tForbiddenEdgesSpawnPoints": make_dict(Struct(
        x=ErrorWithMessage("Not implemented"),
    )),
}))

ActorComponents.add_option("CAnimationComponent", Object({
    **CComponentFields,
}))

ActorComponents.add_option("CModelUpdaterComponent", Object({
    **CComponentFields,
    "sDefaultModelPath": StrId,
}))

ActorComponents.add_option("CColliderTriggerComponent", Object({
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
        "item" / Object({
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

ActorComponents.add_option("CLogicShapeComponent", Object({
    "pLogicShape": Shapes.create_construct(),
    "bWantsToGenerateNavMeshEdges": Flag,
}))

ActorComponents.add_option("CCameraRailComponent", Object({
    # base::global::CRntVector<SCameraSubRail>
    "oCameraRail": Object({
        # SCameraRail
        "tSubRails": make_vector(Object({
            # SCameraSubRail
            "tNodes": make_vector(Object({
                "vPos": CVector3D,
                "wpLogicCamera": StrId,
            })),
        })),
        "fMaxRailSpeed": Float,
        "fMinRailSpeed": Float,
        "fMaxRailDistance": Float,
    }),
}))

ActorComponents.add_option("CDoorLifeComponent", Object({
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
Actors.add_option("CActor", Object({
    **CActorFields
}))
Actors.add_option("CEntity", Object({
    **CActorFields
}))

# Root stuff

CActorSublayer = Object({
    "sName": StrId,
    "dctActors": make_dict(Actors.create_construct()),
})

CScenario = Object({
    "sLevelID": StrId,
    "sScenarioID": StrId,
    "vLayerFiles": PrefixedArray(Int32ul, StrId),
    "rEntitiesLayer": Int32ul,
    "dctSublayers": make_dict(CActorSublayer),
}, debug=True)

BRFLD = Struct(
    magic=Const('CScenario', PropertyEnum),
    intro_a=Hex(Int32ul),
    intro_b=Hex(Int32ul),
    intro_c=Hex(Int32ul),

    # gameeditor::CGameModelRoot
    root=Object({
        "pScenario": PointerSet.construct_pointer_for("CScenario", CScenario),
    }),
    raw=GreedyBytes,
)


class Brfld(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BRFLD
