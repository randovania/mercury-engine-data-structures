from typing import Dict, Union, Type

from construct import (
    Struct, Construct, Const, GreedyBytes, Int32ul, Hex,
    Flag, Int32sl, )

from mercury_engine_data_structures.common_types import (
    StrId, Float, CVector2D, CVector3D, make_dict, make_vector,
    make_enum, UInt,
)
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

# TODO: figure what's the other part. Maybe Pointer to CEntity?
CGameLink_CEntity = make_vector(ErrorWithMessage("Not Implemented"))

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
TriggerLogicActions.add_option("CSaveGameToSnapshotLogicAction", Object({
    "sSnapshotId": StrId,
}))
TriggerLogicActions.add_option("CMarkMinimapLogicAction", Object({
    "wpVisibleLogicShape": StrId,
    "wpVisitedLogicShape": StrId,
}))

# Shapes
Shapes = PointerSet("game::logic::collision::CShape")
Shapes.add_option("game::logic::collision::CPolygonCollectionShape", Object({
    # CShape
    "vPos": CVector3D,
    "bIsSolid": Flag,

    # CPolygonCollectionShape
    # base::spatial::CPolygonCollection2D
    "oPolyCollection": make_vector(Struct(
        # "base::global::CRntVector<base::spatial::CPolygon2D>"
        vPolys_type=PropertyEnum,
        vPolys=make_vector(Object({
            "bClosed": Flag,
            # "base::global::CRntVector<base::spatial::SSegmentData>"
            "oSegmentData": make_vector(Object({
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
    "fDegrees": Float,
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
    **CComponentFields,
}))

ActorComponents.add_option("CStartPointComponent", Object({
    **CComponentFields,

    "sOnTeleport": StrId,
    "sOnTeleportLogicCamera": StrId,
    "bOnTeleportLogicCameraRaw": Flag,

    "bProjectOnFloor": Flag,
    "bMorphballMode": Flag,
    "bSaveGameToCheckpoint": Flag,
    "bIsBossStartPoint": Flag,
}))

ActorComponents.add_option("CScriptComponent", Object({
    **CComponentFields,
}))

ActorComponents.add_option("CRumbleComponent", Object({
    **CComponentFields,
}))

ActorComponents.add_option("CCutsceneComponent", Object({
    "sCutsceneName": StrId,
    "bDisableScenarioEntitiesOnPlay": Flag,
    # "vOriginalPos": CVector3D,
    "vctCutscenesOffsets": make_vector(CVector3D),
    "vctExtraInvolvedSubareas": make_vector(StrId),
    "vctExtraInvolvedActors": make_vector(Object({
        # CCutsceneComponent::SActorInfo
        "sId": StrId,
        "lnkActor": StrId,
        "bStartingVisibleState": Flag,
        "bReceiveLogicUpdate": Flag,
        "vctVisibilityPerTake": make_vector(Flag),
    })),
    "vctOnBeforeCutsceneStartsLA": make_vector(TriggerLogicActions.create_construct()),
    "vctOnAfterCutsceneEndsLA": make_vector(TriggerLogicActions.create_construct()),
    "bHasSamusAsExtraActor": Flag,
}))

# CSpawnGroupComponent

ActorComponents.add_option("CSpawnGroupComponent", Object(CSpawnGroupComponentFields := {
    **CComponentFields,
    "bIsGenerator": Flag,
    "bIsInfinite": Flag,
    "iMaxToGenerate": UInt,
    "iMaxSimultaneous": UInt,
    "fGenerateEvery": Float,
    "sOnBeforeGenerateEntity": StrId,
    "sOnEntityGenerated": StrId,
    "sOnEnable": StrId,
    "sOnDisable": StrId,
    "sOnMaxSimultaneous": StrId,
    "sOnMaxGenerated": StrId,
    "sOnEntityDead": StrId,
    "sOnEntityDamaged": StrId,
    "sOnAllEntitiesDead": StrId,
    "bAutomanaged": Flag,
    "bDisableOnAllDead": Flag,
    "bAutoenabled": Flag,
    "bSpawnPointsNotInFrustrum": Flag,
    "bGenerateEntitiesByOrder": Flag,
    "sLogicCollisionShapeID": StrId,
    "wpAreaOfInterest": StrId,
    "wpAreaOfInterestEnd": StrId,
    "fDropAmmoProb": Float,
    "iInitToGenerate": UInt,
    "sArenaId": StrId,
    "bCheckActiveDrops": Flag,
    # "iNumDeaths": UInt,
    "vectSpawnPoints": make_vector(StrId),
}))
ActorComponents.add_option("CBossSpawnGroupComponent", Object({
    **CSpawnGroupComponentFields,
    "sBossBattleLabel": StrId,
}))

# CSceneComponent

ActorComponents.add_option("CMaterialFXComponent", Object(CComponentFields))
ActorComponents.add_option("CModelInstanceComponent", Object({
    **CComponentFields,
    "sModelPath": StrId,
    "vScale": CVector3D,
}))

#

ActorComponents.add_option("CDropComponent", Object(CComponentFields))

ActorComponents.add_option("CFXComponent", Object({
    **CComponentFields,
    "fSelectedHighRadius": Float,
    "fSelectedLowRadius": Float,
}))

ActorComponents.add_option("CCollisionComponent", Object({
    **CComponentFields,
}))

ActorComponents.add_option("CAnimationComponent", Object({
    **CComponentFields,
}))

ActorComponents.add_option("CModelUpdaterComponent", Object({
    **CComponentFields,
    "sDefaultModelPath": StrId,
}))

EEvent = make_enum(["OnEnter", "OnExit", "OnAllExit", "OnStay", "OnEnable", "OnDisable", "TE_COUNT"])
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
            "eEvent": EEvent,
            "vLogicActions": make_vector(TriggerLogicActions.create_construct()),
        }),
    )),

    # CColliderTriggerComponent
    "lnkShape": StrId,  # TODO: confirm
}))

ActorComponents.add_option("CLogicShapeComponent", Object(CLogicShapeComponentFields := {
    "pLogicShape": Shapes.create_construct(),
    "bWantsToGenerateNavMeshEdges": Flag,
}))

ActorComponents.add_option("CBreakableVignetteComponent", Object({
    **CLogicShapeComponentFields,
    "sVignetteSG": StrId,
    "bUnhideWhenPlayerInside": Flag,
    "bPreventVisibilityOnly": Flag,
    "bForceNotVisible": Flag,
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

# Life Component

ActorComponents.add_option("CLifeComponent", Object(CLifeComponentFields := {
    **CComponentFields,
    "bWantsCameraFXPreset": Flag,
    "fMaxLife": Float,
    "fCurrentLife": Float,
    "bCurrentLifeLocked": Flag,
}))

ActorComponents.add_option("CItemLifeComponent", Object(CLifeComponentFields))

ActorComponents.add_option("CDoorLifeComponent", Object({
    **CLifeComponentFields,
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
    "iAreaLeft": UInt,
    "iAreaRight": UInt,
    "aVignettes": UInt,
}))

ActorComponents.add_option("CPowerBombBlockLifeComponent", Object(CLifeComponentFields))

ActorComponents.add_option("CElectricReactionComponent", Object({
    **CComponentFields,
}))

ActorComponents.add_option("CTimelineComponent", Object({
    **CComponentFields,
}))

ActorComponents.add_option("CThermalReactionComponent", Object({
    **CComponentFields,
}))

ActorComponents.add_option("CLightingComponent", Object({
    **CComponentFields,
}))

ELinkMode = make_enum({"None": 0, "RootToDC_Grab": 1, "FeetToRoot": 2})

ActorComponents.add_option("CGrabComponent", Object({
    **CComponentFields,
    "bIsInGrab": Flag,
    "eLinkModeAsGrabber": ELinkMode,
}))

ActorComponents.add_option("CBreakableScenarioComponent", Object({
    **CComponentFields,
    "aVignettes": UInt,
}))

# CNavMeshItemComponent
ActorComponents.add_option("CNavMeshItemComponent", Object(CNavMeshItemComponentFields := {
    **CComponentFields,
    "tForbiddenEdgesSpawnPoints": CGameLink_CEntity,
}))

ActorComponents.add_option("CAnimationNavMeshItemComponent", Object({
    **CNavMeshItemComponentFields,
}))

# CUsableComponent
ActorComponents.add_option("CUsableComponent", Object(CUsableComponentFields := {
    **CComponentFields,
    "bFadeInActived": Flag,
}))

ActorComponents.add_option("CSaveStationUsableComponent", Object(CUsableComponentFields))
ActorComponents.add_option("CTotalRechargeComponent", Object({
    **CUsableComponentFields,
    "sRechargeFX": StrId,
    "sEyeRFX": StrId,
    "sEyeLFX": StrId,
}))
ActorComponents.add_option("CElevatorCommanderUsableComponent", Object({
    **CUsableComponentFields,
    "sTargetSpawnPoint": StrId,
}))

ActorComponents.add_option("CAccessPointComponent", Object(CAccessPointComponentFields := {
    **CUsableComponentFields,
    "vDoorsToChange": CGameLink_CEntity,
    "sInteractionLiteralID": StrId,

    # CRntDictionary<CStrId,CRntVector<CStrId>>
    "tCaptionList": make_dict(make_vector(StrId)),
    "wpThermalDevice": StrId,
}))

ActorComponents.add_option("CAccessPointCommanderComponent", Object({
    **CAccessPointComponentFields,
    "wpAfterFirstDialogueScenePlayer": StrId,
}))

# Elevator Stuff

EElevatorDirection = make_enum(["UP", "DOWN"])
ELoadingScreen = make_enum([
    "E_LOADINGSCREEN_GUI_2D", "E_LOADINGSCREEN_VIDEO", "E_LOADINGSCREEN_ELEVATOR_UP", "E_LOADINGSCREEN_ELEVATOR_DOWN",
    "E_LOADINGSCREEN_MAIN_ELEVATOR_UP", "E_LOADINGSCREEN_MAIN_ELEVATOR_DOWN", "E_LOADINGSCREEN_TELEPORTER",
    "E_LOADINGSCREEN_TRAIN_LEFT", "E_LOADINGSCREEN_TRAIN_LEFT_AQUA", "E_LOADINGSCREEN_TRAIN_RIGHT",
    "E_LOADINGSCREEN_TRAIN_RIGHT_AQUA",
])

ActorComponents.add_option("CElevatorUsableComponent", Object(CElevatorUsableComponentFields := {
    **CUsableComponentFields,
    "eDirection": EElevatorDirection,
    "eLoadingScreen": ELoadingScreen,
    "sLevelName": StrId,
    "sScenarioName": StrId,
    "sTargetSpawnPoint": StrId,
    "sMapConnectionId": StrId,
    "fMinTimeLoad": Float,
}))
ActorComponents.add_option("CCapsuleUsableComponent", Object({
    **CElevatorUsableComponentFields,
    # CCapsuleUsableComponent
    "wpCapsule": StrId,
    "wpSkybase": StrId,
}))

# CMovementComponent

ActorComponents.add_option("CWeightActivableMovablePlatformComponent", Object({
    **CComponentFields,
    "sOnActivatedLuaCallback": StrId,
}))

# CSmartObjectComponent

ActorComponents.add_option("CWeightActivatedPlatformSmartObjectComponent", Object({
    **CComponentFields,
    # CSmartObjectComponent
    "sOnUseStart": StrId,
    "sOnUseFailure": StrId,
    "sOnUseSuccess": StrId,
    "sUsableEntity": StrId,
    "sDefaultUseAction": StrId,
    "sDefaultAbortAction": StrId,
    "bStartEnabled": Flag,
    "fInterpolationTime": Float,

    # Specific
    "sDustFX": StrId,
    "bDisableWhenEmmyNearby": Flag,
    "bDisableWhenUsed": Flag,
}))

# Actors

Actors = PointerSet("CActor")
Actors.add_option("CActor", Object(CActorFields := {
    "sName": StrId,
    "oActorDefLink": StrId,
    "vPos": CVector3D,
    "vAng": CVector3D,
    "pComponents": PointerSet.construct_pointer_for(
        "base::global::CRntSmallDictionary<base::global::CStrId, CActorComponent*>",
        make_dict(ActorComponents.create_construct())
    ),
    "bEnabled": Flag,
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
    "vLayerFiles": make_vector(StrId),
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
