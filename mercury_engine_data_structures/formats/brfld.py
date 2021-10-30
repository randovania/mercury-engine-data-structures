from typing import Dict, Union, Type

from construct import (
    Struct, Construct, Const, GreedyBytes, Int32ul, Hex,
    Flag, Int32sl, Prefixed, )

from mercury_engine_data_structures.common_types import (
    StrId, Float, CVector2D, CVector3D, make_dict, make_vector,
    make_enum, UInt, CVector4D,
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
CFilePathStrId = StrId

TypedValues = PointerSet("base::reflection::CTypedValue")
TypedValues.add_option("base::global::CRntFile", Prefixed(Int32ul, GreedyBytes))

CGameLink_CEntity = StrId
CGameLink_CActor = StrId

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

# CXParasiteBehavior
CXParasiteBehavior = PointerSet("CXParasiteBehavior")

# CActorComponents
CComponentFields: Dict[str, Union[Construct, Type[Construct]]] = {
    "bWantsEnabled": Flag,
    "bUseDefaultValues": Flag,
}
ActorComponents = PointerSet("CActorComponent")

ActorComponents.add_option("CLogicCameraComponent", Object({
    "rLogicCamera": PointerSet.construct_pointer_for("CLogicCamera", CLogicCamera),
}))

ActorComponents.add_option("CLandmarkComponent", Object({
    "sLandmarkID": StrId,
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
    "vOriginalPos": CVector3D,
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

EXCellSpawnPositionMode = make_enum(["FarthestToSpawnPoint", "ClosestToSpawnPoint"])
EDynamicSpawnPositionMode = make_enum(["ClosestToPlayer", "FarthestToPlayer", "Random"])

ActorComponents.add_option("CSpawnPointComponent", Object({
    **CComponentFields,
    "sOnBeforeGenerate": StrId,
    "sOnEntityGenerated": StrId,
    "sStartAnimation": StrId,
    "bSpawnOnFloor": Flag,
    "bEntityCheckFloor": Flag,
    "bCheckCollisions": Flag,
    "fTimeToActivate": Float,
    "iMaxNumToGenerate": UInt,
    "bAllowSpawnInFrustum": Flag,
    "bStartEnabled": Flag,
    "bAutomanaged": Flag,
    "wpSceneShapeId": StrId,
    "wpCollisionSceneShapeId": StrId,
    "wpNavigableShape": StrId,
    "wpAreaOfInterest": StrId,
    "wpAreaOfInterestEnd": StrId,
    "fTimeOnAOIEndToUseAsMainAOI": Float,
    "fSpawnFromXCellProbability": Float,
    "fSpawnFromXCellProbabilityAfterFirst": Float,
    "eXCellSpawnPositionMode": EXCellSpawnPositionMode,
    "bUseDynamicSpawnPosition": Flag,
    "eDynamicSpawnPositionMode": EDynamicSpawnPositionMode,
    "tDynamicSpawnPositions": Int32ul,
    "tXCellTransformTargets": Int32ul,
    "wpXCellActivationAreaShape": StrId,
    "sCharClass": StrId,
    "voActorBlueprint": make_vector(Object({
        "InnerValue": TypedValues.create_construct(),
    })),
}))

ActorComponents.add_option("CXParasiteDropComponent", Object({
    **CComponentFields,
    "vectBehaviors": make_vector(CXParasiteBehavior.create_construct())
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

EBreakableTileType = make_enum([
    "UNDEFINED", "POWERBEAM", "BOMB", "MISSILE",
    "SUPERMISSILE", "POWERBOMB", "SCREWATTACK",
    "WEIGHT", "BABYHATCHLING", "SPEEDBOOST",
])
EColMat = make_enum([
    "DEFAULT", "SCENARIO_GENERIC", "FLESH_GENERIC", "DAMAGE_BLOCKED",
    "METAL", "ENERGY", "DIRT", "ROCK", "ICE", "UNDER_WATER",
    "UNDER_WATER_SP", "MID_WATER", "MID_WATER_SP", "PUDDLE",
    "OIL", "END_WORLD",
])

ActorComponents.add_option("CMaterialFXComponent", Object(CComponentFields))
ActorComponents.add_option("CModelInstanceComponent", Object({
    **CComponentFields,
    "sModelPath": StrId,
    "vScale": CVector3D,
}))
ActorComponents.add_option("CBreakableTileGroupComponent", Object({
    **CComponentFields,
    "uGroupId": UInt,
    "aGridTiles": make_vector(Object({
        # CBreakableTileGroupComponent::STileInfo
        "eTileType": EBreakableTileType,
        "vGridCoords": CVector2D,
        "sHiddenSG": StrId,
        "bIsHidingSecret": Flag,
        "aVignettes": make_vector(CGameLink_CActor),
    })),
    "bFakeHusks": Flag,
    "eCollisionMaterial": EColMat,
}))

#

ActorComponents.add_option("CSonarTargetComponent", Object(CComponentFields))
ActorComponents.add_option("CBreakableTileGroupSonarTargetComponent", Object(CComponentFields))

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

ActorComponents.add_option("CVideoManagerComponent", Object({
    **CComponentFields,
    "sVideo_1_Path": StrId,
    "sVideo_2_Path": StrId,
    "sVideoAux_1_Path": CFilePathStrId,
    "sVideoAux_2_Path": CFilePathStrId,
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
    "aVignettes": make_vector(CGameLink_CActor),
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
    "aVignettes": make_vector(CGameLink_CActor),
}))

CFilePathStrIdPtr = PointerSet.construct_pointer_for("base::global::CFilePathStrId", CFilePathStrId)

ActorComponents.add_option("CPositionalSoundComponent", Object({
    **CComponentFields,
    "fMinAtt": Float,
    "fMaxAtt": Float,
    "fVol": Float,
    "fPitch": Float,
    "fLaunchEvery": Float,
    "fHorizontalMult": Float,
    "fVerticalMult": Float,
    "bLoop": Flag,
    "fFadeInTime": Float,
    "fFadeOutTime": Float,
    "sSound1": CFilePathStrIdPtr,
    "sSound2": CFilePathStrIdPtr,
    "sSound3": CFilePathStrIdPtr,
    "sSound4": CFilePathStrIdPtr,
}))

ActorComponents.add_option("CCubeMapComponent", Object({
    **CComponentFields,
    "vCubePos": CVector3D,
    "fAttMin": Float,
    "fAttMax": Float,
    "vBoxBounds": CVector3D,
    "fIntensity": Float,
    "bEnableCulling": Flag,
    "sTexturePathSpecular": CFilePathStrId,
    "sTexturePathDiffuse": CFilePathStrId,
}))

# CBaseLightComponent

ELightPreset = make_enum([
    "E_LIGHT_PRESET_NONE", "E_LIGHT_PRESET_PULSE", "E_LIGHT_PRESET_BLINK", "E_LIGHT_PRESET_LIGHTNING",
    "ELIGHT_PRESET_COUNT", "ELIGHT_PRESET_INVALID",
])

ActorComponents.add_option("CBaseLightComponent", Object(CBaseLightComponentFields := {
    **CComponentFields,
    "vLightPos": CVector3D,
    "fIntensity": Float,
    "fVIntensity": Float,
    "fFIntensity": Float,
    "vAmbient": CVector4D,
    "vDiffuse": CVector4D,
    "vSpecular0": CVector4D,
    "vSpecular1": CVector4D,
    "bVertexLight": Flag,
    "eLightPreset": ELightPreset,
    "vLightPresetParams": CVector4D,
    "bSubstractive": Flag,
    "bUseFaceCull": Flag,
    "bUseSpecular": Flag,
}))

ActorComponents.add_option("CSpotLightComponent", Object({
    **CBaseLightComponentFields,
    "fAttMin": Float,
    "fAttMax": Float,
    "fAttIn": Float,
    "fAttOut": Float,
    "fAttConstantFactor": Float,
    "fAttQuadraticFactor": Float,
    "vDir": CVector3D,
    "fAnimFrame": Float,
    "bCastShadows": Flag,
    "vShadowNearFar": CVector2D,
    "fShadowBias": Float,
    "bStaticShadows": Flag,
    "fShadowScl": Float,
    "bHasProjectorTexture": Flag,
    "sTexturePath": CFilePathStrId,
    "vProjectorUVScroll": CVector4D,
}))

ActorComponents.add_option("COmniLightComponent", Object({
    **CBaseLightComponentFields,

    "fAttMin": Float,
    "fAttMax": Float,
    "fAttConstantFactor": Float,
    "fAttQuadraticFactor": Float,
    "bCastShadows": Flag,
    "bStaticShadows": Flag,
    "fShadowScl": Float,
}))

# CNavMeshItemComponent
ActorComponents.add_option("CNavMeshItemComponent", Object(CNavMeshItemComponentFields := {
    **CComponentFields,
    "tForbiddenEdgesSpawnPoints": make_vector(make_vector(ErrorWithMessage("Not Implemented"))),
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
    "vDoorsToChange": make_vector(CGameLink_CEntity),
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

# BaseTrigger

CActivatableComponentFields = {**CComponentFields}
CBaseTriggerComponentFields = {
    **CComponentFields,
    "bCheckAllEntities": Flag,
}

# SoundTrigger

EReverbIntensity = make_enum([
    "NONE", "SMALL_ROOM", "MEDIUM_ROOM", "BIG_ROOM", "CATHEDRAL",
])
ELowPassFilter = make_enum([
    "LPF_DISABLED", "LPF_80HZ", "LPF_100HZ", "LPF_128HZ", "LPF_160HZ", "LPF_200HZ", "LPF_256HZ",
    "LPF_320HZ", "LPF_400HZ", "LPF_500HZ", "LPF_640HZ", "LPF_800HZ", "LPF_1000HZ", "LPF_1280HZ",
    "LPF_1600HZ", "LPF_2000HZ", "LPF_2560HZ", "LPF_3200HZ", "LPF_4000HZ", "LPF_5120HZ", "LPF_6400HZ",
    "LPF_8000HZ", "LPF_10240HZ", "LPF_12800HZ", "LPF_16000HZ",
])
ESndType = make_enum([
    "SFX", "MUSIC", "SPEECH", "GRUNT", "GUI", "ENVIRONMENT_STREAMS", "SFX_EMMY", "CUTSCENE",
])
EPositionalType = make_enum([
    "POS_2D", "POS_3D",
])

CSoundTriggerFields = {
    **CBaseTriggerComponentFields,
    "eReverb": EReverbIntensity,
    "iLowPassFilter": ELowPassFilter,
}

ActorComponents.add_option("CAreaSoundComponent", Object({
    **CSoundTriggerFields,
    "sOnEnterSound": CFilePathStrId,
    "eOnEnterSoundType": ESndType,
    "fEnterVol": Float,
    "fEnterPitch": Float,
    "fEnterFadeInTime": Float,
    "fEnterFadeOutTime": Float,
    "eOnEnterPositional": EPositionalType,
    "sLoopSound": CFilePathStrId,
    "eLoopSoundType": ESndType,
    "fLoopVol": Float,
    "fLoopPitch": Float,
    "fLoopPan": Float,
    "fLoopFadeInTime": Float,
    "fLoopFadeOutTime": Float,
    "sOnExitSound": CFilePathStrId,
    "eOnExitSoundType": ESndType,
    "fExitVol": Float,
    "fExitPitch": Float,
    "fExitFadeInTime": Float,
    "fExitFadeOutTime": Float,
    "eOnExitPositional": EPositionalType,
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

CActorLayer = Object({
    "dctSublayers": make_dict(CActorSublayer),
    # "CRntDictionary<CStrId, CRntVector<CGameLink<CActor>>>"
    "dctActorGroups": make_dict(make_vector(CGameLink_CActor)),
})

CScenario = Object({
    "awpScenarioColliders": StrId,
    "sLevelID": StrId,
    "sScenarioID": StrId,
    "rEntitiesLayer": CActorLayer,
    "rSoundsLayer": CActorLayer,
    "rLightsLayer": CActorLayer,
    "vLayerFiles": make_vector(StrId),
})

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
