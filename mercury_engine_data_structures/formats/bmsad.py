import construct
from construct.core import (
    Array, Byte, Bytes, Const, Construct, ExprAdapter,
    Flag, Float32l, FocusedSeq, GreedyRange, Hex,
    Int16ul, Int32sl, Int32ul, Optional, Peek,
    PrefixedArray, StopIf, Struct, Switch,
)

from mercury_engine_data_structures import common_types
from mercury_engine_data_structures.common_types import Float, StrId, make_dict, make_vector
from mercury_engine_data_structures.construct_extensions.alignment import PrefixedAllowZeroLen
from mercury_engine_data_structures.construct_extensions.misc import ErrorWithMessage
from mercury_engine_data_structures.formats import BaseResource, dread_types
from mercury_engine_data_structures.formats.property_enum import PropertyEnum
from mercury_engine_data_structures.game_check import Game

component_keys = [
    "ABILITY",
    "ACTIVATABLE",
    "ACTIVATABLE_BY_PROJECTILE",
    "AI",
    "AIM",
    "AINAVIGATION",
    "AIMCAMERAVISIBLEONLY",
    "AISMARTOBJECT",
    "ANIMATION",
    "ATTACK",
    "AUDIO",
    "BILLBOARD",
    "BONETOCONSTANT",
    "CAMERA",
    "BREAKABLESCENARIO",
    "BTOBSERVER",
    "CAMERARAIL",
    "CENTRALUNIT",
    "CHAIN_REACTION_ACTION_SWITCHER",
    "CHANGE_STAGE_NAVMESH_ITEM",
    "COLLISION",
    "COOLDOWNFAN",
    "CUTSCENE",
    "DOOREMMYFX",
    "DROP",
    "ELECTRICREACTION",
    "EMMYVALVE",
    "ENHANCEWEAKSPOT",
    "ESCAPE_SEQUENCE_EXPLOSION",
    "EVENTPROP",
    "EVENTSCENARIO",
    "FACTION",
    "FLOATING_PROP_ACTING",
    "FOOTSTEP",
    "FORCED_MOVEMENT_AREA",
    "FROZEN",
    "FUSIBLEBOX",
    "FX",
    "GRAB",
    "GRAPPLEPOINT",
    "GUN",
    "HEATABLESHIELD",
    "INPUT",
    "INTERPOLATION",
    "INVENTORY",
    "LANDMARK",
    "LA_TRIGGER",
    "LIFE",
    "LIGHTING",
    "LOGICCAMERA",
    "LOGICPATH",
    "LOGICSHAPE",
    "LOOKATPLAYER",
    "MAGMA_KRAID_PISTON_PLATFORM",
    "MAGMA_KRAID_SCENARIO_CONTROLLER",
    "MAGMA_KRAID_SPIKE",
    "MAGNETHUSK",
    "MAGNET_SLIDING_BLOCK",
    "MAGNET_SLIDING_BLOCK_RAIL",
    "MAGNET_SURFACE",
    "MATERIALFX",
    "MELEE",
    "MODELINSTANCE",
    "MODELUPDATER",
    "MORPH_BALL_LAUNCHER",
    "MORPH_BALL_LAUNCHER_EXIT",
    "MOVEMENT",
    "MULTI_LOCK_ON_BLOCK",
    "NAVMESHITEM",
    "NOZZLE",
    "PICKABLE",
    "POSITIONALSOUND",
    "RINKAUNIT",
    "ROTATIONAL",
    "RUMBLE",
    "SCENEANIM",
    "SCRIPT",
    "SENSORDOOR",
    "SHOT",
    "SIMULATION",
    "SLIDLEOUTSPAWNPOINT",
    "SMARTOBJECT",
    "SONAR_TARGET",
    "SPAWNGROUP",
    "SPAWNPOINT",
    "STARTPOINT",
    "TARGETCOMP",
    "THERMALREACTION",
    "TILEGROUP",
    "TIMELINE",
    "TIMELINECOMPONENT",
    "TRIGGER",
    "TUNNEL_TRAP",
    "USABLE",
    "VIDEOMANAGER",
    "WEIGHT_ACTIVABLE_PROP",
    "WORLDGRAPH",
    "WTCHANGE",
    "XPARASITEDROP",
    "ZIPLINE_RAIL",
]
component_keys.extend([s + "COMPONENT" for s in component_keys])

Char = construct.PaddedString(1, 'ascii')

FunctionArgument = Struct(
    type=Char,
    value=Switch(
        construct.this.type,
        {
            's': StrId,
            'f': Float,
            'b': Flag,
            'i': Int32ul,
        },
        ErrorWithMessage(lambda ctx: f"Unknown argument type: {ctx.type}", construct.SwitchError)
    )
)
Functions = make_vector(Struct(
    name=StrId,
    unk=Int16ul,
    params=common_types.DictAdapter(common_types.make_vector(
        common_types.DictElement(FunctionArgument, key=PropertyEnum)
    )),
))

fieldtypes = {k: v for k, v in vars(dread_types).items() if isinstance(v, construct.Construct)}


def component_charclass(this):
    field_type = this._._.type

    overrides = {
        "CPickableItemComponent": "CCharClassPickableComponent",
        "CPickableSuitComponent": "CCharClassPickableComponent",

        "CPowerUpLifeComponent": "CCharClassBasicLifeComponent",
        "CHyperBeamBlockLifeComponent": "CCharClassBasicLifeComponent",
        "CBeamDoorLifeComponent": "CCharClassBasicLifeComponent",

        "CSideEnemyMovement": "CCharClassEnemyMovement",
        "CEnemyMovement": "CCharClassEnemyMovement",
        "CMorphBallMovement": "CCharClassMorphBallMovement",

        "CAmmoRechargeComponent": "CCharClassUsableComponent",
        "CLifeRechargeComponent": "CCharClassUsableComponent",
        "CElevatorCommanderUsableComponent": "CCharClassUsableComponent",
        "CThermalDeviceComponent": "CCharClassUsableComponent",

        "CSamusModelUpdaterComponent": "CCharClassMultiModelUpdaterComponent"
    }
    return overrides.get(field_type, "CCharClass" + field_type[1:])


def Dependencies():
    return ExprAdapter(
        GreedyRange(FocusedSeq(
            "byte",
            "next_key" / Optional(Peek(StrId)),
            StopIf(lambda this: this.next_key is not None and this.next_key in component_keys),
            "byte" / Bytes(1)
        )),
        lambda obj, ctx: b''.join(obj),
        lambda obj, ctx: [obj[i:i + 1] for i in range(len(obj))]
    )


Component = Struct(
    type=StrId,
    unk_1=Array(2, Hex(Int32ul)),
    fields=PrefixedAllowZeroLen(
        Int32ul,
        Struct(
            empty_string=PropertyEnum,
            root=PropertyEnum,
            fields=Switch(
                component_charclass,
                fieldtypes,
                ErrorWithMessage(lambda ctx: f"Unknown component type: {ctx._._.type}", construct.SwitchError)
            )
        )
    ),
    unk_2=Int32sl,
    functions=Functions,
    dependencies=Dependencies(),
    z=construct.Probe(),
)

CCharClass = Struct(
    model_name=StrId,
    unk_1=Int16ul,
    unk_2=Int32ul,
    unk_3=Int16ul,
    sub_actors=PrefixedArray(Int32ul, StrId),
    unk_4=Array(9, Float32l),
    magic=Const(0xFFFFFFFF, Hex(Int32ul)),
    unk_5=Int16ul,
    unk_6=Byte,

    components=make_dict(Component),
)

property_types = {
    "CCharClass": CCharClass,
}
#
BMSAD = Struct(
    magic=Const(b"MSAD"),
    version=Const(0x0200000F, Hex(Int32ul)),

    # # gameeditor::CGameModelRoot
    # root_type=construct.Const('Root', PropertyEnum),
    # Root=gameeditor_CGameModelRoot,

    name=StrId,
    type=StrId,

    property=Switch(
        construct.this.type,
        property_types,
        ErrorWithMessage(lambda ctx: f"Unknown property type: {ctx.type}"),
    ),
    rest=construct.GreedyBytes,
    # _end=construct.Terminated,
)


# BMSAD = game_model_root.create('CActorDef', 0x02000031)


class Bmsad(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BMSAD
