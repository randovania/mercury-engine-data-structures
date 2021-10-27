import construct
from construct import (
    Struct, Construct, Const, Bytes, CString, Array, GreedyBytes, Int32ul, PrefixedArray, Int16ul,
    Switch, Int64ul, Hex, HexDisplayedInteger, Computed, Float32l, Flag, )

from mercury_engine_data_structures import resource_names
from mercury_engine_data_structures.construct_extensions.misc import ErrorWithMessage
from mercury_engine_data_structures.formats import BaseResource
from mercury_engine_data_structures.game_check import Game

properties = {}


def add_prop(name: str, value: Construct):
    properties[resource_names.all_name_to_property_id()[name]] = value


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
        ErrorWithMessage("Property id without assigned type"),
    )
)

add_prop("sLevelID", CString("utf-8"))
add_prop("sScenarioID", CString("utf-8"))
add_prop("vLayerFiles", PrefixedArray(Int32ul, CString("utf-8")))
add_prop("rEntitiesLayer", PrefixedArray(Int32ul, PropertyElement))
add_prop("sName", CString("utf-8"))

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
    type=CString("utf-8"),
    data=Switch(
        construct.this.type,
        component_types,
    )
)

CVector3D = Array(3, Float32l)

Object = Struct(
    name=CString("utf-8"),
    u7=Array(5, Int32ul),
    # _=Probe(lookahead=0x20),
    s7=CString("utf-8"),
    property_id=PropertyEnum,
    actor_def=CString("utf-8"),
    u10=Array(14, Int32ul),

    # num_components=Int32ul,
    # component_0=Component,
    components=PrefixedArray(Int32ul, Component),
)


def make_dict(value: Construct, single=True):
    if single:
        return Struct(
            count=Int32ul,
            value=Struct(
                key=CString("utf-8"),
                value=value,
            )
        )
    return PrefixedArray(
        Int32ul,
        Struct(
            key=CString("utf-8"),
            value=value,
        )
    )


add_prop("dctSublayers", make_dict(Struct(
    # Sublayer
    field_count=Int32ul,
    sName=PropertyElement,
    dctActors=PropertyElement,
)))

add_prop("oActorDefLink", CString("utf-8"))
add_prop("vPos", CVector3D)
add_prop("vAng", CVector3D)
add_prop("bEnabled", Flag)
add_prop("v3Position", CVector3D)

add_prop("CLogicCamera", Struct(
    field_count=Int32ul,

    f1_type=PropertyEnum,
    f1=CString("utf-8"),

    # bStatic
    f2_type=PropertyEnum,
    f2=Flag,

    # v3Position
    f3=PropertyElement,

    # v3Dir
    f4_type=PropertyEnum,
    f4=CVector3D,

    # fFovX
    f5_type=PropertyEnum,
    f5=Float32l,

    # fMinExtraZDist
    f6_type=PropertyEnum,
    f6=Float32l,

    # fMaxExtraZDist
    f7_type=PropertyEnum,
    f7=Float32l,

    # fDefaultInterp
    f8_type=PropertyEnum,
    f8=Float32l,
))

add_prop("CLogicCameraComponent", Struct(
    count=Int32ul,
    c2=PropertyEnum,
    rLogicCamera=PropertyElement,
))

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
)))

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
    f5=PropertyElement,

    # f5_type=PropertyEnum,  # dctSublayers
    # #
    # # # num element in dict
    # f5=Int32ul,
    #
    # # key
    # s6=CString("utf-8"),  # expects default
    # u7=Int32ul,
    # u8_a=PropertyElement,
    #
    # enum_1=PropertyEnum,
    # maybe_object_count=Int32ul,

    # first_object=Object,
    # second_object=Object,

    # s9=CString("utf-8"),
    # u11=Array(15, Int16ul),
    # u11=Bytes(0x28),
    # s10=CString("utf-8"),
    # u12=Bytes(0x6a),

    raw=GreedyBytes,
)


class Brfld(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BRFLD
