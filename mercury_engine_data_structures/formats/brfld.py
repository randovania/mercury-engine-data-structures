import construct
from construct import (
    Struct, Construct, Const, Bytes, CString, Array, GreedyBytes, Int32ul, PrefixedArray, Int16ul,
    Switch, Int64ul, Hex, HexDisplayedInteger,
)

from mercury_engine_data_structures import resource_names
from mercury_engine_data_structures.formats import BaseResource
from mercury_engine_data_structures.game_check import Game

PropertyEnum = construct.Enum(Hex(Int64ul), **{
    name: HexDisplayedInteger.new(property_id, "0%sX" % (2 * 8))
    for property_id, name in resource_names.all_property_id_to_name().items()
})

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

BRFLD = Struct(
    intro_a=PropertyEnum,
    intro_b=Hex(Int64ul),
    intro_c=Hex(Int64ul),
    intro_d=PropertyEnum,
    intro_e=PropertyEnum,

    count_for_stuff=Int32ul,

    s1_type=PropertyEnum,
    s1=CString("utf-8"),

    s2_type=PropertyEnum,
    s2=CString("utf-8"),

    u3=PropertyEnum,
    s3=PrefixedArray(Int32ul, CString("utf-8")),
    u4=Array(6, Int32ul),

    s4=CString("utf-8"),  # expects default
    u5=Int32ul,
    u5_a=PropertyEnum,
    s5=CString("utf-8"),  # expects default again
    enum_1=PropertyEnum,

    maybe_object_count=Int32ul,

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
