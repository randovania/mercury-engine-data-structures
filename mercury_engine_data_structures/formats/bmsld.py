import construct
from construct import Array, Construct, Struct, Const, Int32ul, Int8ul, Hex, CString, Float32l, Flag, Int16ul

from mercury_engine_data_structures.common_types import make_vector, StrId, UInt, Float, make_dict
from mercury_engine_data_structures.construct_extensions.misc import ErrorWithMessage
from mercury_engine_data_structures.formats import BaseResource
from mercury_engine_data_structures.formats.bmscc import CollisionPoly, CollisionPoint
from mercury_engine_data_structures.game_check import Game

FunctionArgument = Struct(
    type=construct.PaddedString(4, 'ascii'),
    value=construct.Switch(
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

Components = {
    "TRIGGER": Struct(
        command=StrId,
        arguments=make_vector(FunctionArgument),
    ),
    "SPAWNGROUP": Struct(
        command=StrId,
        arguments=make_vector(FunctionArgument),
    ),
    "SPAWNPOINT": Struct(
        command=StrId,
        arguments=make_vector(FunctionArgument),
    ),
    "STARTPOINT": Struct(
        command=StrId,
        arguments=make_vector(FunctionArgument),
    ),
    "MODELUPDATER": Struct(
        command=StrId,
        arguments=make_vector(FunctionArgument),
    ),
}

ProperActor = Struct(
    type=StrId,

    x=Float,
    y=Float,
    z=Float,
    unk05=Hex(Int32ul),
    unk06=Hex(Int32ul),
    unk07=Hex(Int32ul),

    components=make_vector(Struct(
        component_type=StrId,
        command=StrId,
        arguments=make_vector(FunctionArgument),
        # data=construct.Switch(
        #     construct.this.component_type,
        #     Components,
        #     ErrorWithMessage(lambda ctx: f"Unknown component type: {ctx.component_type}", construct.SwitchError),
        # ),
    )),
)

BMSLD = Struct(
    _magic=Const(b"MSLD"),
    version=Const(0x00140001, Hex(Int32ul)),

    unk1=Int32ul,
    unk2=Int32ul,
    unk3=Int32ul,
    unk4=Int32ul,

    objects_a=make_vector(Struct(
        name=StrId,
        unk1=Hex(Int32ul),
        unk2=Hex(Int32ul),
        unk3=Hex(Int32ul),
        unk4=Hex(Int32ul),
        unk5=Hex(Int32ul),
        unk6=Hex(Int32ul),
    )),

    object_b=make_vector(Struct(
        name=StrId,
        unk01=Hex(Int32ul),
        unk02=make_vector(Struct(
            x=Float32l,
            y=Float32l,
            z=Float32l,
        )),
    )),

    object_c=make_vector(Struct(
        name=StrId,
        unk01=Hex(Int32ul),
        unk02=Float32l,
        unk03=Float32l,
        unk04=Float32l,
        unk05=Hex(Int32ul),
        unk06=Hex(Int32ul),
        unk07=Hex(Int32ul),
        unk08=Hex(Int32ul),
        unk09=Hex(Int8ul),
        count_for_unk12=construct.Rebuild(Int32ul, construct.len_(construct.this.unk12)),
        unk10=Hex(Int8ul),
        unk11=Hex(Int32ul),
        unk12=Array(construct.this.count_for_unk12, Struct(
            x=Float32l,
            y=Float32l,
            z=Int32ul,
        )),
        unk13=Array(4, Struct(
            x=Float32l,
            y=Float32l,
        )),
        unk14=Hex(Int8ul),
    )),

    objects_d=make_vector(Struct(
        name=StrId,
        object_type=StrId,
        data=construct.Switch(
            construct.this.object_type,
            {
                "CIRCLE": Struct(
                    value1=Float,
                    value2=Float,
                    value3=Float,
                    size=Float,
                ),
                "CAPSULE2D": Struct(
                    value1=Float,
                    value2=Float,
                    value3=Float,
                    value4=Float,
                    value5=Float,
                ),
                "POLYCOLLECTION2D": Struct(
                    unknown1=UInt,
                    unknown2=UInt,
                    unknown3=UInt,
                    polys=make_vector(Struct(
                        num_points=UInt,
                        unk=Float,
                        points=Array(construct.this.num_points,
                                     Struct(x=Hex(UInt), y=Hex(UInt), material_attribute=Hex(UInt))),
                        loop=Flag,
                        boundings=Array(4, Float),
                    )),
                    total_boundings=Array(4, Float),
                    something=Flag,
                    check=construct.If(construct.this.something, ErrorWithMessage(
                        lambda ctx: "flag is enabled, but not supported",
                    ))
                    # binary_search_trees=OptionalValue(make_vector(BinarySearchTree)),
                ),
            }
        )
    )),

    objects_e=make_vector(Struct(
        name=StrId,
        unk01=StrId,
        unk02=Hex(Int32ul),
        unk03=Hex(Int32ul),
        unk04=Hex(Int32ul),
        unk05=Hex(Int32ul),
        unk06=Hex(Int32ul),
        unk07=Hex(Int32ul),
        unk08=Hex(Int32ul),
        unk09=Float,
        unk10=Float,
        unk11=Hex(Int32ul),

        # unk12=Hex(Int8ul),
        unk13=StrId,
        unk14=Hex(Int32ul),
    )),

    actors=make_dict(ProperActor)[18],

    count=Int32ul,
    name=StrId,
    actor=Struct(
        type=StrId,

        x=Float,
        y=Float,
        z=Float,
        unk05=Hex(Int32ul),
        unk06=Hex(Int32ul),
        unk07=Hex(Int32ul),

        component_count=Int32ul,
        components=Struct(
            component_type=StrId,
            command=StrId,
            # arguments=make_vector(FunctionArgument),
        ),
    ),

    rest=construct.Bytes(0x100),
)


class Bmsld(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BMSLD
