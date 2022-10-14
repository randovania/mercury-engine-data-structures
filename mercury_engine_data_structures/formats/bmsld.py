import construct
from construct import Array, Construct, Struct, Const, Int32ul, Int16ul, Int8ul, Hex, CString, Float32l

from mercury_engine_data_structures.common_types import make_vector
from mercury_engine_data_structures.formats import BaseResource
from mercury_engine_data_structures.game_check import Game

type_body=construct.Switch(
    construct.this.object_type,
    {
        0x0400: Struct(
            unk12=Array(4, Struct(
                x=Float32l,
                y=Float32l,
                z=Int32ul,
            )),
        ),
        0x0600: Struct(
            unk12=Array(6, Struct(
                x=Float32l,
                y=Float32l,
                z=Int32ul,
            )),
        ),
        0x0800: Struct(
            unk12=Array(8, Struct(
                x=Float32l,
                y=Float32l,
                z=Int32ul,
            )),
        ),
        0x0A00: Struct(
            unk12=Array(10, Struct(
                x=Float32l,
                y=Float32l,
                z=Int32ul,
            )),
        ),
        0x0C00: Struct(
            unk12=Array(12, Struct(
                x=Float32l,
                y=Float32l,
                z=Int32ul,
            )),
        ),
        0x0E00: Struct(
            unk12=Array(14, Struct(
                x=Float32l,
                y=Float32l,
                z=Int32ul,
            )),
        ),
        0x1400: Struct(
            unk12=Array(20, Struct(
                x=Float32l,
                y=Float32l,
                z=Int32ul,
            )),
        ),
        0x1C00: Struct(
            unk12=Array(28, Struct(
                x=Float32l,
                y=Float32l,
                z=Int32ul,
            )),
        ),
    }
)

BMSLD = Struct(
    _magic=Const(b"MSLD"),
    version=Const(0x00140001, Hex(Int32ul)),

    unk1=Int32ul,
    unk2=Int32ul,
    unk3=Int32ul,
    unk4=Int32ul,

    objects_a=make_vector(Struct(
        name=CString("utf-8"),
        unk1=Hex(Int32ul),
        unk2=Hex(Int32ul),
        unk3=Hex(Int32ul),
        unk4=Hex(Int32ul),
        unk5=Hex(Int32ul),
        unk6=Hex(Int32ul),
    )),

    object_b=make_vector(Struct(
        name=CString("utf-8"),
        unk01=Hex(Int32ul),
        unk02=make_vector(Struct(
            x=Float32l,
            y=Float32l,
            z=Float32l,
        )),
    )),

    object_c=make_vector(Struct(
        name=CString("utf-8"),
        unk01=Hex(Int32ul),
        unk02=Float32l,
        unk03=Float32l,
        unk04=Float32l,
        unk05=Hex(Int32ul),
        unk06=Hex(Int32ul),
        unk07=Hex(Int32ul),
        unk08=Hex(Int32ul),
        object_type=Hex(Int16ul),
        unk10=Hex(Int32ul),
        unk11=Hex(Int32ul),
        unk12=type_body,
        unk13=Array(4, Struct(
            x=Float32l,
            y=Float32l,
        )),
        unk14=Hex(Int8ul),
    )),

    objects_count=Int32ul,
    rest=construct.Bytes(0x100),
)


class Bmsld(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BMSLD
