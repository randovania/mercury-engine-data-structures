import construct
from construct import Construct, Struct, Const, Int32ul, Hex, Bytes, CString, Float32l

from mercury_engine_data_structures.common_types import make_vector
from mercury_engine_data_structures.formats import BaseResource
from mercury_engine_data_structures.game_check import Game


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

    rest=construct.Bytes(0x100),
)


class Bmsld(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BMSLD
