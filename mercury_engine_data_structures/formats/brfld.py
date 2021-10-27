from construct import Struct, Construct, Const, Bytes, CString, Array, GreedyBytes, Int32ul, PrefixedArray

from mercury_engine_data_structures.formats import BaseResource
from mercury_engine_data_structures.game_check import Game

BRFLD = Struct(
    intro=Bytes(0x33),
    s1=CString("utf-8"),
    u2=Const(b'\xd0\x98?4\xe8k\x1b:s'),
    s2=CString("utf-8"),
    u3=Array(2, Int32ul),
    s3=PrefixedArray(Int32ul, CString("utf-8")),
    u4=Array(6, Int32ul),

    s4=CString("utf-8"),  # expects default
    u5=Array(3, Int32ul),
    s5=CString("utf-8"),  # expects default again
    u6=Array(2, Int32ul),

    maybe_object_count=Int32ul,

    first_object=Struct(
        name=CString("utf-8"),
        u7=Array(5, Int32ul),
        s7=CString("utf-8"),
        u8=Int32ul,
        u9=Int32ul,
        actor_def=CString("utf-8"),
        u10=Array(15, Int32ul),
    ),

    # second_object=Struct(
    #     name=CString("utf-8"),
    #     u7=Array(5, Int32ul),
    #     s7=CString("utf-8"),
    #     u8=Int32ul,
    #     u9=Int32ul,
    #     actor_def=CString("utf-8"),
    #     u10=Array(15, Int32ul),
    # ),

    # s9=CString("utf-8"),
    # u11=Bytes(0x28),
    # s10=CString("utf-8"),
    # u12=Bytes(0x6a),

    raw=GreedyBytes,
)


class Brfld(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BRFLD
