from construct import Struct, Construct, Const, Bytes, CString, Array

from mercury_engine_data_structures.formats import BaseResource
from mercury_engine_data_structures.game_check import Game

BRFLD = Struct(
    intro=Bytes(0x33),
    s1=CString("utf-8"),
    u2=Const(b'\xd0\x98?4\xe8k\x1b:s'),
    s2=CString("utf-8"),
    u3=Bytes(0xc),
    s3=Array(3, CString("utf-8")),
)


class Brfld(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BRFLD
