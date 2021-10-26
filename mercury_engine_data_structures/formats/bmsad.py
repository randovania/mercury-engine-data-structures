from construct import Struct, Construct, Const, Int32ul, Hex, CString

from mercury_engine_data_structures.formats import BaseResource
from mercury_engine_data_structures.game_check import Game

BMSAD = Struct(
    magic_a=Const(b"MSAD"),
    magic_b=Const(0x0200000F, Hex(Int32ul)),
    name=CString("utf-8"),
    type=CString("utf-8"),
)


class Bmsad(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BMSAD
