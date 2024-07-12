import construct
from construct import (
    Array,
    Const,
    Construct,
    Float32l,
    Int16ul,
    Int32ul,
    Struct,
)

from mercury_engine_data_structures.common_types import StrId, make_vector
from mercury_engine_data_structures.formats import BaseResource
from mercury_engine_data_structures.game_check import Game

VectorArray = Array(3, Float32l)

BMSEM = Struct(
    _magic=Const(b"MSEM"),
    unk1=Int16ul,
    unk2=Int16ul,
    things= make_vector(Struct(
            "layer_name" / StrId,
            "objects" / make_vector(Struct(
                "whatever_name" / StrId,
                # "unk1" / Int32ul
                "inner_things" / make_vector(Struct(
                    "first_part" / StrId,
                    "second_part" / StrId,
                    "unk3" / Int32ul,
                    "unk4" / Int32ul,
                    "unk6" / Int32ul,
                    "unk7" / Int32ul
                ))
            ))
    )),
    rest=construct.GreedyBytes,
)

class Bmsem(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BMSEM
