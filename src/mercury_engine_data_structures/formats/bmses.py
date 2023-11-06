import functools

import construct
from construct.core import (
    Const,
    Construct,
    Float32l,
    Hex,
    Int32sl,
    Int32ul,
    Struct,
)

from mercury_engine_data_structures.common_types import StrId, make_vector
from mercury_engine_data_structures.formats import BaseResource
from mercury_engine_data_structures.game_check import Game

BMSES = Struct(
    "_magic" / Const(b"MSES"),
    "version" / Const(0x00050001, Hex(Int32ul)),
    "sounds" / make_vector(Struct(
        "name" / StrId,
        "sound_file" / StrId,
        "properties" / Struct(
            "fade_in" / Float32l,
            "fade_out" / Float32l,
            "start_delay" / Float32l,
            "volume" / Float32l,
            "unk1" / Int32sl,
            "sub_sounds" / make_vector(Struct(
                "name" / StrId,
                "properties" / Struct(
                    "fade_in" / Float32l,
                    "fade_out" / Float32l,
                    "start_delay" / Float32l,
                    "volume" / Float32l,
                    "unk1" / Int32sl,
            ))),
        ))),
    construct.Terminated,
)


class Bmses(BaseResource):
    @classmethod
    @functools.lru_cache
    def construct_class(cls, target_game: Game) -> Construct:
        return BMSES
