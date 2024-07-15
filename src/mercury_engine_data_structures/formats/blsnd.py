import functools

import construct
from construct.core import (
    Const,
    Construct,
    Hex,
    IfThenElse,
    Int32ul,
    Struct,
)

from mercury_engine_data_structures.common_types import StrId, make_vector
from mercury_engine_data_structures.formats.base_resource import BaseResource
from mercury_engine_data_structures.game_check import Game, current_game_at_most

BLSND = Struct(
    "_magic" / Const(b"LSND"),
    "version" / IfThenElse(
        current_game_at_most(Game.SAMUS_RETURNS),
        Const(0x000B0001, Hex(Int32ul)),
        Const(0x000C0001, Hex(Int32ul))
    ),
    "unk" / Int32ul,
    "sound_limits" / make_vector(Struct(
        "name" / StrId,
        "value" / Int32ul,
        )),
    construct.Terminated,
)


class Blsnd(BaseResource):
    @classmethod
    @functools.lru_cache
    def construct_class(cls, target_game: Game) -> Construct:
        return BLSND
