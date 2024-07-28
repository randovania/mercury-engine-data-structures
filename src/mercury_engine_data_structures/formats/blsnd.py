import functools

import construct
from construct.core import (
    Const,
    Construct,
    Int32ul,
    Struct,
)

from mercury_engine_data_structures.common_types import StrId, VersionAdapter, make_vector
from mercury_engine_data_structures.formats.base_resource import BaseResource
from mercury_engine_data_structures.game_check import Game, is_sr_or_else

BLSND = Struct(
    "_magic" / Const(b"LSND"),
    "version" / is_sr_or_else(
        VersionAdapter("1.11.0"),
        VersionAdapter("1.12.0")
    ),
    "unk" / Int32ul,
    "sound_limits" / make_vector(Struct(
        "name" / StrId,
        "value" / Int32ul,
        )),
    construct.Terminated,
).compile()


class Blsnd(BaseResource):
    @classmethod
    @functools.lru_cache
    def construct_class(cls, target_game: Game) -> Construct:
        return BLSND
