import functools

from construct import (
    Array,
    Const,
    Construct,
    Float32l,
    Struct,
    Terminated,
)

from mercury_engine_data_structures.common_types import StrId, VersionAdapter, make_vector
from mercury_engine_data_structures.formats.base_resource import BaseResource
from mercury_engine_data_structures.game_check import Game

BMSEV = Struct(
    "magic" / Const(b"MSEV"),
    "version" / VersionAdapter(),
    "elements" / make_vector(Struct(
        "name" / StrId,
        "unknown_floats" / Array(59, Float32l),
    )),
    Terminated,
).compile()

class Bmsev(BaseResource):
    @classmethod
    @functools.lru_cache
    def construct_class(cls, target_game: Game) -> Construct:
        return BMSEV
