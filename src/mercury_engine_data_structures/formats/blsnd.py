from __future__ import annotations

import functools

import construct
from construct.core import (
    Const,
    Construct,
    IfThenElse,
    Int32ul,
    Struct,
)

from mercury_engine_data_structures.base_resource import BaseResource
from mercury_engine_data_structures.common_types import StrId, VersionAdapter, make_vector
from mercury_engine_data_structures.game_check import Game, current_game_at_most

BLSND = Struct(
    "_magic" / Const(b"LSND"),
    "version" / IfThenElse(
        current_game_at_most(Game.SAMUS_RETURNS),
        VersionAdapter("1.11.0"),
        VersionAdapter("1.12.0")
    ),
    "unk" / Int32ul,
    "sound_limits" / make_vector(Struct(
        "name" / StrId,
        "value" / Int32ul,
    )),
    construct.Terminated,
)  # fmt: skip


class Blsnd(BaseResource):
    @classmethod
    @functools.lru_cache
    def construct_class(cls, target_game: Game) -> Construct:
        return BLSND
