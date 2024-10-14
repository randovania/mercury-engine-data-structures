from __future__ import annotations

import functools

import construct
from construct.core import (
    Const,
    Construct,
    Float32l,
    Int32sl,
    Struct,
)

from mercury_engine_data_structures.common_types import StrId, VersionAdapter, make_vector
from mercury_engine_data_structures.formats.base_resource import BaseResource
from mercury_engine_data_structures.game_check import Game

BMSES = Struct(
    "_magic" / Const(b"MSES"),
    "version" / VersionAdapter("1.5.0"),
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
)  # fmt: skip


class Bmses(BaseResource):
    @classmethod
    @functools.lru_cache
    def construct_class(cls, target_game: Game) -> Construct:
        return BMSES
