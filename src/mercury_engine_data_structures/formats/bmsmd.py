from __future__ import annotations

import functools
from typing import TYPE_CHECKING

from construct.core import (
    Array,
    Const,
    Construct,
    Float32l,
    Hex,
    Int32sl,
    Int32ul,
    Struct,
)

from mercury_engine_data_structures.base_resource import BaseResource
from mercury_engine_data_structures.common_types import StrId, VersionAdapter, make_vector

if TYPE_CHECKING:
    from mercury_engine_data_structures.game_check import Game

BMSMD = Struct(
    "_magic" / Const(b"MSMD"),
    "version" / VersionAdapter("1.13.0"),
    "map_data" / make_vector(Struct(
        "icon" / StrId,
        "scenarios" / make_vector(Struct(
            "name" / StrId,
            "unk1" / Hex(Int32ul),
            "unk2" / Hex(Int32ul),
            "unk3" / Hex(Int32ul),
            "unk4" / Hex(Int32ul),
            "unk5" / Hex(Int32ul),
            "unk6" / Hex(Int32ul),
            "number_of_tiles" / Int32ul,
            "unk7" / Hex(Int32ul),
            "unk8" / Hex(Int32ul),
            "coordinates" / Array(2, Int32ul),
            "sub_scenarios" / make_vector(Struct(
                "name" / StrId,
                "unk1" / Float32l,
                "unk2" / Float32l,
                "coordinates" / Array(2, Int32sl),
            )),
        )),
    )),
)  # fmt: skip


class Bmsmd(BaseResource):
    @classmethod
    @functools.lru_cache
    def construct_class(cls, target_game: Game) -> Construct:
        return BMSMD
