from __future__ import annotations

import construct
from construct import (
    Const,
    Construct,
    Float32l,
    Int32ul,
    Struct,
)

from mercury_engine_data_structures.common_types import StrId, VersionAdapter, make_vector
from mercury_engine_data_structures.formats.base_resource import BaseResource
from mercury_engine_data_structures.game_check import Game

BMSEM = Struct(
    _magic=Const(b"MSEM"),
    _version=VersionAdapter("1.3.0"),
    groups=make_vector(Struct(
        "group_name" / StrId,
        "layers" / make_vector(Struct(
            "layer_name" / StrId,
            "entries" / make_vector(Struct(
                "collision_camera" / StrId,
                "song" / StrId,  # Is empty if cc is "default".
                "unk1" / Float32l,  # Always either 2.0 or 1.5
                "unk2" / Float32l,  # Always same number as unk1
                "unk3" / Int32ul,  # Always 1
                "unk4" / Int32ul  # Always 0
            ))
        ))
    )),
    rest=construct.GreedyBytes,
)  # fmt: skip


class Bmsem(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BMSEM
