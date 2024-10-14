from __future__ import annotations

from construct.core import Const, Construct, Int32ul, PrefixedArray, Struct

from mercury_engine_data_structures.common_types import Float, VersionAdapter
from mercury_engine_data_structures.formats.base_resource import BaseResource
from mercury_engine_data_structures.game_check import Game

BLUT = Struct(magic=Const(b"LUT"), ver=VersionAdapter("1.1.0"), data=PrefixedArray(Int32ul, Float))


class Blut(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BLUT
