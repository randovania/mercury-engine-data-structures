from __future__ import annotations

from construct import Construct

from mercury_engine_data_structures.formats import standard_format
from mercury_engine_data_structures.formats.base_resource import BaseResource
from mercury_engine_data_structures.game_check import Game

BMSCU = standard_format.create("CCutSceneDef", "8.3.2")


class Bmscu(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BMSCU
