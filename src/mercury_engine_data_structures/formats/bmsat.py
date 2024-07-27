from construct import Construct

from mercury_engine_data_structures.formats import standard_format
from mercury_engine_data_structures.formats.base_resource import BaseResource
from mercury_engine_data_structures.game_check import Game


class Bmsat(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return standard_format.create("animtree::CAnimTreeRes", "3.0.2")
