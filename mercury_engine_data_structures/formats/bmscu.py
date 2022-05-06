from construct import Construct

from mercury_engine_data_structures.formats import BaseResource, standard_format
from mercury_engine_data_structures.game_check import Game

BMSCU = standard_format.create('CCutSceneDef', 0x02030008)


class Bmscu(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BMSCU
