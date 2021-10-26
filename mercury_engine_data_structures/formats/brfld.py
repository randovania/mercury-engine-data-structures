from construct import Struct, Construct, Const

from mercury_engine_data_structures.formats import BaseResource
from mercury_engine_data_structures.game_check import Game

BRFLD = Struct(
)


class Brfld(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BRFLD
