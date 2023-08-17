from construct import Construct, Container

from mercury_engine_data_structures.formats import BaseResource, standard_format
from mercury_engine_data_structures.game_check import Game


class Bmscp(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return standard_format.game_model('GUI::CDisplayObjectContainer', 0x02020001)
