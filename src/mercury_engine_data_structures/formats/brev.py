import construct

from mercury_engine_data_structures.formats import BaseResource, standard_format
from mercury_engine_data_structures.game_check import Game

BREV = standard_format.game_model('CEnvironmentVisualPresets', 0x02020004)


class Brev(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> construct.Construct:
        return BREV
