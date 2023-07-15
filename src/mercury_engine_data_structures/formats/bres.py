import construct

from mercury_engine_data_structures.formats import BaseResource, standard_format
from mercury_engine_data_structures.game_check import Game

BRES = standard_format.game_model('CEnvironmentSoundPresets', 0x02020001)


class Bres(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> construct.Construct:
        return BRES
