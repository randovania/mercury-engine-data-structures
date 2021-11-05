import construct

from mercury_engine_data_structures.formats import BaseResource, game_model_root
from mercury_engine_data_structures.game_check import Game

BREV = game_model_root.create('CEnvironmentVisualPresets', 0x02020004)


class Brev(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> construct.Construct:
        return BREV
