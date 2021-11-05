import construct

from mercury_engine_data_structures.formats import BaseResource, game_model_root
from mercury_engine_data_structures.game_check import Game

BREM = game_model_root.create('CEnvironmentMusicPresets', 0x02000004)


class Brem(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> construct.Construct:
        return BREM
