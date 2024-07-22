import construct

from mercury_engine_data_structures.formats.base_resource import BaseResource
from mercury_engine_data_structures.formats.standard_format import game_model
from mercury_engine_data_structures.game_check import Game

BAPD = game_model('sound::CAudioPresets', "2.3.2")


class Bapd(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> construct.Construct:
        return BAPD
