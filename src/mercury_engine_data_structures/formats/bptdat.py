import construct

from mercury_engine_data_structures.formats import standard_format
from mercury_engine_data_structures.formats.base_resource import BaseResource
from mercury_engine_data_structures.game_check import Game

BPTDAT = standard_format.create('CPlaythrough', "1.0.2")
BPTDEF = standard_format.create('CPlaythroughDef', "1.0.2")

class Bptdat(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> construct.Construct:
        return BPTDAT

class Bptdef(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> construct.Construct:
        return BPTDEF
