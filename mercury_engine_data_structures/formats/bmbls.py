import construct

from mercury_engine_data_structures.formats import BaseResource, standard_format
from mercury_engine_data_structures.game_check import Game

BMBLS = standard_format.create('base::animation::CBlendSpaceResource', 0x02020001)


class Bmbls(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> construct.Construct:
        return BMBLS