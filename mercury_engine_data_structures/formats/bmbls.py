import construct

from mercury_engine_data_structures.formats import BaseResource, game_model_root
from mercury_engine_data_structures.game_check import Game
from mercury_engine_data_structures.formats.dread_types import base_animation_CBlendSpaceResource

BMBLS = game_model_root.create('base::animation::CBlendSpaceResource', 0x02020001, base_animation_CBlendSpaceResource)


class Bmbls(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> construct.Construct:
        return BMBLS