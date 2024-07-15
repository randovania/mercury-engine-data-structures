import construct

from mercury_engine_data_structures.formats import standard_format
from mercury_engine_data_structures.formats.base_resource import BaseResource
from mercury_engine_data_structures.game_check import Game

BMSLGROUP = standard_format.create('navmesh::CDynamicSmartLinkGroup', 0x02000001)


class Bmslgroup(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> construct.Construct:
        return BMSLGROUP
