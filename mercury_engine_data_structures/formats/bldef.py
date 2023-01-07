from construct import Construct, Container, Struct, Const, Int32ul, Terminated, Hex

from mercury_engine_data_structures.formats import BaseResource, standard_format
from mercury_engine_data_structures.formats.property_enum import PropertyEnum
from mercury_engine_data_structures.game_check import Game
from mercury_engine_data_structures import type_lib

class Bldef(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return standard_format.game_model('CLightManager', 0x02000001)
    
    @property
    def lightdefs(self) -> Container:
        return self.raw.Root.pLightManager.dicLightDefs
