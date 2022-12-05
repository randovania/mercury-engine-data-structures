from construct import Construct, Container, Struct, Const, Int32ul, Terminated, Hex

from mercury_engine_data_structures.formats import BaseResource
from mercury_engine_data_structures.formats.property_enum import PropertyEnum
from mercury_engine_data_structures.game_check import Game
from mercury_engine_data_structures import type_lib

BLDEF = Struct(
    # the file uses CLightManager type but then has it as a field inside pLightComponent. 
    # the inside field is the one that type_lib can handle, this is basically a modified version of standard_format.create
    class_crc=Const('CLightManager', PropertyEnum),
    version=Const(0x02000001, Hex(Int32ul)),

    _root_type=Const('Root', PropertyEnum),
    _root_len=Const(1, Int32ul),

    _lm_field=Const('pLightManager', PropertyEnum),
    _lm_type=Const('CLightManager', PropertyEnum),
    pLightManager=type_lib.get_type('CLightManager').construct,
    _end=Terminated,
)


class Bldef(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BLDEF
    
    @property
    def lightdefs(self) -> Container:
        return self.raw.LightManager.dicLightDefs
