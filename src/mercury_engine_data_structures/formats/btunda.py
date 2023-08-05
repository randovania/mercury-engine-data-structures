
import construct
from construct import Container, Struct

from mercury_engine_data_structures import type_lib
from mercury_engine_data_structures.formats import BaseResource
from mercury_engine_data_structures.formats.property_enum import PropertyEnum
from mercury_engine_data_structures.game_check import Game

VALID_BTUNDA_VERSIONS = [
    0x02000077, # 1.0.0
    0x02000080, # 2.1.0
]

BTUNDA = Struct(
    _class_crc=construct.Const('base::tunable::CTunableManager', PropertyEnum),
    _version=construct.OneOf(construct.Int32ul, VALID_BTUNDA_VERSIONS),
    root_type=construct.Const('Root', PropertyEnum),
    Root=type_lib.get_type('base::tunable::CTunableManager').construct,
    _end=construct.Terminated
)

class Btunda(BaseResource):
    """
    /!\\ /!\\ /!\\ READ THIS WHEN USING!!! /!\\ /!\\ /!\\
    
    This format has TWO VERSIONS between 1.0.0 and 2.1.0!

    To prevent unexpected behavior across versions, do not use:\n
    - any key containing EasyMode in Player|CTunablePlayerLifeComponent\n
    - anything in CTunableBossRushManager
    """

    @classmethod
    def construct_class(cls, target_game: Game) -> construct.Construct:
        return BTUNDA

    def get_tunable(self, tunable: str) -> Container:
        return self.raw.Root.hashTunables[tunable]
