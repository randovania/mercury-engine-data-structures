import construct

from construct import Container, Struct
from enum import Enum
from mercury_engine_data_structures.formats import BaseResource, standard_format
from mercury_engine_data_structures.game_check import Game

VALID_BTUNDA_VERSIONS = [
    0x02000077, # 1.0.0
    0x02000080, # 2.1.0
]

class Btunda(BaseResource):
    """
    /!\\ /!\\ /!\\ READ THIS WHEN USING!!! /!\\ /!\\ /!\\
    
    This format has TWO VERSIONS between 1.0.0 and 2.1.0!

    To prevent unexpected behavior across versions, do not use:\n
    - any key containing EasyMode in Player|CTunablePlayerLifeComponent\n
    - anything in CTunableBossRushManager
    """

    @classmethod
    def construct_class(cls, target_game: Game, version:int) -> construct.Construct:
        return standard_format.create('base::tunable::CTunableManager', version)

    @classmethod
    def parse(cls, data: bytes, target_game: Game) -> "BaseResource":
        # peek at data to get version
        version = int.from_bytes(data[8:12], byteorder='little')

        # confirm version is valid
        if version not in VALID_BTUNDA_VERSIONS:
            raise ValueError((f"BTUNDA version {hex(version.to_bytes(4, byteorder='little'))}"
                             " is not an implemented BTUNDA version!"))
        
        return cls(Btunda.construct_class(target_game, version).parse(data, target_game=target_game), target_game)
    
    def get_tunable(self, tunable: str) -> Container:
        return self.raw.Root.hashTunables[tunable]