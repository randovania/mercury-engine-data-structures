import construct

from construct import Container
from enum import Enum
from mercury_engine_data_structures.formats import BaseResource, standard_format
from mercury_engine_data_structures.game_check import Game

# btunda has different file versions between launch version and latest release
class BtundaVersion(Enum):
    V1_0_0 = ("1.0.0", 0x02000077)
    V2_1_0 = ("2.1.0", 0x02000080)

    def __init__(self, string: str, number: int):
        self.as_string = string
        self.as_number = number

    @classmethod
    def get_version(cls, version: str) -> int:
        for el in cls:
            if version == el.as_string:
                return el.as_number
        
        raise ValueError(f"Version {version} is not a valid Btunda version!")

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
        # attempt to parse with 1.0.0 version
        # if it throws an exception, parse with 2.1.0 version
        try:
            parsed = cls(Btunda.construct_class(target_game, BtundaVersion.V1_0_0.as_number).parse(data, target_game=target_game),
                   target_game)
            parsed.version_str = BtundaVersion.V1_0_0.as_string
            return parsed
        except:
            parsed = cls(Btunda.construct_class(target_game, BtundaVersion.V2_1_0.as_number).parse(data, target_game=target_game),
                   target_game)
            parsed.version_str = BtundaVersion.V2_1_0.as_string
            return parsed
    
    def get_tunable(self, tunable: str) -> Container:
        return self.raw.Root.hashTunables[tunable]