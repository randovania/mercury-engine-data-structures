import construct

from construct import Container, ListContainer
from mercury_engine_data_structures.formats import BaseResource, standard_format
from mercury_engine_data_structures.game_check import Game

# btunda has different file versions between launch version and latest release
VERSION__1_0_0 = 0x02000077
VERSION__2_1_0 = 0x02000080

class Btunda(BaseResource):
    """
    /!\\ /!\\ /!\\ READ THIS WHEN USING!!! /!\\ /!\\ /!\\\n
    
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
            parsed = cls(Btunda.construct_class(target_game, VERSION__1_0_0).parse(data, target_game=target_game),
                   target_game)
            return parsed
        except:
            parsed = cls(Btunda.construct_class(target_game, VERSION__2_1_0).parse(data, target_game=target_game),
                   target_game)
            return parsed
    
    def get_tunable(self, tunable: str) -> Container:
        hashTunables: Container = self.raw.Root.hashTunables
        if tunable not in hashTunables:
            raise ValueError(f"Tunable {tunable} not in Btunda -> Root -> hashTunables")
        if tunable == "CTunableBossRushManager":
            raise ValueError(f"CTunableBossRushmanager is not safe for use in 1.0.0!")

        return hashTunables[tunable]