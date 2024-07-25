from typing import Any

import construct
from construct import Struct

from mercury_engine_data_structures import type_lib
from mercury_engine_data_structures.common_types import VersionAdapter
from mercury_engine_data_structures.formats import BaseResource
from mercury_engine_data_structures.formats.property_enum import PropertyEnum
from mercury_engine_data_structures.game_check import Game

VALID_BTUNDA_VERSIONS = [
    "119.0.2", # 1.0.0
    "128.0.2", # 2.1.0
]

BTUNDA = Struct(
    _class_crc=construct.Const('base::tunable::CTunableManager', PropertyEnum),
    version=VersionAdapter(),
    _version_check=construct.Check(lambda ctx: ctx.version in VALID_BTUNDA_VERSIONS),
    root_type=construct.Const('Root', PropertyEnum),
    Root=type_lib.get_type_lib_dread().get_type('base::tunable::CTunableManager').construct,
    _end=construct.Terminated
)

PLAYER_TUNABLE_LATEST_ONLY = [
    "fEasyModeDamageMult",
    "fEasyModeDamageMult_Corpius",
    "fEasyModeDamageMult_Kraid",
    "fEasyModeDamageMult_Drogyga",
    "fEasyModeDamageMult_Experiment57",
    "fEasyModeDamageMult_RavenBeak",
    "fEasyModeDamageMult_EliteChozoSoldier",
    "fEasyModeDamageMult_ChozoSoldierGhavoran",
    "fEasyModeDamageMult_ChozoSoldierElun",
    "fEasyModeDamageMult_ChozoSoldierArtaria",
    "fEasyModeDamageMult_ChozoSoldierHanubia",
    "fEasyModeDamageMult_ChozoRobotGhavoran",
    "fEasyModeDamageMult_ChozoRobotFerenia",
    "fEasyModeDamageMult_ChozoRobotx2Ferenia",
    "fEasyModeDamageMult_ChozoRobotx2Burenia",
    "fEasyModeDamageMult_Escue",
    "fEasyModeDamageMult_Golzuna",
    "fEasyModeDropAmountFactor_Life",
    "fEasyModeDropAmountFactor_LifeBig",
    "fEasyModeDropAmountFactor_Missile",
    "fEasyModeDropAmountFactor_MissileBig",
    "fEasyModeDropAmountFactor_PowerBomb",
    "fEasyModeDropAmountFactor_PowerBombBig",
    "fEasyModeDropAmountFactor_MiniXLife",
    "fEasyModeDropAmountFactor_MiniXMissile",
    "fEasyModeDropAmountFactor_XYellowLife",
    "fEasyModeDropAmountFactor_XGreenMissile",
    "fEasyModeDropAmountFactor_XRedLife",
    "fEasyModeDropAmountFactor_XRedMissile",
    "fEasyModeDropAmountFactor_XRedPowerBomb",
    "fEasyModeDropAmountFactor_XOrangePowerBomb",
    "bEasyModeEnemyProjectileOneHit",
    "fEasyModeKraidBouncingCreatureLifeFactor",
]

class Btunda(BaseResource):
    """
    /!\\ /!\\ /!\\ READ THIS WHEN USING!!! /!\\ /!\\ /!\\

    This format has TWO VERSIONS between 1.0.0 and 2.1.0!

    To prevent unexpected behavior across versions, do not use:\n
    - any key containing EasyMode in Player|CTunablePlayerLifeComponent\n
    - anything in CTunableBossRushManager

    use Btunda.set_tunable(...) to change tunables safely.
    """

    @classmethod
    def construct_class(cls, target_game: Game) -> construct.Construct:
        return BTUNDA

    def get_tunable(self, path: list[str]) -> Any:
        tunable = self.raw.Root.hashTunables
        for p in path:
            if p not in tunable:
                raise ValueError(f"Unknown tunable {'.'.join(path)}!")

            tunable = tunable[p]

        return tunable

    def set_tunable(self, path: list[str], value: Any) -> None:
        # guard against various version-dependent tunables
        if path[0] in ["CTunableBossRushManager", "CTunableProgressStatManager"]:
            if self.raw.version != "128.0.2":
                raise ValueError(f"Cannot set {path[0]} in btunda versions below 128.0.2!")

        if path[0] == "CTunableGameManager" and path[1] == "bForceHardMode":
            if self.raw.version != "119.0.2":
                raise ValueError("Cannot set CTunableGameManager.bForceHardMode in btunda versions above 119.0.2!")

        if path[0] == "Player|CTunablePlayerLifeComponent" and path[1] in PLAYER_TUNABLE_LATEST_ONLY:
            if self.raw.version != "128.0.2":
                raise ValueError(f"Cannot set {path[0]}.{path[1]} in btunda versions below 128.0.2!")

        # actually change the tunable
        tunable = self.get_tunable(path[:-1])

        if path[-1] not in tunable:
            raise ValueError(f"Unknown tunable {'.'.join(path)}!")

        tunable[path[-1]] = value
