from construct import (
    Struct, Construct, Const, GreedyBytes, Int32ul, Hex,
)

from construct import (
    Struct, Construct, Const, GreedyBytes, Int32ul, Hex,
)

from mercury_engine_data_structures.common_types import (
    make_enum, )
from mercury_engine_data_structures.formats import BaseResource
from mercury_engine_data_structures.formats.dread_types import Pointer_CScenario
from mercury_engine_data_structures.game_check import Game
from mercury_engine_data_structures.hashed_names import PropertyEnum
from mercury_engine_data_structures.object import Object

EXCellSpawnPositionMode = make_enum(["FarthestToSpawnPoint", "ClosestToSpawnPoint"])
EDynamicSpawnPositionMode = make_enum(["ClosestToPlayer", "FarthestToPlayer", "Random"])
EBreakableTileType = make_enum([
    "UNDEFINED", "POWERBEAM", "BOMB", "MISSILE",
    "SUPERMISSILE", "POWERBOMB", "SCREWATTACK",
    "WEIGHT", "BABYHATCHLING", "SPEEDBOOST",
])
EColMat = make_enum([
    "DEFAULT", "SCENARIO_GENERIC", "FLESH_GENERIC", "DAMAGE_BLOCKED",
    "METAL", "ENERGY", "DIRT", "ROCK", "ICE", "UNDER_WATER",
    "UNDER_WATER_SP", "MID_WATER", "MID_WATER_SP", "PUDDLE",
    "OIL", "END_WORLD",
])
EEvent = make_enum(["OnEnter", "OnExit", "OnAllExit", "OnStay", "OnEnable", "OnDisable", "TE_COUNT"])
ELinkMode = make_enum({"None": 0, "RootToDC_Grab": 1, "FeetToRoot": 2})
ELightPreset = make_enum([
    "E_LIGHT_PRESET_NONE", "E_LIGHT_PRESET_PULSE", "E_LIGHT_PRESET_BLINK", "E_LIGHT_PRESET_LIGHTNING",
    "ELIGHT_PRESET_COUNT", "ELIGHT_PRESET_INVALID",
])
EElevatorDirection = make_enum(["UP", "DOWN"])
ELoadingScreen = make_enum([
    "E_LOADINGSCREEN_GUI_2D", "E_LOADINGSCREEN_VIDEO", "E_LOADINGSCREEN_ELEVATOR_UP", "E_LOADINGSCREEN_ELEVATOR_DOWN",
    "E_LOADINGSCREEN_MAIN_ELEVATOR_UP", "E_LOADINGSCREEN_MAIN_ELEVATOR_DOWN", "E_LOADINGSCREEN_TELEPORTER",
    "E_LOADINGSCREEN_TRAIN_LEFT", "E_LOADINGSCREEN_TRAIN_LEFT_AQUA", "E_LOADINGSCREEN_TRAIN_RIGHT",
    "E_LOADINGSCREEN_TRAIN_RIGHT_AQUA",
])
EReverbIntensity = make_enum([
    "NONE", "SMALL_ROOM", "MEDIUM_ROOM", "BIG_ROOM", "CATHEDRAL",
])
ELowPassFilter = make_enum([
    "LPF_DISABLED", "LPF_80HZ", "LPF_100HZ", "LPF_128HZ", "LPF_160HZ", "LPF_200HZ", "LPF_256HZ",
    "LPF_320HZ", "LPF_400HZ", "LPF_500HZ", "LPF_640HZ", "LPF_800HZ", "LPF_1000HZ", "LPF_1280HZ",
    "LPF_1600HZ", "LPF_2000HZ", "LPF_2560HZ", "LPF_3200HZ", "LPF_4000HZ", "LPF_5120HZ", "LPF_6400HZ",
    "LPF_8000HZ", "LPF_10240HZ", "LPF_12800HZ", "LPF_16000HZ",
])
ESndType = make_enum([
    "SFX", "MUSIC", "SPEECH", "GRUNT", "GUI", "ENVIRONMENT_STREAMS", "SFX_EMMY", "CUTSCENE",
])
EPositionalType = make_enum([
    "POS_2D", "POS_3D",
])

# Root stuff

BRFLD = Struct(
    magic=Const('CScenario', PropertyEnum),
    intro_a=Hex(Int32ul),
    intro_b=Hex(Int32ul),
    intro_c=Hex(Int32ul),

    # gameeditor::CGameModelRoot
    root=Object({
        "pScenario": Pointer_CScenario.create_construct(),
    }),
    raw=GreedyBytes,
)


class Brfld(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BRFLD
