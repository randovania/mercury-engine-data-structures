from enum import Enum

import construct
from construct.core import Const, Construct, GreedyRange, If, Int16ul, Int32ul, Prefixed, Struct, Terminated

from mercury_engine_data_structures.adapters.enum_adapter import EnumAdapter
from mercury_engine_data_structures.formats.base_resource import BaseResource
from mercury_engine_data_structures.game_check import Game

# Standard switch format. https://switchbrew.org/wiki/BNVIB#Normal_Vibration

class VibrationType(Enum):
    NORMAL = 4
    LOOP = 12
    LOOPWAIT = 16

BNVIB = Struct(
    "vibration_type" / EnumAdapter(VibrationType, Int32ul),
    "_magic" / Const(3, Int16ul),
    "sample_rate" / Int16ul,
    "loop_start" / If(construct.this.vibration_type != VibrationType.NORMAL, Int32ul),
    "loop_end" / If(construct.this.vibration_type != VibrationType.NORMAL, Int32ul),
    "loop_wait" / If(construct.this.vibration_type == VibrationType.LOOPWAIT, Int32ul),
    "data" / Prefixed(Int32ul, GreedyRange(Int32ul)),
    Terminated,
)

class Bnvib(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BNVIB
