from typing import Dict
from construct.core import Struct, Construct, Const, GreedyRange

from mercury_engine_data_structures.common_types import DictAdapter, DictElement
from mercury_engine_data_structures.construct_extensions.strings import CStringRobust
from mercury_engine_data_structures.formats import BaseResource
from mercury_engine_data_structures.game_check import Game


TXT = Struct(
    "magic" / Const(b'BTXT'),
    "version" / Const(b'\x01\x00\x0a\x00'),
    "strings" / DictAdapter(GreedyRange(DictElement(CStringRobust("utf-16-le"))))
)

class Txt(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return TXT

    @property
    def strings(self) -> Dict[str, str]:
        return self._raw.strings
    
    @strings.setter
    def strings(self, value):
        self._raw.strings = value
