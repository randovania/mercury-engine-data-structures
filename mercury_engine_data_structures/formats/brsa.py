from construct import (
    Struct, Construct, Const, GreedyBytes, Int32ul, Hex,
)

from mercury_engine_data_structures.formats import BaseResource
from mercury_engine_data_structures.formats.dread_types import Pointer_CSubAreaManager
from mercury_engine_data_structures.game_check import Game
from mercury_engine_data_structures.hashed_names import PropertyEnum
from mercury_engine_data_structures.object import Object

# Root stuff

BRSA = Struct(
    magic=Const('CSubAreaManager', PropertyEnum),
    magic_number=Const(0x02010002, Hex(Int32ul)),

    # gameeditor::CGameModelRoot
    root_type=Const('Root', PropertyEnum),
    root=Object({
        "pSubareaManager": Pointer_CSubAreaManager.create_construct(),
    }),
    raw=GreedyBytes,
)


class Brsa(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BRSA
