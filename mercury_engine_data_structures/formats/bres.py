from construct import (
    Struct, Construct, Const, GreedyBytes, Int32ul, Hex,
)

from mercury_engine_data_structures.formats import BaseResource
from mercury_engine_data_structures.formats.dread_types import Pointer_CEnvironmentManager
from mercury_engine_data_structures.game_check import Game
from mercury_engine_data_structures.hashed_names import PropertyEnum
from mercury_engine_data_structures.object import Object

# Root stuff

BRES = Struct(
    magic=Const("CEnvironmentSoundPresets", PropertyEnum),
    magic_number=Const(0x02020001, Hex(Int32ul)),

    # gameeditor::CGameModelRoot
    root_type=Const('Root', PropertyEnum),
    root=Object({
        "pEnvironmentManager": Pointer_CEnvironmentManager.create_construct(),
    }),
    raw=GreedyBytes,
)


class Bres(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BRES
