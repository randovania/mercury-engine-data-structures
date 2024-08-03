import construct
from construct.core import (
    Array,
    Const,
    Construct,
    If,
    Int16ul,
    Int32ul,
    Int64ul,
    Rebuild,
    Struct,
    Terminated,
)

from mercury_engine_data_structures import game_check
from mercury_engine_data_structures.common_types import VersionAdapter
from mercury_engine_data_structures.formats.base_resource import BaseResource

BUCT = Struct(
    _magic = Const(b"MUCT"),
    version = game_check.is_sr_or_else(
        VersionAdapter("1.3.0"),
        VersionAdapter("1.4.0")
    ),
    size = Rebuild(Int32ul, construct.len_(construct.this.data)),
    _padding = If(game_check.current_game_at_least(game_check.Game.DREAD), Const(0xFFFFFFFF, Int32ul)),
    _data_start = game_check.is_sr_or_else(
        Const(0x10, Int32ul),
        Const(0x18, Int64ul)
    ),
    data=Array(construct.this.size, Struct(
        char_maybe = Int16ul, # I think this could be utf8 chars?
        _padding = game_check.is_sr_or_else(
            Const(0x0000, Int16ul),
            Const(0xFFFF, Int16ul),
        ),
        index = Int32ul
    )),
    _eof=Terminated
)

class Buct(BaseResource):
    @classmethod
    def construct_class(cls, target_game: game_check.Game) -> Construct:
        return BUCT
