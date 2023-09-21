import functools

import construct
from construct.core import (
    Array,
    Const,
    Construct,
    Flag,
    Float32l,
    Hex,
    Int32sl,
    Int32ul,
    Struct,
    Switch,
)

from mercury_engine_data_structures.common_types import Char, Float, StrId, make_dict
from mercury_engine_data_structures.construct_extensions.misc import ErrorWithMessage
from mercury_engine_data_structures.formats import BaseResource
from mercury_engine_data_structures.game_check import Game

# Functions
TunableParam = Struct(
    type=Char,
    value=Switch(
        construct.this.type,
        {
            's': StrId,
            'f': Float,
            'b': Flag,
            'i': Int32sl,
            'v': Array(3, Float32l)
        },
        ErrorWithMessage(lambda ctx: f"Unknown argument type: {ctx.type}", construct.SwitchError)
    )
)

TunableClass = Struct(
    "tunables" / make_dict(TunableParam),
)

# BMTUN
BMTUN = Struct(
    "_magic" / Const(b"MTUN"),
    "version" / Const(0x00050001, Hex(Int32ul)),
    "classes" / make_dict(TunableClass),
    construct.Terminated,
)


class Bmtun(BaseResource):
    @classmethod
    @functools.lru_cache
    def construct_class(cls, target_game: Game) -> Construct:
        return BMTUN
