import functools

import construct
from construct.core import (
    Const,
    Construct,
    Flag,
    Hex,
    Int32sl,
    Int32ul,
    Struct,
    Switch,
)

from mercury_engine_data_structures.common_types import Char, CVector3D, Float, StrId, make_dict
from mercury_engine_data_structures.construct_extensions.misc import ErrorWithMessage
from mercury_engine_data_structures.formats.base_resource import BaseResource
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
            'v': CVector3D
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
