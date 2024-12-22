from __future__ import annotations

import functools
from typing import TYPE_CHECKING, Any

import construct
from construct.core import (
    Const,
    Construct,
    Container,
    Flag,
    Int32sl,
    Struct,
    Switch,
)

from mercury_engine_data_structures.base_resource import BaseResource
from mercury_engine_data_structures.common_types import Char, CVector3D, Float, StrId, VersionAdapter, make_dict
from mercury_engine_data_structures.construct_extensions.misc import ErrorWithMessage

if TYPE_CHECKING:
    from mercury_engine_data_structures.game_check import Game

# Functions
TunableParam = Struct(
    type=Char,
    value=Switch(
        construct.this.type,
        {"s": StrId, "f": Float, "b": Flag, "i": Int32sl, "v": CVector3D},
        ErrorWithMessage(lambda ctx: f"Unknown argument type: {ctx.type}", construct.SwitchError),
    ),
)

TunableClass = Struct(
    "tunables" / make_dict(TunableParam),
)

# BMTUN
BMTUN = Struct(
    "_magic" / Const(b"MTUN"),
    "version" / VersionAdapter("1.5.0"),
    "classes" / make_dict(TunableClass),
    construct.Terminated,
)  # fmt: skip


class Bmtun(BaseResource):
    @classmethod
    @functools.lru_cache
    def construct_class(cls, target_game: Game) -> Construct:
        return BMTUN

    def get_tunable(self, tunable: str, param: str) -> Container:
        classes = self.raw.classes
        if tunable not in classes:
            raise ValueError(f"Unknown tunable: {tunable}!")
        if param not in classes[tunable].tunables:
            raise ValueError(f"Unknown tunable param: {param}!")
        return self.raw.classes[tunable].tunables[param]

    def set_tunable(self, tunable_name: str, param: str, value: Any) -> None:
        tunable = self.get_tunable(tunable_name, param)
        tunable.value = value
