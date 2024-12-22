from __future__ import annotations

import functools
from typing import TYPE_CHECKING

import construct
from construct.core import (
    Const,
    Construct,
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

    def _check_tunable_exists(self, class_name: str, tunable_name: str) -> None:
        classes = self.raw.classes
        if class_name not in classes:
            raise KeyError(f"Unknown tunable: {class_name}!")
        if tunable_name not in classes[class_name].tunables:
            raise KeyError(f"Unknown tunable param: {tunable_name}!")

    def get_tunable(self, class_name: str, tunable_name: str) -> None:
        self._check_tunable_exists(class_name, tunable_name)
        return self.raw.classes[class_name].tunables[tunable_name].value

    def set_tunable(self, class_name: str, tunable_name: str, value: str | float | bool | int | list[float]) -> None:
        self._check_tunable_exists(class_name, tunable_name)
        self.raw.classes[class_name].tunables[tunable_name].value = value
