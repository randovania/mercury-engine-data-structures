"""
For checking which game is being parsed
"""
from enum import Enum
from typing import Any, Callable

import construct
from construct.core import IfThenElse

from mercury_engine_data_structures import crc


class Game(Enum):
    SAMUS_RETURNS = 10
    DREAD = 11

    def __eq__(self, other):
        if self.__class__ is other.__class__:
            return self.value == other.value
        elif isinstance(other, int):
            return self.value == other
        else:
            return False

    def __hash__(self):
        return id(self)

    def __ge__(self, other):
        if self.__class__ is other.__class__:
            return self.value >= other.value
        return NotImplemented

    def __gt__(self, other):
        if self.__class__ is other.__class__:
            return self.value > other.value
        return NotImplemented

    def __le__(self, other):
        if self.__class__ is other.__class__:
            return self.value <= other.value
        return NotImplemented

    def __lt__(self, other):
        if self.__class__ is other.__class__:
            return self.value < other.value
        return NotImplemented

    def hash_asset(self, msg: str) -> int:
        if self == Game.SAMUS_RETURNS:
            func = crc.crc32
        elif self == Game.DREAD:
            func = crc.crc64
        else:
            raise ValueError(f"Unsupported game: {self}")

        return func(msg)


def get_current_game(ctx):
    result = ctx["_params"]["target_game"]
    if not isinstance(result, Game):
        raise ValueError(f"build/parse didn't set a valid target_game. Expected `Game`, got {result}")

    return result


def is_samus_returns(ctx):
    return get_current_game(ctx) == Game.SAMUS_RETURNS


def is_dread(ctx):
    return get_current_game(ctx) == Game.DREAD


def current_game_at_most(target: Game) -> Callable[[Any], bool]:
    def result(ctx):
        return get_current_game(ctx) <= target

    return result


def current_game_at_least(target: Game) -> Callable[[Any], bool]:
    def result(ctx):
        return get_current_game(ctx) >= target

    return result


def is_sr_or_else(subcon1, subcon2) -> IfThenElse:
    return IfThenElse(construct.this._params.target_game == Game.SAMUS_RETURNS.value, subcon1, subcon2)
