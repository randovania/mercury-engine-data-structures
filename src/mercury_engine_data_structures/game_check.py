"""
For checking which game is being parsed
"""

from __future__ import annotations

from enum import Enum
from functools import cached_property
from typing import TYPE_CHECKING, Any

import construct
from construct.core import IfThenElse

from mercury_engine_data_structures import crc

if TYPE_CHECKING:
    from collections.abc import Callable


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

    @cached_property
    def known_hashes_table(self):
        if self == Game.DREAD:
            from mercury_engine_data_structures import dread_data

            return dread_data.all_name_to_asset_id()
        elif self == Game.SAMUS_RETURNS:
            from mercury_engine_data_structures import samus_returns_data

            return samus_returns_data.all_name_to_asset_id()
        else:
            raise ValueError(f"Unsupported game: {self}")


class GameVersion(Enum):
    as_string: str
    game: Game
    bitmask: int
    toc_hash: bytes
    all_files_hash: bytes

    MSR = (0, "1.0.0", Game.SAMUS_RETURNS, 1, "E9F1963CCCD5002CF6DE6E844528DF46", "83E382FB3E95061185184CE7FCB45AF8")
    DREAD_1_0_0 = (1, "1.0.0", Game.DREAD, 1, "8DEC0C18622C6DAC370F84CF3A3AC0B4", "862EB0111C28082F5730FACF583CEF7B")
    DREAD_1_0_1 = (2, "1.0.1", Game.DREAD, 2, "35309081AF05C60CEBC476F78F3609B6", "00")
    DREAD_2_0_0 = (3, "2.0.0", Game.DREAD, 4, "B36FB05261F2E4EAF0408760E1B983FD", "00")
    DREAD_2_1_0 = (4, "2.1.0", Game.DREAD, 8, "782820635AC434A18DF11DE3D4052DD1", "F1A3ABE49305A16F4671E9E64EBCA119")
    UNDEFINED = (-1, "UNDEFINED", None, 2**15, "", "")

    def __new__(cls, value: int, string: str, game: Game, bitmask: int, toc_hash: str, all_files_hash: str):
        member = object.__new__(cls)
        member._value_ = value
        member.as_string = string
        member.game = game
        member.bitmask = bitmask
        member.toc_hash = bytes.fromhex(toc_hash)
        member.all_files_hash = bytes.fromhex(all_files_hash)

        return member

    @classmethod
    def get_value(cls, game: Game, version: str):
        for gv in cls:
            if gv.game == game and gv.version == version:
                return gv.value

        return -1

    @classmethod
    def versions_for_game(cls, game: Game) -> dict[str, GameVersion]:
        return {gv.as_string: gv for gv in cls if gv.game == game}


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


def is_at_most(target: Game, subcon_true, subcon_false) -> IfThenElse:
    result = IfThenElse(construct.this._params.target_game <= target, subcon_true, subcon_false)

    def _emitbuild(code: construct.CodeGen):
        code.append("from mercury_engine_data_structures.game_check import Game")
        return (
            f"(({result.thensubcon._compilebuild(code)}) "
            f"if ({result.condfunc}) "
            f"else ({result.elsesubcon._compilebuild(code)}))"
        )

    result._emitbuild = _emitbuild

    return result


class GameSpecificStruct(construct.Subconstruct):
    def __init__(self, subcon, game: Game):
        super().__init__(subcon)
        self.target_game = game

    def _parse(self, stream, context, path):
        if get_current_game(context) != self.target_game:
            raise construct.ExplicitError(f"Expected {self.target_game}, got {get_current_game(context)}", path=path)

        return super()._parse(stream, context, path)

    def _build(self, obj, stream, context, path):
        if get_current_game(context) != self.target_game:
            raise construct.ExplicitError(f"Expected {self.target_game}, got {get_current_game(context)}", path=path)

        return super()._build(obj, stream, context, path)

    def _emitparse(self, code: construct.CodeGen):
        code.append("from mercury_engine_data_structures.game_check import Game")
        code.append(f"TARGET_GAME = Game.{self.target_game.name}")
        return self.subcon._emitparse(code)

    def _emitbuild(self, code: construct.CodeGen):
        code.append("from mercury_engine_data_structures.game_check import Game")
        code.append(f"TARGET_GAME = Game.{self.target_game.name}")
        return self.subcon._emitbuild(code)
