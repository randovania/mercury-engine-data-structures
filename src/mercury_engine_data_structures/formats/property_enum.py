import enum
import functools
import typing
import warnings
from typing import Dict

import construct

from mercury_engine_data_structures import dread_data, samus_returns_data
from mercury_engine_data_structures.game_check import Game, is_sr_or_else


@functools.lru_cache
def _correct_data(game: Game):
    if game is Game.SAMUS_RETURNS:
        return samus_returns_data
    elif game is Game.DREAD:
        return dread_data
    else:
        raise ValueError("Unknown")


class HashSet(enum.Enum):
    PROPERTY = enum.auto()
    FILE_NAME = enum.auto()

    def known_hashes(self, context) -> Dict[str, int]:
        if self == HashSet.PROPERTY:
            return _correct_data(context._params.target_game).all_name_to_property_id()
        elif self == HashSet.FILE_NAME:
            return _correct_data(context._params.target_game).all_name_to_asset_id()
        else:
            raise ValueError("Unknown")

    def inverted_hashes(self, context) -> Dict[int, str]:
        if self == HashSet.PROPERTY:
            return _correct_data(context._params.target_game).all_property_id_to_name()
        elif self == HashSet.FILE_NAME:
            return _correct_data(context._params.target_game).all_asset_id_to_name()
        else:
            raise ValueError("Unknown")


HashedName = typing.Union[str, int]


class CRCAdapter(construct.Adapter):
    def __init__(self, hash_set: HashSet, allow_unknowns=False, display_warnings=True):
        self._raw_subcon = is_sr_or_else(construct.Int32ul, construct.Int64ul)
        super().__init__(construct.Hex(self._raw_subcon))
        self.hash_set = hash_set
        self.allow_unknowns = allow_unknowns
        self.display_warnings = display_warnings

    def _decode(self, obj: int, context, path) -> HashedName:
        try:
            return self.hash_set.inverted_hashes(context)[obj]
        except KeyError:
            msg = "no mapping for 0x{:08X} ({})".format(
                obj, obj.to_bytes(self._raw_subcon.sizeof(target_game=context._params.target_game),
                                  "little")
            )
            if self.allow_unknowns:
                if self.display_warnings:
                    warnings.warn(UserWarning(msg))
                return obj
            raise construct.MappingError(
                "parsing failed, " + msg,
                path=path,
            )

    def _encode(self, obj: HashedName, context, path):
        try:
            return self.hash_set.known_hashes(context)[obj]
        except KeyError:
            msg = f"no mapping for {obj}"
            if self.allow_unknowns:
                if self.display_warnings:
                    warnings.warn(UserWarning(msg))
                if isinstance(obj, int):
                    return obj
                else:
                    game: Game = context._params.target_game
                    return game.hash_asset(obj)

            raise construct.MappingError(
                "building failed, " + msg,
                path=path
            )

    def _emitparse(self, code: construct.CodeGen):
        n = self.hash_set.name
        code.append("from mercury_engine_data_structures.formats.property_enum import HashSet")

        if self.allow_unknowns:
            return (f"reuse({self.subcon._compileparse(code)}, "
                    f"lambda key: HashSet.{n}.inverted_hashes(this).get(key, key))")
        else:
            return f"HashSet.{n}.inverted_hashes(this)[{self.subcon._compileparse(code)}]"

    def _emitbuild(self, code: construct.CodeGen):
        if self.allow_unknowns:
            raise NotImplementedError

        n = self.hash_set.name
        code.append("from mercury_engine_data_structures.formats.property_enum import HashSet")

        ret: str = self._raw_subcon._compilebuild(code)
        return ret.replace(".pack(obj)", f".pack(HashSet.{n}.known_hashes(this)[obj])")


PropertyEnum = CRCAdapter(HashSet.PROPERTY)
PropertyEnumUnsafe = CRCAdapter(HashSet.PROPERTY, True)
PropertyEnumDoubleUnsafe = CRCAdapter(HashSet.PROPERTY, True, False)

FileNameEnum = CRCAdapter(HashSet.FILE_NAME)
FileNameEnumUnsafe = CRCAdapter(HashSet.FILE_NAME, True, False)
