from __future__ import annotations

import functools

import construct
from construct.core import Const, Construct, GreedyRange, Struct

from mercury_engine_data_structures.base_resource import BaseResource
from mercury_engine_data_structures.common_types import DictAdapter, DictElement, VersionAdapter
from mercury_engine_data_structures.construct_extensions.strings import CStringRobust
from mercury_engine_data_structures.game_check import Game, is_sr_or_else

_string_range = GreedyRange(DictElement(CStringRobust("utf-16-le")))


def _emitparse(code: construct.CodeGen) -> str:
    n = code.allocateId()
    code.append(f"""
    def _parse_{n}(io, this):
        result = ListContainer()
        try:
            for i in itertools.count():
                this._index = i
                fallback = io.tell()
                result.append({_string_range.subcon._compileparse(code)})
        except StopFieldError:
            pass
        except ExplicitError:
            raise
        except Exception:
            io.seek(fallback)
        return result
    """)
    return f"_parse_{n}(io, this)"


_string_range._emitparse = _emitparse


TXT = Struct(
    "magic" / Const(b'BTXT'),
    "version" / is_sr_or_else(
        VersionAdapter("1.8.0"),
        VersionAdapter("1.10.0"),
    ),
    "strings" / DictAdapter(_string_range),
    "_end" / construct.Terminated,
)  # fmt: skip


class Txt(BaseResource):
    @classmethod
    @functools.lru_cache
    def construct_class(cls, target_game: Game) -> Construct:
        return TXT.compile()

    @property
    def strings(self) -> dict[str, str]:
        return self._raw.strings

    @strings.setter
    def strings(self, value):
        self._raw.strings = value
