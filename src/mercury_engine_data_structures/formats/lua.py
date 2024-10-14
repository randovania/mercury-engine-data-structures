from __future__ import annotations

import typing

import construct

from mercury_engine_data_structures.base_resource import BaseResource
from mercury_engine_data_structures.common_types import StrId
from mercury_engine_data_structures.game_check import Game

if typing.TYPE_CHECKING:
    import typing_extensions

    from mercury_engine_data_structures.file_tree_editor import FileTreeEditor

LUA = construct.Struct(
    lua_text=StrId,
)


class Lua(BaseResource):
    @classmethod
    def parse(cls, data: bytes, target_game: Game, editor: FileTreeEditor | None = None) -> typing_extensions.Self:
        raise ValueError("Lua files cannot be parsed because it requires decompilation")

    def build(self) -> bytes:
        if self.target_game == Game.SAMUS_RETURNS:
            import randovania_lupa.lua51_sr as lupa
        elif self.target_game == Game.DREAD:
            import randovania_lupa.lua51_dread as lupa
        else:
            raise ValueError("Unknown game")
        lua = lupa.LuaRuntime()
        byte_ret = lua.compile_to_bytes(self._raw["lua_text"])
        return byte_ret
