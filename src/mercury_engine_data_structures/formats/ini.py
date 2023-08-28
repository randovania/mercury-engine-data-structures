from __future__ import annotations

import io
import typing
from configparser import ConfigParser
from typing import Any

from construct import Construct, Container, GreedyString, Struct

from mercury_engine_data_structures.formats.base_resource import BaseResource
from mercury_engine_data_structures.game_check import Game

if typing.TYPE_CHECKING:
    from mercury_engine_data_structures.file_tree_editor import FileTreeEditor

INI = Struct('text' / GreedyString('utf-8'))


class Ini(BaseResource):
    def __init__(self, raw: Container, target_game: Game, editor: FileTreeEditor | None = None):
        super().__init__(raw, target_game, editor)
        self._config = None

    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return INI

    @staticmethod
    def parse_option(value: Any) -> str:
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, int):
            return f"{value:d}"
        if isinstance(value, float):
            return f"{value:#f}"
        raise TypeError(f"Unsupported config.ini type {type(value)}")

    @property
    def config(self) -> ConfigParser:
        if self._config is None:
            self._config = ConfigParser(strict=False)
            self._config.optionxform = lambda option: option
            self._config.read_string(self.raw.text, source='config.ini')
        return self._config

    def build(self) -> bytes:
        out = io.StringIO()
        self.config.write(out)
        self._raw.text = out.getvalue()
        return super().build()
