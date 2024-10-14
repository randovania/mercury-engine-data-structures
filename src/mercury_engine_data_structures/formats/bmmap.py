from __future__ import annotations

import functools
from typing import TYPE_CHECKING

from mercury_engine_data_structures.base_resource import BaseResource
from mercury_engine_data_structures.formats import standard_format

if TYPE_CHECKING:
    from construct import Construct, Container

    from mercury_engine_data_structures.game_check import Game

BMMAP = standard_format.create("CMinimapData", "1.0.2")


class Bmmap(BaseResource):
    @classmethod
    @functools.lru_cache
    def construct_class(cls, target_game: Game) -> Construct:
        return BMMAP.compile()

    @property
    def items(self) -> Container:
        return self.raw.Root.mapItems

    @property
    def ability_labels(self) -> Container:
        return self.raw.Root.mapAbilityLabels

    def get_category(self, name: str) -> Container:
        return self.raw.Root[name]
