from __future__ import annotations

import functools
from typing import TYPE_CHECKING

from mercury_engine_data_structures.base_resource import BaseResource
from mercury_engine_data_structures.formats import standard_format

if TYPE_CHECKING:
    from collections.abc import Iterator

    from construct import Construct, Container

    from mercury_engine_data_structures.game_check import Game


class Brsa(BaseResource):
    @classmethod
    @functools.lru_cache
    def construct_class(cls, target_game: Game) -> Construct:
        return standard_format.game_model("CSubAreaManager", "2.1.2")

    @property
    def subarea_setups(self) -> Iterator[Container]:
        yield from self.raw.Root.pSubareaManager.vSubareaSetups

    def get_subarea_setup(self, id: str) -> Container:
        return next(setup for setup in self.subarea_setups if setup.sId == id)

    def get_subarea_config(self, id: str, setup_id: str) -> Container:
        return next(config for config in self.get_subarea_setup(setup_id).vSubareaConfigs if config.sId == id)
