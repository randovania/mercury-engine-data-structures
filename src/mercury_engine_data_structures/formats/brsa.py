import functools
from typing import Iterator

from construct import Construct, Container

from mercury_engine_data_structures.formats import BaseResource, standard_format
from mercury_engine_data_structures.game_check import Game


class Brsa(BaseResource):
    @classmethod
    @functools.lru_cache
    def construct_class(cls, target_game: Game) -> Construct:
        return standard_format.game_model('CSubAreaManager', 0x02010002)

    @property
    def subarea_setups(self) -> Iterator[Container]:
        yield from self.raw.Root.pSubareaManager.vSubareaSetups

    def get_subarea_setup(self, id: str) -> Container:
        return next(setup for setup in self.subarea_setups if setup.sId == id)

    def get_subarea_config(self, id: str, setup_id: str) -> Container:
        return next(config for config in self.get_subarea_setup(setup_id).vSubareaConfigs if config.sId == id)
