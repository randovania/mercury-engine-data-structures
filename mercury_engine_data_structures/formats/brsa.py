from typing import Iterator
from construct import Construct, Container

from mercury_engine_data_structures.formats import BaseResource, standard_format
from mercury_engine_data_structures.game_check import Game

BRSA = standard_format.game_model('CSubAreaManager', 0x02010002).compile()


class Brsa(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BRSA

    @property
    def subarea_setups(self) -> Iterator[Container]:
        for setup in self.raw.Root.pSubareaManager.vSubareaSetups:
            yield setup

    def get_subarea_setup(self, id: str) -> Container:
        return next(setup for setup in self.subarea_setups if setup.sId == id)
    
    def get_subarea_config(self, id: str, setup_id: str) -> Container:
        return next(config for config in self.get_subarea_setup(setup_id).vSubareaConfigs if config.sId == id)
