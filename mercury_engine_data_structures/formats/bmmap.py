from construct import Construct, Container

from mercury_engine_data_structures.formats import BaseResource, standard_format
from mercury_engine_data_structures.game_check import Game

BMMAP = standard_format.create('CMinimapData', 0x02000001)


class Bmmap(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BMMAP

    @property
    def items(self) -> Container:
        return self.raw.Root.mapItems

    @property
    def ability_labels(self) -> Container:
        return self.raw.Root.mapAbilityLabels

    def get_category(self, name: str) -> Container:
        return self.raw.Root[name]
