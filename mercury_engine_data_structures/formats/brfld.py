from typing import Iterator

import construct

from mercury_engine_data_structures.formats import BaseResource, game_model_root
from mercury_engine_data_structures.game_check import Game

BRFLD = game_model_root.create('CScenario', 0x02000031)


class Brfld(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> construct.Construct:
        return BRFLD

    def actors_for_layer(self, name: str) -> dict:
        return self.raw.Root.pScenario.rEntitiesLayer.dctSublayers[name].dctActors

    def all_layers(self) -> Iterator[str]:
        yield from self.raw.Root.pScenario.rEntitiesLayer.dctSublayers.keys()

    def all_actors(self):
        for sublayer in self.raw.Root.pScenario.rEntitiesLayer.dctSublayers.values():
            yield from sublayer.dctActors.values()

    def follow_link(self, link: str):
        if link != '{EMPTY}':
            result = self.raw
            for part in link.split(":"):
                result = result[part]
            return result
