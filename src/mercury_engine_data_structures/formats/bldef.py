from __future__ import annotations

from construct import Construct, Container

from mercury_engine_data_structures.formats import standard_format
from mercury_engine_data_structures.formats.base_resource import BaseResource
from mercury_engine_data_structures.game_check import Game


class Bldef(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return standard_format.game_model("CLightManager", "1.0.2")

    @property
    def lightdefs(self) -> Container:
        return self.raw.Root.pLightManager.dicLightDefs
