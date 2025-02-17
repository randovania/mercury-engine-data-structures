from __future__ import annotations

from typing import TYPE_CHECKING

from mercury_engine_data_structures.base_resource import BaseResource
from mercury_engine_data_structures.formats import standard_format

if TYPE_CHECKING:
    import construct

    from mercury_engine_data_structures.game_check import Game


class Brev(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> construct.Construct:
        return standard_format.game_model("CEnvironmentVisualPresets", "4.2.2")
