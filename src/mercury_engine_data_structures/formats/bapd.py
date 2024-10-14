from __future__ import annotations

from typing import TYPE_CHECKING

from mercury_engine_data_structures.base_resource import BaseResource
from mercury_engine_data_structures.formats.standard_format import game_model

if TYPE_CHECKING:
    import construct

    from mercury_engine_data_structures.game_check import Game

BAPD = game_model("sound::CAudioPresets", "2.3.2")


class Bapd(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> construct.Construct:
        return BAPD
