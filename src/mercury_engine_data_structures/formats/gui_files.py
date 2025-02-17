from __future__ import annotations

from typing import TYPE_CHECKING

from mercury_engine_data_structures.base_resource import BaseResource
from mercury_engine_data_structures.formats import standard_format

if TYPE_CHECKING:
    from construct import Construct, Container

    from mercury_engine_data_structures.game_check import Game

BMSCP = standard_format.create("GUI::CDisplayObjectContainer", "1.2.2", explicit_root=True)
BMSSH = standard_format.create("GUI::CGUIManager::ShapeContainer", "1.2.2", explicit_root=True)
BMSSK = standard_format.create("GUI::CGUIManager::SkinContainer", "1.2.2", explicit_root=True)
BMSSS = standard_format.create("GUI::CGUIManager::SpriteSheetContainer", "1.2.2", explicit_root=True)


class Bmscp(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BMSCP

    def get_child(self, path: str) -> Container:
        hier = path.split(".")
        root = self.raw.Root
        for child in hier:
            root = next(item for item in root.lstChildren if item.sID == child)
        return root


class Bmssh(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BMSSH


class Bmssk(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BMSSK


class Bmsss(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BMSSS
