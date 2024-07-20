from typing import Tuple

from construct import Construct, Container

from mercury_engine_data_structures.formats import standard_format
from mercury_engine_data_structures.formats.base_resource import BaseResource
from mercury_engine_data_structures.game_check import Game

BMMDEF = standard_format.create('CMinimapDef', "1.0.2")


class Bmmdef(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BMMDEF

    @property
    def icons(self) -> Container:
        return self.raw.Root.mapIconDefs

    def add_icon(self, icon_id: str, uSpriteRow: int, uSpriteCol: int,
            sInspectorLabel: str, sDisabledIconId: str = '',
            vAnchorOffset: Tuple[int, int] = (0, 0), bAutoScale: bool = True, **kwargs):
        icon = Container()
        icon.uSpriteRow = uSpriteRow
        icon.uSpriteCol = uSpriteCol
        icon.sDisabledIconId = sDisabledIconId
        icon.sInspectorLabel = sInspectorLabel
        icon.vAnchorOffset = list(vAnchorOffset)
        icon.bAutoScale = bAutoScale
        for k, v in kwargs.items():
            icon[k] = v

        self.icons[icon_id] = icon
