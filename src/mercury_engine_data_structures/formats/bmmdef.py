from __future__ import annotations

from typing import TYPE_CHECKING

from construct import Construct, Container

from mercury_engine_data_structures.base_resource import BaseResource
from mercury_engine_data_structures.common_types import Vec2
from mercury_engine_data_structures.formats import standard_format

if TYPE_CHECKING:
    from mercury_engine_data_structures.game_check import Game

BMMDEF = standard_format.create("CMinimapDef", "1.0.2")


class Bmmdef(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BMMDEF

    @property
    def icons(self) -> Container:
        return self.raw.Root.mapIconDefs

    def add_icon(
        self,
        icon_id: str,
        uSpriteRow: int,
        uSpriteCol: int,
        sInspectorLabel: str,
        sDisabledIconId: str = "",
        vAnchorOffset: Vec2 | None = None,
        bAutoScale: bool = True,
        **kwargs,
    ):
        if vAnchorOffset is None:
            vAnchorOffset = Vec2(0.0, 0.0)

        icon = Container()
        icon.uSpriteRow = uSpriteRow
        icon.uSpriteCol = uSpriteCol
        icon.sDisabledIconId = sDisabledIconId
        icon.sInspectorLabel = sInspectorLabel
        icon.vAnchorOffset = vAnchorOffset
        icon.bAutoScale = bAutoScale
        for k, v in kwargs.items():
            icon[k] = v

        self.icons[icon_id] = icon
