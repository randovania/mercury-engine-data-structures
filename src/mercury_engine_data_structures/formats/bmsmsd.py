from __future__ import annotations

import functools
from enum import Enum
from typing import TYPE_CHECKING

import construct
from construct.core import (
    Const,
    Construct,
    Container,
    Int32sl,
    Int32ul,
    Struct,
)

from mercury_engine_data_structures.adapters.enum_adapter import EnumAdapter
from mercury_engine_data_structures.adapters.flagsenum_adapter import FlagsEnumAdapter
from mercury_engine_data_structures.base_resource import BaseResource
from mercury_engine_data_structures.common_types import (
    BoundingBox2D,
    CVector2D,
    CVector3D,
    StrId,
    Vec2,
    Vec3,
    VersionAdapter,
    make_vector,
)

if TYPE_CHECKING:
    from mercury_engine_data_structures.game_check import Game


class TileBorder(int, Enum):
    TOP = 1
    BOTTOM = 2
    LEFT = 4
    RIGHT = 8
    OPEN_TOP = 16
    OPEN_BOTTOM = 32
    OPEN_LEFT = 64
    OPEN_RIGHT = 128


TileBorderConstruct = FlagsEnumAdapter(TileBorder, Int32sl)


class TileType(int, Enum):
    NORMAL = 1
    HEAT = 2
    ACID = 4
    ACID_RISE = 8
    ACID_FALL = 12


TileTypeConstruct = EnumAdapter(TileType, Int32ul)


class IconPriority(int, Enum):
    METROID = -1
    ACTOR = 0
    SHIP = 1
    ENERGY_CLOUD = 2
    DOOR = 3
    CHOZO_SEAL = 4
    HIDDEN_ITEM = 5


IconPriorityConstruct = EnumAdapter(IconPriority, Int32sl)

# BMSMSD
BMSMSD = Struct(
    "_magic" / Const(b"MMSD"),
    "version" / VersionAdapter("1.7.0"),
    "scenario" / StrId,
    "tile_size" / CVector2D,
    "x_tiles" / Int32sl,
    "y_tiles" / Int32sl,
    "map_dimensions" / BoundingBox2D,
    "tiles" / make_vector(
        Struct(
            "tile_coordinates" / construct.Array(2, Int32sl),
            "tile_dimensions" / BoundingBox2D,
            "tile_borders" / TileBorderConstruct,
            "tile_type" / TileTypeConstruct,
            "icons" / make_vector(
                Struct(
                    "actor_name" / StrId,
                    "clear_condition" / StrId,
                    "icon" / StrId,
                    "icon_priority" / IconPriorityConstruct,
                    "coordinates" / CVector3D,
                )
            ),
        )
    ),
    construct.Terminated,
)  # fmt: skip


class IconProperties:
    def __init__(self, raw: Container) -> None:
        self._raw = raw

    @property
    def actor_name(self) -> str:
        return self._raw.actor_name

    @actor_name.setter
    def actor_name(self, value: str) -> None:
        self._raw.actor_name = value

    @property
    def clear_condition(self) -> str:
        return self._raw.clear_condition

    @clear_condition.setter
    def clear_condition(self, value: str) -> None:
        self._raw.clear_condition = value

    @property
    def icon(self) -> str:
        return self._raw.icon

    @icon.setter
    def icon(self, value: str) -> None:
        self._raw.icon = value

    @property
    def icon_priority(self) -> IconPriority:
        return self._raw.icon_priority

    @icon_priority.setter
    def icon_priority(self, value: IconPriority) -> None:
        self._raw.icon_priority = value

    @property
    def coordinates(self) -> Vec3:
        return self._raw.coordinates

    @coordinates.setter
    def coordinates(self, value: Vec3) -> None:
        self._raw.coordinates = value


class TileProperties:
    def __init__(self, raw: Container) -> None:
        self._raw = raw

    @property
    def tile_coordinates(self) -> list[int]:
        return self._raw.tile_coordinates

    @tile_coordinates.setter
    def tile_coordinates(self, value: list[int]) -> None:
        self._raw.tile_coordinates = value

    @property
    def tile_dimensions(self) -> dict[Vec2, Vec2]:
        return self._raw.tile_dimensions

    @tile_dimensions.setter
    def tile_dimensions(self, value: dict[Vec2, Vec2]) -> None:
        self._raw.tile_dimensions = value

    @property
    def tile_borders(self) -> dict[TileBorder, bool]:
        return self._raw.tile_borders

    @tile_borders.setter
    def tile_borders(self, border_type: dict[TileBorder, bool], value: bool) -> None:
        self._raw.tile_borders[border_type] = value

    @property
    def tile_type(self) -> TileType:
        return self._raw.tile_type

    @tile_type.setter
    def tile_type(self, value: TileType):
        self._raw.tile_type = value

    def get_icon(self, icon_idx: int = 0) -> IconProperties:
        return IconProperties(self._raw.icons[icon_idx])

    def add_icon(
        self,
        actor_name: str,
        clear_condition: str,
        icon: str,
        icon_priority: str,
        coordinates: Vec3,
    ) -> Container:
        new_icon = Container(
            {
                "actor_name": actor_name,
                "clear_condition": clear_condition,
                "icon": icon,
                "icon_priority": icon_priority,
                "coordinates": coordinates,
            }
        )

        self._raw.icons.append(new_icon)

    def remove_icon(self, icon_idx: int = 0) -> None:
        self._raw.icons.pop(icon_idx)


class Bmsmsd(BaseResource):
    @classmethod
    @functools.lru_cache
    def construct_class(cls, target_game: Game) -> Construct:
        return BMSMSD

    def get_tile(self, tile_idx: int) -> TileProperties:
        return TileProperties(self.raw.tiles[tile_idx])
