from __future__ import annotations

from typing import TYPE_CHECKING

import construct
from construct.core import (
    Const,
    Construct,
    Container,
    Int8ul,
    Int16ul,
    Struct,
    Switch,
)

from mercury_engine_data_structures import game_check
from mercury_engine_data_structures.base_resource import BaseResource
from mercury_engine_data_structures.common_types import (
    StrId,
    VersionAdapter,
    make_vector,
)
from mercury_engine_data_structures.construct_extensions.misc import ErrorWithMessage
from mercury_engine_data_structures.formats.collision import collision_formats

if TYPE_CHECKING:
    from mercury_engine_data_structures.game_check import Game

CollisionEntryData = Struct(
    "name" / StrId,
    "prop1" / StrId,
    "prop2" / StrId,
    "prop3" / StrId,
    "flag"
    / game_check.is_sr_or_else(
        Int8ul,
        Int16ul,
    ),
    "type" / StrId,
    "data"
    / Switch(
        construct.this.type,
        collision_formats,
        ErrorWithMessage(lambda ctx: f"Type {ctx.type} not known, valid types are {list(collision_formats.keys())}."),
    ),
)

CollisionLayer = Struct(
    "name" / StrId,
    "entries" / make_vector(CollisionEntryData),
)

PartsComponent = Struct(
    "group" / StrId,
    "components" / make_vector(Struct("name" / StrId)),
)

BMSCC = Struct(
    "_magic" / Const(b"MSCD"),
    "_version"
    / game_check.is_sr_or_else(
        VersionAdapter("1.13.0"),
        VersionAdapter("1.16.0"),
    ),
    "layers" / make_vector(CollisionLayer),
    "parts" / construct.Optional(make_vector(PartsComponent)),
    construct.Terminated,
)


class CollisionEntry:
    def __init__(self, raw: Container):
        self._raw = raw

    def get_data(self) -> Container:
        """Returns all data of collision/collision_camera"""
        return self._raw.data

    def get_poly(self, poly_idx: int):
        """Returns all data associated with a poly (points, boundings)"""
        return self.get_data().polys[poly_idx]

    def get_point(self, poly_idx: int, point_idx: int) -> Container:
        """Returns a specific point in a poly"""
        return self.get_poly(poly_idx).points[point_idx]

    def get_total_boundings(self) -> Container:
        """Returns the total boundary of collision/collision_camera"""
        return self.get_data().total_boundings

    def get_poly_boundings(self, poly_idx: int) -> Container:
        """Returns the boundary of a poly"""
        return self.get_poly(poly_idx).boundings


class Bmscc(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BMSCC

    # Bmscc has an entry per collision_camera, Bmscd has one entry per file
    def get_entry(self, entry_idx: int = 0) -> CollisionEntry:
        return CollisionEntry(self.raw.layers[0].entries[entry_idx])
