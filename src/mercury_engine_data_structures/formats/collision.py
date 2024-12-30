from __future__ import annotations

import construct
from construct import Array, Container, Flag, Hex, Int8ul, Int16ul, Rebuild, Struct, Switch

from mercury_engine_data_structures import game_check
from mercury_engine_data_structures.common_types import (
    CVector2D,
    CVector3D,
    Float,
    StrId,
    UInt,
    make_vector,
)
from mercury_engine_data_structures.construct_extensions.misc import ErrorWithMessage, OptionalValue
from mercury_engine_data_structures.game_check import Game

CollisionPoint = Struct(
    "x" / Float,
    "y" / Float,
    "material_attribute" / UInt,
)
CollisionPolySR = Struct(
    "num_points" / Rebuild(UInt, construct.len_(construct.this.points)),
    "unk4" / Hex(construct.Byte),
    "unk5" / Hex(UInt),
    "points" / Array(construct.this.num_points, CollisionPoint),
    "boundings" / Array(4, Float),
)
CollisionPolyDread = Struct(
    "num_points" / Rebuild(UInt, construct.len_(construct.this.points)),
    "unk" / Hex(UInt),
    "points" / Array(construct.this.num_points, CollisionPoint),
    "loop" / Flag,
    "boundings" / Array(4, Float),
)
CollisionPoly = game_check.is_at_most(Game.SAMUS_RETURNS, CollisionPolySR, CollisionPolyDread)

BinarySearchTree = Struct(
    "binary_search_index1" / Int16ul,
    "binary_search_index2" / Int16ul,
    "boundings" / Array(4, Float),
)

collision_formats = {
    "AABOX2D": Struct(
        "position" / CVector3D,
        "size" / CVector2D,
    ),
    "CIRCLE": Struct(
        "position" / CVector3D,
        "size" / Float,
    ),
    "CAPSULE2D": Struct(
        "value1" / Float,
        "value2" / Float,
        "value3" / Float,
        "value4" / Float,
        "value5" / Float,
    ),
    "OBOX2D": Struct(
        "position" / CVector3D,
        "angle" / Float,
        "size" / CVector2D,
    ),
    "POLYCOLLECTION2D": Struct(
        "position" / CVector3D,
        "polys" / make_vector(CollisionPoly),
        "total_boundings" / Array(4, Float),
        "binary_search_trees" / OptionalValue(make_vector(BinarySearchTree)),
    ),
}

CollisionEntryConstruct = Struct(
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


class CollisionEntry:
    def __init__(self, raw: Container):
        self._raw = raw

    def get_data(self) -> Container:
        """Returns all data of collision/collision_camera/logic shape"""
        return self._raw.data

    def get_poly(self, poly_idx: int):
        """Returns all data associated with a poly (points, boundings)"""
        return self.get_data().polys[poly_idx]

    def get_point(self, poly_idx: int, point_idx: int) -> Container:
        """Returns a specific point in a poly"""
        return self.get_poly(poly_idx).points[point_idx]

    def get_total_boundings(self) -> Container:
        """Returns the total boundary of collision/collision_camera/logic shape"""
        return self.get_data().total_boundings

    def get_poly_boundings(self, poly_idx: int) -> Container:
        """Returns the boundary of a poly"""
        return self.get_poly(poly_idx).boundings
