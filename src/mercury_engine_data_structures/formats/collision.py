from __future__ import annotations

import copy

import construct
from construct import (
    Array,
    BitsInteger,
    BitStruct,
    ByteSwapped,
    Container,
    Flag,
    Hex,
    Int8ul,
    Int16ul,
    Rebuild,
    Struct,
    Switch,
)

from mercury_engine_data_structures import game_check
from mercury_engine_data_structures.common_types import (
    CVector2D,
    CVector3D,
    Float,
    StrId,
    UInt,
    Vec2,
    Vec3,
    Vec4,
    make_vector,
)
from mercury_engine_data_structures.construct_extensions.misc import ErrorWithMessage, OptionalValue


def calculate_poly_boundings(ctx: Container) -> Container:
    x1 = min(point.position.x for point in ctx.points)
    y1 = min(point.position.y for point in ctx.points)
    x2 = max(point.position.x for point in ctx.points)
    y2 = max(point.position.y for point in ctx.points)
    return Container({"min": Vec2(x1, y1), "max": Vec2(x2, y2)})


def calculate_collection_boundings(ctx: Container) -> Container:
    x1 = min(poly.boundings.min.x for poly in ctx.polys)
    y1 = min(poly.boundings.min.y for poly in ctx.polys)
    x2 = max(poly.boundings.max.x for poly in ctx.polys)
    y2 = max(poly.boundings.max.y for poly in ctx.polys)
    return Container({"min": Vec2(x1, y1), "max": Vec2(x2, y2)})


BoundingBox2D = Struct("min" / CVector2D, "max" / CVector2D)

CollisionPoint = Struct(
    "position" / CVector2D,
    "material_attribute" / UInt,
)
CollisionPolySR = Struct(
    "num_points" / Rebuild(UInt, construct.len_(construct.this.points)),
    "unk4" / Hex(construct.Byte),
    "unk5" / Hex(UInt),
    "points" / Array(construct.this.num_points, CollisionPoint),
    "boundings" / Rebuild(BoundingBox2D, calculate_poly_boundings),
)
CollisionPolyDread = Struct(
    "num_points" / Rebuild(UInt, construct.len_(construct.this.points)),
    "unk" / Hex(UInt),
    "points" / Array(construct.this.num_points, CollisionPoint),
    "loop" / Flag,
    "boundings" / Rebuild(BoundingBox2D, calculate_poly_boundings),
)
CollisionPoly = game_check.is_sr_or_else(CollisionPolySR, CollisionPolyDread)

BinarySearchTree = Struct(
    "search_result" / ByteSwapped(
        BitStruct(
            "is_leaf" / Flag,
            "pass" / BitsInteger(15),
            "fail" / BitsInteger(16),
        )
    ),
    "boundings" / BoundingBox2D,
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
        "total_boundings" / Rebuild(BoundingBox2D, calculate_collection_boundings),
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


class Bounds2D:
    def __init__(self, raw: Container):
        self._raw = raw

    @property
    def min(self) -> Vec2:
        return self._raw.min

    @min.setter
    def min(self, value: Vec2) -> None:
        self._raw.min = value

    @property
    def max(self) -> Vec2:
        return self._raw.max

    @max.setter
    def max(self, value: Vec2) -> None:
        self._raw.max = value


class PolyData:
    def __init__(self, raw: Container):
        self._raw = raw

    @property
    def num_points(self) -> int:
        return len(self._raw.points)

    @property
    def boundings(self) -> Vec4:
        return self._raw.boundings

    def get_boundings(self) -> Bounds2D:
        return Bounds2D(calculate_poly_boundings(self._raw))

    def get_point(self, point_idx: int) -> PointData:
        return PointData(self._raw.points[point_idx])

    def add_point(self, position: Vec2, idx: int = 0) -> None:
        """
        Adds a new point by copying an existing point and inserting it at a specified index
        param position: the x,y position of the new point
        param idx: the index the new point will be placed in the poly
        """
        new_point = copy.deepcopy(self.get_point(0))
        new_point.position = position
        self._raw.points.insert(idx, new_point)

    def remove_point(self, idx: int) -> None:
        """
        Removes a point from a poly by index
        param idx: the index of the point to remove
        """
        self._raw.points.pop(idx)


class PointData:
    def __init__(self, raw: Container):
        self._raw = raw

    @property
    def position(self) -> Vec2:
        return self._raw.position

    @position.setter
    def position(self, value: Vec2) -> None:
        self._raw.position = value

    @property
    def material_attribute(self) -> int:
        return self._raw.material_attribute

    @material_attribute.setter
    def material_attribute(self, value: int = 1) -> None:
        self._raw.material_attribute = value


class CollisionEntry:
    def __init__(self, raw: Container):
        self._raw = raw

    @property
    def data(self) -> Container:
        return self._raw.data

    @data.setter
    def data(self, value: Container) -> None:
        self._raw.data = value

    @property
    def position(self) -> Vec3:
        return self.data.position

    @position.setter
    def position(self, value: Vec3) -> None:
        self.data.position = value

    @property
    def total_boundings(self) -> Vec4:
        return self.data.total_boundings

    def get_total_boundings(self) -> Bounds2D:
        return Bounds2D(calculate_collection_boundings(self._raw))

    def get_poly(self, poly_idx: int) -> PolyData:
        """Returns all data associated with a poly"""
        return PolyData(self._raw.data.polys[poly_idx])
