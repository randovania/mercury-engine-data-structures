from __future__ import annotations

import copy

import construct
from construct import Array, Container, Flag, Hex, Int8ul, Int16ul, Rebuild, Struct, Switch

from mercury_engine_data_structures import game_check
from mercury_engine_data_structures.common_types import (
    CVector2D,
    CVector3D,
    CVector4D,
    Float,
    StrId,
    UInt,
    Vec2,
    Vec3,
    Vec4,
    make_vector,
)
from mercury_engine_data_structures.construct_extensions.misc import ErrorWithMessage, OptionalValue

CollisionPoint = Struct(
    "position" / CVector2D,
    "material_attribute" / UInt,
)
CollisionPolySR = Struct(
    "num_points" / Rebuild(UInt, construct.len_(construct.this.points)),
    "unk4" / Hex(construct.Byte),
    "unk5" / Hex(UInt),
    "points" / Array(construct.this.num_points, CollisionPoint),
    "boundings" / CVector4D,
)
CollisionPolyDread = Struct(
    "num_points" / Rebuild(UInt, construct.len_(construct.this.points)),
    "unk" / Hex(UInt),
    "points" / Array(construct.this.num_points, CollisionPoint),
    "loop" / Flag,
    "boundings" / CVector4D,
)
CollisionPoly = game_check.is_sr_or_else(CollisionPolySR, CollisionPolyDread)

BinarySearchTree = Struct(
    "binary_search_index1" / Int16ul,
    "binary_search_index2" / Int16ul,
    "boundings" / CVector4D,
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
        "total_boundings" / CVector4D,
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


class PolyData:
    def __init__(self, raw: Container):
        self._raw = raw

    @property
    def num_points(self) -> int:
        return self._raw.num_points

    @num_points.setter
    def num_points(self, value: int) -> None:
        self._raw.num_points = value

    @property
    def boundings(self) -> Vec4:
        return self._raw.boundings

    @boundings.setter
    def boundings(self, value: Vec4) -> None:
        self._raw.boundings = value

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
        self.num_points += 1


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
    def data(self) -> dict[Vec3, list[dict], Vec4, list[dict]]:
        return self._raw.data

    @data.setter
    def data(self, value: dict[Vec3, list[dict], Vec4, list[dict]]) -> None:
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

    @total_boundings.setter
    def total_boundings(self, value: Vec4) -> None:
        self.data.total_boundings = value

    @property
    def polys(self) -> list[dict]:
        return self.data.polys

    @polys.setter
    def polys(self, value: list[dict]) -> None:
        self.data.polys = value

    def get_poly(self, poly_idx: int) -> PolyData:
        """Returns all data associated with a poly"""
        return PolyData(self.polys[poly_idx])

    def get_bst(self, bst_idx: int) -> Container:
        """Returns a binary search tree"""
        return self.data.binary_search_trees[bst_idx]
