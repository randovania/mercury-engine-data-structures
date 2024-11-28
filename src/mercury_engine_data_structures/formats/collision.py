from __future__ import annotations

import construct
from construct import Array, BitsInteger, BitStruct, ByteSwapped, Flag, Hex, Rebuild, Struct

from mercury_engine_data_structures import game_check
from mercury_engine_data_structures.common_types import CVector2D, CVector3D, Float, UInt, make_vector
from mercury_engine_data_structures.construct_extensions.misc import OptionalValue
from mercury_engine_data_structures.game_check import Game

CollisionPoint = Struct(
    x=Float,
    y=Float,
    material_attribute=UInt,
)
CollisionPolySR = Struct(
    num_points=Rebuild(UInt, construct.len_(construct.this.points)),
    unk4=Hex(construct.Byte),
    unk5=Hex(UInt),
    points=Array(construct.this.num_points, CollisionPoint),
    boundings=Array(4, Float),
)
CollisionPolyDread = Struct(
    num_points=Rebuild(UInt, construct.len_(construct.this.points)),
    unk=Hex(UInt),
    points=Array(construct.this.num_points, CollisionPoint),
    loop=Flag,
    boundings=Array(4, Float),
)
CollisionPoly = game_check.is_at_most(Game.SAMUS_RETURNS, CollisionPolySR, CollisionPolyDread)

BinarySearchTree = Struct(
    test=ByteSwapped(
        BitStruct(
            "is_leaf" / Flag,
            "pass" / BitsInteger(15),
            "fail" / BitsInteger(16),
        )
    ),
    boundings=Array(4, Float),
)

collision_formats = {
    "AABOX2D": Struct(
        position=CVector3D,
        size=CVector2D,
    ),
    "CIRCLE": Struct(
        position=CVector3D,
        size=Float,
    ),
    "CAPSULE2D": Struct(
        value1=Float,
        value2=Float,
        value3=Float,
        value4=Float,
        value5=Float,
    ),
    "OBOX2D": Struct(
        position=CVector3D,
        angle=Float,
        size=CVector2D,
    ),
    "POLYCOLLECTION2D": Struct(
        position=CVector3D,
        polys=make_vector(CollisionPoly),
        total_boundings=Array(4, Float),
        binary_search_trees=OptionalValue(make_vector(BinarySearchTree)),
    ),
}
