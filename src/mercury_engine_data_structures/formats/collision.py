import construct
from construct.core import Array, Flag, Hex, Int16ul, Rebuild, Struct

from mercury_engine_data_structures import game_check
from mercury_engine_data_structures.common_types import CVector2D, CVector3D, Float, UInt, make_vector
from mercury_engine_data_structures.construct_extensions.misc import OptionalValue
from mercury_engine_data_structures.game_check import Game

CollisionPoint = Struct(
    x=Float,
    y=Float,
    material_attribute=UInt,
).compile()

CollisionPolySR = Struct(
    num_points=Rebuild(UInt, construct.len_(construct.this.points)),
    unk4=Hex(construct.Byte),
    unk5=Hex(UInt),
    points=Array(construct.this.num_points, CollisionPoint),
    boundings=Array(4, Float),
).compile()

CollisionPolyDread = Struct(
    num_points=Rebuild(UInt, construct.len_(construct.this.points)),
    unk=Hex(UInt),
    points=Array(construct.this.num_points, CollisionPoint),
    loop=Flag,
    boundings=Array(4, Float),
)
CollisionPoly = game_check.is_at_most(Game.SAMUS_RETURNS, CollisionPolySR, CollisionPolyDread).compile()

BinarySearchTree = Struct(
    binary_search_index1=Int16ul,
    binary_search_index2=Int16ul,
    boundings=Array(4, Float),
).compile()

collision_formats = {
    "AABOX2D": Struct(
        position=CVector3D,
        size=CVector2D,
    ).compile(),
    "CIRCLE": Struct(
        position=CVector3D,
        size=Float,
    ).compile(),
    "CAPSULE2D": Struct(
        value1=Float,
        value2=Float,
        value3=Float,
        value4=Float,
        value5=Float,
    ).compile(),
    "OBOX2D": Struct(
        position=CVector3D,
        angle=Float,
        size=CVector2D,
    ).compile(),
    "POLYCOLLECTION2D": Struct(
        position=CVector3D,
        polys=make_vector(CollisionPoly),
        total_boundings=Array(4, Float),
        binary_search_trees=OptionalValue(make_vector(BinarySearchTree)),
    ).compile(),
}
