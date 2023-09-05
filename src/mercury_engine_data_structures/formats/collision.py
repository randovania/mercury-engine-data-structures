import construct
from construct import Array, Flag, Hex, IfThenElse, Int16ul, Rebuild, Struct

from mercury_engine_data_structures import game_check
from mercury_engine_data_structures.common_types import CVector2D, Float, UInt, make_vector
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
    unk=Float,
    points=Array(construct.this.num_points, CollisionPoint),
    loop=Flag,
    boundings=Array(4, Float),
)
CollisionPoly = IfThenElse(
    game_check.current_game_at_most(Game.SAMUS_RETURNS),
    CollisionPolySR,
    CollisionPolyDread,
)
BinarySearchTree = Struct(
    binary_search_index1=Int16ul,
    binary_search_index2=Int16ul,
    boundings=Array(4, Float),
)

collision_formats = {
    "AABOX2D": Struct(
        unknown1=UInt,
        min=CVector2D,
        max=CVector2D,
    ),
    "CIRCLE": Struct(
        value1=Float,
        value2=Float,
        value3=Float,
        size=Float,
    ),
    "CAPSULE2D": Struct(
        value1=Float,
        value2=Float,
        value3=Float,
        value4=Float,
        value5=Float,
    ),
    "POLYCOLLECTION2D": Struct(
        unknown1=UInt,
        unknown2=UInt,
        unknown3=UInt,
        polys=make_vector(CollisionPoly),
        total_boundings=Array(4, Float),
        binary_search_trees=OptionalValue(make_vector(BinarySearchTree)),
    ),
}
