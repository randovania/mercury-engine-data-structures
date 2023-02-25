import construct
from construct import Construct, IfThenElse, Struct, Const, Hex, Int16ul, Int8ul, Switch, Array, Rebuild, Flag, \
    Terminated, GreedyBytes
from mercury_engine_data_structures import game_check

from mercury_engine_data_structures.common_types import UInt, make_vector, StrId, Float, CVector2D
from mercury_engine_data_structures.construct_extensions.misc import ErrorWithMessage, OptionalValue, ForceQuit
from mercury_engine_data_structures.formats import BaseResource
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

_collision_formats = {
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

CollisionEntry = Struct(
    name=StrId,
    prop1=StrId,
    prop2=StrId,
    prop3=StrId,
    flag=IfThenElse(
        game_check.current_game_at_most(Game.SAMUS_RETURNS),
        Int8ul,
        Int16ul,
    ),
    type=StrId,
    data=Switch(
        construct.this.type,
        _collision_formats,
        ErrorWithMessage(
            lambda ctx: f"Type {ctx.type} not known, valid types are {list(_collision_formats.keys())}."
        )
    ),
)

CollisionLayer = Struct(
    name=StrId,
    entries=make_vector(CollisionEntry),
)

BMSCC = Struct(
    _magic=Const(b"MSCD"),
    _version=IfThenElse(
        game_check.current_game_at_most(Game.SAMUS_RETURNS),
        Const(0x000D0001, Hex(UInt)),
        Const(0x00100001, Hex(UInt)),
    ),
    layers=make_vector(CollisionLayer),
    eof=GreedyBytes,
)


class Bmscc(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BMSCC
