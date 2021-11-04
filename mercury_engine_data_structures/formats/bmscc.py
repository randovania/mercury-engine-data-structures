import construct
from construct import Construct, Struct, Const, Hex, Int16ul, Switch, Array, Optional, Rebuild, Flag, Probe, Terminated

from mercury_engine_data_structures.common_types import UInt, make_vector, StrId, Float
from mercury_engine_data_structures.construct_extensions.misc import ErrorWithMessage, ForceQuit, OptionalValue
from mercury_engine_data_structures.formats import BaseResource
from mercury_engine_data_structures.game_check import Game

CollisionPoint = Struct(
    x=Float,
    y=Float,
    material_attribute=UInt,
)

CollisionPoly = Struct(
    num_points=Rebuild(UInt, construct.len_(construct.this.points)),
    unk=Float,
    points=Array(construct.this.num_points, CollisionPoint),
    loop=Flag,
    boundings=Array(4, Float),
)

BinarySearchTree = Struct(
    binary_search_index1=Int16ul,
    binary_search_index2=Int16ul,
    boundings=Array(4, Float),
)

_collision_formats = {
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
    flag=Int16ul,
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
    magic=Const(0x4443534D, Hex(UInt)),
    version=Const(0x00100001, Hex(UInt)),
    layers=make_vector(CollisionLayer),
    _eof=Terminated,
)


class Bmscc(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BMSCC
