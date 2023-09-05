import construct
from construct import (
    Const,
    Construct,
    GreedyBytes,
    Hex,
    IfThenElse,
    Int8ul,
    Int16ul,
    Struct,
    Switch,
)

from mercury_engine_data_structures import game_check
from mercury_engine_data_structures.common_types import StrId, UInt, make_vector
from mercury_engine_data_structures.construct_extensions.misc import ErrorWithMessage
from mercury_engine_data_structures.formats import BaseResource
from mercury_engine_data_structures.formats.collision import collision_formats
from mercury_engine_data_structures.game_check import Game

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
        collision_formats,
        ErrorWithMessage(
            lambda ctx: f"Type {ctx.type} not known, valid types are {list(collision_formats.keys())}."
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
