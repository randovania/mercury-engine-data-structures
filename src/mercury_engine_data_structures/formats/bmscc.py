import construct
from construct.core import (
    Const,
    Construct,
    GreedyBytes,
    Int8ul,
    Int16ul,
    Struct,
    Switch,
)

from mercury_engine_data_structures import game_check
from mercury_engine_data_structures.common_types import StrId, VersionAdapter, make_vector
from mercury_engine_data_structures.construct_extensions.misc import ErrorWithMessage
from mercury_engine_data_structures.formats.base_resource import BaseResource
from mercury_engine_data_structures.formats.collision import collision_formats
from mercury_engine_data_structures.game_check import Game

CollisionEntry = Struct(
    name=StrId,
    prop1=StrId,
    prop2=StrId,
    prop3=StrId,
    flag=game_check.is_sr_or_else(Int8ul, Int16ul),
    type=StrId,
    data=Switch(
        construct.this.type,
        collision_formats,
        ErrorWithMessage(
            lambda ctx: f"Type {ctx.type} not known, valid types are {list(collision_formats.keys())}."
        )
    ),
).compile()

CollisionLayer = Struct(
    name=StrId,
    entries=make_vector(CollisionEntry),
).compile()

BMSCC = Struct(
    _magic=Const(b"MSCD"),
    _version=game_check.is_sr_or_else(
        VersionAdapter("1.13.0"),
        VersionAdapter("1.16.0"),
    ),
    layers=make_vector(CollisionLayer),
    eof=GreedyBytes,
).compile()


class Bmscc(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BMSCC
