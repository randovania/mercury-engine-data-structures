import functools

from construct import (
    Array,
    Const,
    Construct,
    Container,
    Flag,
    Float32l,
    Hex,
    Int32ul,
    Rebuild,
    Struct,
    Terminated,
)

from mercury_engine_data_structures.common_types import CVector3D, StrId, make_vector
from mercury_engine_data_structures.formats.base_resource import BaseResource
from mercury_engine_data_structures.game_check import Game

Block = Struct(
    "pos" / CVector3D,
    "unk2" / Int32ul,
    "unk3" / Int32ul,
    "respawn_time" / Float32l,
    "name1" / StrId,
    "name2" / StrId,
)

def _rebuild_blocks(ctx: Container) -> int:
    return sum(len(group.blocks) for group in ctx.types)

def _rebuild_types(ctx: Container) -> int:
    return len(ctx.types)

BlockGroup = Struct(
    "_num_blocks" / Rebuild(Int32ul, _rebuild_blocks),
    "_num_types" / Rebuild(Int32ul, _rebuild_types),
    "unk_bool" / Flag, # always true?
    "types" / Array(lambda this: this._num_types, Struct(
        "block_type" / StrId,
        "blocks" / make_vector(Block),
    )),
)

BMSBK = Struct(
    "magic" / Const(b"MSBK"),
    "version" / Hex(Int32ul),
    "block_groups" / make_vector(BlockGroup),
    "collision_cameras" / make_vector(Struct(
        "name" / StrId,
        "entries" / make_vector(Int32ul),
    )),
    Terminated,
)

class Bmsbk(BaseResource):
    @classmethod
    @functools.lru_cache
    def construct_class(cls, target_game: Game) -> Construct:
        return BMSBK
