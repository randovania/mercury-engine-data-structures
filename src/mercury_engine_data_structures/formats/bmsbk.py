from __future__ import annotations

import functools
from enum import Enum
from typing import TYPE_CHECKING

import construct
from construct.core import (
    Array,
    Const,
    Construct,
    Container,
    Flag,
    Float32l,
    Int32ul,
    Rebuild,
    Struct,
)

from mercury_engine_data_structures.base_resource import BaseResource
from mercury_engine_data_structures.common_types import CVector3D, StrId, VersionAdapter, make_vector

if TYPE_CHECKING:
    from mercury_engine_data_structures.game_check import Game

Block = Struct(
    "pos" / CVector3D,
    "unk2" / Int32ul,
    "unk3" / Int32ul,
    "respawn_time" / Float32l,
    "model_name" / StrId,
    "vignette_name" / StrId,
)  # fmt: skip


def _rebuild_blocks(ctx: Container) -> int:
    return sum(len(group.blocks) for group in ctx.types)


def _rebuild_types(ctx: Container) -> int:
    return len(ctx.types)


BlockGroup = Struct(
    "_num_blocks" / Rebuild(Int32ul, _rebuild_blocks),
    "_num_types" / Rebuild(Int32ul, _rebuild_types),
    "is_enabled" / Flag, # always true?
    "types" / Array(lambda this: this._num_types, Struct(
        "block_type" / StrId,
        "blocks" / make_vector(Block),
    )),
)  # fmt: skip

BMSBK = Struct(
    "magic" / Const(b"MSBK"),
    "version" / VersionAdapter("1.10.0"),
    "block_groups" / make_vector(BlockGroup),
    "collision_cameras" / make_vector(Struct(
        "name" / StrId,
        "entries" / make_vector(Int32ul),
    )),
    construct.Terminated,
)  # fmt: skip


class BlockType(Enum):
    POWER_BEAM = "power_beam"
    BOMB = "bomb"
    MISSILE = "missile"
    SUPER_MISSILE = "super_missile"
    POWER_BOMB = "power_bomb"
    BABY = "baby"
    SCREW_ATTACK = "screw_attack"
    WEIGHT = "weight"


class Bmsbk(BaseResource):
    @classmethod
    @functools.lru_cache
    def construct_class(cls, target_game: Game) -> Construct:
        return BMSBK

    def get_block_group(self, block_group: int) -> Container:
        """Returns a block group by index"""
        return self.raw.block_groups[block_group]

    def set_block_type(self, block_group: int, block_type: BlockType) -> None:
        """Change a given block's block_type into another"""
        assert len(self.get_block_group(block_group).types) == 1
        self.get_block_group(block_group).types[0].block_type = block_type

    def get_block(self, block_group: int, block_idx: int) -> Container:
        """Returns a block from a block group by index"""
        assert len(self.get_block_group(block_group).types) == 1
        return self.get_block_group(block_group).types[0].blocks[block_idx]

    def set_respawn_time(self, block_group: int, block_idx: int, respawn_time: float) -> None:
        """Change the respawn time of a given block"""
        block = self.get_block(block_group, block_idx)
        block.respawn_time = respawn_time
