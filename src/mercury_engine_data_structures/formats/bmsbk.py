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
from mercury_engine_data_structures.common_types import CVector3D, StrId, Vec3, VersionAdapter, make_dict, make_vector

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
    "collision_cameras" / make_dict(make_vector(Int32ul)),
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


class BlockData:
    def __init__(self, raw: Container) -> None:
        self._raw = raw

    @property
    def position(self) -> Vec3:
        return self._raw.position

    @position.setter
    def position(self, value: Vec3) -> None:
        self._raw.position = value

    @property
    def respawn_time(self) -> float:
        return self._raw.respawn_time

    @respawn_time.setter
    def respawn_time(self, value: float) -> None:
        self._raw.respawn_time = value

    @property
    def model_name(self) -> str:
        return self._raw.model_name

    @model_name.setter
    def model_name(self, value: str) -> None:
        self._raw.model_name = value

    @property
    def vignette_name(self) -> str:
        return self._raw.vignette_name

    @vignette_name.setter
    def vignette_name(self, value: str) -> None:
        self._raw.vignette_name = value


class BlockGroupData:
    def __init__(self, raw: Container):
        self._raw = raw

    @property
    def block_type(self) -> BlockType:
        return self._raw.types[0].block_type

    @block_type.setter
    def block_type(self, block_type: BlockType) -> None:
        self._raw.types[0].block_type = block_type

    def get_block(self, block_idx: int) -> BlockData:
        return BlockData(self._raw.types[0].blocks[block_idx])


class Bmsbk(BaseResource):
    @classmethod
    @functools.lru_cache
    def construct_class(cls, target_game: Game) -> Construct:
        return BMSBK

    def get_block_group(self, block_group: int) -> BlockGroupData:
        """Returns a block group by index"""
        assert len(self.raw.block_groups[block_group].types) == 1
        return BlockGroupData(self.raw.block_groups[block_group])
