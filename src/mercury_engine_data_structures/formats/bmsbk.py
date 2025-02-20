from __future__ import annotations

import functools
import typing
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
    ListContainer,
    Rebuild,
    Struct,
)

from mercury_engine_data_structures.adapters.enum_adapter import EnumAdapter
from mercury_engine_data_structures.base_resource import BaseResource
from mercury_engine_data_structures.common_types import CVector3D, StrId, Vec3, VersionAdapter, make_dict, make_vector

if TYPE_CHECKING:
    from mercury_engine_data_structures.game_check import Game

Block = Struct(
    "position" / CVector3D,
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


class BlockType(str, Enum):
    POWER_BEAM = "power_beam"
    BOMB = "bomb"
    MISSILE = "missile"
    SUPER_MISSILE = "super_missile"
    POWER_BOMB = "power_bomb"
    BABY = "baby"
    SCREW_ATTACK = "screw_attack"
    WEIGHT = "weight"


BlockTypeConstruct = EnumAdapter(BlockType, StrId)

BlockGroup = Struct(
    "_num_blocks" / Rebuild(Int32ul, _rebuild_blocks),
    "_num_types" / Rebuild(Int32ul, _rebuild_types),
    "is_enabled" / Flag, # always true?
    "types" / Array(lambda this: this._num_types, Struct(
        "block_type" / BlockTypeConstruct,
        "blocks" / make_vector(Block),
    )),
)  # fmt: skip

BMSBK = Struct(
    "_magic" / Const(b"MSBK"),
    "version" / VersionAdapter("1.10.0"),
    "block_groups" / make_vector(BlockGroup),
    "collision_cameras" / make_dict(make_vector(Int32ul)),
    construct.Terminated,
)  # fmt: skip


class BlockData:
    def __init__(self, raw: Container) -> None:
        self._raw = raw

    @classmethod
    def create(
        cls, position: Vec3, respawn_time: float, model_name: str, vignette_name: str, unk2: int = 0
    ) -> typing.Self:
        return cls(
            Container(
                {
                    "position": position,
                    "unk2": unk2,
                    "unk3": 0,
                    "respawn_time": respawn_time,
                    "model_name": model_name,
                    "vignette_name": vignette_name,
                }
            )
        )

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

    def add_block(self, new_block: BlockData) -> None:
        self._raw.types[0].blocks.append(new_block)

    def remove_block(self, block_idx: int) -> None:
        self._raw.types[0].blocks.pop(block_idx)


class Bmsbk(BaseResource):
    @classmethod
    @functools.lru_cache
    def construct_class(cls, target_game: Game) -> Construct:
        return BMSBK

    @property
    def collision_cameras(self) -> dict[list[int]]:
        return self.raw.collision_cameras

    @collision_cameras.setter
    def collision_cameras(self, collision_camera: str, value: dict[list[int]]) -> None:
        self.raw.collision_cameras[collision_camera] = value

    def get_block_group(self, block_group: int) -> BlockGroupData:
        """
        Returns a block group by index

        param block_group: the index of the block_group
        """
        assert len(self.raw.block_groups[block_group].types) == 1
        return BlockGroupData(self.raw.block_groups[block_group])

    def add_block_group(self, collision_camera: str, type: BlockType) -> None:
        """
        Adds a new block group to a collision_camera

        param collision_camera: the collision_camera the block_group will be added to
        param type: the weakness of the block_group
        """
        new_group = Container(
            is_enabled=True, types=ListContainer([Container(block_type=type, blocks=ListContainer([]))])
        )
        self.raw.block_groups.append(new_group)

        all_collision_cameras = self.collision_cameras
        if collision_camera not in all_collision_cameras:
            all_collision_cameras[collision_camera] = Container({collision_camera: ListContainer([])})

        all_collision_cameras[collision_camera].append(len(self.raw.block_groups) - 1)

    def remove_block_group(self, collision_camera: str, group_idx: int) -> None:
        """
        Removes a block_group from a collision_camera

        param collision_camera: the collision_camera the block_group is in
        param group_idx: the index of the block group to be removed
        """
        self.raw.block_groups.pop(group_idx)
        self.collision_cameras[collision_camera].pop(group_idx)

    def remove_collision_camera_group(self, collision_camera: str) -> None:
        """
        Removes all groups in a collision_camera and the collision_camera group itself

        param collision_camera: the collision_camera to be removed
        """
        camera = self.collision_cameras[collision_camera]
        i = 0
        for group in camera:
            self.raw.block_groups.pop(group - i)
            camera.pop(0)
            i += 1

        self.collision_cameras.pop(collision_camera)
