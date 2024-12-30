from __future__ import annotations

import dataclasses
import math
from typing import TYPE_CHECKING

import py_tegra_swizzle

from mercury_engine_data_structures.formats.bctex import Bctex, BlockType, XTX_Tegra_Format
from mercury_engine_data_structures.game_check import Game

if TYPE_CHECKING:
    from construct.core import Container


def div_round_up(n: int, d: int) -> int:
    return (n + d - 1) // d


@dataclasses.dataclass
class Surface:
    width: int
    height: int
    data: bytes


@dataclasses.dataclass
class Texture2D:
    mips: list[Surface]

    def mip0(self) -> Surface:
        return self.mips[0]


@dataclasses.dataclass
class Array:
    width: int
    height: int
    format: XTX_Tegra_Format
    members: list[Texture2D]


class RawTexture:
    bctex: Bctex
    name: str
    textures: list[Array]

    def __init__(self, texture: Bctex) -> None:
        if texture.target_game != Game.DREAD:
            raise ValueError("Only Dread bctex can be exported!")

        self.bctex = texture
        self.name = texture.raw.data.name

        self.parse()

    def parse(self):
        self.textures = []
        blocks = self.bctex.raw.data.xtx.blocks
        infos = [blk for blk in blocks if blk.block_type == BlockType.TEXTURE.name]
        datas = [blk for blk in blocks if blk.block_type == BlockType.DATA.name]

        for info, data in zip(infos, datas):
            self.textures.append(self.parse_array(info, data))

    @dataclasses.dataclass
    class Mip0Data:
        # data calculated at the array level and used for texture2d/surface handling
        format: XTX_Tegra_Format
        width: int
        height: int
        block_height: int
        block_dim: py_tegra_swizzle.PyBlockDim

    def parse_array(self, info: Container, data: Container) -> Array:
        xtx_format = [x for x in XTX_Tegra_Format if x.name == info.data.xtx_format][0]
        width = info.data.width
        height = info.data.height
        assert info.data.depth == 1
        block_height_mip0 = py_tegra_swizzle.block_height_mip0(div_round_up(height, xtx_format.block_height))
        block_dim = py_tegra_swizzle.PyBlockDim(xtx_format.block_width, xtx_format.block_height, xtx_format.block_depth)

        mip0_data = self.Mip0Data(xtx_format, width, height, block_height_mip0, block_dim)

        res = Array(width, height, xtx_format, [])
        array_size = info.data.data_size // info.data.slice_size  # usually 1, but 6 for cubemaps
        for array_level in range(array_size):
            mipped_surface = self.parse_texture2d(info, data, info.data.slice_size * array_level, mip0_data)
            res.members.append(mipped_surface)

        return res

    def parse_texture2d(self, info: Container, data: Container, array_offset: int, mip0: Mip0Data) -> Texture2D:
        mips = []

        mip_offset = 0
        for mip_level in range(info.data.mip_count):
            mip_width = max(1, mip0.width >> mip_level)
            mip_height = max(1, mip0.height >> mip_level)
            mip_depth = max(1, 1 >> mip_level)

            mip_height_in_blocks = div_round_up(mip_height, mip0.format.block_height)

            mip_block_height = py_tegra_swizzle.mip_block_height(mip_height_in_blocks, mip0.block_height)
            block_height_log2 = math.floor(math.log2(mip_block_height))

            mip_size = py_tegra_swizzle.get_swizzled_surface_size(
                mip_width, mip_height, mip_depth, mip0.block_dim, mip0.block_height, mip0.format.bytes_per_pixel
            )
            mip_start = array_offset + mip_offset

            mip_data = data.data[mip_start : mip_start + mip_size]

            deswizzled = self._deswizzle(mip_width, mip_height, mip_depth, mip0, block_height_log2, mip_data)

            if deswizzled is None:
                raise ValueError(f"Deswizzle Failed, mip={mip_level}")

            mips.append(Surface(mip_width, mip_height, deswizzled))
            mip_offset += mip_size

        return Texture2D(mips)

    def _deswizzle(self, width: int, height: int, depth: int, mip0: Mip0Data, heightLog2: int, data: bytes) -> bytes:
        height_mip0 = 1 << max(min(heightLog2, 5), 0)

        width_blks = div_round_up(width, mip0.format.block_width)
        height_blks = div_round_up(height, mip0.format.block_height)
        depth_blks = div_round_up(depth, mip0.format.block_depth)

        try:
            res = py_tegra_swizzle.deswizzle_block_linear(
                width_blks, height_blks, depth_blks, data, height_mip0, mip0.format.bytes_per_pixel
            )
            return res
        except Exception:
            return None
