from __future__ import annotations

from enum import Enum

import construct
from construct.core import Error

from mercury_engine_data_structures.common_types import StrId, UInt
from mercury_engine_data_structures.formats.base_resource import BaseResource
from mercury_engine_data_structures.game_check import Game

BlockType = construct.Enum(
    UInt,
    texture=2,
    data=3,
)

XTX_TextureBlock = construct.Struct(
    data_size=construct.Int64ul,
    alignment=UInt,
    width=UInt,
    height=UInt,
    depth=UInt,
    target=UInt,
    xtx_format=UInt,
    mip_count=UInt,
    slice_size=UInt,
    mip_offsets=UInt[17],
    texture_layout_1=UInt,
    texture_layout_2=UInt,
    boolean=UInt,
    _terminated=construct.Terminated,
)

XTX_Block = construct.Struct(
    _start=construct.Tell,
    _magic=construct.Const(b"HBvN"),
    block_size=UInt,
    data_size=construct.Int64ul,
    data_offset=construct.Int64sl,
    block_type=BlockType,
    global_block_index=UInt,
    inc_block_type_index=UInt,
    _data_seek=construct.Seek(construct.this._start + construct.this.data_offset),
    data=construct.FixedSized(
        construct.this.data_size,
        construct.Switch(
            construct.this.block_type,
            {
                BlockType.texture: XTX_TextureBlock,
            },
            construct.GreedyBytes,
        ),
    ),
)

XTX = construct.Struct(
    _start=construct.Tell,
    _magic=construct.Const(b"DFvN"),
    header_size=UInt,
    major_version=UInt,
    minor_version=UInt,
    _header_end=construct.Seek(construct.this._start + construct.this.header_size),
    blocks=construct.GreedyRange(XTX_Block),
)

BCTEX_Dread = construct.Struct(
    _magic=construct.Const(b"MTXT"),
    flags=UInt,
    data=construct.Compressed(
        construct.Struct(
            unk_1=construct.Int64ul,
            width=UInt,
            height=UInt,
            mip_count=UInt,
            texture_flag=UInt,  # unk
            name_offset=UInt,
            name=construct.Peek(
                construct.FocusedSeq(
                    "value",
                    construct.Seek(construct.this._.name_offset - 8),
                    value=StrId,
                )
            ),
            unk_2=UInt,
            texture_offset=UInt,  # texture xtx offset
            unk_3=UInt,
            texture_size=UInt,  # texture xtx size
            _xtx_bytes_seek=construct.Seek(construct.this.texture_offset - 8),
            xtx=construct.FixedSized(construct.this.texture_size, XTX),
            rest=construct.GreedyBytes,
        ),
        "gzip",
        level=9,
    ),
)


class PICATextureFormat(Enum):
    L8 = 0
    A8 = 1
    LA4 = 2
    LA8 = 3
    HiLo8 = 4
    RGB565 = 5
    RGB8 = 6
    RGBA5551 = 7
    RGBA4 = 8
    RGBA8 = 9
    ETC1 = 10
    ETC1A4 = 11
    L4 = 12
    A4 = 13


BCTEXFormat = construct.Enum(
    UInt,
    RGB8_0=0x10001,  # 65537
    RGBA8_0=0x20001,  # 65538,
    L8_0=0x40001,  # 65540
    LA8_0=0x50001,  # 65541
    ETC1_0=0x10003,  # 196609
    ETC1a4_0=0x20003,  # 196610
)

CTPK = construct.Struct(
    _start=construct.Tell,
    _magic=construct.Const(b"CTPK"),
    file_header=construct.Struct(
        version=construct.Int16ul,
        textures_count=construct.Int16ul,
        texture_data_offset=UInt,
        texture_data_size=UInt,
        hash_list_offset=UInt,
        mipmap_entries_offset=UInt,
        _padding=construct.Int64ul,
    ),
    image_header=construct.Struct(
        name_offset=UInt,
        image_size=UInt,
        data_offset=UInt,
        texture_format=construct.Enum(UInt, PICATextureFormat),
        width=construct.Int16ul,
        height=construct.Int16ul,
        mip_count=construct.Byte,
        type=construct.Byte,
        face_count=construct.Int16ul,
        size_offset=UInt,
        unix_time_stamp=UInt,
    ),
    mip_map_sizes=construct.Array(construct.this.image_header.mip_count, UInt),
    name=StrId,
    _hashlist_begin=construct.Seek(construct.this._start + construct.this.file_header.hash_list_offset),
    hash=UInt,
    _mip_map_entries_begin=construct.Seek(construct.this._start + construct.this.file_header.mipmap_entries_offset),
    mip_map_entry=construct.Struct(
        texture_format=construct.Enum(construct.Byte, PICATextureFormat),
        mip_count=construct.Byte,
        compressed=construct.Byte,
        etc1_quality=construct.Byte,
    ),
    image_data=construct.Bytes(construct.this.file_header.texture_data_size),
)

# this and all related structures is a mixture of some own work + most parts taken from:
# https://github.com/M-1-RLG/010-Editor-Templates/
# https://github.com/MapStudioProject/CTR-Studio
# https://github.com/FanTranslatorsInternational/Kuriimu2/
BCTEX_SR = construct.Struct(
    _magic=construct.Const(b"MTXT"),
    major_version=construct.Int16ul,
    minor_version=construct.Int16ul,
    texture_format=BCTEXFormat,
    width=UInt,
    height=UInt,
    mipmap_count=UInt,
    name_offset=UInt,
    data_offset=UInt,
    ctpk_size=UInt,
    _ctpk_start=construct.Seek(construct.this.data_offset),
    ctpk=construct.FixedSized(construct.this.ctpk_size, CTPK),
    name=StrId,
    _terminated=construct.Terminated,
)


class Bctex(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> construct.Construct:
        if target_game == Game.DREAD:
            return BCTEX_Dread
        if target_game == Game.SAMUS_RETURNS:
            return BCTEX_SR
        return Error
