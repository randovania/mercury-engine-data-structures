from enum import Enum

import construct
from construct.core import (
    Adapter,
    Array,
    Byte,
    Const,
    Flag,
    Int16ul,
    Int32ul,
    Pointer,
    Rebuild,
    Struct,
    Tell,
)
from construct.expr import Path
from construct.lib.containers import Container, ListContainer

from mercury_engine_data_structures.adapters.enum_adapter import EnumAdapter
from mercury_engine_data_structures.common_types import VersionAdapter
from mercury_engine_data_structures.construct_extensions.alignment import AlignTo
from mercury_engine_data_structures.formats.base_resource import BaseResource
from mercury_engine_data_structures.game_check import Game

# source https://mk8.tockdom.com/w/index.php?title=BFSTM_(File_Format)

def RebuildOffset(target_offset: int | Path, starting_from = 0, subcon = Int32ul):
    if isinstance(target_offset, Path):
        target_offset = target_offset.offset

    return Struct(
        "cur_offset" / Tell,
        "updated" / Pointer(target_offset, Rebuild(subcon, construct.this.cur_offset - starting_from)),
    )

def RebuildableOffset(subcon: construct.FormatField = Int32ul) -> Struct:
    return Struct(
        "offset" / Tell,
        "value" / subcon
    )

class ReferenceTable(Adapter):
    def __init__(self, info_sc_flag: int, info_sc: Struct, sc2_flag: int, subcon2: Struct):
        self.info_sc_flag = info_sc_flag
        self.sc2_flag = sc2_flag
        self.info_sc_size = info_sc.sizeof()

        inner_subcon = Struct(
            "length" / Int32ul,
            "data" / Array(
                construct.this.length,
                Struct(
                    "section_flag" / Const(info_sc_flag, Int32ul),
                    "offset" / Int32ul,
                )
            ),
            "info_subcons" / Array(
                construct.this.length,
                info_sc
            ),
            "subcons" / Array(construct.this.length, subcon2)
        )

        super().__init__(inner_subcon)

    def _decode(self, obj, context, path):
        return ListContainer([
            Container(info=isc, data=sc)
            for isc, sc in zip(obj.info_subcons, obj.subcons)
        ])

    def _encode(self, obj, context, path):
        count = len(obj)
        data_size = 4 + 8 * count

        return Container(
            length = count,
            data = ListContainer([
                Container(section_flag = self.info_sc_flag, offset = data_size + self.info_sc_size * i)
                for i in range(count)
            ]),
            info_subcons = ListContainer([x.info for x in obj]),
            subcons = ListContainer([x.data for x in obj])
        )

DspAdpcmInfo = Struct(
    "coefficients" / Int16ul[8][2],
    "pred_scale" / Int16ul,
    "yn_1" / Int16ul,
    "yn_2" / Int16ul,
    "loop_pred_scale" / Int16ul,
    "loop_yn_1" / Int16ul,
    "loop_yn_2" / Int16ul,
    AlignTo(0x20),
)

TrackInfo = Struct(
    "volume" / Byte,
    "pan" / Byte,
    "span" / Byte,
    "flags" / Byte, # TODO figure out what the flags are
    "section_flag" / Int32ul, # TODO find the value to const
    "offset" / Int32ul,
)

ChannelInfo = Struct(
    "section_flag" / Const(0x0300, Int32ul),
    "offset" / Int32ul,
)

class SoundEncodingEnum(Enum):
    PCM8 = 0
    PCM16 = 1
    DSP_ADPCM = 2
    IMA_ADPCM = 3

StreamInfo = Struct(
    "sound_encoding" / EnumAdapter(SoundEncodingEnum, Byte),
    "loop" / Flag,
    "num_channels" / Byte,
    "num_regions" / Byte,
    "sample_rate" / Int32ul,
    "loop_start" / Int32ul,
    "num_frames" / Int32ul,
    "num_blocks" / Int32ul,
    "block_byte_size" / Int32ul,
    "block_sample_size" / Int32ul,
    "last_unpadded_block_bytes" / Int32ul, # size of last block without padding in bytes
    "last_unpadded_block_samples" / Int32ul, # size of last block without padding in samples
    "last_padded_block_bytes" / Int32ul, # sizeof last block with padding in bytes
    "seek_info_size" / Const(4, Int32ul),
    "seek_sample_interval" / Int32ul,
    "sample_data_flag" / Const(0x1F00, Int32ul),
    "sample_data_offset" / RebuildableOffset(), # relative to 0x08 in DATA
    "region_info_size" / RebuildableOffset(),
    "region_info_flag" / Const(0, Int32ul),
    "region_info_offset" / RebuildableOffset(),
    "orig_loop_start" / Int32ul,
    "orig_loop_end" / Int32ul, # same as num_frames?
    "unk" / Int32ul, # float maybe? idk what this is, doesn't make sense as a float or int
)

InfoSection = Struct(
    RebuildOffset(construct.this._._.header.info_offset),

    "_start" / Tell,
    "_magic" / Const(b"INFO"),
    "_size_addr" / Tell,
    "size" / RebuildableOffset(), # size
    "_info_flag" / Const(0x4100, Int32ul), # int16 wiht 2b padding
    "info_offset" / RebuildableOffset(),
    "track_info_flag" / Int32ul, # int16 with 2b padding
    "track_info_offset" / RebuildableOffset(),
    "channel_info_flag" / Const(0x101, Int32ul),
    "channel_info_offset" / RebuildableOffset(),
    RebuildOffset(construct.this._.info_offset, construct.this._._start + 8),
    "stream_info" / StreamInfo,
    # TODO track info, unsure if any dread files use it
    RebuildOffset(construct.this._.channel_info_offset, construct.this._._start + 8),
    "channel_infos" / ReferenceTable(0x4102, ChannelInfo, 0x0300, DspAdpcmInfo),
    AlignTo(0x20),

    RebuildOffset(construct.this._._.header.size, construct.this._._start),
    RebuildOffset(construct.this._._.header.info_size, construct.this._._start),
    RebuildOffset(construct.this._.size, construct.this._._start),
)

Header = Struct(
    "_magic" / Const(b"FSTM"),
    Const(b"\xff\xfe"), # Byte-Order Mark, always uses little endian
    "_header_size" / Const(0x40, Int16ul),
    "version" / VersionAdapter("1024.6.0"),
    "size" / RebuildableOffset(),
    "_num_datablocks" / Const(3, Int32ul),
    "_info_flag" / Const(0x4000, Int32ul),
    "info_offset" / RebuildableOffset(),
    "info_size" / RebuildableOffset(),
    "_seek_flag" / Const(0x4001, Int32ul),
    "seek_offset" / RebuildableOffset(),
    "seek_size" / RebuildableOffset(),
    "_data_flag" / Const(0x4002, Int32ul),
    "data_offset" / RebuildableOffset(),
    "data_size" / RebuildableOffset(),
    "hdr_end" / Tell,
    AlignTo(0x20),
)

BFSTM = Struct(
    "header" / Header,
    "INFO" / InfoSection,

    RebuildOffset(0xC)
)

class Bfstm(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> construct.Construct:
        return BFSTM
