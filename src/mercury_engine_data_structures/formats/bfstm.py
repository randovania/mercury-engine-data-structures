from enum import Enum

import construct
from construct.core import (
    Adapter,
    Array,
    Byte,
    Bytes,
    Const,
    Flag,
    Int16sl,
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

def RebuildOffset(target_offset: Path, starting_from = 0, subcon = Int32ul):
    return Struct(
        "cur_offset" / Tell,
        "updated" / Pointer(target_offset._offset, Rebuild(subcon, construct.this.cur_offset - starting_from)),
    )

def RebuildableOffset(subcon: construct.FormatField = Int32ul) -> Struct:
    return Struct(
        "_offset" / Tell,
        "value" / subcon
    )

DspAdpcmInfo = Struct(
    "coefficients" / Int16sl[8][2],
    "pred_scale" / Int16ul,
    "yn_1" / Int16ul,
    "yn_2" / Int16ul,
    "loop_pred_scale" / Int16ul,
    "loop_yn_1" / Int16ul,
    "loop_yn_2" / Int16ul,
    Const(0, Int16ul), # padding
)

class ReferenceTable(Adapter):
    CHANNEL_INFO_FLAG = 0x4102
    DSPADPCM_CHANNEL_INFO_FLAG = 0x300

    def __init__(self):

        inner_subcon = Struct(
            "length" / Int32ul,
            "data" / Array(
                construct.this.length,
                Struct(
                    "CHANNEL_INFO_FLAG" / Const(self.CHANNEL_INFO_FLAG, Int32ul),
                    "offset" / Int32ul,
                )
            ),
            "info_subcons" / Array(
                construct.this.length,
                Struct(
                    "DSP_ADPCM_CHANNEL_INFO_FLAG" / Const(self.DSPADPCM_CHANNEL_INFO_FLAG, Int32ul),
                    "offset" / Int32ul,
                )
            ),
            "dsp_adpcm_infos" / Array(construct.this.length, DspAdpcmInfo),
        ).compile()

        super().__init__(inner_subcon)

    def _decode(self, obj, context, path):
        return obj.dsp_adpcm_infos

    def _encode(self, obj, context, path):
        count = len(obj)
        data_size = 4 + 8 * count

        return Container(
            length = count,
            # offsets can be calculated since this is constant
            data = ListContainer([
                Container(section_flag = self.CHANNEL_INFO_FLAG, offset = data_size + 8 * i)
                for i in range(count)
            ]),
            # info offsets can also be calculated
            info_subcons = ListContainer([
                Container(
                    section_flag=self.DSPADPCM_CHANNEL_INFO_FLAG,
                    offset = DspAdpcmInfo.sizeof() * i + 8 * (count - i),
                )
                for i in range(count)
            ]),
            dsp_adpcm_infos = obj
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
    "NUM_REGIONS" / Const(0, Byte),
    "sample_rate" / Int32ul,
    "loop_start" / Int32ul,
    "num_frames" / Int32ul,
    "num_blocks" / Int32ul,
    "block_byte_size" / Int32ul,
    "block_sample_size" / Int32ul,
    "last_unpadded_block_bytes" / Int32ul, # size of last block without padding in bytes
    "last_unpadded_block_samples" / Int32ul, # size of last block without padding in samples
    "last_padded_block_bytes" / Int32ul, # sizeof last block with padding in bytes
    "SEEK_INFO_SIZE" / Const(4, Int32ul),
    "seek_sample_interval" / Int32ul,
    "SAMPLE_DATA_FLAG" / Const(0x1F00, Int32ul),
    "sample_data_offset" / RebuildableOffset(), # relative to 0x08 in DATA
    "REGION_INFO_SIZE" / Const(0x100, Int32ul),
    "REGION_INFO_FLAG" / Const(0, Int32ul),
    "REGION_INFO_OFFSET" / Const(0xFFFFFFFF, Int32ul),
    "orig_loop_start" / Int32ul,
    "orig_loop_end" / Int32ul, # same as num_frames?
    # no idea what the following 2 are, it's not an int or float unless its a real weird float or real big int.
    # guessing its 2 ushorts and some sort of
    "unk1" / Int16sl,
    "unk2" / Int16sl,
)

INFO = Struct(
    RebuildOffset(construct.this._._.header.info_offset),

    "_start" / Tell,
    Const(b"INFO"),
    "size" / RebuildableOffset(),
    "STREAM_INFO_FLAG" / Const(0x4100, Int32ul),
    "stream_info_offset" / RebuildableOffset(),
    "TRACK_INFO_FLAG" / Const(0x0, Int32ul), # unused in basegame files
    "TRACK_INFO_OFFSET" / Const(0xFFFFFFFF, Int32ul), # unused in basegame files
    "CHANNEL_INFO_FLAG" / Const(0x101, Int32ul),
    "channel_info_offset" / RebuildableOffset(),

    RebuildOffset(construct.this._.stream_info_offset, construct.this._._start + 8),
    "stream_info" / StreamInfo,

    RebuildOffset(construct.this._.channel_info_offset, construct.this._._start + 8),
    "channel_infos" / ReferenceTable(),

    AlignTo(0x20),
    RebuildOffset(construct.this._._.header.info_size, construct.this._._start),
    RebuildOffset(construct.this._.size, construct.this._._start),
)

HistoryInfo = Struct(
    "sample_1" / Int16ul,
    "sample_2" / Int16ul,
)

SEEK = Struct(
    RebuildOffset(construct.this._._.header.seek_offset),

    "_start" / Tell,
    "_magic" / Const(b"SEEK"),
    "size" / RebuildableOffset(),
    "history_info" / Array(
        construct.this._.INFO.stream_info.num_blocks,
        HistoryInfo[construct.this._.INFO.stream_info.num_channels],
    ),
    AlignTo(0x20),


    RebuildOffset(construct.this._._.header.seek_size, construct.this._._start),
    RebuildOffset(construct.this._.size, construct.this._._start),
)

DATA = Struct(
    RebuildOffset(construct.this._._.header.data_offset),

    "_start" / Tell,
    "_magic" / Const(b"DATA"),
    "size" / RebuildableOffset(),
    "data" / Bytes(construct.this.size.value - 8),

    RebuildOffset(construct.this._._.header.data_size, construct.this._._start),
    RebuildOffset(construct.this._.size, construct.this._._start)
)

Header = Struct(
    "_magic" / Const(b"FSTM"),
    Const(b"\xff\xfe"), # Byte-Order Mark, always uses little endian
    "_header_size" / Const(0x40, Int16ul),
    "version" / VersionAdapter("1024.6.0"),
    "size" / RebuildableOffset(),
    "_num_datablocks" / Const(3, Int32ul),
    "INFO_FLAG" / Const(0x4000, Int32ul),
    "info_offset" / RebuildableOffset(),
    "info_size" / RebuildableOffset(),
    "SEEK_FLAG" / Const(0x4001, Int32ul),
    "seek_offset" / RebuildableOffset(),
    "seek_size" / RebuildableOffset(),
    "DATA_FLAG" / Const(0x4002, Int32ul),
    "data_offset" / RebuildableOffset(),
    "data_size" / RebuildableOffset(),
    AlignTo(0x20),
)

BFSTM = Struct(
    "header" / Header,
    "INFO" / INFO,
    "SEEK" / SEEK,
    "DATA" / DATA,

    RebuildOffset(construct.this._.header.size)
)

class Bfstm(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> construct.Construct:
        return BFSTM
