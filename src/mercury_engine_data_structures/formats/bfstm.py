from enum import IntEnum

import construct
from construct.core import (
    Array,
    Byte,
    Bytes,
    Const,
    Flag,
    Int16sl,
    Int16ul,
    Int32ul,
    Rebuild,
    Struct,
    Tell,
)

from mercury_engine_data_structures.adapters.enum_adapter import EnumAdapter
from mercury_engine_data_structures.construct_extensions.alignment import AlignTo
from mercury_engine_data_structures.formats.audio_common import (
    Block,
    Header,
    RebuildableOffset,
    RebuildOffset,
    ReferenceTableOfOffsets,
)
from mercury_engine_data_structures.formats.base_resource import BaseResource
from mercury_engine_data_structures.game_check import Game

# source https://mk8.tockdom.com/w/index.php?title=BFSTM_(File_Format)


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

class SoundEncodingEnum(IntEnum):
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
    "sample_data_offset" / RebuildableOffset, # relative to 0x08 in DATA
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
    Const(b"INFO"),
    "size" / RebuildableOffset,
    "_checkpoint" / Tell,
    "STREAM_INFO_FLAG" / Const(0x4100, Int32ul),
    "stream_info_offset" / RebuildableOffset,
    "TRACK_INFO_FLAG" / Const(0x0, Int32ul), # unused in basegame files
    "TRACK_INFO_OFFSET" / Const(0xFFFFFFFF, Int32ul), # unused in basegame files
    "CHANNEL_INFO_FLAG" / Const(0x101, Int32ul),
    "channel_info_offset" / RebuildableOffset,

    RebuildOffset(construct.this._.stream_info_offset, construct.this._._checkpoint),
    "stream_info" / StreamInfo,

    RebuildOffset(construct.this._.channel_info_offset, construct.this._._checkpoint),
    "channel_infos" / ReferenceTableOfOffsets(0x4102, 0x300, DspAdpcmInfo),

    AlignTo(0x20),
    RebuildOffset(construct.this._.size, construct.this._._._start),
)

HistoryInfo = Struct(
    "sample_1" / Int16ul,
    "sample_2" / Int16ul,
)

SEEK = Struct(
    "_magic" / Const(b"SEEK"),
    "size" / RebuildableOffset,
    "history_info" / Array(
        construct.this._root.INFO.stream_info.num_blocks,
        HistoryInfo[construct.this._root.INFO.stream_info.num_channels],
    ),
    AlignTo(0x20),

    RebuildOffset(construct.this._.size, construct.this._._._start),
)

DATA = Struct(
    "_magic" / Const(b"DATA"),
    "size" / Rebuild(Int32ul, construct.len_(construct.this.data) + 8),
    "data" / Bytes(construct.this.size - 8),
)

BFSTM = Struct(
    "header" / Header(
        b"FSTM",
        "4.6.0",
        {
            "INFO": 0x4000,
            "SEEK": 0x4001,
            "DATA": 0x4002,
        }
    ),
    "INFO" / Block("INFO", INFO),
    "SEEK" / Block("SEEK", SEEK),
    "DATA" / Block("DATA", DATA),

    RebuildOffset(construct.this._root.header.size)
)

class Bfstm(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> construct.Construct:
        return BFSTM
