import enum

import construct
from construct.core import (
    Array,
    Byte,
    Check,
    Const,
    Construct,
    Enum,
    Int24ul,
    Int32ul,
    Int64ul,
    PaddedString,
    PrefixedArray,
    Rebuild,
    Struct,
)

from mercury_engine_data_structures.formats.base_resource import BaseResource
from mercury_engine_data_structures.formats.property_enum import PropertyEnum
from mercury_engine_data_structures.game_check import Game


class FileTypeEnum(enum.Enum):
    SOUND = 1
    SOUNDGROUP = 2
    BANK = 3
    PLAYER = 4
    WAVE_ARCHIVE = 5
    GROUP = 6


FileId = Struct(
    "file_idx" / Int24ul,
    "file_type" / Enum(Byte, FileTypeEnum),
)

WaveArchiveData = Struct(
    Const(0x20, Int32ul),
    "wav_name" / PropertyEnum,
    "file_id" / FileId,
    "warc_index" / Int32ul,  # index of the WARC listed in BFSAR (starts offset from 0)
    "idx" / Rebuild(Int32ul, lambda ctx: ctx._index),  # 0 to max wave archives
    Check(construct.this._index == construct.this.idx),
    Const(0, Int32ul),
    Const(0, Int32ul),
    Const(0, Int32ul),
)

SoundStreams = Struct(
    Const(0x10, Int32ul),
    "fstm_name" / PropertyEnum,
    "file_id"
    / Rebuild(
        FileId,
        lambda ctx: construct.Container(file_idx=ctx._index, file_type=ctx.file_id.file_type),  # 0 to max sound streams
    ),
    Check(construct.this._index == construct.this.file_id.file_idx),
    "stream_index" / Int32ul,  # index in bfsar
)

GroupData = Struct(
    Const(0xB0, Int32ul),
    "group_crc" / PropertyEnum,
    "file_id" / FileId,
    "file_size" / Int32ul,  # ==  length of romfs:/packs/sounds/<group>.bfgrp
    Const(0, Int64ul),
    "group" / PaddedString(0x80, "ascii"),
    "_len" / Rebuild(Int32ul, lambda ctx: len(ctx.wavs)),
    Const(0, Int32ul),
    Const(b"\x0d\xf0\xad\xba" * 4),  # 16B of BAADF00D magic from heap alloc
    "wavs" / Array(construct.this._len, PropertyEnum),
)

BMSSTOC = Struct(
    "wave_archives" / PrefixedArray(Int32ul, WaveArchiveData),
    "sound_streams" / PrefixedArray(Int32ul, SoundStreams),
    "groups" / PrefixedArray(Int32ul, GroupData),
    construct.Terminated,
)


class Bmsstoc(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BMSSTOC
