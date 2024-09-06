import math

import construct
from construct import Construct
from construct.core import (
    Const,
    Int16sl,
    Int16ul,
    Int32ul,
    Int64ul,
    Rebuild,
    Struct,
    Terminated,
)

from mercury_engine_data_structures.common_types import StrId, VersionAdapter
from mercury_engine_data_structures.construct_extensions.alignment import AlignTo
from mercury_engine_data_structures.formats.base_resource import BaseResource
from mercury_engine_data_structures.game_check import Game, GameSpecificStruct


# helper func to calculate padding for rebuild
def calc_padding(pad_to, offset):
    return math.ceil(offset / pad_to) * pad_to


Sprite = Struct("pos" / Int16sl[2], "width" / Int16sl, "height" / Int16sl, "unk1" / Int16sl, "unk2" / Int16sl[2])

BFONT_MSR = Struct(
    "magic" / Const(b"MFNT"),
    "version" / VersionAdapter("1.9.0"),
    Const(0x28, Int32ul),  # pointer to name
    "width" / Int32ul,
    "height" / Int32ul,
    "unk1" / Int32ul,
    "unk2" / Int32ul,
    "glyph_count" / Rebuild(Int32ul, lambda ctx: len(ctx.glyph_data)),
    "_data_start" / Rebuild(Int32ul, lambda ctx: calc_padding(0x10, 0x28 + len(ctx.atlas_path))),
    "_buct_name_offset" / Rebuild(Int32ul, lambda ctx: calc_padding(0x4, ctx._data_start + ctx.glyph_count * 14)),
    "atlas_path" / StrId,
    AlignTo(0x10),
    "glyph_data" / Sprite[construct.this.glyph_count],
    AlignTo(0x4),
    "buct_path" / StrId,
    Terminated,
)

BFONT_DREAD = Struct(
    "magic" / Const(b"MFNT"),
    "version" / VersionAdapter("1.10.0"),
    Const(0x38, Int64ul),  # pointer to name
    "width" / Int32ul,
    "height" / Int32ul,
    "unk1" / Int16ul,
    Const(b"\xff\xff"),
    "unk2" / Int32ul,
    "glyph_count" / Rebuild(Int32ul, lambda ctx: len(ctx.glyph_data)),
    Const(b"\xff\xff\xff\xff"),
    "_data_start" / Rebuild(Int64ul, lambda ctx: calc_padding(0x10, 0x38 + len(ctx.atlas_path))),
    "_buct_name_offset" / Rebuild(Int64ul, lambda ctx: ctx._data_start + ctx.glyph_count * 14),
    "atlas_path" / StrId,
    AlignTo(0x10, pattern=b"\xff"),
    "glyph_data" / Sprite[construct.this.glyph_count],
    "buct_path" / StrId,
    Terminated,
)


class Bfont(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return GameSpecificStruct({Game.SAMUS_RETURNS: BFONT_MSR, Game.DREAD: BFONT_DREAD}[target_game], target_game)
