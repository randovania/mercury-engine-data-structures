from __future__ import annotations

import construct
from construct.core import Int16sl, Int16ul, Int32ul, Rebuild, Struct

from mercury_engine_data_structures.base_resource import BaseResource
from mercury_engine_data_structures.common_types import StrId
from mercury_engine_data_structures.formats.msapi.msapi import MsapiAlign, MsapiPointer, StandardModelMsapi
from mercury_engine_data_structures.game_check import Game

Glyph = Struct(
    "pos" / Int16sl[2],
    "width" / Int16sl,
    "height" / Int16sl,
    "unk1" / Int16sl,
    "unk2" / Int16sl[2],
)


def GlyphVector(this):
    return Struct("values" / Glyph[this.glyph_count])


BfontHeader = Struct(
    "name" / MsapiPointer(StrId),
    "width" / Int32ul,
    "height" / Int32ul,
    "unk1" / Int16ul,
    "unk2" / Int16ul,  # Always 0xffff in dread, 0x0000 in msr. Does not match standard alignment.
    "unk3" / Int32ul,
    "glyph_count" / Rebuild(Int32ul, construct.len_(construct.this.glyphs.values)),
    MsapiAlign(),
    "glyphs" / MsapiPointer(GlyphVector),
    "buct_path" / MsapiPointer(StrId),
)


class Bfont(BaseResource):
    @classmethod
    def construct_class(cls, target_game):
        return StandardModelMsapi(
            b"MFNT",
            {
                Game.SAMUS_RETURNS: "1.9.0",
                Game.DREAD: "1.10.0",
            }[target_game],
            BfontHeader,
            target_game,
        ).compile()
