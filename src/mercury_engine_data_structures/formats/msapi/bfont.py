from __future__ import annotations

import construct
from construct.core import Const, Int16sl, Int16ul, Int32ul, Rebuild, Struct

from mercury_engine_data_structures.base_resource import BaseResource
from mercury_engine_data_structures.common_types import StrId
from mercury_engine_data_structures.formats.msapi.msapi import MsapiPointer, StandardModelMsapi

Glyph = Struct(
    "pos" / Int16sl[2],
    "width" / Int16sl,
    "height" / Int16sl,
    "unk1" / Int16sl,
    "unk2" / Int16sl[2],
)


def GlyphVector(this):
    return Struct("values" / Glyph[this.glyph_count])


HeaderDread = Struct(
    "name" / MsapiPointer(StrId),
    "width" / Int32ul,
    "height" / Int32ul,
    "unk1" / Int16ul,
    Const(b"\xff\xff"),
    "unk2" / Int32ul,
    "glyph_count" / Rebuild(Int32ul, construct.len_(construct.this.glyphs.values)),
    Const(b"\xff\xff\xff\xff"),
    "glyphs" / MsapiPointer(GlyphVector),
    "buct_path" / MsapiPointer(StrId),
)


class Bfont(BaseResource):
    @classmethod
    def construct_class(cls, target_game):
        return StandardModelMsapi(b"MFNT", "1.10.0", HeaderDread)
