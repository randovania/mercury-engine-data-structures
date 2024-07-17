from dataclasses import dataclass
from pprint import pprint
from typing import Union

import construct
from construct.core import (
    Array,
    Computed,
    Const,
    Construct,
    Container,
    FocusedSeq,
    If,
    IfThenElse,
    Int8ul,
    Int16ul,
    Int32ul,
    Pointer,
    Rebuild,
    Struct,
    Seek,
    Tell,
    this,
)

from mercury_engine_data_structures.common_types import CVector2D, Float
from mercury_engine_data_structures.construct_extensions.alignment import AlignTo
from mercury_engine_data_structures.formats.base_resource import BaseResource
from mercury_engine_data_structures.formats.property_enum import PropertyEnumDoubleUnsafe
from mercury_engine_data_structures.game_check import Game


def _rebuild_flags(ctx):
    flags = 0
    for i, val in enumerate(ctx.data):
        if isinstance(val, Container):
            flags += 2 ** i
    return flags

def _update_next_kfv(ctx):
    ctx._._._._next_kfv_offset = ctx._new_eof

BcsklaKFVStruct = Struct(
    timing_type=Int16ul,
    count=Rebuild(Int16ul, construct.len_(this.timings)),
    timings=IfThenElse(
        construct.this.timing_type == 0,
        Array(construct.this.count, Int16ul),
        Array(construct.this.count, Int8ul)
    ),
    _padding=AlignTo(4, b"\xff"),
    values=Array(construct.this.count, Struct(value=Float, derivative=Float)),
    _new_eof=Tell,
    _new_kfv=Computed(_update_next_kfv)
)

BcsklaBoneTrackStruct = Struct(
    bone_hash=PropertyEnumDoubleUnsafe,
    flags=Rebuild(Int32ul, _rebuild_flags),
    offset=Tell,
    data=Array(9, IfThenElse(
        2 ** this._index & this.flags == 0,
        Float,
        FocusedSeq(
            "kfv",
            off = Rebuild(Int32ul, lambda ctx: ctx._._._next_kfv_offset - ctx._.offset),
            kfv = Pointer(this.off + this._.offset, BcsklaKFVStruct)
        )
    ))
)

BCSKLA = Struct(
    _magic = Const(b"MANM"),
    ver=Const(0x000A0001, Int32ul),
    unk=Int32ul,
    frame_count=Float,
    track_count=Rebuild(Int32ul, construct.len_(this.tracks)),
    _padding=AlignTo(8, b"\xff"),
    _next_kfv_offset=Computed(this.track_count * 0x30 + 0x18),
    tracks=Array(this.track_count, BcsklaBoneTrackStruct)
)

class Bcskla(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BCSKLA
