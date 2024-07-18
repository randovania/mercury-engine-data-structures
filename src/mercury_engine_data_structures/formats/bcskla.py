
import construct
from construct.core import (
    Array,
    Computed,
    Const,
    Construct,
    Container,
    FocusedSeq,
    IfThenElse,
    Int8ul,
    Int16ul,
    Int32ul,
    Pointer,
    Rebuild,
    Struct,
    Tell,
    this,
)

from mercury_engine_data_structures.common_types import CVector3D, Float
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

KeyFramedValues_Dread = Struct(
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

KeyFramedValues_SR = Struct(
    count=Rebuild(Int16ul, lambda ctx: 0 if isinstance(ctx.data, float) else len(ctx.data)),
    _data_type = Const(2, Int16ul),
    data = IfThenElse(
        this.count == 0,
        FocusedSeq(
            "value",
            time = Const(0, Int32ul),
            value = Float
        ),
        Array(this.count,
            Struct(timing=Float, values=CVector3D)
        )
    ),
    _new_eof=Tell,
    _new_kfv=Computed(_update_next_kfv)

)

BoneTrack_Dread = Struct(
    bone_name=PropertyEnumDoubleUnsafe,
    flags=Rebuild(Int32ul, _rebuild_flags),
    offset=Tell,
    data=Array(9, IfThenElse(
        # if the flag for an index is zero, the track
        2 ** this._index & this.flags == 0,
        Float,
        FocusedSeq(
            "kfv",
            off = Rebuild(Int32ul, lambda ctx: ctx._._._next_kfv_offset - ctx._.offset),
            kfv = Pointer(this.off + this._.offset, KeyFramedValues_Dread)
        )
    ))
)

BoneTrack_SR = Struct(
    bone_hash=Int32ul, # TODO have a property CrcAdapter for sr lmao
    offset=Tell,
    data=Array(9, FocusedSeq(
        "kfv",
        off = Rebuild(Int32ul, lambda ctx: 0 if isinstance(ctx.kfv, float) else ctx._._._next_kfv_offset),
        kfv = IfThenElse(
            this.off > 0,
            Pointer(this.off, KeyFramedValues_SR),
            IfThenElse(lambda ctx: ctx._index < 6, Computed(0.0), Computed(1.0))
        )
    ))
)

BCSKLA_DREAD = Struct(
    _magic = Const(b"MANM"),
    ver=Const(0x000A0001, Int32ul),
    unk=Int32ul,
    frame_count=Float,
    track_count=Rebuild(Int32ul, construct.len_(this.tracks)),
    _padding=If(this.track_count > 0, AlignTo(8, b"\xff")),
    _next_kfv_offset=Computed(this.track_count * 0x30 + 0x18),
    tracks=Array(this.track_count, BoneTrack_Dread)
)

BCSKLA_SR = Struct(
    _magic = Const(b"MANM"),
    ver = Const(0x00060001, Int32ul),
    unk = Int32ul,
    frame_count=Float,
    track_count=Rebuild(Int32ul, construct.len_(this.tracks)),
    _next_kfv_offset=Computed(this.track_count * 0x28 + 0x14),
    tracks = Array(this.track_count, BoneTrack_SR)
)

class Bcskla(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        if target_game == Game.DREAD:
            return BCSKLA_DREAD
        elif target_game == Game.SAMUS_RETURNS:
            return BCSKLA_SR
