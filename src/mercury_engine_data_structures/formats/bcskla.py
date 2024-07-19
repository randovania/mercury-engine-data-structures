
import construct
from construct.core import (
    Array,
    Check,
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
    _integrity_check=Check(construct.len_(this.values) == construct.len_(this.timings)),
    _new_eof=Tell,
    _new_kfv=Computed(_update_next_kfv)
)

# if data is keyframed, it builds to { count = c, data = [ { timing = t, values = [a, b, c] }, ... ] }
# if data is constant, it builds to { count = 0, data = { value = x } }
KeyFramedValues_SR = Struct(
    count=Rebuild(Int16ul, lambda ctx: 0 if isinstance(ctx.data, float) else len(ctx.data)),
    _data_type = Const(2, Int16ul),
    data = IfThenElse(
        this.count == 0,
        FocusedSeq(
            "value",
            timing = Const(0, Int32ul),
            value = Float
        ),
        # guessing on left/right_derivative. they are almost always the same value. 
        Array(this.count, Struct(timing=Float, value=Float, left_derivative=Float, right_derivative=Float))
    ),
    _new_eof=Tell,
    _new_kfv=Computed(_update_next_kfv)

)

BoneTrack_Dread = Struct(
    # guess. almost always the bone names but some values still don't parse after dumping all model data >:(
    bone_name=PropertyEnumDoubleUnsafe,
    flags=Rebuild(Int32ul, _rebuild_flags),
    _offset=Tell,
    data=Array(9, IfThenElse(
        # if the flag for an index is zero, the value is keyframed
        2 ** this._index & this.flags == 0,
        Float,
        FocusedSeq(
            "kfv",
            # offsets are relative to immediately after the flag field
            off = Rebuild(Int32ul, lambda ctx: ctx._._._next_kfv_offset - ctx._._offset),
            kfv = Pointer(this.off + this._._offset, KeyFramedValues_Dread)
        )
    ))
)

BoneTrack_SR = Struct(
    bone_hash=Int32ul, # TODO have a property CrcAdapter for sr lmao
    data=Array(9, FocusedSeq(
        "kfv",
        off = Rebuild(Int32ul, lambda ctx: 0 if isinstance(ctx.kfv, float) else ctx._._._next_kfv_offset),
        kfv = IfThenElse(
            this.off > 0,
            Pointer(this.off, KeyFramedValues_SR),
            # if offset is 0, this is the default value pos/rot=0, scale=1
            IfThenElse(lambda ctx: ctx._index < 6, Computed(0.0), Computed(1.0))
        )
    ))
)

BCSKLA_DREAD = Struct(
    _magic = Const(b"MANM"),
    ver=Const(0x000A0001, Int32ul),
    unk=Int32ul, # seems to be 0 or 1, possibly determines if anim is looping?
    frame_count=Float,
    track_count=Rebuild(Int32ul, construct.len_(this.tracks)),
    _padding=If(this.track_count > 0, AlignTo(8, b"\xff")),
    _next_kfv_offset=Computed(this.track_count * 0x30 + 0x18), # end of BoneTracks, used to rebuild
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
