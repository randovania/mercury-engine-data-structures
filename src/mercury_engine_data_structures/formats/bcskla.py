from enum import Enum

import construct
from construct.core import (
    Adapter,
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
    ListContainer,
    Pointer,
    Rebuild,
    Struct,
    Tell,
    this,
)

from mercury_engine_data_structures.adapters.enum_adapter import EnumAdapter
from mercury_engine_data_structures.common_types import Float, VersionAdapter
from mercury_engine_data_structures.construct_extensions.alignment import AlignTo
from mercury_engine_data_structures.formats.base_resource import BaseResource
from mercury_engine_data_structures.formats.property_enum import PropertyEnumDoubleUnsafe
from mercury_engine_data_structures.game_check import Game


class TimingTypeEnum(Enum):
    ONE_BYTE = 8
    TWO_BYTE = 0


class DreadKFVAdapter(Adapter):
    SUBCON = Struct(
        timing_type=EnumAdapter(TimingTypeEnum, Int16ul),
        count=Int16ul,
        timings=IfThenElse(this.timing_type == TimingTypeEnum.TWO_BYTE, Int16ul[this.count], Int8ul[this.count]),
        _padding=AlignTo(4, b"\xff"),
        values=Array(this.count, Struct(value=Float, derivative=Float)),
    )

    def __init__(self):
        super().__init__(self.SUBCON)

    def _decode(self, obj, context, path):
        res = ListContainer()
        for i in range(obj.count):
            res.append(
                Container(
                    time=obj.timings[i],
                    value=obj["values"][i].value,
                    derivative=obj["values"][i].derivative,
                )
            )

        return res

    def _encode(self, obj, context, path):
        res = Container(
            timing_type=TimingTypeEnum.TWO_BYTE if obj[-1].time > 0xFF else TimingTypeEnum.ONE_BYTE,
            count=len(obj),
            timings=ListContainer([v.time for v in obj]),
            values=ListContainer([Container(value=v.value, derivative=v.derivative) for v in obj]),
        )

        return res


def _update_next_kfv(ctx):
    ctx._._._._next_kfv_offset = ctx._new_eof


KeyFramedValues_Dread = FocusedSeq("data", data=DreadKFVAdapter(), _new_eof=Tell, _new_kfv=Computed(_update_next_kfv))

# if data is keyframed, it builds to { count = c, data = [ { timing = t, values = [a, b, c] }, ... ] }
# if data is constant, it builds to { count = 0, data = { value = x } }
KeyFramedValues_SR = Struct(
    count=Rebuild(Int16ul, lambda ctx: 0 if isinstance(ctx.data, float) else len(ctx.data)),
    _data_type=Const(2, Int16ul),
    data=IfThenElse(
        this.count == 0,
        FocusedSeq("value", timing=Const(0, Int32ul), value=Float),
        # guessing on left/right_derivative. they are almost always the same value.
        Array(this.count, Struct(timing=Float, value=Float, left_derivative=Float, right_derivative=Float)),
    ),
    _new_eof=Tell,
    _new_kfv=Computed(_update_next_kfv),
)


def _rebuild_flags(ctx):
    flags = 0
    for i, val in enumerate(ctx.data):
        if isinstance(val, ListContainer):
            flags += 2**i
    return flags


class TrackDataAdapter(Adapter):
    def _decode(self, obj, context, path):
        return Container(
            bone_name=obj.bone_name,
            position=Container(x=obj.data[0], y=obj.data[1], z=obj.data[2]),
            rotation=Container(x=obj.data[3], y=obj.data[4], z=obj.data[5]),
            scale=Container(x=obj.data[6], y=obj.data[7], z=obj.data[8]),
        )

    def _encode(self, obj, context, path):
        return Container(
            bone_name=obj.bone_name,
            data=ListContainer(
                [
                    obj.position.x,
                    obj.position.y,
                    obj.position.z,
                    obj.rotation.x,
                    obj.rotation.y,
                    obj.rotation.z,
                    obj.scale.x,
                    obj.scale.y,
                    obj.scale.z,
                ]
            ),
        )


BoneTrack_Dread = TrackDataAdapter(
    Struct(
        # guess. almost always the bone names but some values still don't parse after dumping all model data >:(
        bone_name=PropertyEnumDoubleUnsafe,
        flags=Rebuild(Int32ul, _rebuild_flags),
        _offset=Tell,
        data=Array(
            9,
            IfThenElse(
                # if the flag for an index is zero, the value is keyframed
                2**this._index & this.flags == 0,
                Float,
                FocusedSeq(
                    "kfv",
                    # offsets are relative to immediately after the flag field
                    off=Rebuild(Int32ul, lambda ctx: ctx._._._next_kfv_offset - ctx._._offset),
                    kfv=Pointer(this.off + this._._offset, KeyFramedValues_Dread),
                ),
            ),
        ),
    )
)

BoneTrack_SR = TrackDataAdapter(
    Struct(
        bone_name=PropertyEnumDoubleUnsafe,
        data=Array(
            9,
            FocusedSeq(
                "kfv",
                off=Rebuild(Int32ul, lambda ctx: 0 if isinstance(ctx.kfv, float) else ctx._._._next_kfv_offset),
                kfv=IfThenElse(
                    this.off > 0,
                    Pointer(this.off, KeyFramedValues_SR),
                    # if offset is 0, this is the default value pos/rot=0, scale=1
                    IfThenElse(lambda ctx: ctx._index < 6, Computed(0.0), Computed(1.0)),
                ),
            ),
        ),
    )
)

BCSKLA_DREAD = Struct(
    _magic=Const(b"MANM"),
    ver=VersionAdapter("1.10.0"),
    unk=Int32ul,  # seems to be 0 or 1, possibly determines if anim is looping?
    frame_count=Float,
    track_count=Rebuild(Int32ul, construct.len_(this.tracks)),
    _padding=If(this.track_count > 0, AlignTo(8, b"\xff")),
    _next_kfv_offset=Computed(this.track_count * 0x30 + 0x18),  # end of BoneTracks, used to rebuild
    tracks=Array(this.track_count, BoneTrack_Dread),
)

BCSKLA_SR = Struct(
    _magic=Const(b"MANM"),
    ver=VersionAdapter("1.6.0"),
    unk=Int32ul,
    frame_count=Float,
    track_count=Rebuild(Int32ul, construct.len_(this.tracks)),
    _next_kfv_offset=Computed(this.track_count * 0x28 + 0x14),
    tracks=Array(this.track_count, BoneTrack_SR),
)


class Bcskla(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        if target_game == Game.DREAD:
            return BCSKLA_DREAD
        elif target_game == Game.SAMUS_RETURNS:
            return BCSKLA_SR
