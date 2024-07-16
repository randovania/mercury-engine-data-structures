import construct
from construct.core import (
    Array,
    Const,
    Construct,
    Container,
    Hex,
    If,
    IfThenElse,
    Int8ul,
    Int16ul,
    Int32ul,
    Int64ul,
    ListContainer,
    Struct,
    Tell
)

from pprint import pprint
from dataclasses import dataclass
from typing import Union

from mercury_engine_data_structures.construct_extensions.alignment import AlignTo
from mercury_engine_data_structures.common_types import Float, CVector2D
from mercury_engine_data_structures.formats.base_resource import BaseResource
from mercury_engine_data_structures.formats.property_enum import PropertyEnumDoubleUnsafe
from mercury_engine_data_structures.game_check import Game


@dataclass
class KeyFrameValue:
    time: int # byte or short, dependent on timing_type
    value: float
    derivative: float

    def init(self, t: int, v: int, d: int):
        self.time = t
        self.value = v
        self.derivative = d


@dataclass
class KeyFramedValues:
    timing_type: int # short, 0 or 8
    keyframes: list[KeyFrameValue]

    def auto_set_timing_type(self) -> int:
        tt = 8

        for kf in self.keyframes:
            if kf.time > 0xFF:
                tt = 0
            if kf.time > 0xFFFF:
                raise ValueError(f"Keyframe has too large of a time! Max size is 65535, keyframe has {kf.time}")
        
        self.timing_type = tt
        return tt
    
    def add(self, time: int, val: int, derivative: int):
        if time > 0xFFFF:
            raise ValueError(f"Cannot add time {time} as max value is {0xFFFF}")
        
        new_kf = KeyFrameValue(time, val, derivative)
        self.keyframes.append(new_kf)
        self.keyframes.sort(key=lambda kfv: kfv.time)
    

class KeyFramedValuesConstruct(Construct):
    @classmethod
    def _parse(self, stream, context, path) -> KeyFramedValues:
        timing_type = Int16ul._parsereport(stream, context, path)
        kf_count = Int16ul._parsereport(stream, context, path)

        # timings
        timings = Array(kf_count, Int8ul if timing_type == 8 else Int16ul)._parsereport(stream, context, f"{path} -> Timings")
        AlignTo(4, b"\xff")._parse(stream, context, path)
        
        values = Array(kf_count, CVector2D)._parsereport(stream, context, f"{path} -> Values")

        kf_data = [KeyFrameValue(timings[i], values[i][0], values[i][1]) for i in range(kf_count)]
        return KeyFramedValues(timing_type=timing_type, keyframes=kf_data)
    
    @classmethod
    def _build(self, obj: KeyFramedValues, stream, context, path) -> None:
        count = len(obj.keyframes)
        Int16ul._build(obj.timing_type, stream, context, path)
        Int16ul._build(count, stream, context, path)
        
        field = Int8ul if obj.timing_type == 8 else Int16ul
        Array(count, field)._build([k.time for k in obj.keyframes], stream, context, path)
        AlignTo(4, b"\xff")._build(None, stream, context, path)
        Array(count, CVector2D)._build([[k.value, k.derivative] for k in obj.keyframes], stream, context, path)
        context["final_offset"] = construct.stream_tell(stream, path)


@dataclass
class BcsklaTrack:
    bone_name: str
    values: list[Union[KeyFramedValues, float]]

    def __init__(self, bone_name: str, values: list[Union[KeyFramedValues, float]]) -> None:
        self.bone_name = bone_name
        self.values = values

    @property
    def pos_x(self) -> Union[KeyFramedValues, float]:
        return self.values[0]

    @property
    def pos_y(self) -> Union[KeyFramedValues, float]:
        return self.values[1]

    @property
    def pos_z(self) -> Union[KeyFramedValues, float]:
        return self.values[2]

    @property
    def rot_x(self) -> Union[KeyFramedValues, float]:
        return self.values[3]

    @property
    def rot_y(self) -> Union[KeyFramedValues, float]:
        return self.values[4]

    @property
    def rot_z(self) -> Union[KeyFramedValues, float]:
        return self.values[5]

    @property
    def scale_x(self) -> Union[KeyFramedValues, float]:
        return self.values[6]

    @property
    def scale_y(self) -> Union[KeyFramedValues, float]:
        return self.values[7]

    @property
    def scale_z(self) -> Union[KeyFramedValues, float]:
        return self.values[8]


class BcsklaTrackConstruct(Construct):
    STRUCT = Struct(
        # TODO add bone names into dread_properties.json
        bone_hash = PropertyEnumDoubleUnsafe,
        flags = Int32ul,
        offset = Tell,
    )

    @classmethod
    def _parse(self, stream, context, path) -> BcsklaTrack:
        data = self.STRUCT._parse(stream, context, path)
        values: list[Union[KeyFramedValues, float]] = []
        for i in range(9):
            construct.stream_seek(stream, data.offset + (4 * i), 0, path)
            if (2 ** i) & data.flags:
                off = Int32ul._parsereport(stream, context, path)
                construct.stream_seek(stream, data.offset + off, 0, path)
                values.append(KeyFramedValuesConstruct._parse(stream, context, f"{path} -> KF Value {i}"))
            else:
                values.append(Float._parsereport(stream, context, path))
        
        return BcsklaTrack(data.bone_hash, values)
    
    @classmethod
    def _build(self, obj: BcsklaTrack, stream, context, path) -> None:
        flags = 0
        for i, val in enumerate(obj.values):
            if type(val) == KeyFramedValues:
                flags += 2**i
        
        self.STRUCT._build(Container(bone_hash=obj.bone_name, flags=flags), stream, context, path)
        offset = construct.stream_tell(stream, path)

        for i, val in enumerate(obj.values):
            construct.stream_seek(stream, offset + (4 * i), 0, path)
            if type(val) == KeyFramedValues:
                Int32ul._build(context["final_offset"] - offset, stream, context, path)
                construct.stream_seek(stream, context["final_offset"], 0, path)
                KeyFramedValuesConstruct._build(val, stream, context, f"{path} -> value {i}")
            else:
                Float._build(val, stream, context, path)


@dataclass
class BcsklaData:
    unk: int
    frame_count: float
    tracks: list[BcsklaTrack]

    def validate(self) -> None:
        if not self.frame_count.is_integer():
            raise ValueError("Frame count must be an integer!")
        
        expected_timing_type = 8 if self.frame_count <= 0xFF else 0

        for track in self.tracks:
            for i, value in enumerate(track.values):
                if type(value) == KeyFramedValues:
                    value.auto_set_timing_type()
                    if expected_timing_type != value.timing_type:
                        raise ValueError(f"Track {track.bone_name} ({i}) has unexpected TT!")
                    
                    if value.keyframes[-1].time != self.frame_count:
                        raise ValueError(f"KFV for {track.bone_name}, value {i} does not end on keyframe {self.frame_count}!")

    def __str__(self) -> str:
        pprint(self)
        return ""


class BcsklaConstruct(Construct):
    HEADER_STRUCT: Struct = Struct(
        _magic=Const(b"MANM"),
        ver=Const(0x000A0001, Int32ul),
        unk=Int32ul,
        frame_count=Float,
        track_count=Int32ul,
        padding=If(
            construct.this.track_count != 0,
            Const(0xFFFFFFFF, Int32ul)
        ),
    )

    def _parse(self, stream, context, path) -> BcsklaData:
        hdr = self.HEADER_STRUCT._parse(stream, context, f"{path} -> Header")
        
        offset = construct.stream_tell(stream, path)
        tracks: list[BcsklaTrack] = []
        for i in range(hdr.track_count):
            construct.stream_seek(stream, offset + (i * 0x30), 0, path)
            tracks.append(BcsklaTrackConstruct._parse(stream, context, f"{path} -> Track {i}"))

        return BcsklaData(hdr.unk, hdr.frame_count, tracks)
    
    def _build(self, obj: BcsklaData, stream, context, path):
        obj.validate()
        hdr = Container(
            unk=obj.unk,
            frame_count=obj.frame_count,
            track_count=len(obj.tracks)
        )
        self.HEADER_STRUCT._build(hdr, stream, context, f"{path} -> Header")

        context["final_offset"] = (hdr.track_count * 0x30) + construct.stream_tell(stream, path)
        for i, track in enumerate(obj.tracks):
            construct.stream_seek(stream, 0x18 + (i * 0x30), 0, path)
            BcsklaTrackConstruct._build(track, stream, context, f"{path} -> Track {i}")

    
class Bcskla(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BcsklaConstruct()

    def validate(self) -> None:
        # shortcut for the BcsklaData validator
        return self.raw.validate()