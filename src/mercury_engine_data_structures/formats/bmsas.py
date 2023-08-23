import construct
from construct.core import (
    Array,
    Byte,
    Const,
    Construct,
    Error,
    Flag,
    Hex,
    If,
    Int16ul,
    Int32sl,
    Int32ul,
    Int64ul,
    Select,
    Struct,
    Switch,
)

from mercury_engine_data_structures.common_types import Char, DictAdapter, Float, make_vector
from mercury_engine_data_structures.common_types import StrId as StrIdSR
from mercury_engine_data_structures.construct_extensions.strings import PascalStringRobust
from mercury_engine_data_structures.formats import BaseResource
from mercury_engine_data_structures.formats.property_enum import PropertyEnum, PropertyEnumDoubleUnsafe
from mercury_engine_data_structures.game_check import Game

StrId = PascalStringRobust(Int16ul, "utf-8")


class StrIdOrInt(Select):
    def __init__(self, str_subcon, int_subcon):
        self.str_subcon = str_subcon
        self.int_subcon = int_subcon
        super().__init__(self.str_subcon, Hex(self.int_subcon))

    def _emitparse(self, code: construct.CodeGen):
        code.append(f"""
            def parse_str_or_int(io):
                fallback = io.tell()
                try:
                    return {self.str_subcon._compileparse(code)}
                except UnicodeDecodeError:
                    io.seek(fallback)
                    return {self.int_subcon._compileparse(code)}
        """)
        return "parse_str_or_int(io)"

    def _emitbuild(self, code: construct.CodeGen):
        return (
            f"({self.int_subcon._compilebuild(code)})"
            "if isinstance(obj, int) else "
            f"({self.str_subcon._compilebuild(code)})"
        )

ArgTypes = {
    'f': Float,
    'b': Flag,
    'u': Int32ul,
    'i': Int32sl,
    'e': Int32ul,
    'o': Int32ul,
    't': Int32ul,
}

ArgTypesDread = {
    **ArgTypes,
    's': StrIdOrInt(StrId, Int64ul),
    'v': Switch(
        construct.this.key,
        {
            'vColorStart': Int32ul,
            'vColorEnd': Int32ul,
        },
        default=Array(3, Float)
    ),
}

ArgTypesSR = {
    **ArgTypes,
    's': StrIdOrInt(StrIdSR, Int32ul),
}


ArgListDread = DictAdapter(make_vector(Struct(
    key=PropertyEnum,
    value=Switch(
        construct.this.key[0],
        ArgTypesDread,
        default=construct.Error,
    )
)))

ArgListSR = DictAdapter(make_vector(Struct(
    key=PropertyEnumDoubleUnsafe,
    value=Struct(
        type=Char,
        value=Switch(
            construct.this.type,
            ArgTypesSR,
            default=construct.Error
        )
    )
)))

EventDread = Struct(
    type=PropertyEnum,
    unk=Int32ul,
    args=ArgListDread
)
EventSR = Struct(
    unk=Int32ul,
    args=ArgListSR,
)

EventListDread = Struct(
    counts=Array(5, Int16ul),
    events0=Array(construct.this.counts[0], Struct(
        unk=Int32ul,
        event=EventDread,
    )),
    events1=Array(construct.this.counts[1], EventDread),
    events2=Array(construct.this.counts[2], EventDread),
    events3=Array(construct.this.counts[3], EventDread),
    events4=Array(construct.this.counts[4], EventDread),
)

TrackDread = Struct(
    type=PropertyEnum,
    unk0=Int32ul,
    unk1=Int32ul,
    args=ArgListDread,
)

TrackList = make_vector(TrackDread)

AnimationDread = Struct(
    prefix=PropertyEnum,  # CAnimationPrefix::SPrefix
    name=StrId,
    action_type=PropertyEnum,
    unk0=Int32ul,
    unk1=Flag,
    unk2=Byte,  # Between 0 and 3
    unk3=Flag,
    unk4=Flag,
    unk5=Int32ul,
    unk6=Float,
    unk7=Float,
    unk8=Int32ul,
    unk9=Float,
    unk10=If(construct.this.unk0 & 32, Hex(Int64ul)),
    unk11=If(construct.this.unk0 & 64, StrId),
    unk12=make_vector(Struct(
        unk1=Float,
        unk2=Float,
        unk3=Float,
    )),
    unk13=make_vector(Struct(
        name=StrId,
        unk0=make_vector(Struct(
            unk0=Array(3, Hex(Int64ul)),
            unk1=StrId,
        )),
        tracks=TrackList,
        events=EventListDread,
    )),
    tracks=TrackList,
    events=EventListDread,
    unk14=make_vector(Struct(
        unk0=Int64ul,
        curve=StrId,
        unk1=make_vector(Hex(Int64ul)),
        unk2=Int32ul,
    )),
)

Action = Struct(
    action_name=StrIdSR,
    bcskla=StrIdSR,
)

AnimationSR = Struct(
    animation_id=Int16ul,
    track_count=Byte,
    extra_actions_count=Byte,
    event_counts=Byte[4],
    action=Action,
    transition_to_action=StrIdSR,
    unk1=Int32ul,
    unk2=Int32ul,
    unk3=Float,
    unk4=Float,
    tracks=construct.Array(
        construct.this.track_count,
        Struct(
            count=Int32ul,
            name=StrIdSR,
            events=construct.Array(
                construct.this.count,
                Struct(
                    unk1=Int32ul,
                    unk2=Int32ul,
                    args=ArgListSR,
                )
            )
        )
    ),
    events0=construct.Array(
        construct.this.event_counts[0],
        Struct(
            unk1=Int32ul,
            unk2=Int32ul,
            unk3=Byte,
            args=ArgListSR,
        )
    ),
    events1=construct.Array(construct.this.event_counts[1], EventSR),
    events2=construct.Array(construct.this.event_counts[2], EventSR),
    events3=construct.Array(construct.this.event_counts[3], EventSR),
    extra_actions=construct.Array(construct.this.extra_actions_count, Action),
)

BMSAS_Dread = Struct(
    _magic=Const(b"MSAS"),
    _version=Const(0x00170003, Hex(Int32ul)),
    name=StrId,
    unk=Hex(Int32ul),
    animations=make_vector(AnimationDread),
    _end=construct.Terminated,
).compile()


BMSAS_SR = Struct(
    name=StrIdSR,
    animations=make_vector(AnimationSR),
)
'''
`.bmsas` files don't exist in Samus Returns. The format is instead embedded in `.bmsad`.
'''


class Bmsas(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        if target_game == Game.DREAD:
            return BMSAS_Dread
        if target_game == Game.SAMUS_RETURNS:
            return BMSAS_SR
        return Error
