from construct.core import Array, BitsInteger, Bitwise, Byte, Bytes, Computed, Const, Construct, Flag, Float32l, FocusedSeq, GreedyRange, Hex, Int16ul, Int32sl, Int32ul, LazyBound, Optional, Pass, Peek, PrefixedArray, StopIf, Struct, Switch, this
from construct.debug import Probe
from mercury_engine_data_structures.type_lib import is_child_of
from mercury_engine_data_structures.common_types import CVector3D, StrId, Version, make_vector
from mercury_engine_data_structures.construct_extensions.strings import PascalStringRobust
from mercury_engine_data_structures.formats import dread_types
from mercury_engine_data_structures.formats.property_enum import PropertyEnum, PropertyEnumUnsafe
from mercury_engine_data_structures.construct_extensions.misc import Skip


something = Struct(
    "name" / StrId,
    "unk1" / make_vector(Struct(
        "unk1" / Array(3, Int32ul),
        "unk2" / CVector3D
    )),
    "file" / StrId,
    "unk2" / Bytes(14)
)

fieldtypes = {k: v for k, v in vars(dread_types).items() if isinstance(v, Construct)}

something2 = Struct(
    "id" / PropertyEnum,
    "unk1" / Int32ul,
    "unk2" / Int32ul, 
    "fields" / Switch(this.id, fieldtypes),
)

def GoUntil(subcon, stopcon, condition=lambda x: True):
    return GreedyRange(FocusedSeq(
        "data",
        "_next" / Optional(Peek(stopcon)),
        StopIf(lambda this: this._parsing and this._next is not None and condition(this._next)),
        "data" / subcon,
    ))

something3 = Struct(
    "extra" / GoUntil(Int32ul, PropertyEnum),
    "id" / PropertyEnum,
    "unk1" / Int32ul,
    "fields" / Switch(this.id, fieldtypes),
)

BMSAS = Struct(
    "magic" / Const(b'MSAS'),
    "version" / Version(3, 23, 0),
    "id" / StrId,
    "flags" / Bitwise(FocusedSeq(
        "flags",
        "flags" / Array(18, Flag),
        Const(0, BitsInteger(14)),
    )),
    "actions" / make_vector(Struct(
        "id" / PropertyEnum,
        "anim" / StrId,
        "actionclass" / PropertyEnum,
        "unk1" / Int32ul,
        "flags?" / Array(4, Byte),
        "unk3" / Int32ul,
        "unk4" / Array(4, "unk1" / Hex(Int32sl) + "unk2" / Float32l),
        "anims" / make_vector(something),
        "tracks" / make_vector(something2),
        "unk8" / Int16ul,
        "unk81" / Int32ul,
        "unk82" / Int32ul,
        "unk83" / Int32ul,
        "events" / GoUntil(something3, PropertyEnum, lambda x: not is_child_of(x, "base::global::timeline::CEvent")),
    )),
    Probe()
)
