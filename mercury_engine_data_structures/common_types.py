import typing

import construct
from construct import CString, Float32l, Array, Construct, PrefixedArray, Int32ul, Struct

StrId = CString("utf-8")
Float: construct.FormatField = typing.cast(construct.FormatField, Float32l)
CVector2D = Array(2, Float)
CVector3D = Array(3, Float)
CVector4D = Array(4, Float)


def make_dict(value: Construct):
    return PrefixedArray(
        Int32ul,
        Struct(
            key=StrId,
            value=value,
        )
    )


def make_vector(value: Construct):
    return PrefixedArray(Int32ul, value)
