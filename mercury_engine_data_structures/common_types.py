import copy
import typing

import construct

StrId = construct.CString("utf-8")
UInt: construct.FormatField = typing.cast(construct.FormatField, construct.Int32ul)
Float: construct.FormatField = typing.cast(construct.FormatField, construct.Float32l)
CVector2D = construct.Array(2, Float)
CVector3D = construct.Array(3, Float)
CVector4D = construct.Array(4, Float)


def make_dict(value: construct.Construct):
    return construct.PrefixedArray(
        construct.Int32ul,
        construct.Struct(
            key=StrId,
            value=value,
        )
    )


def make_vector(value: construct.Construct):
    return construct.PrefixedArray(construct.Int32ul, value)


def make_enum(values: typing.Union[typing.List[str], typing.Dict[str, int]], *,
              add_invalid: bool = True):
    if isinstance(values, dict):
        mapping = copy.copy(values)
    else:
        mapping = {
            name: i
            for i, name in enumerate(values)
        }
    if add_invalid:
        mapping["Invalid"] = 0x7fffffff
    return construct.Enum(construct.Int32ul, **mapping)
