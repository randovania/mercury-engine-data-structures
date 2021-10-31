import copy
import typing

import construct
from construct import Adapter

StrId = construct.CString("utf-8")
Int: construct.FormatField = typing.cast(construct.FormatField, construct.Int32sl)
UInt: construct.FormatField = typing.cast(construct.FormatField, construct.Int32ul)
Float: construct.FormatField = typing.cast(construct.FormatField, construct.Float32l)
CVector2D = construct.Array(2, Float)
CVector3D = construct.Array(3, Float)
CVector4D = construct.Array(4, Float)


class DictAdapter(Adapter):
    def _decode(self, obj: construct.ListContainer, context, path):
        result = construct.Container()
        for item in obj:
            key = item[0]
            if key in result:
                raise construct.ConstructError(f"Key {key} found twice in object", path)
            result[key] = item[1]
        return result

    def _encode(self, obj: construct.Container, context, path):
        return construct.ListContainer(
            construct.ListContainer([type_, item])
            for type_, item in obj.items()
        )


def make_dict(value: construct.Construct):
    return DictAdapter(make_vector(construct.Sequence(StrId, value)))


def make_vector(value: construct.Construct):
    arr = construct.Array(
        construct.this.count,
        value,
    )
    arr.name = "items"

    def get_len(ctx):
        return len(ctx['items'])

    return construct.FocusedSeq(
        "items",
        "count" / construct.Rebuild(construct.Int32ul, get_len),
        arr,
    )


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
