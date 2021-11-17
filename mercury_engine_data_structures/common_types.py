import copy
import typing

import construct
from construct.core import Adapter, Byte, Const, Construct, ConstructError, Enum, FocusedSeq, FormatField, Int16ul, Int32sl, Int32ul, Float32l, Array, Rebuild, Struct, IfThenElse, this
from construct.lib.containers import Container, ListContainer

from mercury_engine_data_structures.construct_extensions.strings import CStringRobust, PascalStringRobust

def Version(major, minor, patch):
    return Struct(
        "major" / Const(major, Int16ul),
        "minor" / Const(minor, Byte),
        "patch" / Const(patch, Byte)
    )

StrId = IfThenElse(
    lambda this: hasattr(this._params, "prefixed_string"),
    PascalStringRobust(Int16ul, "utf-8"),
    CStringRobust("utf-8")
)

Int: FormatField = typing.cast(FormatField, Int32sl)
UInt: FormatField = typing.cast(FormatField, Int32ul)
Float: FormatField = typing.cast(FormatField, Float32l)
CVector2D = Array(2, Float)
CVector3D = Array(3, Float)
CVector4D = Array(4, Float)


class ListContainerWithKeyAccess(construct.ListContainer):
    def __init__(self, item_key_field: str, item_value_field: str = "value"):
        super().__init__()
        self.item_key_field = item_key_field
        self.item_value_field = item_value_field

    def _wrap(self, key, value):
        new_item = construct.Container()
        new_item[self.item_key_field] = key
        new_item[self.item_value_field] = value
        return new_item

    def __getitem__(self, key):
        for it in reversed(self):
            if it[self.item_key_field] == key:
                return it[self.item_value_field]
        return super().__getitem__(key)

    def __setitem__(self, key, value):
        for i, it in enumerate(self):
            if i == key:
                return super().__setitem__(i, value)
            if it[self.item_key_field] == key:
                return super().__setitem__(i, self._wrap(key, value))
        self.append(value)

    def items(self):
        for it in self:
            yield it[self.item_key_field], it[self.item_value_field]


class DictAdapter(Adapter):
    def _decode(self, obj: ListContainer, context, path):
        result = Container()
        for item in obj:
            key = item.key
            if key in result:
                raise ConstructError(f"Key {key} found twice in object", path)
            result[key] = item.value
        return result

    def _encode(self, obj: Container, context, path):
        return ListContainer(
            Container(key=type_, value=item)
            for type_, item in obj.items()
        )


class DictElement(construct.Construct):
    def __init__(self, field, key=StrId):
        super().__init__()
        self.field = field
        self.key = key

    def _parse(self, stream, context, path):
        context = Container(
            _=context, _params=context._params, _root=None, _parsing=context._parsing,
            _building=context._building, _sizing=context._sizing, _io=stream,
            _index=context.get("_index", None))
        context._root = context._.get("_root", context)

        key = self.key._parsereport(stream, context, path)
        value = self.field._parsereport(stream, context, f"{path} -> {key}")

        return Container(
            key=key,
            value=value,
        )

    def _build(self, obj, stream, context, path):
        context = Container(
            _=context, _params=context._params, _root=None, _parsing=context._parsing,
            _building=context._building, _sizing=context._sizing, _io=stream,
            _index=context.get("_index", None))
        context._root = context._.get("_root", context)

        key = self.key._build(obj.key, stream, context, path)
        value = self.field._build(obj.value, stream, context, f"{path} -> {key}")

        return Container(
            key=key,
            value=value,
        )

    def _sizeof(self, context, path):
        context = Container(
            _=context, _params=context._params, _root=None, _parsing=context._parsing,
            _building=context._building, _sizing=context._sizing, _io=None,
            _index=context.get("_index", None))
        context._root = context._.get("_root", context)

        key = self.key._sizeof(context, path)
        value = self.field._sizeof(context, f"{path} -> {key}")
        return key + value


def make_dict(value: construct.Construct, key=StrId):
    return DictAdapter(make_vector(DictElement(value, key)))


def make_vector(value: Construct):
    arr = Array(
        this.count,
        value,
    )
    arr.name = "items"

    def get_len(ctx):
        return len(ctx['items'])

    return FocusedSeq(
        "items",
        "count" / Rebuild(Int32ul, get_len),
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
    return Enum(Int32ul, **mapping)
