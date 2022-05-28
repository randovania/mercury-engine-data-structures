import copy
import typing

import construct
from construct import Adapter

from mercury_engine_data_structures.construct_extensions.strings import CStringRobust

StrId = CStringRobust("utf-8")
Int: construct.FormatField = typing.cast(construct.FormatField, construct.Int32sl)
UInt: construct.FormatField = typing.cast(construct.FormatField, construct.Int32ul)
Float: construct.FormatField = typing.cast(construct.FormatField, construct.Float32l)
CVector2D = construct.Array(2, Float)
CVector3D = construct.Array(3, Float)
CVector4D = construct.Array(4, Float)


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
    def _decode(self, obj: construct.ListContainer, context, path):
        result = construct.Container()
        for item in obj:
            key = item.key
            if key in result:
                raise construct.ConstructError(f"Key {key} found twice in object", path)
            result[key] = item.value
        return result

    def _encode(self, obj: construct.Container, context, path):
        return construct.ListContainer(
            construct.Container(key=type_, value=item)
            for type_, item in obj.items()
        )

    def _emitparse(self, code):
        fname = f"parse_dict_adapter_{code.allocateId()}"
        block = f"""
            def {fname}(io, this):
                obj = {self.subcon._compileparse(code)}
                result = Container()
                for item in obj:
                    result[item.key] = item.value
                if len(result) != len(obj):
                    raise ConstructError("Duplicated keys found in object")
                return result
        """
        code.append(block)
        return f"{fname}(io, this)"

    def _emitbuild(self, code):
        fname = f"build_dict_adapter_{code.allocateId()}"
        block = f"""
            def {fname}(original_obj, io, this):
                obj = ListContainer(
                    Container(key=type_, value=item)
                    for type_, item in original_obj.items()
                )
                return {self.subcon._compilebuild(code)}
        """
        code.append(block)
        return f"{fname}(obj, io, this)"


class DictElement(construct.Construct):
    def __init__(self, field, key=StrId):
        super().__init__()
        self.field = field
        self.key = key

        assert not self.key.flagbuildnone

    def _parse(self, stream, context, path):
        context = construct.Container(
            _=context, _params=context._params, _root=None, _parsing=context._parsing,
            _building=context._building, _sizing=context._sizing, _io=stream,
            _index=context.get("_index", None))
        context._root = context._.get("_root", context)

        key = self.key._parsereport(stream, context, path)
        value = self.field._parsereport(stream, context, f"{path} -> {key}")

        return construct.Container(
            key=key,
            value=value,
        )

    def _build(self, obj, stream, context, path):
        context = construct.Container(
            _=context, _params=context._params, _root=None, _parsing=context._parsing,
            _building=context._building, _sizing=context._sizing, _io=stream,
            _index=context.get("_index", None))
        context._root = context._.get("_root", context)

        key = self.key._build(obj.key, stream, context, path)
        value = self.field._build(obj.value, stream, context, f"{path} -> {key}")

        return construct.Container(
            key=key,
            value=value,
        )

    def _sizeof(self, context, path):
        context = construct.Container(
            _=context, _params=context._params, _root=None, _parsing=context._parsing,
            _building=context._building, _sizing=context._sizing, _io=None,
            _index=context.get("_index", None))
        context._root = context._.get("_root", context)

        key = self.key._sizeof(context, path)
        value = self.field._sizeof(context, f"{path} -> {key}")
        return key + value

    def _emitparse(self, code):
        fname = f"parse_dict_element_{code.allocateId()}"
        block = f"""
            def {fname}(io, this) -> Container:
                result = Container()
                this = Container(_=this, _params=this['_params'], _root=None, _parsing=True, _building=False,
                                 _sizing=False, _subcons=None, _io=io, _index=this.get('_index', None))
                this['_root'] = this['_'].get('_root', this)
                result['key'] = this['key'] = {self.key._compileparse(code)}
                result['value'] = this['value'] = {self.field._compileparse(code)}
                return result
        """
        code.append(block)
        return f"{fname}(io, this)"

    def _emitbuild(self, code):
        fname = f"build_dict_element_{code.allocateId()}"
        block = f"""
            def {fname}(obj, io, this):
                this = Container(_ = this, _params = this['_params'], _root = None, _parsing = False, _building = True,
                                 _sizing = False, _subcons = None, _io = io, _index = this.get('_index', None))
                this['_root'] = this['_'].get('_root', this)

                objdict = obj
                
                obj = objdict["key"]
                this['key'] = obj
                this['key'] = {self.key._compilebuild(code)}
                
                {f'obj = objdict.get("value", None)' if self.field.flagbuildnone else f'obj = objdict["value"]'}
                this['value'] = obj
                this['value'] = {self.field._compilebuild(code)}

                return this
        """
        code.append(block)
        return f"{fname}(obj, io, this)"


class DictConstruct(construct.Construct):
    def __init__(self, key_type: construct.Construct, value_type: construct.Construct,
                 count_type: construct.Construct = construct.Int32ul):
        super().__init__()
        self.key_type = key_type
        self.value_type = value_type
        self.count_type = count_type

        assert not self.key_type.flagbuildnone

    def _parse(self, stream, context, path) -> construct.Container:
        field_count = self.count_type._parsereport(stream, context, path)

        result = construct.Container()

        for i in range(field_count):
            field_path = f"{path}.field_{i}"
            key = self.key_type._parsereport(stream, context, field_path)
            value = self.value_type._parsereport(stream, context, field_path)
            result[key] = value

        return result

    def _build(self, obj: construct.Container, stream, context, path):
        self.count_type._build(len(obj), stream, context, path)

        for i, (key, value) in enumerate(obj.items()):
            field_path = f"{path}.field_{i}"
            self.key_type._build(key, stream, context, field_path)
            self.value_type._build(value, stream, context, field_path)

    def _emitparse(self, code):
        return "Container((%s, %s) for i in range(%s))" % (
            self.key_type._compileparse(code),
            self.value_type._compileparse(code),
            self.count_type._compileparse(code),
        )

    def _emitbuild(self, code):
        fname = f"build_dict_{code.allocateId()}"
        block = f"""
            def {fname}(key, value, io, this):
                obj = key
                {self.key_type._compilebuild(code)}

                obj = value
                {self.value_type._compilebuild(code)}
        """
        code.append(block)
        return f"(reuse(len(obj), lambda obj: {self.count_type._compilebuild(code)}), list({fname}(key, value, io, this) for key, value in obj.items()), obj)[2]"


def make_dict(value: construct.Construct, key=StrId):
    return DictConstruct(
        key_type=key,
        value_type=value,
    )


def make_vector(value: construct.Construct):
    arr = construct.Array(
        construct.this.count,
        value,
    )
    arr.name = "items"
    get_len = construct.len_(construct.this.items)

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
