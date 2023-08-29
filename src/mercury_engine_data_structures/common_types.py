import copy
import functools
import typing

import construct
from construct import Adapter

from mercury_engine_data_structures.construct_extensions.strings import CStringRobust, PaddedStringRobust

StrId = CStringRobust("utf-8")
Char = PaddedStringRobust(1, "utf-8")
Int: construct.FormatField = typing.cast(construct.FormatField, construct.Int32sl)
UInt: construct.FormatField = typing.cast(construct.FormatField, construct.Int32ul)
Float: construct.FormatField = typing.cast(construct.FormatField, construct.Float32l)
CVector2D = construct.Array(2, Float)
CVector3D = construct.Array(3, Float)
CVector4D = construct.Array(4, Float)


def _cvector_emitparse(length: int, code: construct.CodeGen) -> str:
    """Specialized construct compile for CVector2/3/4D"""
    code.append(f"CVector{length}D_Format = struct.Struct('<{length}f')")
    return f"ListContainer(CVector{length}D_Format.unpack(io.read({length * 4})))"


def _vector_cvector_emitparse(length: int, code: construct.CodeGen) -> str:
    """Specialized construct compile for a dynamic array of CVector2/3/4D"""

    code.append(f"""
    def _parse_cvector{length}d_array(io, this):
        count = {construct.Int32ul._compileparse(code)}
        raw = struct.unpack(f'<{{{length} * count}}f', io.read({length * 4} * count))
        args = [iter(raw)] * {length}
        return ListContainer(zip(*args))
    """)
    return f"_parse_cvector{length}d_array(io, this)"


def _cvector_emitbuild(length: int, code: construct.CodeGen):
    code.append(f"CVector{length}D_Format = struct.Struct('<{length}f')")
    return f"(io.write(CVector{length}D_Format.pack(*obj)), obj)"


for i, vec in enumerate([CVector2D, CVector3D, CVector4D]):
    vec._emitparse = functools.partial(_cvector_emitparse, i + 2)
    vec._emitparse_vector = functools.partial(_vector_cvector_emitparse, i + 2)
    vec._emitbuild = functools.partial(_cvector_emitbuild, i + 2)


def _fmtfield_vector_emitparse(fmt_field: construct.FormatField, code: construct.CodeGen) -> str:
    code.append(f"""
    def _parse_{id(fmt_field)}_array(io, this):
        count = {construct.Int32ul._compileparse(code)}
        return ListContainer(struct.unpack(f'{fmt_field.fmtstr[0]}{{count}}{fmt_field.fmtstr[1]}',
                             io.read({fmt_field.length} * count)))
    """)
    return f"_parse_{id(fmt_field)}_array(io, this)"


for fmt in [Int, UInt, Float, construct.Int16ul]:
    fmt._emitparse_vector = functools.partial(_fmtfield_vector_emitparse, fmt)


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
    def __init__(self, subcon, *, allow_duplicates: bool = False):
        super().__init__(subcon)
        self.allow_duplicates = allow_duplicates

    def _decode(self, obj: construct.ListContainer, context: construct.Container, path: str,
                ) -> construct.ListContainer | construct.Container:
        result = construct.Container()
        for item in obj:
            key = item.key
            if key in result:
                if self.allow_duplicates:
                    return obj
                raise construct.ConstructError(f"Key {key} found twice in object", path)
            result[key] = item.value
        return result

    def _encode(self, obj: construct.ListContainer | construct.Container, context: construct.Container, path: str,
                ) -> list:
        if self.allow_duplicates and isinstance(obj, list):
            return obj
        return construct.ListContainer(
            construct.Container(key=type_, value=item)
            for type_, item in obj.items()
        )

    def _emitparse(self, code):
        fname = f"parse_dict_adapter_{code.allocateId()}"
        if self.allow_duplicates:
            on_duplicate = "return obj"
        else:
            on_duplicate = 'raise ConstructError("Duplicated keys found in object")'

        block = f"""
            def {fname}(io, this):
                obj = {self.subcon._compileparse(code)}
                result = Container()
                for item in obj:
                    result[item.key] = item.value
                if len(result) != len(obj):
                    {on_duplicate}
                return result
        """
        code.append(block)
        return f"{fname}(io, this)"

    def _emitbuild(self, code):
        fname = f"build_dict_adapter_{code.allocateId()}"
        wrap = "obj = ListContainer(Container(key=type_, value=item) for type_, item in original_obj.items())"
        if self.allow_duplicates:
            wrap = f"""
                if isinstance(original_obj, list):
                    obj = original_obj
                else:
                    {wrap}
            """
        code.append(f"""
            def {fname}(original_obj, io, this):
                {wrap}
                return {self.subcon._compilebuild(code)}
        """)
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

                {'obj = objdict.get("value", None)' if self.field.flagbuildnone else 'obj = objdict["value"]'}
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
        return "Container(({}, {}) for i in range({}))".format(
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
        return (f"(reuse(len(obj), "
                f"lambda obj: {self.count_type._compilebuild(code)}), "
                f"list({fname}(key, value, io, this) for key, value in obj.items()), obj)[2]")


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

    result = construct.FocusedSeq(
        "items",
        "count" / construct.Rebuild(construct.Int32ul, get_len),
        arr,
    )

    if hasattr(value, "_emitparse_vector"):
        _emitparse = value._emitparse_vector
    else:
        def _emitparse(code: construct.CodeGen) -> str:
            return (f"ListContainer(({value._compileparse(code)}) "
                    f"for i in range({construct.Int32ul._compileparse(code)}))")

    result._emitparse = _emitparse

    def _emitbuild(code):
        return (f"(reuse(len(obj), lambda obj: {construct.Int32ul._compilebuild(code)}),"
                f" list({value._compilebuild(code)} for obj in obj), obj)[2]")

    result._emitbuild = _emitbuild

    return result


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
