import typing
from typing import Dict, Type, Union

import construct

from mercury_engine_data_structures.construct_extensions.function_complex import (
    emit_switch_cases_build,
    emit_switch_cases_parse,
)
from mercury_engine_data_structures.formats.property_enum import PropertyEnum


class Object(construct.Construct):
    def __init__(self, fields: Dict[str, Union[construct.Construct, Type[construct.Construct]]]):
        super().__init__()
        self.fields = fields

    def _parse(self, stream, context, path) -> typing.Union[construct.Container, construct.ListContainer]:
        field_count = construct.Int32ul._parsereport(stream, context, path)

        array_response = False
        result = construct.Container()

        for i in range(field_count):
            field_path = f"{path}.field_{i}"
            field_type = PropertyEnum._parsereport(stream, context, field_path)
            try:
                field_construct = self.fields[field_type]
            except KeyError:
                raise construct.ExplicitError(f"Type {field_type} not known, valid types are {list(self.fields)}.",
                                              path=field_path)

            field_value = field_construct._parsereport(stream, context, field_path)
            if array_response or field_type in result:
                if not array_response:
                    result = construct.ListContainer(
                        construct.Container(type=name, item=value)
                        for name, value in result.items()
                    )
                    array_response = True
                result.append(construct.Container(type=field_type, item=field_value))
            else:
                result[field_type] = field_value

        return result

    def _build(self, obj: typing.Union[construct.Container, construct.ListContainer], stream, context, path):
        construct.Int32ul._build(len(obj), stream, context, path)

        if isinstance(obj, list):
            def list_iter():
                for it in obj:
                    yield it["type"], it["item"]
        else:
            list_iter = obj.items

        for i, (field_type, field_value) in enumerate(list_iter()):
            field_path = f"{path}.field_{i}"
            PropertyEnum._build(field_type, stream, context, field_path)
            self.fields[field_type]._build(field_value, stream, context, field_path)

    def _emitparse(self, code: construct.CodeGen) -> str:
        n = code.allocateId()
        fname = f"parse_object_{n}"

        code.append(f"""
        def _parse_object(io, this, type_table):
            field_count = {construct.Int32ul._compileparse(code)}
            result = Container()
            array_response = False

            for i in range(field_count):
                field_type = {PropertyEnum._compileparse(code)}
                field_value = type_table[field_type](io, this)

                if array_response or field_type in result:
                    if not array_response:
                        result = ListContainer(
                            Container(type=name, item=value)
                            for name, value in result.items()
                        )
                        array_response = True
                    result.append(Container(type=field_type, item=field_value))
                else:
                    result[field_type] = field_value

            return result
        """)

        type_table = emit_switch_cases_parse(code, self.fields, f"parse_object_types_{n}")

        code.append(f"""
            def {fname}(io, this):
                # {self.name}
                return _parse_object(io, this, {type_table})
        """)
        return f"{fname}(io, this)"

    def _emitbuild(self, code: construct.CodeGen) -> str:
        n = code.allocateId()
        fname = f"build_object_{n}"

        code.append(f"""
        def _build_object(the_obj, io, this, type_table):
            obj = len_(the_obj)
            {construct.Int32ul._compilebuild(code)}
            if isinstance(the_obj, list):
                for it in the_obj:
                    obj = it["type"]
                    {PropertyEnum._compilebuild(code)}
                    type_table[it["type"]](it["item"], io, this)
            else:
                for field_type, field_value in the_obj.items():
                    obj = field_type
                    {PropertyEnum._compilebuild(code)}
                    type_table[field_type](field_value, io, this)
        """)

        type_table = emit_switch_cases_build(code, self.fields, f"build_object_types_{n}")

        code.append(f"""
            def {fname}(the_obj, io, this):
                # {self.name}
                _build_object(the_obj, io, this, {type_table})
        """)
        return f"{fname}(obj, io, this)"
