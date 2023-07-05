import typing
from typing import Dict, Union, Type

import construct

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

    def _emitparse(self, code):
        fname = f"parse_object_{code.allocateId()}"
        type_table = f"parse_object_types_{code.allocateId()}"

        block = f"""
            {type_table} = {{}}
        """

        for type_name, type_class in self.fields.items():
            block += f"""
            {type_table}[{repr(type_name)}] = lambda io, this: {type_class._compileparse(code)}
        """

        block += f"""
            def {fname}(io, this):
                field_count = {construct.Int32ul._compileparse(code)}
                result = Container()
                array_response = False

                for i in range(field_count):
                    field_type = {PropertyEnum._compileparse(code)}
                    field_value = {type_table}[field_type](io, this)

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
        """
        code.append(block)
        return f"{fname}(io, this)"

    def _emitbuild(self, code):
        fname = f"build_object_{code.allocateId()}"
        type_table = f"build_object_types_{code.allocateId()}"

        block = f"""
            {type_table} = {{}}
        """

        for type_name, type_class in self.fields.items():
            block += f"""
            {type_table}[{repr(type_name)}] = lambda obj, io, this: {type_class._compilebuild(code)}
        """

        block += f"""
            def {fname}(the_obj, io, this):
                obj = len_(the_obj)
                {construct.Int32ul._compilebuild(code)}
                if isinstance(the_obj, list):
                    for it in the_obj:
                        obj = it["type"]
                        {PropertyEnum._compilebuild(code)}
                        {type_table}[it["type"]](it["item"], io, this)
                else:
                    for field_type, field_value in the_obj.items():
                        obj = field_type
                        {PropertyEnum._compilebuild(code)}
                        {type_table}[field_type](field_value, io, this)
        """
        code.append(block)
        return f"{fname}(obj, io, this)"
