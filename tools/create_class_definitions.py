import collections
import copy
from pathlib import Path
from typing import Optional

from mercury_engine_data_structures import type_lib
from mercury_engine_data_structures.type_lib import (
    PrimitiveKind, BaseType, StructType, EnumType,
    TypedefType, PrimitiveType, VectorType, DictionaryType, PointerType, FlagsetType
)

primitive_to_construct = {
    PrimitiveKind.VECTOR_2: "common_types.CVector2D",
    PrimitiveKind.VECTOR_3: "common_types.CVector3D",
    PrimitiveKind.VECTOR_4: "common_types.CVector4D",
    PrimitiveKind.FLOAT: "common_types.Float",
    PrimitiveKind.INT: "common_types.Int",
    PrimitiveKind.STRING: "common_types.StrId",
    PrimitiveKind.UINT: "common_types.UInt",
    PrimitiveKind.BOOL: "construct.Flag",
    PrimitiveKind.UINT_16: "construct.Int16ul",
    PrimitiveKind.UINT_64: "construct.Int64ul",
    PrimitiveKind.BYTES: "construct.Prefixed(construct.Int32ul, construct.GreedyBytes)",
    PrimitiveKind.PROPERTY: "PropertyEnum",
}


def _type_name_to_python_identifier(type_name: str):
    return type_name.replace("::", "_").replace(" ", "_").replace("<", "_").replace(
        ">", "_").replace(",", "_").replace("*", "Ptr")


class TypeExporter:
    def __init__(self, all_types: dict[str, BaseType]):
        self.all_types = all_types
        self._exported_types = {}
        self._types_with_pointer = set()
        self._types_being_exported = set()
        self._children_for = collections.defaultdict(set)
        self._type_definition_code = ""

        for type_name, data in all_types.items():
            if isinstance(data, StructType) and data.parent is not None:
                self._children_for[data.parent].add(type_name)

    def children_for(self, type_name: str, recursive: bool = True):
        for child in self._children_for[type_name]:
            yield child
            if recursive:
                yield from self.children_for(child)

    def _debug(self, msg: str):
        print("  " * len(self._types_being_exported) + f"* {msg}")

    def _export_enum_type(self, type_variable: str, type_name: str):
        data = self.all_types[type_name]
        if not isinstance(data, EnumType):
            raise ValueError(f"_export_enum_type called for {type_name}, a non-Enum")

        enum_definition = f"\n\n\nclass {type_variable}(enum.IntEnum):\n"
        for key, value in data.values.items():
            if key == "None":
                key = "NONE"
            enum_definition += f'    {key} = {value}\n'

        code = f"{enum_definition}\n\nconstruct_{type_variable} = construct.Enum(construct.Int32ul, {type_variable})"

        return "construct_" + type_variable, code

    def _export_struct_type(self, type_variable: str, type_name: str):
        data = self.all_types[type_name]

        parent_name = None
        if isinstance(data, StructType) and data.parent is not None:
            parent_name = self.ensure_exported_type(data.parent)

        if isinstance(data, StructType):
            field_lines = []
            for field_name, field_type in data.fields.items():
                self._debug(f"Exporting field! {field_name} = {field_type}")
                converted_type = self.ensure_exported_type(field_type)
                field_lines.append(f'    "{field_name}": {converted_type},')

            if parent_name is not None:
                field_lines.insert(0, f"    **{parent_name}Fields,")

            fields_def = "{{\n{}\n}}".format("\n".join(field_lines))
        elif parent_name is not None:
            # No fields, just use the parent dict
            fields_def = f"{parent_name}Fields"
        else:
            # No fields and no parent, empty dict!
            fields_def = "{}"

        field_var = ""
        if self._children_for[type_name]:
            # We have children, create a field vars
            field_var = f"{type_variable}Fields := "

        return f'Object({field_var}{fields_def})'

    def _export_type(self, type_name: str):
        type_variable = _type_name_to_python_identifier(type_name)
        type_data = self.all_types[type_name]

        if isinstance(type_data, EnumType):
            type_variable, type_code = self._export_enum_type(type_variable, type_name)
            self._type_definition_code += type_code

        elif isinstance(type_data, TypedefType):
            reference = self.ensure_exported_type(type_data.alias)
            self._type_definition_code += f'\n\n{type_variable} = {reference}'

        elif isinstance(type_data, FlagsetType):
            reference = self.ensure_exported_type(type_data.enum)
            self._type_definition_code += f'\n\n{type_variable} = {reference}'

        elif isinstance(type_data, VectorType):
            inner_field = self.ensure_exported_type(type_data.value_type)
            type_code = f"common_types.make_vector({inner_field})"
            self._type_definition_code += f'\n\n{type_variable} = {type_code}'

        elif isinstance(type_data, DictionaryType):
            key_field = self.ensure_exported_type(type_data.key_type)
            inner_field = self.ensure_exported_type(type_data.value_type)
            type_code = f"common_types.make_dict({inner_field}, key={key_field})"
            self._type_definition_code += f'\n\n{type_variable} = {type_code}'

        elif isinstance(type_data, StructType):
            type_code = self._export_struct_type(type_variable, type_name)
            self._type_definition_code += f'\n\n{type_variable} = {type_code}'
        else:
            type_code = self.convert_type_to_construct(type_name)
            self._type_definition_code += f'\n\n{type_variable} = {type_code}'

        self._exported_types[type_name] = type_variable

    def ensure_exported_type(self, type_name: str) -> str:
        if type_name in self._exported_types:
            return self._exported_types[type_name]

        self._debug(f"Exporting new type! {type_name}")

        if type_name in self._types_being_exported:
            raise RuntimeError(f"Recursive export for {type_name} detected.")

        self._types_being_exported.add(type_name)
        self._export_type(type_name)
        self._types_being_exported.remove(type_name)

        self._debug(f"Finish exporting type {type_name}")

        return self._exported_types[type_name]

    def pointer_to_type(self, type_name: str) -> str:
        self._types_with_pointer.add(type_name)
        self.ensure_exported_type(type_name)
        return "Pointer_" + _type_name_to_python_identifier(type_name)

    def convert_type_to_construct(self, field_type: str):
        field_data = self.all_types[field_type]

        if isinstance(field_data, PrimitiveType):
            return primitive_to_construct[field_data.primitive_kind]

        # Containers
        if isinstance(field_data, VectorType):
            inner_field = self.convert_type_to_construct(field_data.value_type)
            return f"common_types.make_vector({inner_field})"

        if isinstance(field_data, DictionaryType):
            key_field = self.convert_type_to_construct(field_data.key_type)
            inner_field = self.convert_type_to_construct(field_data.value_type)
            return f"common_types.make_dict({inner_field}, key={key_field})"

        # Pointers
        if isinstance(field_data, PointerType):
            inner_field = self.pointer_to_type(field_data.target)
            return f"{inner_field}.create_construct()"

        return self.ensure_exported_type(field_type)

    def export_code(self):
        code = """# This file was generated!
import enum

import construct

from mercury_engine_data_structures import common_types
from mercury_engine_data_structures.object import Object
from mercury_engine_data_structures.pointer_set import PointerSet
from mercury_engine_data_structures.formats.property_enum import PropertyEnum, PropertyEnumUnsafe

"""
        seen_types_with_pointer = set()
        while unchecked_types := self._types_with_pointer - seen_types_with_pointer:
            for type_name in sorted(unchecked_types):
                seen_types_with_pointer.add(type_name)
                for child in sorted(self.children_for(type_name)):
                    self.ensure_exported_type(child)

        for type_name in sorted(self._types_with_pointer):
            code += '{} = PointerSet("{}")\n'.format(
                self.pointer_to_type(type_name),
                type_name,
            )

        # for type_name in self.all_types.keys():
        #     self.ensure_exported_type(type_name)

        code += self._type_definition_code

        code += "\n\n"

        for type_name in sorted(self._types_with_pointer):
            if type_name != "base::reflection::CTypedValue":
                code += '{}.add_option("{}", {})\n'.format(
                    self.pointer_to_type(type_name),
                    type_name,
                    self.ensure_exported_type(type_name),
                )
            for child in sorted(self.children_for(type_name)):
                code += f'{self.pointer_to_type(type_name)}.add_option("{child}", {self.ensure_exported_type(child)})\n'
            code += "\n"

        return code


def main():
    output_path = Path(__file__).parents[1].joinpath("mercury_engine_data_structures", "formats", "dread_types.py")

    all_types: dict[str, BaseType] = copy.copy(type_lib.all_types())

    # all_types.pop("base::global::CStrId")
    # all_types.pop("base::global::CRntString")
    # all_types.pop("base::global::CFilePathStrId")
    # all_types.pop("base::global::CRntFile")
    all_types.pop("CBlackboard")
    all_types.pop("CGameBlackboard")

    type_exporter = TypeExporter(all_types)

    needs_exporting = {"gameeditor::CGameModelRoot", "CCharClass", "CActorComponentDef"}
    while needs_exporting:
        next_type = needs_exporting.pop()
        if next_type not in type_exporter._exported_types:
            type_exporter.ensure_exported_type(next_type)
            needs_exporting.update(type_exporter._children_for[next_type])

    output_path.write_text(type_exporter.export_code())


if __name__ == '__main__':
    main()
