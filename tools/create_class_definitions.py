from __future__ import annotations

import argparse
import collections
import copy
import json
from pathlib import Path
from typing import Any

import construct

meds_root = Path(__file__).parents[1].joinpath("src", "mercury_engine_data_structures")

dread_data_construct_path = meds_root.joinpath("_dread_data_construct.py")
data_construct = construct.Container()
exec(compile(dread_data_construct_path.read_text(), dread_data_construct_path, "exec"), data_construct)

# This must be updated along with src/mercury_engine_data_structures/game_check.py!
GAME_VERSION_BUILD_DATA = {
    "sr": {
        "1.0.0": 1,
    },
    "dread": {
        "1.0.0": 1,
        "1.0.1": 2,
        "2.0.0": 4,
        "2.1.0": 8,
    },
}


def _type_name_to_python_identifier(type_name: str):
    return (
        type_name.replace("::", "_")
        .replace(" ", "_")
        .replace("<", "_")
        .replace(">", "_")
        .replace(",", "_")
        .replace("*", "Ptr")
    )


class TypeExporter:
    def __init__(self, all_types: dict[str, Any], primitive_to_construct, type_lib):
        self.all_types = all_types
        self._exported_types = {}
        self._types_with_pointer = set()
        self._types_being_exported = set()
        self._children_for = collections.defaultdict(set)
        self._type_definition_code = ""
        self._primitive_to_construct = primitive_to_construct
        self._type_lib = type_lib

        for type_name, data in all_types.items():
            if isinstance(data, type_lib.StructType) and data.parent is not None:
                self._children_for[data.parent].add(type_name)

    def children_for(self, type_name: str, recursive: bool = True):
        for child in self._children_for[type_name]:
            yield child
            if recursive:
                yield from self.children_for(child)

    def _debug(self, msg: str):
        pass
        # print("  " * len(self._types_being_exported) + f"* {msg}")

    def _export_enum_type(self, type_variable: str, type_name: str):
        data = self.all_types[type_name]
        if not isinstance(data, self._type_lib.EnumType):
            raise ValueError(f"_export_enum_type called for {type_name}, a non-Enum")

        enum_definition = f"\n\n\nclass {type_variable}(enum.IntEnum):\n"
        for key, value in data.values.items():
            if key == "None":
                key = "NONE"
            enum_definition += f"    {key} = {value}\n"

        code = f"{enum_definition}\n\nconstruct_{type_variable} = StrictEnum({type_variable})"

        return "construct_" + type_variable, code

    def _export_struct_type(self, type_variable: str, type_name: str):
        data = self.all_types[type_name]
        assert isinstance(data, self._type_lib.StructType)

        parent_name = None
        if data.parent is not None:
            parent_name = self.ensure_exported_type(data.parent)

        if data.fields:
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

        return f"Object({field_var}{fields_def})"

    def _export_type(self, type_name: str):
        type_data = self.all_types[type_name]
        type_variable = type_data.name_as_python_identifier

        if isinstance(type_data, self._type_lib.PrimitiveType):
            type_variable = self._primitive_to_construct[type_data.primitive_kind]

        elif isinstance(type_data, self._type_lib.StructType):
            type_code = self._export_struct_type(type_variable, type_name)
            self._type_definition_code += f"\n\n{type_variable} = {type_code}"

        elif isinstance(type_data, self._type_lib.EnumType):
            type_variable, type_code = self._export_enum_type(type_variable, type_name)
            self._type_definition_code += type_code

        elif isinstance(type_data, self._type_lib.FlagsetType):
            reference = self.ensure_exported_type(type_data.enum)
            flags = f"BitMaskEnum({reference}.enum_class)"
            self._type_definition_code += f"\n\n{type_variable} = {flags}"

        elif isinstance(type_data, self._type_lib.TypedefType):
            reference = self.ensure_exported_type(type_data.alias)
            self._type_definition_code += f"\n\n{type_variable} = {reference}"

        elif isinstance(type_data, self._type_lib.PointerType):
            inner_field = self.pointer_to_type(type_data.target)
            self._type_definition_code += f"\n\n{type_variable} = {inner_field}.create_construct()"

        elif isinstance(type_data, self._type_lib.VectorType):
            inner_field = self.ensure_exported_type(type_data.value_type)
            type_code = f"common_types.make_vector({inner_field})"
            self._type_definition_code += f"\n\n{type_variable} = {type_code}"

        elif isinstance(type_data, self._type_lib.DictionaryType):
            key_field = self.ensure_exported_type(type_data.key_type)
            inner_field = self.ensure_exported_type(type_data.value_type)
            type_code = f"common_types.make_dict({inner_field}, key={key_field})"
            self._type_definition_code += f"\n\n{type_variable} = {type_code}"

        else:
            raise ValueError(f"Unknown type_data: {type_data}")

        self._type_definition_code += f"\n{type_variable}.name = {repr(type_name)}"

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
        return "Pointer_" + _type_name_to_python_identifier(type_name)

    def export_code(self):
        code = """# This file was generated!
import enum

import construct

from mercury_engine_data_structures import common_types
from mercury_engine_data_structures.object import Object
from mercury_engine_data_structures.pointer_set import PointerSet
from mercury_engine_data_structures.formats.property_enum import PropertyEnum, PropertyEnumUnsafe
from mercury_engine_data_structures.construct_extensions.enum import StrictEnum, BitMaskEnum

"""
        code += "primitive_to_construct = {\n"
        code += "".join(f'    "{k.value}": {v},\n' for k, v in self._primitive_to_construct.items())
        code += "}\n\n"

        seen_types_with_pointer = set()
        while unchecked_types := self._types_with_pointer - seen_types_with_pointer:
            for type_name in sorted(unchecked_types):
                seen_types_with_pointer.add(type_name)
                self.ensure_exported_type(type_name)
                for child in sorted(self.children_for(type_name)):
                    self.ensure_exported_type(child)

        for type_name in sorted(self._types_with_pointer):
            code += f'{self.pointer_to_type(type_name)} = PointerSet("{type_name}")\n'

        # for type_name in self.all_types.keys():
        #     self.ensure_exported_type(type_name)

        code += self._type_definition_code

        code += "\n\n"

        for type_name in sorted(self._types_with_pointer):
            if type_name != "base::reflection::CTypedValue":
                code += (
                    f'{self.pointer_to_type(type_name)}.add_option("{type_name}", '
                    f"{self.ensure_exported_type(type_name)})\n"
                )
            for child in sorted(self.children_for(type_name)):
                code += f'{self.pointer_to_type(type_name)}.add_option("{child}", {self.ensure_exported_type(child)})\n'
            code += "\n"

        return code


def game_argument_type(s: str) -> str:
    if s not in ["dread", "sr"]:
        raise ValueError(f"No enum named {s} found")
    return s


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "game", help="The game to create the class definitions for", type=game_argument_type, choices=["dread", "sr"]
    )
    args = parser.parse_args()

    if args.game == "dread":
        types_path = meds_root.joinpath("dread_types.json")
        output_name = "dread_types.py"
        resource_name = "dread_resource_names"
        property_name = "dread_property_names"
    else:
        types_path = meds_root.joinpath("samus_returns_types.json")
        output_name = "sr_types.py"
        resource_name = "sr_resource_names"
        property_name = "sr_property_names"

    game_types = json.loads(types_path.read_text())

    type_lib_path = meds_root.joinpath("type_lib.py")
    type_lib_source = type_lib_path.read_text()
    type_lib = construct.Container(game_types=game_types)
    exec(compile(type_lib_source, type_lib_path, "exec"), type_lib)
    primitive_to_construct = {
        type_lib.PrimitiveKind.VECTOR_2: "common_types.CVector2D",
        type_lib.PrimitiveKind.VECTOR_3: "common_types.CVector3D",
        type_lib.PrimitiveKind.VECTOR_4: "common_types.CVector4D",
        type_lib.PrimitiveKind.FLOAT: "common_types.Float",
        type_lib.PrimitiveKind.INT: "common_types.Int",
        type_lib.PrimitiveKind.STRING: "common_types.StrId",
        type_lib.PrimitiveKind.UINT: "common_types.UInt",
        type_lib.PrimitiveKind.BOOL: "construct.Flag",
        type_lib.PrimitiveKind.UINT_16: "construct.Int16ul",
        type_lib.PrimitiveKind.UINT_64: "construct.Int64ul",
        type_lib.PrimitiveKind.BYTES: "construct.Prefixed(construct.Int32ul, construct.GreedyBytes)",
        type_lib.PrimitiveKind.PROPERTY: "PropertyEnum",
    }

    output_path = meds_root.joinpath("formats", output_name)

    # Skip it for sr as it has some errors in its types json
    if args.game != "sr":
        all_types: dict[str, type_lib.BaseType] = copy.copy(type_lib.TypeLib(game_types, 11).all_types())

        type_exporter = TypeExporter(all_types, primitive_to_construct, type_lib)
        for type_name in sorted(all_types.keys()):
            type_exporter.ensure_exported_type(type_name)

        output_path.write_text(type_exporter.export_code())

    with meds_root.joinpath(f"{property_name}.json").open() as f:
        property_data: dict[str, int] = json.load(f)

    data_construct.KnownHashes.build_file(property_data, meds_root.joinpath(f"{property_name}.bin"))

    with meds_root.joinpath(f"{resource_name}.json").open() as f:
        resource_data: dict[str, dict] = json.load(f)

    data_construct.VersionedHashes.build_file(
        resource_data, meds_root.joinpath(f"{resource_name}.bin"), versions=GAME_VERSION_BUILD_DATA[args.game]
    )


if __name__ == "__main__":
    main()
