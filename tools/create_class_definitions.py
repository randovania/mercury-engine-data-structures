import collections
import json
import re
import typing
from pathlib import Path
from typing import Optional

known_types_to_construct = {
    "bool": "construct.Flag",
    "float": "common_types.Float",
    "float32": "common_types.Float",
    "int": "common_types.Int",
    "unsigned": "common_types.UInt",
    "unsigned_int": "common_types.UInt",
    "unsigned_long": "construct.Int64ul",
    "base::global::CStrId": "common_types.StrId",
    "base::global::CFilePathStrId": "common_types.StrId",
    "base::global::CRntString": "common_types.StrId",
    "base::math::CVector2D": "common_types.CVector2D",
    "base::math::CVector3D": "common_types.CVector3D",
    "base::math::CVector4D": "common_types.CVector4D",
    "CGameLink<CActor>": "common_types.StrId",
    "CGameLink<CEntity>": "common_types.StrId",
    "CGameLink<CSpawnPointComponent>": "common_types.StrId",
    "base::global::CRntFile": "construct.Prefixed(construct.Int32ul, construct.GreedyBytes)",

    # ESubAreaItem::Count = 9
    "base::global::CArray<base::global::CStrId, EnumClass<ESubAreaItem>::Count, ESubAreaItem>": (
        "common_types.make_vector(common_types.StrId)"
    ),

    # TODO: test if works
    "base::global::CName": "common_types.StrId",
    "base::core::CAssetLink": "common_types.StrId",

    # Hacky
    # Enums that don't use enum-like names in fields
    "CDoorLifeComponent::SState": "common_types.UInt",
    "base::snd::ELowPassFilter": "common_types.UInt",
    "EShinesparkTravellingDirection": "common_types.UInt",
    "ECoolShinesparkSituation": "common_types.UInt",
}

vector_re = re.compile(r"(?:base::)?global::CRntVector<(.*?)(?:, false)?>$")
dict_re = re.compile(r"base::global::CRnt(?:Small)?Dictionary<base::global::CStrId,[\s_](.*)>$")
all_container_re = {
    "common_types.make_vector": vector_re,
    "common_types.make_dict": dict_re,
}

unique_ptr_re = re.compile(r"std::unique_ptr<(.*)>$")
weak_ptr_re = re.compile(r"base::global::CWeakPtr<(.*)>$")
raw_ptr_re = re.compile(r"(.*?)(?:[ ]?const)?\*$")
ref_re = re.compile(r"CGameObjectRef<(.*)>$")
typed_var_re = re.compile(r"(base::reflection::CTypedValue)$")
all_ptr_re = [unique_ptr_re, weak_ptr_re, raw_ptr_re, ref_re, typed_var_re]


def _type_name_to_python_identifier(type_name: str):
    return type_name.replace("::", "_").replace(" ", "_").replace("<", "_").replace(
        ">", "_").replace(",", "_").replace("*", "Ptr")


class TypeExporter:
    def __init__(self, all_types: dict[str, dict[str, typing.Any]]):
        self.all_types = all_types
        self._exported_types = {}
        self._types_with_pointer = set()
        self._types_being_exported = set()
        self._children_for = collections.defaultdict(set)
        self._type_definition_code = ""

        self._exported_types["base::reflection::CTypedValue"] = _type_name_to_python_identifier(
            "base::reflection::CTypedValue"
        )
        self._children_for["base::reflection::CTypedValue"].add("base::global::CRntFile")

        for type_name, data in all_types.items():
            if data["parent"] is not None:
                self._children_for[data["parent"]].add(type_name)

    def children_for(self, type_name: str, recursive: bool = True):
        for child in self._children_for[type_name]:
            yield child
            if recursive:
                yield from self.children_for(child)

    def _debug(self, msg: str):
        print("  " * len(self._types_being_exported) + f"* {msg}")

    def _export_enum_type(self, type_variable: str, type_name: str):
        data = self.all_types[type_name]
        if data["values"] is None:
            raise ValueError(f"_export_enum_type called for {type_name}, a non-Enum")

        enum_definition = f"\n\n\nclass {type_variable}(enum.IntEnum):\n"
        for key, value in data["values"].items():
            if key == "None":
                key = "NONE"
            enum_definition += f'    {key} = {value}\n'

        code = f"{enum_definition}\n\nconstruct_{type_variable} = construct.Enum(construct.Int32ul, {type_variable})"

        return "construct_" + type_variable, code

    def _export_known_type(self, type_variable: str, type_name: str):
        data = self.all_types[type_name]

        parent_name = None
        if data["parent"] is not None:
            parent_name = self.ensure_exported_type(data["parent"])

        if data["fields"]:
            field_lines = []
            for field_name, field_type in data["fields"].items():
                self._debug(f"Exporting field! {field_name} = {field_type}")
                converted_type = self.convert_type_to_construct(field_name, field_type)
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

        if type_name in self.all_types:
            if self.all_types[type_name]["values"] is not None:
                type_variable, type_code = self._export_enum_type(type_variable, type_name)
                self._type_definition_code += type_code
            else:
                type_code = self._export_known_type(type_variable, type_name)
                self._type_definition_code += f'\n\n{type_variable} = {type_code}'
        else:
            type_code = self.convert_type_to_construct(None, type_name)
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

    def convert_type_to_construct(self, field_name: Optional[str], field_type: str):
        if field_type in known_types_to_construct:
            return known_types_to_construct[field_type]

        # Containers
        try:
            make, m = next((make, x) for make, r in all_container_re.items() if (x := r.match(field_type)))
            if (inner_field := self.convert_type_to_construct(field_name, m.group(1))) is not None:
                self._debug(f"Container! {field_name} -> {field_type} -> {make} -> {inner_field}")
                return f"{make}({inner_field})"
            return None
        except StopIteration:
            pass

        # Pointers
        try:
            m = next(x for r in all_ptr_re if (x := r.match(field_type)))
            return f'{self.pointer_to_type(m.group(1))}.create_construct()'
        except StopIteration:
            pass

        if field_type not in self.all_types:
            raise ValueError(f"Unknown type: {field_type}")

        return self.ensure_exported_type(field_type)

    def export_code(self):
        code = """# This file was generated!
import enum

import construct

from mercury_engine_data_structures import common_types
from mercury_engine_data_structures.object import Object
from mercury_engine_data_structures.pointer_set import PointerSet

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
    p = Path(__file__).parents[1].joinpath("mercury_engine_data_structures", "dread_types.json")
    output_path = Path(__file__).parents[1].joinpath("mercury_engine_data_structures", "formats", "dread_types.py")

    with p.open() as f:
        all_types: dict[str, dict[str, str]] = json.load(f)

    all_types.pop("base::global::CStrId")
    all_types.pop("base::global::CRntString")
    all_types.pop("base::global::CFilePathStrId")
    all_types.pop("base::global::CRntFile")

    all_types.pop("CBlackboard")
    all_types.pop("CGameBlackboard")
    all_types["gameeditor::CGameModelRoot"]["fields"].pop("pSoundManager")
    all_types["gameeditor::CGameModelRoot"]["fields"].pop("pShotManager")
    all_types["gameeditor::CGameModelRoot"]["fields"].pop("pLightManager")
    all_types["gameeditor::CGameModelRoot"]["fields"].pop("pMusicManager")

    type_exporter = TypeExporter(all_types)

    needs_exporting = {"gameeditor::CGameModelRoot", "CActor", "CCharClass"}
    while needs_exporting:
        next_type = needs_exporting.pop()
        if next_type not in type_exporter._exported_types:
            type_exporter.ensure_exported_type(next_type)
            needs_exporting.update(type_exporter._children_for[next_type])

    output_path.write_text(type_exporter.export_code())


if __name__ == '__main__':
    main()
