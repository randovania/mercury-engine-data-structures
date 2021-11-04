import collections
import json
import re
from pathlib import Path
from typing import Any, Optional


def parse_all_types(all_types: dict[str, Any]):
    type_objects = {
        name: {
            "fields": data["fields"],
            "children": {},
        }
        for name, data in all_types.items()
    }
    type_objects[None] = {
        "children": {},
    }

    for name, data in all_types.items():
        try:
            type_objects[data["parent"]]["children"][name] = type_objects[name]
        except KeyError as e:
            print(f"Missing type: {e}")
            continue

    return type_objects[None]["children"]


known_types_to_construct = {
    "bool": "construct.Flag",
    "float": "common_types.Float",
    "int": "common_types.Int",
    "unsigned": "common_types.UInt",
    "base::global::CStrId": "common_types.StrId",
    "base::global::CFilePathStrId": "common_types.StrId",
    "base::global::CRntString": "common_types.StrId",
    "base::math::CVector2D": "common_types.CVector2D",
    "base::math::CVector3D": "common_types.CVector3D",
    "base::math::CVector4D": "common_types.CVector4D",
    "CGameLink<CActor>": "common_types.StrId",
    "CGameLink<CEntity>": "common_types.StrId",
    "CGameLink<CSpawnPointComponent>": "common_types.StrId",

    "base::reflection::CTypedValue": "ErrorWithMessage('nope')",

    # TODO: test if works
    "base::global::CName": "common_types.StrId",

    # Hacky
    # Enums that don't use enum-like names in fields
    "CDoorLifeComponent::SState": "common_types.UInt",
    "base::snd::ELowPassFilter": "common_types.UInt",
    "EShinesparkTravellingDirection": "common_types.UInt",
    "ECoolShinesparkSituation": "common_types.UInt",
}

vector_re = re.compile(r"(?:base::)?global::CRntVector<(.*)>$")
dict_re = re.compile(r"base::global::CRnt(?:Small)?Dictionary<base::global::CStrId,[\s_](.*)>$")
all_container_re = {
    "common_types.make_vector": vector_re,
    "common_types.make_dict": dict_re,
}

unique_ptr_re = re.compile(r"std::unique_ptr<(.*)>$")
raw_ptr_re = re.compile(r"(.*?)(?:_const)?Ptr$")
ref_re = re.compile(r"CGameObjectRef<(.*)>$")
all_ptr_re = [unique_ptr_re, raw_ptr_re, ref_re]


def convert_type_to_construct(field_name: str, field_type: str, all_types: dict[str, Any]):
    if field_type in known_types_to_construct:
        return known_types_to_construct[field_type]

    if field_name.startswith("e"):
        return "common_types.UInt"

    # Vector
    if (m := vector_re.match(field_type)) is not None:
        if (inner_field := convert_type_to_construct(field_name, m.group(1), all_types)) is not None:
            return f"common_types.make_vector({inner_field})"
        return None

    # Containers
    try:
        make, m = next((make, x) for make, r in all_container_re.items() if (x := r.match(field_type)))
        if (inner_field := convert_type_to_construct(field_name, m.group(1), all_types)) is not None:
            return f"{make}({inner_field})"
        return None
    except StopIteration:
        pass

    # Pointers
    try:
        m = next(x for r in all_ptr_re if (x := r.match(field_type)))
        return f'make_pointer_to("{m.group(1)}")'
    except StopIteration:
        pass

    if field_type in all_types:
        return f'make_object_for("{field_type}")'

    return None


def _type_name_to_python_identifier(type_name: str):
    return type_name.replace("::", "_").replace(" ", "_").replace("<", "_").replace(">", "_").replace(",", "_")


class TypeExporter:
    def __init__(self, all_types: dict[str, dict[str, str]]):
        self.all_types = all_types
        self._exported_types = {}
        self._types_with_pointer = set()
        self._types_being_exported = set()
        self._children_for = collections.defaultdict(set)
        self._type_definition_code = ""

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
            type_code = self._export_known_type(type_variable, type_name)
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

        if field_name is not None and field_name.startswith("e"):
            return "common_types.UInt"

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
    p = Path("all_types.json")

    with p.open() as f:
        all_types: dict[str, dict[str, str]] = json.load(f)

    all_types.pop("CBlackboard")
    all_types.pop("CGameBlackboard")

    type_hierarchy = parse_all_types(all_types)
    type_exporter = TypeExporter(all_types)

    needs_exporting = {"CActor"}
    while needs_exporting:
        next_type = needs_exporting.pop()
        if next_type not in type_exporter._exported_types:
            type_exporter.ensure_exported_type(next_type)
            needs_exporting.update(type_exporter._children_for[next_type])


#     root = type_hierarchy
#     for it in ["base::core::CBaseObject", "CGameObject", "CActorComponent"]:
#         root = root[it]["children"]
#
#     def process_type(obj, self_name: str, parent_name: str, pointer_set: str):
#         if obj["fields"]:
#             field_lines = []
#             for field_name, field_type in obj["fields"].items():
#                 if (converted_type := convert_type_to_construct(field_name, field_type, all_types)) is not None:
#                     field_lines.append(f'    "{field_name}": {converted_type},')
#                 else:
#                     field_lines.append(f'    # "{field_name}": {field_type},')
#
#             fields_def = "{{\n    **{}Fields,\n{}\n}}".format(
#                 parent_name,
#                 "\n".join(field_lines)
#             )
#         else:
#             # No fields, just use the parent dict
#             fields_def = f"{parent_name}Fields"
#
#         field_var = ""
#         if obj["children"]:
#             # We have children, create a field vars
#             field_var = f"{self_name}Fields := "
#
#         result = f'\n\n{pointer_set}.add_option("{self_name}", Object({field_var}{fields_def}))'
#
#         for child_name, child_details in obj["children"].items():
#             result += process_type(child_details, child_name, self_name, pointer_set)
#
#         return result
#
#     code = """# This file was generated!
# import construct
#
# from mercury_engine_data_structures import common_types
# from mercury_engine_data_structures.object import Object
# from mercury_engine_data_structures.pointer_set import PointerSet
#
# ActorComponents = PointerSet("CActorComponent")
# CActorComponentFields = {}
# """
#
#     for name, details in root.items():
#         code += process_type(details, name, "CActorComponent", "ActorComponents")

    Path("custom_types.py").write_text(type_exporter.export_code())

    with open("type_tree.json", "w") as f:
        json.dump(type_hierarchy, f, indent=4)


if __name__ == '__main__':
    main()
