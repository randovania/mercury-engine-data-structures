import json
from pathlib import Path


def parse_all_types(all_types):
    result: dict = {
        "base": {
            "children": {
                "core": {
                    "children": {},
                }
            }
        }
    }

    for type_name, type_fields in all_types.items():
        full_path = type_name.split("::")

        parent = result
        for p in full_path[:-1]:
            if p not in parent:
                parent = None
                break
            parent = parent[p]["children"]

        if parent is None:
            # print(f"Skipping {type_name}")
            continue

        parent[full_path[-1]] = {
            "fields": type_fields,
            "children": {},
        }

    return result


type_to_construct = {
    "bool": "Flag",
    "float": "Float",
    "int": "Int",
    "unsigned": "UInt",
    "global::CStrId": "StrId",

    "&DAT_7172642b18": "StrId",  # CGameLink<CActor>
    "&DAT_717275c0d8": "StrId",  # CGameLink<CEntity>
    "&DAT_7172642ed8": "make_vector(StrId)",  # CRntVector<CGameLink<CActor>>
    "&DAT_717275c498": "make_vector(StrId)",  # CRntVector<CGameLink<CEntity>>

    # &DAT_71729a98a8,  # CRntVector<SFallBackPath>
    # &DAT_71726bb4c0,  # CRntVector<CCentralUnitComponent::SStartPointInfo>
}


def main():
    p = Path(r"C:\Users\henri\programming\mercury-engine-data-structures\tools\all_types.json")

    with p.open() as f:
        all_types: dict[str, dict[str, str]] = json.load(f)

    type_hierarchy = parse_all_types(all_types)
    root = type_hierarchy
    for it in ["base", "core", "CBaseObject", "CGameObject", "CActorComponent"]:
        root = root[it]["children"]

    def process_type(obj, self_name: str, parent_name: str, pointer_set: str):
        prepared_fields = [
            (
                f'"{field_name}": {type_to_construct[field_type]},'
                if field_type in type_to_construct
                else f'# "{field_name}": {field_type},'
            )
            for field_name, field_type in obj["fields"].items()
        ]
        if prepared_fields:
            fields_def = "{{\n    **{}Fields,\n{}\n}}".format(
                parent_name,
                "\n".join(f"    {field}" for field in prepared_fields)
            )
        else:
            # No fields, just use the parent dict
            fields_def = f"{parent_name}Fields"

        field_var = ""
        if obj["children"]:
            # We have children, create a field vars
            field_var = f"{self_name}Fields := "

        result = f'\n\n{pointer_set}.add_option("{self_name}", Object({field_var}{fields_def}))'

        for child_name, child_details in obj["children"].items():
            result += process_type(child_details, child_name, self_name, pointer_set)

        return result

    code = """# This file was generated!
from construct import (
    Struct, Construct, Const, GreedyBytes, Int32ul, Hex,
    Flag, Int32sl, Prefixed,
)

from mercury_engine_data_structures.common_types import (
    StrId, Float, Int, UInt,
    make_dict, make_vector, make_enum,
    CVector2D, CVector3D, CVector4D,
)
from mercury_engine_data_structures.object import Object
from mercury_engine_data_structures.pointer_set import PointerSet

ActorComponents = PointerSet("CActorComponent")
CActorComponentFields = {}
"""

    for name, details in root.items():
        code += process_type(details, name, "CActorComponent", "ActorComponents")

    Path("custom_types.py").write_text(code)

    # with open("type_tree.json", "w") as f:
    #     json.dump(result, f, indent=4)


if __name__ == '__main__':
    main()
