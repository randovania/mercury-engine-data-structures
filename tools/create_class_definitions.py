import json
import re
from pathlib import Path
from typing import Any


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

    # TODO: test if works
    "base::global::CName": "common_types.StrId",
}

_aliases = {
    # weirdness
    "(undefined **)base::global::CFilePathStrId": "base::global::CFilePathStrId",

    # custom names
    "&DAT_7172642b18": "CGameLink<CActor>",
    "&DAT_717275c0d8": "CGameLink<CEntity>",
    "&DAT_7172642ed8": "base::global::CRntVector<CGameLink<CActor>>",
    "&DAT_717275c498": "base::global::CRntVector<CGameLink<CEntity>>",

    "&CGameLink_CActor_DAT_7172642b18": "CGameLink<CActor>",
    "&CGameLink<CEntity>::Serializer": "CGameLink<CEntity>",
    "&Vector_GameLink_CActor_7172642ed8": "base::global::CRntVector<CGameLink<CActor>>",
    "&Vector_CGameLink_CEntity_DAT_717275c498": "base::global::CRntVector<CGameLink<CEntity>>",

    "&Vector_PtrCTriggerLogicAction_DAT_71726f3930": "base::global::CRntVector<std::unique_ptr<CTriggerLogicAction>>",

    "&Vector_CXParasiteBehavior_71726c3030": "base::global::CRntVector<std::unique_ptr<CXParasiteBehavior>>",
    "&base::snd::ELowPassFilter_DAT_7108b13de8": "unsigned",

    "&DAT_71726bb4c0": "base::global::CRntVector<CCentralUnitComponent::SStartPointInfo>",
    "&DAT_71726baee8": "base::global::CRntVector<std::unique_ptr<CCentralUnitWeightedEdges>>",
    "&DAT_71729a98a8": "base::global::CRntVector<SFallBackPath>",
    "&DAT_7172686f58": "base::global::CRntVector<std::unique_ptr<CEmmyOverrideDeathPositionDef>>",
    "&DAT_7172687378": "base::global::CRntVector<std::unique_ptr<CEmmyAutoForbiddenEdgesDef>>",
    "&DAT_7172687798": "base::global::CRntVector<std::unique_ptr<CEmmyAutoGlobalSmartLinkDef>>",
    "&DAT_71726ecbf0": "CFreezeRoomConfig",
    "&DAT_71726ecd30": "CFreezeRoomCoolConfig",
    "&DAT_71726ed380": "CHeatRoomConfig",
    "&DAT_71726ed4c0": "CHeatRoomCoolConfig",
    "&DAT_71726d53e0": "base::global::CRntVector<SBeamBoxActivatable>",
    "&vectSpawnPoints_DAT_71729aaf30": "base::global::CRntVector<CGameLink<CSpawnPointComponent>>",
    "&Vector_CSpawnerActorBlueprint_DAT_71729aa9d0": "base::global::CRntVector<CSpawnerActorBlueprint>",
    "&Trigger_DAT_71726f4968": "base::global::CRntVector<std::unique_ptr<CTriggerComponent::SActivationCondition>>",
    "&DictStr_ListStr_DAT_71726f5da0": "base::global::CRntDictionary<base::global::CStrId, base::global::CRntVector<base::global::CStrId>>",
    "&VectorStrId_DAT_7101d03998": "base::global::CRntVector<base::global::CStrId>",
    "&DAT_71726f8e78": "base::global::CRntVector<SDoorInfo>",
    "&DAT_71726fd0c0": "base::global::CRntVector<SWorldGraphNode>",
}

vector_re = re.compile(r"base::global::CRntVector<(.*)>$")
dict_re = re.compile(r"base::global::CRntDictionary<base::global::CStrId, (.*)>$")
all_container_re = {
    "common_types.make_vector": vector_re,
    "common_types.make_dict": dict_re,
}

unique_ptr_re = re.compile(r"std::unique_ptr<(.*)>$")
raw_ptr_re = re.compile(r"(.*)_(?:constPtr)$")
ref_re = re.compile(r"CGameObjectRef<(.*)>$")
all_ptr_re = [unique_ptr_re, raw_ptr_re, ref_re]


def convert_type_to_construct(field_name: str, field_type: str, all_types: dict[str, Any]):
    field_type = _aliases.get(field_type, field_type)

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


def main():
    p = Path(r"C:\Users\henri\programming\mercury-engine-data-structures\tools\all_types.json")

    with p.open() as f:
        all_types: dict[str, dict[str, str]] = json.load(f)

    type_hierarchy = parse_all_types(all_types)
    root = type_hierarchy
    for it in ["base::core::CBaseObject", "CGameObject", "CActorComponent"]:
        root = root[it]["children"]

    # Missing types
    all_types["SLogicPath"] = {}
    all_types["SWorldGraphNode"] = {}
    all_types["SCameraRail"] = {}
    all_types["CCentralUnitComponent::SStartPointInfo"] = {}
    all_types["SFallBackPath"] = {}
    all_types["CFreezeRoomConfig"] = {}
    all_types["CFreezeRoomCoolConfig"] = {}
    all_types["CHeatRoomConfig"] = {}
    all_types["CHeatRoomCoolConfig"] = {}
    all_types["SBeamBoxActivatable"] = {}
    all_types["CSpawnPointComponent"] = {}
    all_types["CSpawnerActorBlueprint"] = {}
    all_types["SDoorInfo"] = {}

    def process_type(obj, self_name: str, parent_name: str, pointer_set: str):
        if obj["fields"]:
            field_lines = []
            for field_name, field_type in obj["fields"].items():
                if (converted_type := convert_type_to_construct(field_name, field_type, all_types)) is not None:
                    field_lines.append(f'    "{field_name}": {converted_type},')
                else:
                    field_lines.append(f'    # "{field_name}": {_aliases.get(field_type, field_type)},')

            fields_def = "{{\n    **{}Fields,\n{}\n}}".format(
                parent_name,
                "\n".join(field_lines)
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
import construct

from mercury_engine_data_structures import common_types
from mercury_engine_data_structures.object import Object
from mercury_engine_data_structures.pointer_set import PointerSet

ActorComponents = PointerSet("CActorComponent")
CActorComponentFields = {}
"""

    for name, details in root.items():
        code += process_type(details, name, "CActorComponent", "ActorComponents")

    Path("custom_types.py").write_text(code)

    with open("type_tree.json", "w") as f:
        json.dump(type_hierarchy, f, indent=4)


if __name__ == '__main__':
    main()
