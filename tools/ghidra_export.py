import collections
import functools
import json
import math
import multiprocessing
import re
import traceback
import typing
from pathlib import Path

import ghidra_bridge

from mercury_engine_data_structures import dread_data
from mercury_engine_data_structures.type_lib import TypeKind, PrimitiveKind

# New JSON Format
known_types_to_construct = {
    "bool": PrimitiveKind.BOOL,
    "float": PrimitiveKind.FLOAT,
    "float32": PrimitiveKind.FLOAT,
    "int": PrimitiveKind.INT,
    "unsigned_short": PrimitiveKind.UINT_16,
    "unsigned": PrimitiveKind.UINT,
    "unsigned_int": PrimitiveKind.UINT,
    "unsigned_long": PrimitiveKind.UINT_64,
    "uint64": PrimitiveKind.UINT_64,
    "base::global::CStrId": PrimitiveKind.STRING,
    "base::global::CFilePathStrId": PrimitiveKind.STRING,
    "base::global::CRntString": PrimitiveKind.STRING,
    "base::math::CVector2D": PrimitiveKind.VECTOR_2,
    "base::math::CVector3D": PrimitiveKind.VECTOR_3,
    "base::math::CVector4D": PrimitiveKind.VECTOR_4,
    "CGameLink<CActor>": PrimitiveKind.STRING,
    "CGameLink<CEntity>": PrimitiveKind.STRING,
    "CGameLink<CSpawnPointComponent>": PrimitiveKind.STRING,
    "base::global::CRntFile": PrimitiveKind.BYTES,

    # TODO: test if works
    "base::global::CName": PrimitiveKind.PROPERTY,
    "base::core::CAssetLink": PrimitiveKind.STRING,
}
known_flagsets = {
    "base::global::timeline::TLayers": "base::global::timeline::ELayer",
    "TShinesparkTravellingDirectionFlagSet": "EShinesparkTravellingDirection",
    "TCoolShinesparkSituation": "ECoolShinesparkSituation",
    "TActionInsertFlagset": "EActionInsertFlags",
    "TAnimationTagFlagSet": "EAnimationTag",
}
known_typedefs = {
    "TPatterns": "base::global::CRntVector<COffset>",
    "CCharClassRodotukAIComponent::TVAbsorbConfigs": "base::global::CRntVector<CCharClassRodotukAIComponent::SAbsorbConfig>",
    "TLaunchPattern": "base::global::CRntVector<SLaunchPatternStep>",
    "TLaunchConfigs": "base::global::CRntVector<SLaunchConfig>",
    "TBigkranXSpitLaunchPattern": "base::global::CRntVector<SBigkranXSpitLaunchPatternStep>",
    "CCharClassRodomithonXAIComponent::TVFirePillarConfigs": "base::global::CRntVector<CCharClassRodomithonXAIComponent::SFirePillarConfig>",
    "CMinimapDef::TMapLabelDefs": "base::global::CRntDictionary<base::global::CStrId, SMapLabelDef>",
    "CMinimapDef::TMapIconDefs": "base::global::CRntDictionary<base::global::CStrId, SMapIconDef>",
    "CBlackboard::TSectionContainer": "base::global::CRntDictionary<base::global::CStrId, CBlackboard::CSection*>",
    "CPlaythrough::TDictCheckpointDatas": "base::global::CRntDictionary<base::global::CStrId, std::unique_ptr<CPlaythrough::SCheckpointData>>",
    "TSoundEventRules": "base::global::CRntVector<std::unique_ptr<sound::CSoundEventsDef::SSoundEventsRule>>",
    "CGameBlackboard::TPropDeltaValues": "base::global::CRntSmallDictionary<base::global::CStrId, float>",
    "CMinimapData::TOccludedIcons": "base::global::CRntVector<base::global::CStrId>",
    "CMinimapData::TColliderGeoDatasMap": "base::global::CRntSmallDictionary<uint64, SGeoData>",

    'GUI::CDisplayObjectTrack<bool>::SKey': 'GUI::CDisplayObjectTrackBool::SKey',
    'GUI::CDisplayObjectTrack<float>::SKey': 'GUI::CDisplayObjectTrackFloat::SKey',
    'GUI::CDisplayObjectTrack<base::global::CRntString>::SKey': 'GUI::CDisplayObjectTrackString::SKey',
}

vector_re = re.compile(r"base::global::CRntVector<\s*(.*?)(?:, false)?\s*>$")
list_re = re.compile(r"base::global::C(?:Pooled)?List<\s*(.*?)\s*>$")
array_re = re.compile(r"base::global::CArray<\s*(.*?), [^,]*?, [^>]*?>$")
dict_re = re.compile(r"base::global::CRnt(?:Small)?(?:Pooled)?Dictionary<\s*([^,]+?)\s*,[\s_]*(.*)\s*>$")
all_container_re = [
    ("common_types.make_vector", vector_re),
    ("common_types.make_vector", array_re),
    ("common_types.make_dict", dict_re),
]

unique_ptr_re = re.compile(r"std::unique_ptr<\s*(.*)\s*>$")
weak_ptr_re = re.compile(r"base::global::CWeakPtr<\s*(.*)\s*>$")
raw_ptr_re = re.compile(r"(.*?)(?:[ ]?const)?\s*\*$")
ref_re = re.compile(r"CGameObjectRef<(.*)>$")
typed_var_re = re.compile(r"(base::reflection::CTypedValue)$")
all_ptr_re = [unique_ptr_re, weak_ptr_re, raw_ptr_re, ref_re, typed_var_re]


def find_ptr_match(type_name: str):
    for expr in all_ptr_re:
        m = expr.match(type_name)
        if m is not None:
            return m


def convert_type(type_name: str, type_data: dict):
    if type_name in known_types_to_construct:
        return {
            "kind": TypeKind.PRIMITIVE.value,
            "primitive_kind": known_types_to_construct[type_name].value
        }

    if type_name in known_typedefs:
        return {
            "kind": TypeKind.TYPEDEF.value,
            "alias": known_typedefs[type_name]
        }

    if type_name in known_flagsets:
        return {
            "kind": TypeKind.FLAGSET.value,
            "enum": known_flagsets[type_name]
        }

    if type_data["values"] is not None:
        return {
            "kind": TypeKind.ENUM.value,
            "values": type_data["values"],
        }

    if (m := vector_re.match(type_name) or array_re.match(type_name) or list_re.match(type_name)) is not None:
        return {
            "kind": TypeKind.VECTOR.value,
            "value_type": m.group(1),
        }

    elif (m := dict_re.match(type_name)) is not None:
        return {
            "kind": TypeKind.DICTIONARY.value,
            "key_type": m.group(1).strip(),
            "value_type": m.group(2).strip(),
        }

    elif (m := find_ptr_match(type_name)) is not None:
        return {
            "kind": TypeKind.POINTER.value,
            "target": m.group(1),
        }

    return {
        "kind": TypeKind.STRUCT.value,
        "parent": type_data["parent"],
        "fields": type_data["fields"],
    }


def convert_old_to_new(old_types: dict[str, dict[str, typing.Any]]):
    to_add = set()
    converted = {}
    for type_name, type_data in old_types.items():
        converted[type_name] = convert_type(type_name, type_data)

        # Try to find extra types from the values
        if converted[type_name]["kind"] == TypeKind.STRUCT.value:
            for field_type in converted[type_name]["fields"].values():
                if field_type not in old_types:
                    to_add.add(field_type)

    while to_add:
        new_type = to_add.pop()
        converted[new_type] = convert_type(new_type, {"values": None, "parent": None, "fields": {}})

        next_type = None
        next_type2 = None

        new_kind = TypeKind(converted[new_type]["kind"])

        if new_kind in (TypeKind.PRIMITIVE, TypeKind.STRUCT, TypeKind.ENUM):
            pass

        elif new_kind == TypeKind.FLAGSET:
            next_type = converted[new_type]["enum"]

        elif new_kind == TypeKind.TYPEDEF:
            next_type = converted[new_type]["alias"]

        elif new_kind == TypeKind.POINTER:
            next_type = converted[new_type]["target"]

        elif new_kind == TypeKind.VECTOR:
            next_type = converted[new_type]["value_type"]

        elif new_kind == TypeKind.DICTIONARY:
            next_type2 = converted[new_type]["key_type"]
            next_type = converted[new_type]["value_type"]

        else:
            raise ValueError(f"unknown kind: {new_kind}")

        for it in [next_type, next_type2]:
            if it is not None and it not in converted:
                to_add.add(it)

    return {key: converted[key] for key in sorted(converted)}


hash_str = "HashString"
register_field = "RegisterField"
add_enum_value = "(?:FUN_71000148b8|AddEnumValue)"
prefixes_to_remove = [
    "(ObjectField *)",
    "&",
    "(CClass *)",
    "Reflection::"
]

_aliases = {
    # weirdness
    "(undefined **)base::global::CFilePathStrId": "base::global::CFilePathStrId",
    "global::CStrId": "base::global::CStrId",
    "global::CFilePathStrId": "base::global::CFilePathStrId",
    "math::CVector3D": "base::math::CVector3D",

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
    "&base::snd::ELowPassFilter_DAT_7108b13de8": "base::snd::ELowPassFilter",

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
    "&DAT_71726d8090": "CDoorLifeComponent::SState",
    "&DAT_7101cf5c20": "base::core::CAssetLink",
    "&DAT_7101cf4aa8": "base::core::AssetID",
    "&SCameraSubRail_DAT_7172721790": "base::global::CRntVector<SCameraSubRail>",
    "&DAT_71726ee5e8": "base::global::CRntVector<EShinesparkTravellingDirection>",
    "&DAT_71726ee9e0": "base::global::CRntVector<ECoolShinesparkSituation>",
    "&Vector_STileInfo_71726b8960": "base::global::CRntVector<CBreakableTileGroupComponent::STileInfo>",
    "&DAT_7172721398": "CEditorRailSegment",
    "&DAT_71726efbb0": "base::global::CRntVector<DoorStateInfo>",
    "&DAT_7101d062b0": "base::global::CRntSmallDictionary<base::global::CStrId, base::global::CStrId>",
    "&DAT_7108b143d0": "base::spatial::CAABox",
    "&DAT_71729a2688": "base::global::CRntVector<SLogicSubPath>",
    "&DAT_71729a2290": "base::global::CRntVector<SLogicPathNode>",
}


def clean_crc_var(crc_var: str) -> str:
    for prefix in prefixes_to_remove:
        if crc_var.startswith(prefix):
            crc_var = crc_var[len(prefix):].strip()
    return crc_var


def fix_alternative_ghidra_name(name: str) -> str:
    if name.endswith("Ptr"):
        name = name[:-len("Ptr")] + "*"
    name = name.replace("_const", " const")
    name = name.replace(",_", ", ")
    name = name.replace("_Ptr", " Ptr")
    name = name.replace("Ptr>", "*>")
    return name


def get_field_registrations(bridge: ghidra_bridge.GhidraBridge, ifc, monitor, fields_function):
    if fields_function is None:
        return {}

    res = bridge.remote_eval("""
        ifc.decompileFunction(fields_function, 180, monitor)
    """, timeout_override=200, fields_function=fields_function, ifc=ifc, monitor=monitor)

    decompiled_code = str(res.getCCodeMarkup())
    hash_call_re = re.compile(hash_str + r'\(([^,]+?),"?([^,]+?)"?,(?:1|true)\);')
    register_call_re = re.compile(register_field + r'\([^,]+?,([^,]+?),(.+?),([^,]+?),([^,]+?),([^,]+?)\);')

    crc_mapping = collections.defaultdict(list)
    fields = {}

    for m in hash_call_re.finditer(decompiled_code):
        crc_var, crc_string = m.group(1, 2)
        crc_mapping[clean_crc_var(crc_var)].append((m.start(), crc_string))

    for m in register_call_re.finditer(decompiled_code):
        crc_var, type_var = m.group(1, 2)

        offset = None
        crc_string = None
        for offset, crc_string in reversed(crc_mapping[clean_crc_var(crc_var)]):
            if offset < m.start():
                break

        if crc_string is None:
            raise ValueError(f"Could not find the correct string for {crc_var}")

        if "&" in type_var:
            if "::_" in type_var:
                type_name = type_var[type_var.find("&") + 1:type_var.find("::_")]
            else:
                type_name = type_var
        else:
            i = decompiled_code.rfind(type_var, offset, m.start())
            end = decompiled_code.find(';', i)
            type_name = decompiled_code[i + len(type_var) + len(" = "):end]
            for prefix in prefixes_to_remove:
                if type_name.startswith(prefix):
                    type_name = type_name[len(prefix):].strip()
            if type_name.endswith("()"):
                type_name = type_name[:-len("()")]
            if type_name.endswith("::init"):
                type_name = type_name[:-len("::init")]

        fields[crc_string] = _aliases.get(type_name, type_name)

    return fields


def get_value_registrations(bridge: ghidra_bridge.GhidraBridge, ifc, monitor, values_function):
    if values_function is None:
        return None

    res = bridge.remote_eval("""
        ifc.decompileFunction(values_function, 180, monitor)
    """, timeout_override=200, values_function=values_function, ifc=ifc, monitor=monitor)

    decompiled_code = str(res.getCCodeMarkup())
    hash_call_re = re.compile(hash_str + r'\(([^,]+?),"?([^,]+?)"?,(?:1|true)\);')
    enum_call_re = re.compile(add_enum_value + r'\([^,]+?,([^,]+?),(.+?)\);')

    crc_mapping = collections.defaultdict(list)
    values = {}

    for m in hash_call_re.finditer(decompiled_code):
        crc_var, crc_string = m.group(1, 2)
        crc_mapping[clean_crc_var(crc_var)].append((m.start(), crc_string))

    for m in enum_call_re.finditer(decompiled_code):
        crc_var, value_var = m.group(1, 2)

        offset = None
        crc_string = None
        for offset, crc_string in reversed(crc_mapping[clean_crc_var(crc_var)]):
            if offset < m.start():
                break

        if crc_string is None:
            raise ValueError(f"Could not find the correct string for {crc_var}")

        values[crc_string] = int(value_var, 0)

    return values


def get_function_list() -> dict[str, tuple[int, int, int]]:
    with ghidra_bridge.GhidraBridge() as init_bridge:
        result_fields = init_bridge.remote_eval("""
        [
            (f.getName(True), f.getID()) for f in currentProgram.getSymbolTable().getSymbols("fields")
        ]
        """)
        result_init = init_bridge.remote_eval("""
        [
            (f.getName(True), f.getID()) for f in currentProgram.getSymbolTable().getSymbols("init")
        ]
        """)
        result_values = init_bridge.remote_eval("""
        [
            (f.getName(True), f.getID()) for f in currentProgram.getSymbolTable().getSymbols("values")
        ]
        """)

        print("Found {} init, {} fields and {} values".format(
            len(result_init),
            len(result_fields),
            len(result_values),
        ))

        init_funcs = {}
        fields_funcs = {}
        values_funcs = {}
        for name, func_id in result_fields + result_init + result_values:
            if name.startswith("Reflection::"):
                name = name[len("Reflection::"):]

            if name.startswith("base::reflection::CollectionTypeMapper"):
                continue

            if name.endswith("::init"):
                init_funcs[name[:-len("::init")]] = func_id
            elif name.endswith("::fields"):
                fields_funcs[name[:-len("::fields")]] = func_id
            elif name.endswith("::values"):
                values_funcs[name[:-len("::values")]] = func_id

        return {
            name: (init_funcs.get(name), fields_funcs.get(name), values_funcs.get(name))
            for name in fields_funcs.keys() | init_funcs.keys() | values_funcs.keys()
        }


bridge: typing.Optional[ghidra_bridge.GhidraBridge] = None


def initialize_worker():
    global bridge, monitor, ifc
    bridge = ghidra_bridge.GhidraBridge(response_timeout=10)

    flat_api = bridge.get_flat_api()
    DecompileOptions = bridge.remote_import("ghidra.app.decompiler.DecompileOptions")
    DecompInterface = bridge.remote_import("ghidra.app.decompiler.DecompInterface")
    ConsoleTaskMonitor = bridge.remote_import("ghidra.util.task.ConsoleTaskMonitor")

    monitor = ConsoleTaskMonitor()
    ifc = DecompInterface()
    options = DecompileOptions()
    # make sure you have namespaces set to Always, and casting disabled
    options.grabFromProgram(flat_api.currentProgram)
    ifc.setOptions(options)
    ifc.openProgram(flat_api.currentProgram)


def decompile_type(type_name: str, init_id: typing.Optional[int], fields_id: typing.Optional[int],
                   values_id: typing.Optional[int]
                   ) -> tuple[str, typing.Optional[str], dict[str, str], dict[str, int]]:
    if bridge is None:
        raise ValueError("Bridge not initialized")

    bridge.remote_exec("""
def find_parent(f):
    super_namespace = f.getParentNamespace().getParentNamespace()
    for other in f.getCalledFunctions(None):
        if other.getName().startswith("init") and super_namespace != other.getParentNamespace():
            return other.getName(True)
    """)

    parent_init: typing.Optional[str] = None
    if init_id is not None:
        parent_init = bridge.remote_eval("""find_parent(
            currentProgram.getFunctionManager().getFunctionAt(
                currentProgram.getSymbolTable().getSymbol(func_id).getAddress()
            )
        )""", func_id=init_id)

    func = None
    if fields_id is not None:
        func = bridge.remote_eval("""
            currentProgram.getFunctionManager().getFunctionAt(
                currentProgram.getSymbolTable().getSymbol(func_id).getAddress()
            )
        """, func_id=fields_id)

    fields = get_field_registrations(bridge, ifc, monitor, func)

    func = None
    if values_id is not None:
        func = bridge.remote_eval("""
            currentProgram.getFunctionManager().getFunctionAt(
                currentProgram.getSymbolTable().getSymbol(func_id).getAddress()
            )
        """, func_id=values_id)
    values = get_value_registrations(bridge, ifc, monitor, func)

    if parent_init is not None:
        if parent_init.startswith("Reflection::"):
            parent_init = parent_init[len("Reflection::"):]
        parent_init = parent_init[:-len("::init")]

    return type_name, parent_init, fields, values


def decompile_in_background(all_fields_functions: dict[str, tuple[int, int, int]]):
    process_count = max(multiprocessing.cpu_count() - 2, 2)

    finished_count = 0
    failed = []

    total_count = len(all_fields_functions)
    num_digits = math.ceil(math.log10(total_count + 1))
    number_format = "[{0:" + str(num_digits) + "d}/{1}] "

    def report_update(msg: str):
        nonlocal finished_count
        finished_count += 1
        print(number_format.format(finished_count, total_count) + msg)

    result = {}

    def callback(r):
        type_name, parent, fields, values = r
        result[type_name] = {"parent": parent, "fields": fields, "values": values}
        report_update(f"Parsed {type_name}")

    if total_count > process_count:
        with multiprocessing.Pool(processes=process_count, initializer=initialize_worker) as pool:
            def error_callback(name, e):
                failed.append(name)
                msg = "".join(traceback.format_exception(type(e), e, e.__traceback__))
                report_update(f"Failed {name}: {msg}")

            for n, f in all_fields_functions.items():
                pool.apply_async(
                    func=decompile_type,
                    args=(n, *f),
                    callback=callback,
                    error_callback=functools.partial(error_callback, n),
                )

            pool.close()
            pool.join()
    else:
        print("Less tasks than CPUs, just do it single-threaded.")
        failed.extend(all_fields_functions.keys())

    if failed:
        print(f"{len(failed)} function(s) failed, retrying on main thread.")
        initialize_worker()

    for n in failed:
        try:
            callback(decompile_type(n, *all_fields_functions[n]))
        except Exception as e:
            report_update(f"Failed {n}: {e}")

    return result


def is_invalid_data(name: str, data: dict[str, typing.Any]):
    # if "null" in data["fields"]:
    #     return True

    # if data["values"] is not None and "null" in data["values"]:
    #     return True

    return False


def is_container_or_ptr(name: str):
    prefixes = [
        "base::global::CRntSmallDictionary",
        "base::global::CRntDictionary",
        "base::global::CRntVector",
        "base::global::CWeakPtr",
        "base::global::CSmartPtr",
        "base::global::CArray",
        "std::unique_ptr",
    ]
    suffixes = [
        "Ptr",
        "::value_type",
        "::TKeyElementIterator",
        "::TKeyElementConstIterator",
        "::TElementIterator",
        "::TElementConstIterator",
    ]

    return any(name.endswith(suffix) for suffix in suffixes) or any(name.startswith(prefix) for prefix in prefixes)


def main(only_missing: bool = True, ignore_without_hash: bool = True,
         ignore_container_or_ptr: bool = True, query_ghidra: bool = True):
    print("Getting function list")
    all_fields_functions = get_function_list() if query_ghidra else {}
    print(f"Got {len(all_fields_functions)} functions!")

    path = Path(__file__).parents[1].joinpath("mercury_engine_data_structures", "dread_types.json")

    try:
        with path.open() as f:
            old_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        old_data = {}

    old_data = typing.cast(dict[str, typing.Any], old_data)

    if ignore_container_or_ptr:
        for key in list(all_fields_functions.keys()):
            if is_container_or_ptr(key):
                all_fields_functions.pop(key)

    if only_missing:
        for key in old_data.keys():
            all_fields_functions.pop(key, None)

    if ignore_without_hash:
        # for key in list(final_results.keys()):
        #     if key not in dread_data.all_name_to_property_id():
        #         print(f"Removing {key}: no known hash")
        #         final_results.pop(key)

        for key in list(all_fields_functions.keys()):
            if key not in dread_data.all_name_to_property_id():
                # print(f"Skipping {key}: no known hash - {all_fields_functions[key]}")
                all_fields_functions.pop(key)

    process_results = decompile_in_background(all_fields_functions) if query_ghidra else {}

    for data in process_results.values():
        for field in data["fields"].keys():
            value = data["fields"][field]
            if value in _aliases:
                value = _aliases[value]

            if not value.startswith("&"):
                value = fix_alternative_ghidra_name(value)

            data["fields"][field] = value

    for key in list(process_results.keys()):
        # Something causes a type to inherit from a pointer to itself, that's wrong
        if process_results[key]["parent"] in (f"{key}Ptr", key):
            print(f'Removing parent for {key}: {process_results[key]["parent"]}')
            process_results[key]["parent"] = None

        if process_results[key]["parent"] is not None and is_container_or_ptr(process_results[key]["parent"]):
            print(f"Inheriting from ptr or container: {key}")

    _merge_split_types(process_results)

    for key, value in convert_old_to_new(process_results).items():
        old_data[key] = value

    with path.open("w") as f:
        json.dump({
            key: old_data[key]
            for key in sorted(old_data.keys())
        }, f, indent=4)


def _merge_split_types(final_results: dict[str, typing.Any]):
    hashes = dread_data.all_name_to_property_id()
    wrong_to_correct = {}

    for key in list(final_results.keys()):
        if len(key.split("::")) == 1:
            continue

        last_part = key.split("::")[-1]
        if last_part.startswith("E") or last_part in {"SKey", "CParams", "SState", "CDefinition", "SSubState",
                                                      "CActorDef"}:
            continue

        similar = [other for other in final_results.keys() if other.endswith(last_part) and other != key]
        if similar:
            if len(similar) != 1:
                raise ValueError(f"OH NO too many similar {similar}")

            both_hash = key in hashes and similar[0] in hashes
            if both_hash:
                print("{} (Hash: {}) is similar to {} (Hash: {})".format(
                    key, key in dread_data.all_name_to_property_id(),
                    similar[0], similar[0] in dread_data.all_name_to_property_id(),
                ))
            elif key in hashes:
                wrong_to_correct[similar[0]] = key
            elif similar[0] in hashes:
                wrong_to_correct[key] = similar[0]
            else:
                print(f"BOTH ARE WRONG! {key} - {similar[0]}")

    for wrong, correct in wrong_to_correct.items():
        final_results[correct]["fields"] = final_results.pop(wrong)["fields"]

    for key in list(final_results.keys()):
        if final_results[key]["parent"] in wrong_to_correct:
            final_results[key]["parent"] = wrong_to_correct[final_results[key]["parent"]]


def simple_decompile():
    all_fields_functions = get_function_list()
    initialize_worker()

    func_name = "EBreakableTileType"
    print(decompile_type(func_name, *all_fields_functions[func_name]))

    # print(decompile_function(*all_fields_functions[4]))


if __name__ == '__main__':
    main()
