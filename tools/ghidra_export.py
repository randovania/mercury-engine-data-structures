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

hash_str = "HashString"
register_field = "RegisterField"
prefixes_to_remove = [
    "(ObjectField *)",
    "&",
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


def get_field_registrations(bridge: ghidra_bridge.GhidraBridge, ifc, monitor, fields_function):
    res = bridge.remote_eval("""
        ifc.decompileFunction(fields_function, 180, monitor)
    """, timeout_override=200, fields_function=fields_function, ifc=ifc, monitor=monitor)

    decompiled_code = str(res.getCCodeMarkup())
    hash_call_re = re.compile(hash_str + r'\(([^,]+?),"?([^,]+?)"?,1\);')
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

        if "&" in type_var:
            if "::_" in type_var:
                type_name = type_var[1:type_var.find("::_")]
            else:
                type_name = type_var
        else:
            i = decompiled_code.rfind(type_var, offset, m.start())
            end = decompiled_code.find(';', i)
            type_name = decompiled_code[i + len(type_var) + len(" = "):end]
            if type_name.endswith("::init()"):
                type_name = type_name[:-len("::init()")]

        fields[crc_string] = _aliases.get(type_name, type_name)

    return fields


def get_function_list() -> dict[str, tuple[int, int]]:
    with ghidra_bridge.GhidraBridge() as init_bridge:
        result = init_bridge.remote_eval("""
        [
            (f.getName(True), f.getID()) for f in currentProgram.getSymbolTable().getDefinedSymbols()
            if f.getName() == "fields" or f.getName() == "init"
        ]
        """)
        init_funcs = {}
        fields_funcs = {}
        for name, func_id in result:
            if not name.startswith("Reflection::"):
                continue
            name = name[len("Reflection::"):]

            if name.endswith("::init"):
                init_funcs[name[:-len("::init")]] = func_id
            elif name.endswith("::fields"):
                fields_funcs[name[:-len("::fields")]] = func_id

        return {
            name: (init_funcs.get(name), fields_funcs[name])
            for name in fields_funcs
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
    ifc.setOptions(DecompileOptions())
    ifc.openProgram(flat_api.currentProgram)


def decompile_type(type_name: str, init_id: typing.Optional[int], fields_id: int,
                   ) -> tuple[str, typing.Optional[str], dict[str, str]]:
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

    func = bridge.remote_eval("""
        currentProgram.getFunctionManager().getFunctionAt(
            currentProgram.getSymbolTable().getSymbol(func_id).getAddress()
        )
    """, func_id=fields_id)

    fields = get_field_registrations(bridge, ifc, monitor, func)

    if parent_init is not None:
        if parent_init.startswith("Reflection::"):
            parent_init = parent_init[len("Reflection::"):]
        parent_init = parent_init[:-len("::init")]

    return type_name, parent_init, fields


def decompile_in_background(all_fields_functions: dict[str, tuple[int, int]]):
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
        type_name, parent, fields = r
        result[type_name] = {"parent": parent, "fields": fields}
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


def main(only_missing: bool = True):
    print("Getting function list")
    all_fields_functions = get_function_list()
    print(f"Got {len(all_fields_functions)} functions!")

    path = Path(__file__).parents[1].joinpath("mercury_engine_data_structures", "dread_types.json")

    try:
        with path.open() as f:
            final_results = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        final_results = {}

    if only_missing:
        for key in final_results.keys():
            all_fields_functions.pop(key, None)

    process_results = decompile_in_background(all_fields_functions)
    for key in sorted(process_results.keys()):
        final_results[key] = process_results[key]

    for data in final_results.values():
        for field in data["fields"].keys():
            value = data["fields"][field]
            if value in _aliases:
                value = _aliases[value]

            if not value.startswith("&"):
                if value.endswith("Ptr"):
                    value = value[:-len("Ptr")] + "*"
                value = value.replace("_const", " const")
                value = value.replace(",_", ", ")
                value = value.replace("Ptr>", "*>")

            data["fields"][field] = value

    with path.open("w") as f:
        json.dump({
            key: final_results[key]
            for key in sorted(final_results.keys())
        }, f, indent=4)


def simple_decompile():
    all_fields_functions = get_function_list()
    initialize_worker()

    func_name = "CComponent"
    print(decompile_type(func_name, *all_fields_functions[func_name]))

    # print(decompile_function(*all_fields_functions[4]))


if __name__ == '__main__':
    main()
