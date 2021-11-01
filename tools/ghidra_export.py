import collections
import functools
import json
import math
import multiprocessing
import re
import traceback
import typing

import ghidra_bridge

hash_str = "HashString"
register_field = "RegisterField"


def get_field_registrations(bridge: ghidra_bridge.GhidraBridge, ifc, monitor, fields_function):
    res = bridge.remote_eval("""
        ifc.decompileFunction(fields_function, 180, monitor)
    """, timeout_override=200, fields_function=fields_function, ifc=ifc, monitor=monitor)

    decompiled_code = str(res.getCCodeMarkup())
    hash_call_re = re.compile(hash_str + r'\([^,]*?([a-zA-Z0-9]+),"([^"]+)",1\);')
    register_call_re = re.compile(register_field + r'\([^,]+?,[^,]*?([a-zA-Z0-9]+),([^,]+?),([^;]+?)\);')

    crc_mapping = collections.defaultdict(list)
    fields = {}

    for m in hash_call_re.finditer(decompiled_code):
        crc_var, crc_string = m.group(1, 2)
        crc_mapping[crc_var].append((m.start(), crc_string))

    for m in register_call_re.finditer(decompiled_code):
        crc_var, type_var = m.group(1, 2)

        offset = None
        crc_string = None
        for offset, crc_string in reversed(crc_mapping[crc_var]):
            if offset < m.start():
                break

        if type_var.startswith("&"):
            type_name = type_var
        else:
            i = decompiled_code.rfind(type_var, offset, m.start())
            end = decompiled_code.find(';', i)
            type_name = decompiled_code[i + len(type_var) + len(" = "):end]
            if type_name.endswith("::init()"):
                type_name = type_name[:-len("::init()")]

        fields[crc_string] = type_name

    return fields


def get_function_list() -> list[tuple[str, int]]:
    with ghidra_bridge.GhidraBridge() as init_bridge:
        return init_bridge.remote_eval("""
        [
            (f.getName(True), f.getID()) for f in currentProgram.getSymbolTable().getDefinedSymbols()
            if f.getName() == "fields"
        ]
        """)


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


def decompile_function(full_name: str, func_id: int) -> tuple[str, dict[str, str]]:
    if bridge is None:
        raise ValueError("Bridge not initialized")

    assert full_name.startswith("Reflection::")
    assert full_name.endswith("::fields")
    type_name = full_name[len("Reflection::"):-len("::fields")]

    func = bridge.remote_eval("""
        currentProgram.getFunctionManager().getFunctionAt(
            currentProgram.getSymbolTable().getSymbol(func_id).getAddress()
        )
    """, func_id=func_id)

    return type_name, get_field_registrations(
        bridge,
        ifc,
        monitor,
        func,
    )


def main():
    print("Getting function list")
    all_fields_functions = get_function_list()
    print(f"Got {len(all_fields_functions)} functions!")

    process_count = max(multiprocessing.cpu_count() - 2, 2)

    finished_count = 0
    fail_count = collections.defaultdict(int)
    max_retries = 5

    total_count = len(all_fields_functions)
    num_digits = math.ceil(math.log10(total_count + 1))
    number_format = "[{0:" + str(num_digits) + "d}/{1}] "

    def report_update(msg: str):
        nonlocal finished_count
        finished_count += 1
        print(number_format.format(finished_count, total_count) + msg)

    result = {}

    def callback(r):
        type_name, fields = r
        result[type_name] = fields
        report_update(f"Parsed {type_name}")

    with multiprocessing.Pool(processes=process_count, initializer=initialize_worker) as pool:
        def error_callback(entry, e):
            name = entry[0]
            fail_count[name] += 1
            if fail_count[name] < max_retries:
                pool.apply_async(
                    func=decompile_function,
                    args=entry,
                    callback=callback,
                    error_callback=functools.partial(error_callback, f),
                )
            else:
                msg = "".join(traceback.format_exception(type(e), e, e.__traceback__))
                report_update(f"Failed {name}: {msg}")

        for f in all_fields_functions:
            pool.apply_async(
                func=decompile_function,
                args=f,
                callback=callback,
                error_callback=functools.partial(error_callback, f),
            )

        pool.join()
        pool.close()

    with open("all_types.json", "w") as f:
        json.dump({
            key: result[key]
            for key in sorted(result.keys())
        }, f, indent=4)


def simple_decompile():
    all_fields_functions = get_function_list()
    initialize_worker()

    for name, i in all_fields_functions:
        if name == "Reflection::base::global::timeline::CEvent::CCharClassSetMaterialPropertyTransitionEvent::fields":
            print(decompile_function(name, i))
            return

    # print(decompile_function(*all_fields_functions[4]))


if __name__ == '__main__':
    main()
