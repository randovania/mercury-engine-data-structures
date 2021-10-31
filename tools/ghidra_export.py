import collections
import json
import math
import multiprocessing
import re
import typing

import ghidra_bridge

hash_str = "HashStr_71000003d4"
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
            if type_name.endswith("::get()"):
                type_name = type_name[:-len("::get()")]

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
    bridge = ghidra_bridge.GhidraBridge()

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

    flat_api = bridge.get_flat_api()
    function_manager = flat_api.currentProgram.getFunctionManager()
    symbol_table = flat_api.currentProgram.getSymbolTable()

    assert full_name.startswith("Reflection::")
    assert full_name.endswith("::fields")
    type_name = full_name[len("Reflection::"):-len("::fields")]

    func = function_manager.getFunctionAt(symbol_table.getSymbol(func_id).getAddress())

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

    def error_callback(e):
        report_update(f"Failed {e}")

    with multiprocessing.Pool(processes=process_count, initializer=initialize_worker) as pool:
        for f in all_fields_functions:
            pool.apply_async(
                func=decompile_function,
                args=f,
                callback=callback,
                error_callback=error_callback,
            )
        pool.close()
        pool.join()

    with open("all_types.json", "w") as f:
        json.dump({
            key: result[key]
            for key in sorted(result.keys())
        }, f, indent=4)


if __name__ == '__main__':
    main()
