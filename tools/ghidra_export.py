import collections
import json
import math
import multiprocessing
import re
import typing

import ghidra_bridge

hash_str = "HashStr_71000003d4"
register_field = "RegisterField"


def get_address_to(flat_api, func_name: str):
    funcs = flat_api.getGlobalFunctions(func_name)
    for func in funcs:
        if func.getName() == func_name:
            print("\nFound {} @ 0x{}".format(func_name, func.getEntryPoint()))
            return func.getEntryPoint()


def get_field_registrations(bridge: ghidra_bridge.GhidraBridge, ifc, monitor, fields_function):
    res = bridge.remote_eval("""
        ifc.decompileFunction(fields_function, 180, monitor)
    """, timeout_override=200, fields_function=fields_function, ifc=ifc, monitor=monitor)
    # res = ifc.decompileFunction(fields_function, 180, monitor)
    # high_func = res.getHighFunction()
    # lsm = high_func.getLocalSymbolMap()
    # symbols = lsm.getSymbols()

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


#
#     return
#
#     for i, symbol in enumerate(symbols):
#         print("Symbol {}: {} (type: {}, address: {})".format(i + 1, symbol.getName(), symbol.getDataType(),
#                                                              symbol.getHighVariable().getInstances()))
#
#     bridge.remote_exec("""
# def get_call_ops_to(opiter, target_addr):
#     result = []
#     foo = []
#     while opiter.hasNext():
#         op = opiter.next()
#         foo.append(str(op))
#         mnemonic = str(op.getMnemonic())
#         if mnemonic == "CALL":
#             inputs = op.getInputs()
#             addr = inputs[0].getAddress()
#             if addr == target_addr:
#                 result.append(op)
#     return foo, result
#     """)
#
#     if high_func:
#         opiter = high_func.getPcodeOps()
#         foo, all_call_ops = bridge.remote_eval("""get_call_ops_to(opiter, target_addr)""",
#                                                opiter=opiter, target_addr=target_addr)
#
#         print("=========================")
#         for it in foo:
#             print("----")
#             print(it)
#         print("num results", len(all_call_ops))
#         for op in all_call_ops:
#             inputs = op.getInputs()
#             # args = inputs[1:] # List of VarnodeAST types
#             hash_arg = inputs[2]
#             type_arg = inputs[3]
#             print("Call to {} at {} has hash {}, type {}, control {}".format(
#                 target_addr, op.getSeqnum().getTarget(), hash_arg, type_arg, inputs[4]))
#

def get_function_list() -> list[tuple[str, int]]:
    with ghidra_bridge.GhidraBridge() as init_bridge:
        return init_bridge.remote_eval("""
        [
            (f.getName(True), f.getID()) for f in currentProgram.getSymbolTable().getDefinedSymbols()
            if f.getName() == "fields"
        ]
        """)


bridge = None

#
# def initialize_worker():
#     global bridge, monitor, ifc
#     bridge = ghidra_bridge.GhidraBridge()
#
#     flat_api = bridge.get_flat_api()
#     DecompileOptions = bridge.remote_import("ghidra.app.decompiler.DecompileOptions")
#     DecompInterface = bridge.remote_import("ghidra.app.decompiler.DecompInterface")
#     ConsoleTaskMonitor = bridge.remote_import("ghidra.util.task.ConsoleTaskMonitor")
#
#     monitor = ConsoleTaskMonitor()
#     ifc = DecompInterface()
#     ifc.setOptions(DecompileOptions())
#     ifc.openProgram(flat_api.currentProgram)


def decompile_functions(field_functions: dict[str, int]):
    with ghidra_bridge.GhidraBridge() as bridge:
        flat_api = bridge.get_flat_api()
        DecompileOptions = bridge.remote_import("ghidra.app.decompiler.DecompileOptions")
        DecompInterface = bridge.remote_import("ghidra.app.decompiler.DecompInterface")
        ConsoleTaskMonitor = bridge.remote_import("ghidra.util.task.ConsoleTaskMonitor")

        monitor = ConsoleTaskMonitor()
        ifc = DecompInterface()
        ifc.setOptions(DecompileOptions())
        ifc.openProgram(flat_api.currentProgram)

        function_manager = flat_api.currentProgram.getFunctionManager()
        symbol_table = flat_api.currentProgram.getSymbolTable()

        result = {}

        for i, (full_name, func_id) in enumerate(field_functions.items()):
            full_name = typing.cast(str, full_name)
            assert full_name.startswith("Reflection::")
            assert full_name.endswith("::fields")
            type_name = full_name[len("Reflection::"):-len("::fields")]

            func = function_manager.getFunctionAt(symbol_table.getSymbol(func_id).getAddress())
            try:
                result[type_name] = get_field_registrations(
                    bridge,
                    ifc,
                    monitor,
                    func,
                )
                print(f"Parsed {full_name} [{i + 1} of {len(field_functions)}]")
            except Exception as e:
                print(f"Unable to parse {full_name} (index {i}): {e}")

        return result


def main():
    all_fields_functions = get_function_list()

    process_count = math.ceil(multiprocessing.cpu_count() / 2)
    expected_size_per = math.ceil(len(all_fields_functions) / process_count)

    split_functions = [
        all_fields_functions[i * expected_size_per:(i + 1) * expected_size_per]
        for i in range(process_count)
    ]

    result = {}

    def callback(r):
        result.update(r)

    def error_callback(e):
        print(f"Pool thread failed due to: {e}")

    with multiprocessing.Pool(processes=len(split_functions)) as pool:
        for split in split_functions:
            pool.apply_async(
                func=decompile_functions,
                args=[{name: i for name, i in split}],
                callback=callback,
                error_callback=error_callback,
            )
        pool.close()
        pool.join()

    with open("all_types.json", "w") as f:
        json.dump(result, f, indent=4)


if __name__ == '__main__':
    main()
