from typing import Dict, Optional, Type, Union

import construct


def emit_switch_cases_parse(
        code: construct.CodeGen,
        fields: Dict[str, Union[construct.Construct, Type[construct.Construct]]],
        custom_table_name: Optional[str] = None,
) -> str:
    """Construct codegen helper for handling the switch cases dict in _emitparse."""
    table_name = custom_table_name
    if table_name is None:
        table_name = f"parse_switch_cases_{code.allocateId()}"

    block = f"{table_name} = {{\n"
    for type_name, type_class in fields.items():
        code.append(f"""
        def _parse_{id(type_class)}(io, this):
            return {type_class._compileparse(code)}
        """)

        block += f"    {repr(type_name)}: _parse_{id(type_class)},  # {type_class.name}\n"
    block += "}"
    code.append(block)

    return table_name


def emit_switch_cases_build(
        code: construct.CodeGen,
        fields: Dict[str, Union[construct.Construct, Type[construct.Construct]]],
        custom_table_name: Optional[str] = None,
) -> str:
    """Construct codegen helper for handling the switch cases dict in _emitbuild."""
    table_name = custom_table_name
    if table_name is None:
        table_name = f"build_switch_cases_{code.allocateId()}"

    block = f"{table_name} = {{\n"
    for type_name, type_class in fields.items():
        code.append(f"""
        def _build_{id(type_class)}(obj, io, this):
            return {type_class._compilebuild(code)}
        """)
        block += f"    {repr(type_name)}: _build_{id(type_class)},  # {type_class.name}\n"
    block += "}"
    code.append(block)
    return table_name


class SwitchComplexKey(construct.Switch):
    def _insert_keyfunc(self, code: construct.CodeGen):
        if id(self.keyfunc) not in code.linkedinstances:
            code.linkedinstances[id(self.keyfunc)] = self.keyfunc
        return f"linkedinstances[{id(self.keyfunc)}](this)"

    def _emitparse(self, code: construct.CodeGen):
        fname = f"switch_cases_{code.allocateId()}"
        code.append(f"{fname} = {{}}")
        for key, sc in self.cases.items():
            code.append(f"{fname}[{repr(key)}] = lambda io,this: {sc._compileparse(code)}")
        defaultfname = f"switch_defaultcase_{code.allocateId()}"
        code.append(f"{defaultfname} = lambda io,this: {self.default._compileparse(code)}")
        return f"{fname}.get({self._insert_keyfunc(code)}, {defaultfname})(io, this)"

    def _emitbuild(self, code: construct.CodeGen):
        fname = f"switch_cases_{code.allocateId()}"
        code.append(f"{fname} = {{}}")
        for key, sc in self.cases.items():
            code.append(f"{fname}[{repr(key)}] = lambda obj,io,this: {sc._compilebuild(code)}")
        defaultfname = f"switch_defaultcase_{code.allocateId()}"
        code.append(f"{defaultfname} = lambda obj,io,this: {self.default._compilebuild(code)}")
        return f"{fname}.get({self._insert_keyfunc(code)}, {defaultfname})(obj, io, this)"


class ComplexIfThenElse(construct.IfThenElse):
    def _insert_cond(self, code: construct.CodeGen):
        if id(self.condfunc) not in code.linkedinstances:
            code.linkedinstances[id(self.condfunc)] = self.condfunc
        return f"linkedinstances[{id(self.condfunc)}](this)"

    def _emitparse(self, code):
        return "(({}) if ({}) else ({}))".format(self.thensubcon._compileparse(code),
                                                 self._insert_cond(code),
                                                 self.elsesubcon._compileparse(code), )

    def _emitbuild(self, code):
        return (f"(({self.thensubcon._compilebuild(code)}) if ("
                f"{self._insert_cond(code)}) else ({self.elsesubcon._compilebuild(code)}))")


def ComplexIf(condfunc, subcon):
    return ComplexIfThenElse(condfunc, subcon, construct.Pass)
