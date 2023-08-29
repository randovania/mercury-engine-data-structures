import re
from typing import Dict, Optional, Type, Union

import construct


def _resolve_id(type_class: Union[construct.Construct, Type[construct.Construct]]) -> int:
    if isinstance(type_class, construct.Renamed):
        return _resolve_id(type_class.subcon)
    return id(type_class)


_simple_parse_re = re.compile(r"^(\w+)\(io, this\)$")
_simple_build_re = re.compile(r"^(\w+)\(obj, io, this\)$")


def emit_switch_cases_parse(
        code: construct.CodeGen,
        fields: Dict[Union[str, int], Union[construct.Construct, Type[construct.Construct]]],
        custom_table_name: Optional[str] = None,
) -> str:
    """Construct codegen helper for handling the switch cases dict in _emitparse."""
    table_name = custom_table_name
    if table_name is None:
        table_name = f"parse_switch_cases_{code.allocateId()}"

    block = f"{table_name} = {{\n"
    for type_name, type_class in fields.items():
        type_code = type_class._compileparse(code)

        # if the type's code is just a function call, wrap it
        code_match = _simple_parse_re.match(type_code)
        if code_match is not None:
            code_name = code_match.group(1)
        else:
            code_name = f"_parse_{_resolve_id(type_class)}"
            code.append(f"""
            def {code_name}(io, this):
                return {type_code}
            """)

        block += f"    {repr(type_name)}: {code_name},\n"
    block += "}"
    code.append(block)

    return table_name


def emit_switch_cases_build(
        code: construct.CodeGen,
        fields: Dict[Union[str, int], Union[construct.Construct, Type[construct.Construct]]],
        custom_table_name: Optional[str] = None,
) -> str:
    """Construct codegen helper for handling the switch cases dict in _emitbuild."""
    table_name = custom_table_name
    if table_name is None:
        table_name = f"build_switch_cases_{code.allocateId()}"

    block = f"{table_name} = {{\n"
    for type_name, type_class in fields.items():
        type_code = type_class._compilebuild(code)

        # if the type's code is just a function call, wrap it
        code_match = _simple_build_re.match(type_code)
        if code_match is not None:
            code_name = code_match.group(1)
        else:
            code_name = f"_build_{_resolve_id(type_class)}"
            code.append(f"""
            def {code_name}(obj, io, this):
                return {type_code}
            """)

        block += f"    {repr(type_name)}: {code_name},\n"

    block += "}"
    code.append(block)
    return table_name


class SwitchComplexKey(construct.Switch):
    def _insert_keyfunc(self, code: construct.CodeGen):
        if id(self.keyfunc) not in code.linkedinstances:
            code.linkedinstances[id(self.keyfunc)] = self.keyfunc
        return f"linkedinstances[{id(self.keyfunc)}](this)"

    def _emitparse(self, code: construct.CodeGen):
        fname = emit_switch_cases_parse(code, self.cases)

        defaultfname = f"default_{fname}"
        code.append(f"{defaultfname} = lambda io,this: {self.default._compileparse(code)}")

        return f"{fname}.get({self._insert_keyfunc(code)}, {defaultfname})(io, this)"

    def _emitbuild(self, code: construct.CodeGen):
        fname = emit_switch_cases_build(code, self.cases)

        defaultfname = f"default_{fname}"
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
