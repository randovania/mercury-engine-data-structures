import construct


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
                                             self.elsesubcon._compileparse(code),)

    def _emitbuild(self, code):
        return (f"(({self.thensubcon._compilebuild(code)}) if ("
                f"{self._insert_cond(code)}) else ({self.elsesubcon._compilebuild(code)}))")


def ComplexIf(condfunc, subcon):
    return ComplexIfThenElse(condfunc, subcon, construct.Pass)
