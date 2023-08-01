import construct


class LimitedStruct(construct.Struct):
    r"""The same as Struct, but when compiled it supports less features in order to be faster."""

    def _emitbuild(self, code):
        fname = f"build_struct_{code.allocateId()}"
        block = f"""
            def {fname}(objdict, io):
        """
        for sc in self.subcons:
            block += f"""
                {f'obj = objdict.get({repr(sc.name)}, None)' if sc.flagbuildnone else f'obj = objdict[{repr(sc.name)}]'}
                {sc._compilebuild(code)}
            """
        code.append(block)
        return f"{fname}(obj, io)"
