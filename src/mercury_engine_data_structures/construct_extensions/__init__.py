import operator

import construct.expr

# Workaround construct's bug (See https://github.com/construct/construct/issues/1039)
construct.expr.opnames[operator.and_] = "&"
construct.expr.opnames[operator.or_] = "|"


# Hex for some reason doesn't support compilation for building, despite being trivial to do
# So let's hack it in.
def _hex_emitbuild(self, code):
    return self.subcon._compilebuild(code)


construct.Hex._emitbuild = _hex_emitbuild
