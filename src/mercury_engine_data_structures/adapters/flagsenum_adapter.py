from __future__ import annotations

from construct import Adapter, FlagsEnum, Int32ub


class FlagsEnumAdapter(Adapter):
    def __init__(self, enum_class, subcon=Int32ub):
        super().__init__(FlagsEnum(subcon, enum_class))
        self._enum_class = enum_class

    def _decode(self, obj, context, path):
        return {
            self._enum_class[k]: v
            for k, v in obj.items()
            if k != "_flagsenum" and v is True
        }

    def _encode(self, obj, context, path):
        return obj
