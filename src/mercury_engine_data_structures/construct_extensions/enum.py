import enum
import typing

import construct


class StrictEnum(construct.Adapter):
    def __init__(self, enum_class: typing.Type[enum.IntEnum]):
        super().__init__(construct.Int32ul)
        self.enum_class = enum_class

    def _decode(self, obj: int, context, path):
        return self.enum_class(obj)

    def _encode(self, obj: typing.Union[str, enum.IntEnum], context, path) -> int:
        if isinstance(obj, str):
            obj = getattr(self.enum_class, obj)

        return obj.value


def BitMaskEnum(enum_type: typing.Type[enum.IntEnum]):
    flags = {}
    for enumentry in enum_type:
        flags[enumentry.name] = 2 ** enumentry.value
    return construct.FlagsEnum(construct.Int32ul, **flags)
