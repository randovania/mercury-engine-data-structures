import enum
import typing

import construct


class StrictEnum(construct.Adapter):
    def __init__(self, enum_class: typing.Type[enum.IntEnum]):
        super().__init__(construct.Int32ul)
        self.enum_class = enum_class

    def _decode(self, obj: int, context, path):
        return self.enum_class(obj)

    def _encode(self, obj: typing.Union[str, enum.IntEnum, int], context, path) -> int:
        if isinstance(obj, str):
            obj = getattr(self.enum_class, obj)

        if isinstance(obj, enum.IntEnum):
            obj = obj.value

        return obj

    def _emitbuild(self, code: construct.CodeGen):
        i = code.allocateId()

        mapping = ", ".join(
            f"{repr(enum_entry.name)}: {enum_entry.value}"
            for enum_entry in self.enum_class
        )

        code.append(f"""
        _enum_name_to_value_{i} = {{{mapping}}}
        def _encode_enum_{i}(obj, io, this):
            # {self.name}
            try:
                obj = obj.value
            except AttributeError:
                obj = _enum_name_to_value_{i}.get(obj, obj)
            return {construct.Int32ul._compilebuild(code)}
        """)
        return f"_encode_enum_{i}(obj, io, this)"


def BitMaskEnum(enum_type: typing.Type[enum.IntEnum]):
    flags = {}
    for enumentry in enum_type:
        flags[enumentry.name] = 2 ** enumentry.value
    return construct.FlagsEnum(construct.Int32ul, **flags)
