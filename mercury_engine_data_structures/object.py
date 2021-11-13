from typing import Dict, Union, Type

import construct
from construct import Construct, Probe, Struct, Adapter
from construct.core import FocusedSeq, Byte, If, IfThenElse, Optional, Peek

import mercury_engine_data_structures.dread_data
from mercury_engine_data_structures.common_types import make_vector
from mercury_engine_data_structures.construct_extensions.misc import ErrorWithMessage, ForceQuit
from mercury_engine_data_structures.formats.property_enum import PropertyEnum


def ConfirmType(name: str):
    def check(ctx):
        return ctx[f"{name}_type"] != name

    return construct.If(
        check,
        ErrorWithMessage(
            lambda ctx: f"Expected {name}, got {ctx[f'{name}_type']} ("
                        f"{mercury_engine_data_structures.dread_data.all_property_id_to_name().get(ctx[f'{name}_type'])}) "
                        "without assigned type"
        ),
    )


def _has_duplicated_keys(obj):
    seen = set()
    for item in obj:
        if item.type in seen:
            return True
        seen.add(item.type)
    return False


class ObjectAdapter(Adapter):
    def _decode(self, obj: construct.ListContainer, context, path):
        if _has_duplicated_keys(obj):
            return obj

        result = construct.Container()
        for item in obj:
            if item.type in result:
                raise construct.ConstructError(f"Type {item.type} found twice in object", path)
            result[item.type] = item.item

        return result

    def _encode(self, obj: construct.Container, context, path):
        if isinstance(obj, construct.ListContainer):
            return obj
        return construct.ListContainer(
            construct.Container(
                type=type_,
                item=item
            )
            for type_, item in obj.items()
        )


def Object(fields: Dict[str, Union[Construct, Type[Construct]]], *,
           debug=False) -> Construct:
    all_types = list(fields)

    fields = {
        name: FocusedSeq(
            name,
            "next_field" / Optional(Peek(PropertyEnum)),
            "remaining" / Optional(Peek(Byte)),
            name / IfThenElse(
                construct.this._parsing,
                If(lambda this: this.remaining is not None and (this.next_field is None or this.next_field not in fields.keys()), conn),
                Optional(conn)
            )
        )
        for name, conn in fields.items()
    }
    for type_name in all_types:
        if type_name not in mercury_engine_data_structures.dread_data.all_name_to_property_id():
            raise ValueError(f"Unknown type name: {type_name}, not in hashes database")

    switch = construct.Switch(
        construct.this.type,
        fields,
        ErrorWithMessage(
            lambda ctx: f"Type {ctx.type} not known, valid types are {all_types}."
        )
    )
    switch.name = "item"
    r = ObjectAdapter(make_vector(
        Struct(
            "type" / PropertyEnum,
            switch,
        )
    ))
    if debug:
        r.name = "fields"
        r = construct.FocusedSeq(
            "fields",
            r,
            "next_enum" / PropertyEnum,
            "probe" / Probe(lookahead=0x8),
            ForceQuit(),
        )

    return r
