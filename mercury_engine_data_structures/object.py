from typing import Dict, Union, Type

import construct
from construct import Construct, Int32ul, Probe, Struct, Adapter

from mercury_engine_data_structures import hashed_names
from mercury_engine_data_structures.construct_extensions.misc import ErrorWithMessage, ForceQuit
from mercury_engine_data_structures.hashed_names import PropertyEnum


def ConfirmType(name: str):
    def check(ctx):
        return ctx[f"{name}_type"] != name

    return construct.If(
        check,
        ErrorWithMessage(
            lambda ctx: f"Expected {name}, got {ctx[f'{name}_type']} ("
                        f"{hashed_names.all_property_id_to_name().get(ctx[f'{name}_type'])}) "
                        "without assigned type"
        ),
    )


class ObjectAdapter(Adapter):
    def __init__(self, subcon, fields: Dict[str, Union[Construct, Type[Construct]]]):
        super().__init__(subcon)
        self.fields = fields

    def _decode(self, obj: construct.ListContainer, context, path):
        result = construct.Container()
        for item in obj:
            if item.type in result:
                raise construct.ConstructError(f"Type {item.type} found twice in object", path)
            result[item.type] = item.item
        return result

    def _encode(self, obj: construct.Container, context, path):
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

    r = [
        "fields" / construct.PrefixedArray(
            Int32ul,
            Struct(
                "type" / PropertyEnum,
                "item" / construct.Switch(
                    construct.this.type,
                    fields,
                    ErrorWithMessage(
                        lambda ctx: f"Type {ctx.type} not known, valid types are {all_types}."
                    )
                )
            )
        )
    ]
    if debug:
        r.extend([
            "next_enum" / PropertyEnum,
            "probe" / Probe(lookahead=0x8),
        ])

    r.append("_check_field_count" / construct.If(
        lambda ctx: len(ctx.fields) > len(fields),
        ErrorWithMessage(lambda ctx: f"Got {ctx.field_count} fields, but we have only {len(fields)} types."),
    ))

    if debug:
        r.append(ForceQuit())

    return ObjectAdapter(construct.FocusedSeq("fields", *r), fields)
