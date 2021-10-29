from typing import Dict, Union, Type, Iterable

import construct
from construct import Construct, Int32ul, Probe, Struct

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


def Object(fields: Dict[str, Union[Construct, Type[Construct]]], *,
           extra_before_fields: Iterable[Construct] = (), debug=False) -> Construct:
    r = [
        "field_count" / Int32ul,
    ]
    r.extend(extra_before_fields)
    for name, subcon in fields.items():
        r.extend([
            f"{name}_type" / PropertyEnum,
            f"_{name}_check" / ConfirmType(name),
            name / subcon,
        ])

    if debug:
        r.extend([
            "next_enum" / PropertyEnum,
            "probe" / Probe(lookahead=0x8),
        ])

    # Right now, always adding the check_field_count to help development. So far, it has always matched the data.
    r.append("check_field_count" / construct.If(
        lambda ctx: ctx.field_count != len(fields),
        ErrorWithMessage(lambda ctx: f"Expected {len(fields)} fields, got {ctx.field_count}"),
    ))

    if debug:
        r.append(ForceQuit())

    return Struct(*r)
