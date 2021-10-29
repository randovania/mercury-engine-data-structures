"""
Helper class to handle objects that contain a pointer to objects of varied types, usually all with the same base type.
"""
from typing import Dict, Union, Type

import construct
from construct import Construct, Struct, Hex, Int64ul, Computed, Switch

from mercury_engine_data_structures import hashed_names
from mercury_engine_data_structures.construct_extensions.misc import ErrorWithMessage


class PointerSet:
    types: Dict[int, Union[Construct, Type[Construct]]]

    def __init__(self, category: str, *, allow_null: bool = False):
        self.category = category
        self.types = {}

    @classmethod
    def construct_pointer_for(cls, name: str, conn: Union[Construct, Type[Construct]]) -> Struct:
        ret = cls(name, allow_null=True)
        ret.add_option(name, conn)
        return ret.create_construct()

    def add_option(self, name: str, value: Union[Construct, Type[Construct]]) -> None:
        prop_id = hashed_names.all_name_to_property_id()[name]
        if prop_id in self.types:
            raise ValueError(f"Attempting to add {name} to {self.category}, but already present.")
        self.types[prop_id] = value

    def create_construct(self) -> Struct:
        fields = {
            prop_id: hashed_names.all_property_id_to_name()[prop_id] / conn
            for prop_id, conn in self.types.items()
        }
        return Struct(
            type=Hex(Int64ul),
            type_name=Computed(lambda ctx: hashed_names.all_property_id_to_name().get(ctx.type)),
            ptr=Switch(
                construct.this.type,
                fields,
                ErrorWithMessage(
                    lambda ctx: f"Property {ctx.type} ({hashed_names.all_property_id_to_name().get(ctx.type)}) "
                                "without assigned type"),
            )
        )
