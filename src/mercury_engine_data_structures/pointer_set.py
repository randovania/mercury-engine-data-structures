"""
Helper class to handle objects that contain a pointer to objects of varied types, usually all with the same base type.
"""
import copy
import struct
from typing import Dict, Type, Union

import construct
from construct import Adapter, Construct, Container, Hex, Int64ul, ListContainer, Struct, Switch

import mercury_engine_data_structures.dread_data
from mercury_engine_data_structures.construct_extensions.function_complex import (
    emit_switch_cases_build,
    emit_switch_cases_parse,
)
from mercury_engine_data_structures.construct_extensions.misc import ErrorWithMessage


class PointerAdapter(Adapter):
    types: Dict[int, Union[Construct, Type[Construct]]]

    def __init__(self, types: Dict[int, Union[Construct, Type[Construct]]], category: str):
        get_name = mercury_engine_data_structures.dread_data.all_property_id_to_name().get
        self.switch_con = Switch(
            construct.this.type,
            types,
            ErrorWithMessage(lambda ctx: (
                f"Property {ctx.type} ({get_name(ctx.type)}) without assigned type"
            )),
        )
        super().__init__(Struct(
            type=Hex(Int64ul),
            ptr=self.switch_con,
        ))
        self.types = types
        self.category = category

    @property
    def _allow_null(self):
        return mercury_engine_data_structures.dread_data.all_name_to_property_id()["void"] in self.types

    @property
    def _single_type(self):
        return len(self.types) == (2 if self._allow_null else 1)

    def _decode(self, obj: construct.Container, context, path):
        if obj.ptr is None:
            return None

        if self._single_type:
            return obj.ptr

        ret = construct.Container()
        ret["@type"] = mercury_engine_data_structures.dread_data.all_property_id_to_name()[obj.type]

        if isinstance(obj.ptr, ListContainer):
            try:
                obj.ptr = Container({field.type: field.item for field in obj.ptr})
            except AttributeError:
                pass

        if isinstance(obj.ptr, Container):
            for key, value in obj.ptr.items():
                ret[key] = value
        else:
            ret["@value"] = obj.ptr
        return ret

    def _encode(self, obj: construct.Container, context, path):
        if obj is None:
            type_id = mercury_engine_data_structures.dread_data.all_name_to_property_id()["void"]

        elif self._single_type:
            type_id = list(self.types.keys())[1]

        else:
            obj = copy.copy(obj)
            type_name: str = obj.pop("@type")
            type_id = mercury_engine_data_structures.dread_data.all_name_to_property_id()[type_name]

        if obj is not None and "@value" in obj:
            obj = obj["@value"]

        return construct.Container(
            type=type_id,
            ptr=obj,
        )

    def _emitparse(self, code: construct.CodeGen) -> str:
        n = code.allocateId()

        fname = f"parse_pointer_{n}"
        case_name = f"pointer_switch_cases_{n}"

        if self._single_type:
            code.parsercache[id(self)] = f"{case_name}[{Int64ul._compileparse(code)}](io, this)"
        else:
            code.parsercache[id(self)] = f"{fname}(io, this)"
            code.append("import mercury_engine_data_structures.dread_data")
            block = f"""
                def {fname}(io, this):
                    # {self.category} supports {len(self.types)} types
                    obj_type = {Int64ul._compileparse(code)}
                    ptr = {case_name}[obj_type](io, this)
                    if ptr is None:
                        return None
                    ptr["@type"] = mercury_engine_data_structures.dread_data.all_property_id_to_name()[obj_type]
                    return ptr
            """
            code.append(block)

        emit_switch_cases_parse(code, self.types, case_name)

        return code.parsercache[id(self)]

    def _emitbuild(self, code: construct.CodeGen) -> str:
        void_id = mercury_engine_data_structures.dread_data.all_name_to_property_id()["void"]

        n = code.allocateId()

        fname = f"build_pointer_{n}"
        case_name = f"pointer_switch_cases_{n}"

        # PointerSet is used recursively, so break the infinite loop by prefilling the cache
        code.buildercache[id(self)] = f"{fname}(obj, io, this)"

        # Switch cases
        emit_switch_cases_build(code, self.types, case_name)

        block = f"""
            def {fname}(the_obj, io, this):
                # {self.category} supports {len(self.types)} types
                if the_obj is None:
                    return io.write({repr(struct.pack(Int64ul.fmtstr, void_id))})
        """

        if self._single_type:
            type_id = list(self.types.keys())[1]
            block += f"""
                io.write({repr(struct.pack(Int64ul.fmtstr, type_id))})
                return {case_name}[{type_id}](the_obj, io, this)
        """
        else:
            code.append("import mercury_engine_data_structures.dread_data")
            block += f"""
                new_obj = Container(**the_obj)
                obj = mercury_engine_data_structures.dread_data.all_name_to_property_id()[new_obj.pop("@type")]
                {Int64ul._compilebuild(code)}
                return {case_name}[obj](new_obj, io, this)
        """

        code.append(block)
        return code.buildercache[id(self)]


class PointerSet:
    types: Dict[int, Union[Construct, Type[Construct]]]

    def __init__(self, category: str, *, allow_null: bool = True):
        self.category = category
        self.types = {}
        if allow_null:
            self.add_option("void", construct.Pass)

    @classmethod
    def construct_pointer_for(cls, name: str, conn: Union[Construct, Type[Construct]]) -> Construct:
        ret = cls(name, allow_null=True)
        ret.add_option(name, conn)
        return ret.create_construct()

    def add_option(self, name: str, value: Union[Construct, Type[Construct]]) -> None:
        prop_id = mercury_engine_data_structures.dread_data.all_name_to_property_id()[name]
        if prop_id in self.types:
            raise ValueError(f"Attempting to add {name} to {self.category}, but already present.")
        self.types[prop_id] = name / value

    @property
    def type_names(self) -> tuple[str, ...]:
        all_names = mercury_engine_data_structures.dread_data.all_property_id_to_name()
        return tuple(all_names[prop_id] for prop_id in self.types)

    def create_construct(self) -> Construct:
        return PointerAdapter(self.types, self.category)
