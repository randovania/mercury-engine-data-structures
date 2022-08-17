import collections
import dataclasses
import enum
import functools
import importlib
import typing
from enum import Enum
from typing import Optional, Dict, Type, Set
import construct

from mercury_engine_data_structures import dread_data
# from mercury_engine_data_structures.construct_extensions.misc import ErrorWithMessage

@dataclasses.dataclass(frozen=True)
class BaseType:
    name: str

    @property
    def kind(self) -> "TypeKind":
        raise NotImplementedError()

    @classmethod
    def from_json(cls, name: str, data: dict) -> "BaseType":
        raise NotImplementedError()

    @property
    def name_as_python_identifier(self) -> str:
        return self.name.replace("::", "_").replace(" ", "_").replace("<", "_").replace(
            ">", "_").replace(",", "_").replace("*", "Ptr")
    
    @property
    def construct(self) -> construct.Construct:
        from mercury_engine_data_structures.formats import dread_types
        return getattr(dread_types, self.name_as_python_identifier)


class TypeKind(Enum):
    PRIMITIVE = "primitive"
    STRUCT = "struct"
    ENUM = "enum"
    FLAGSET = "flagset"
    TYPEDEF = "typedef"
    POINTER = "pointer"
    VECTOR = "vector"
    DICTIONARY = "dictionary"

    @property
    def type_class(self) -> Type[BaseType]:
        if self == TypeKind.PRIMITIVE:
            return PrimitiveType
        if self == TypeKind.STRUCT:
            return StructType
        if self == TypeKind.ENUM:
            return EnumType
        if self == TypeKind.FLAGSET:
            return FlagsetType
        if self == TypeKind.TYPEDEF:
            return TypedefType
        if self == TypeKind.POINTER:
            return PointerType
        if self == TypeKind.VECTOR:
            return VectorType
        if self == TypeKind.DICTIONARY:
            return DictionaryType
        raise ValueError(f"Unknown enum value: {self}")


class PrimitiveKind(Enum):
    STRING = "string"
    BOOL = "bool"
    INT = "int"
    UINT = "uint"
    UINT_16 = "uint16"
    UINT_64 = "uint64"
    FLOAT = "float"
    VECTOR_2 = "float_vec2"
    VECTOR_3 = "float_vec3"
    VECTOR_4 = "float_vec4"
    BYTES = "bytes"
    PROPERTY = "property"


@dataclasses.dataclass(frozen=True)
class PrimitiveType(BaseType):
    primitive_kind: PrimitiveKind

    @property
    def kind(self):
        return TypeKind.PRIMITIVE

    @classmethod
    def from_json(cls, name: str, data: dict) -> "PrimitiveType":
        return cls(name, PrimitiveKind(data["primitive_kind"]))
    
    @property
    def construct(self) -> construct.Construct:
        from mercury_engine_data_structures.formats import dread_types
        return dread_types.primitive_to_construct[self.primitive_kind.value]


@dataclasses.dataclass(frozen=True)
class StructType(BaseType):
    parent: Optional[str]
    fields: Dict[str, str]

    @property
    def kind(self):
        return TypeKind.STRUCT

    @classmethod
    def from_json(cls, name: str, data: dict) -> "StructType":
        return cls(name, data["parent"], data["fields"])


@dataclasses.dataclass(frozen=True)
class EnumType(BaseType):
    values: Dict[str, int]

    @property
    def kind(self):
        return TypeKind.ENUM

    @classmethod
    def from_json(cls, name: str, data: dict) -> "EnumType":
        return cls(name, data["values"])

    def enum_class(self) -> typing.Type[enum.IntEnum]:
        return getattr(importlib.import_module("mercury_engine_data_structures.formats.dread_types"),
                       self.name_as_python_identifier)


@dataclasses.dataclass(frozen=True)
class FlagsetType(BaseType):
    enum: str

    @property
    def kind(self):
        return TypeKind.FLAGSET

    @classmethod
    def from_json(cls, name: str, data: dict) -> "FlagsetType":
        return cls(name, data["enum"])


@dataclasses.dataclass(frozen=True)
class TypedefType(BaseType):
    alias: str

    @property
    def kind(self):
        return TypeKind.TYPEDEF

    @classmethod
    def from_json(cls, name: str, data: dict) -> "TypedefType":
        return cls(name, data["alias"])


@dataclasses.dataclass(frozen=True)
class PointerType(BaseType):
    target: str

    @property
    def kind(self):
        return TypeKind.POINTER

    @classmethod
    def from_json(cls, name: str, data: dict) -> "PointerType":
        return cls(name, data["target"])


@dataclasses.dataclass(frozen=True)
class VectorType(BaseType):
    value_type: str

    @property
    def kind(self):
        return TypeKind.VECTOR

    @classmethod
    def from_json(cls, name: str, data: dict) -> "VectorType":
        return cls(name, data["value_type"])


@dataclasses.dataclass(frozen=True)
class DictionaryType(BaseType):
    key_type: str
    value_type: str

    @property
    def kind(self):
        return TypeKind.DICTIONARY

    @classmethod
    def from_json(cls, name: str, data: dict) -> "DictionaryType":
        return cls(name, data["key_type"], data["value_type"])


def decode_type(name: str, data: dict) -> BaseType:
    kind: TypeKind = TypeKind(data["kind"])
    return kind.type_class.from_json(name, data)


@functools.lru_cache()
def all_types() -> Dict[str, BaseType]:
    return {
        name: decode_type(name, data)
        for name, data in dread_data.get_raw_types().items()
    }


@functools.lru_cache()
def all_constructs() -> Dict[str, construct.Construct]:
    return {
        name: type.construct
        for name, type in all_types().items()
    }


def get_type(type_name: str, *, follow_typedef: bool = True) -> BaseType:
    result = all_types()[type_name]

    if follow_typedef and result.kind == TypeKind.TYPEDEF:
        assert isinstance(result, TypedefType)
        return get_type(result.alias, follow_typedef=follow_typedef)

    return result


def GetTypeConstruct(keyfunc, follow_typedef: bool = True) -> construct.Construct:
    return construct.FocusedSeq(
        "switch",
        "key" / construct.Computed(keyfunc),
        "type" / construct.Computed(lambda this: get_type(this.key, follow_typedef=follow_typedef).name),
        "switch" / construct.Switch(
            lambda this: this.type,
            all_constructs(),
            construct.Error
            # ErrorWithMessage(lambda this: f"Unknown type: {this.type}", construct.SwitchError)
        )
    )


def get_parent_for(type_name: str) -> Optional[str]:
    data = get_type(type_name)

    if data.kind == TypeKind.STRUCT:
        assert isinstance(data, StructType)
        return data.parent

    return None


def is_child_of(type_name: Optional[str], parent_name: str) -> bool:
    """
    Checks if the type_name is a direct or indirect child of the type parent_name
    """
    if type_name == parent_name:
        return True

    if type_name is None:
        return False

    return is_child_of(get_parent_for(type_name), parent_name)


@functools.lru_cache()
def all_direct_children() -> Dict[str, Set[str]]:
    """
    Returns a mapping of type names to all their direct children.
    """
    result = collections.defaultdict(set)

    for type_name in all_types().keys():
        if (parent := get_parent_for(type_name)) is not None:
            result[parent].add(type_name)

    return dict(result)


def get_all_children_for(type_name: str) -> Set[str]:
    """
    Get all direct and indirect children for a given type.
    """
    result = set()

    types_to_check = {type_name}
    while types_to_check:
        next_type = types_to_check.pop()

        if next_type in result:
            continue
        result.add(next_type)

        types_to_check.update(all_direct_children().get(next_type, set()))

    return result
