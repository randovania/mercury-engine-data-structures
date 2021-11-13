import dataclasses
import functools
from enum import Enum
from typing import Optional, Dict, Type

from mercury_engine_data_structures import dread_data


@dataclasses.dataclass(frozen=True)
class BaseType:
    @property
    def kind(self) -> "TypeKind":
        raise NotImplementedError()

    @classmethod
    def from_json(cls, data: dict) -> "BaseType":
        raise NotImplementedError()


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
    def from_json(cls, data: dict) -> "PrimitiveType":
        return cls(PrimitiveKind(data["primitive_kind"]))


@dataclasses.dataclass(frozen=True)
class StructType(BaseType):
    parent: Optional[str]
    fields: Dict[str, str]

    @property
    def kind(self):
        return TypeKind.STRUCT

    @classmethod
    def from_json(cls, data: dict) -> "StructType":
        return cls(data["parent"], data["fields"])


@dataclasses.dataclass(frozen=True)
class EnumType(BaseType):
    values: Dict[str, int]

    @property
    def kind(self):
        return TypeKind.ENUM

    @classmethod
    def from_json(cls, data: dict) -> "EnumType":
        return cls(data["values"])


@dataclasses.dataclass(frozen=True)
class FlagsetType(BaseType):
    enum: str

    @property
    def kind(self):
        return TypeKind.FLAGSET

    @classmethod
    def from_json(cls, data: dict) -> "FlagsetType":
        return cls(data["enum"])


@dataclasses.dataclass(frozen=True)
class TypedefType(BaseType):
    alias: str

    @property
    def kind(self):
        return TypeKind.TYPEDEF

    @classmethod
    def from_json(cls, data: dict) -> "TypedefType":
        return cls(data["alias"])


@dataclasses.dataclass(frozen=True)
class PointerType(BaseType):
    target: str

    @property
    def kind(self):
        return TypeKind.POINTER

    @classmethod
    def from_json(cls, data: dict) -> "PointerType":
        return cls(data["target"])


@dataclasses.dataclass(frozen=True)
class VectorType(BaseType):
    value_type: str

    @property
    def kind(self):
        return TypeKind.VECTOR

    @classmethod
    def from_json(cls, data: dict) -> "VectorType":
        return cls(data["value_type"])


@dataclasses.dataclass(frozen=True)
class DictionaryType(BaseType):
    key_type: str
    value_type: str

    @property
    def kind(self):
        return TypeKind.DICTIONARY

    @classmethod
    def from_json(cls, data: dict) -> "DictionaryType":
        return cls(data["key_type"], data["value_type"])


def decode_type(data: dict) -> BaseType:
    kind: TypeKind = TypeKind(data["kind"])
    return kind.type_class.from_json(data)


@functools.lru_cache()
def all_types() -> Dict[str, BaseType]:
    return {
        name: decode_type(data)
        for name, data in dread_data.get_raw_types().items()
    }


def get_type(type_name: str) -> BaseType:
    return all_types()[type_name]


def get_parent_for(type_name: str) -> Optional[str]:
    data = get_type(type_name)
    if data.kind == TypeKind.STRUCT:
        assert isinstance(data, StructType)
        return data.parent

    return None


def is_child_of(type_name: Optional[str], parent_name: str) -> bool:
    if type_name == parent_name:
        return True

    if type_name is None:
        return False

    return is_child_of(get_parent_for(type_name), parent_name)
