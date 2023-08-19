import collections
import dataclasses
import enum
import functools
import importlib
import typing
from enum import Enum
from typing import Dict, Optional, Set, Type

import construct

from mercury_engine_data_structures.formats.property_enum import HashedName
from mercury_engine_data_structures.game_check import Game
from mercury_engine_data_structures.pointer_set import PointerSet

# from mercury_engine_data_structures.construct_extensions.misc import ErrorWithMessage

@dataclasses.dataclass(frozen=True)
class BaseType:
    name: str
    target_game: Game

    @property
    def kind(self) -> "TypeKind":
        raise NotImplementedError

    @classmethod
    def from_json(cls, name: str, data: dict, target_game: Game) -> "BaseType":
        raise NotImplementedError

    @property
    def name_as_python_identifier(self) -> str:
        return self.name.replace("::", "_").replace(" ", "_").replace("<", "_").replace(
            ">", "_").replace(",", "_").replace("*", "Ptr")

    @property
    def construct(self) -> construct.Construct:
        from mercury_engine_data_structures.formats import dread_types
        return getattr(dread_types, self.name_as_python_identifier)

    @property
    def type_lib(self) -> "TypeLib":
        return get_type_lib_for_game(self.target_game)

    def _find_type_errors(self, __value: typing.Any) -> BaseException | None:
        raise NotImplementedError

    def is_value_of_type(self, __value: typing.Any) -> bool:
        return self._find_type_errors(__value) is None

    def verify_integrity(self, __value: typing.Any):
        err = self._find_type_errors(__value)
        if err is not None:
            raise err


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

primitive_to_type = {
    PrimitiveKind.STRING: str,
    PrimitiveKind.BOOL: bool,
    PrimitiveKind.INT: int,
    PrimitiveKind.UINT: int,
    PrimitiveKind.UINT_16: int,
    PrimitiveKind.UINT_64: int,
    PrimitiveKind.FLOAT: float,
    PrimitiveKind.VECTOR_2: typing.Sequence,
    PrimitiveKind.VECTOR_3: typing.Sequence,
    PrimitiveKind.VECTOR_4: typing.Sequence,
    PrimitiveKind.BYTES: bytes,
    PrimitiveKind.PROPERTY: HashedName,
}

primitive_int_bounds = {
    PrimitiveKind.INT:      (-2**31, 2**31 - 1),
    PrimitiveKind.UINT_16:  (0,      2**16 - 1),
    PrimitiveKind.UINT:     (0,      2**32 - 1),
    PrimitiveKind.UINT_64:  (0,      2**64 - 1),
}

primitive_vector_lengths = {
    PrimitiveKind.VECTOR_2: 2,
    PrimitiveKind.VECTOR_3: 3,
    PrimitiveKind.VECTOR_4: 4,
}


@dataclasses.dataclass(frozen=True)
class PrimitiveType(BaseType):
    primitive_kind: PrimitiveKind

    @property
    def kind(self):
        return TypeKind.PRIMITIVE

    @classmethod
    def from_json(cls, name: str, data: dict, target_game: Game) -> "PrimitiveType":
        return cls(name, target_game, PrimitiveKind(data["primitive_kind"]))

    @property
    def construct(self) -> construct.Construct:
        from mercury_engine_data_structures.formats import dread_types
        return dread_types.primitive_to_construct[self.primitive_kind.value]

    def _find_type_errors(self, __value: typing.Any) -> BaseException | None:
        expected_type = primitive_to_type[self.primitive_kind]
        if not isinstance(__value, expected_type):
            return TypeError(f"Expected {expected_type}; got {type(__value)}")

        if self.primitive_kind in primitive_int_bounds:
            low, high = primitive_int_bounds[self.primitive_kind]
            if low <= __value <= high:
                return None
            return ValueError(f"{__value} is out of range of [{low}, {high}]")

        if self.primitive_kind in primitive_vector_lengths:
            length = primitive_vector_lengths[self.primitive_kind]
            if (
                len(__value) == length
                and all(isinstance(v, float) for v in __value)
            ):
                return None
            return ValueError(f"Invalid CVector{length}D: {__value}")

        return None

@dataclasses.dataclass(frozen=True)
class StructType(BaseType):
    parent: Optional[str]
    fields: Dict[str, str]

    @property
    def kind(self):
        return TypeKind.STRUCT

    @classmethod
    def from_json(cls, name: str, data: dict, target_game: Game) -> "StructType":
        return cls(name, target_game, data["parent"], data["fields"])

    def _find_type_errors(self, __value: typing.Any) -> BaseException | None:
        if not isinstance(__value, dict):
            return TypeError(f"Expected dict; got {type(__value)}")

        errors = []
        for k, v in __value.items():
            if k not in self.fields:
                errors.append(AttributeError(name=k, obj=self))
            err = self.type_lib.get_type(self.fields[k])._find_type_errors(v)
            if err is not None:
                errors.append(err)

        if errors:
            return TypeError(errors)
        return None


@dataclasses.dataclass(frozen=True)
class EnumType(BaseType):
    values: Dict[str, int]

    @property
    def kind(self):
        return TypeKind.ENUM

    @classmethod
    def from_json(cls, name: str, data: dict, target_game: Game) -> "EnumType":
        return cls(name, target_game, data["values"])

    def enum_class(self) -> typing.Type[enum.IntEnum]:
        if self.target_game == Game.DREAD:
            return getattr(importlib.import_module("mercury_engine_data_structures.formats.dread_types"),
                       self.name_as_python_identifier)
        raise NotImplementedError

    def _find_type_errors(self, __value: typing.Any) -> BaseException | None:
        expected = self.enum_class()

        if isinstance(__value, int) and not isinstance(__value, enum.IntEnum):
            if __value not in {v.value for v in expected}:
                return ValueError(f"{__value} is not a valid {expected}")
            __value = expected(__value)

        if not isinstance(__value, expected):
            return TypeError(f"Expected {expected}; got {type(__value)}")

        return None


@dataclasses.dataclass(frozen=True)
class FlagsetType(BaseType):
    enum: str

    @property
    def kind(self):
        return TypeKind.FLAGSET

    @classmethod
    def from_json(cls, name: str, data: dict, target_game: Game) -> "FlagsetType":
        return cls(name, target_game, data["enum"])

    def _find_type_errors(self, __value: typing.Any) -> BaseException | None:
        enum_type: EnumType = self.type_lib.get_type(self.enum)
        expected = enum_type.enum_class()

        if isinstance(__value, expected):
            return None

        if isinstance(__value, int):
            mask = 0
            for v in expected:
                mask |= v.value
            mask = ~mask

            if __value & mask:
                return TypeError(f"{__value} is not a valid {type(self)}")
            return None

        names = {v.name for v in expected}

        if isinstance(__value, dict):
            if not all(
                isinstance(k, str) and isinstance(v, bool)
                for k, v in __value.items()
            ):
                return TypeError(f"Expected dict[str, bool]; got {__value}")
            invalid = [k for k in __value if k not in names]
        elif isinstance(__value, str):
            invalid = [v for v in __value.split('|') if v not in names]
        else:
            return TypeError(f"Expected {type(self)}; got {type(__value)}")

        if invalid:
            return TypeError(f"Contains invalid {self.enum} names: {invalid}")

        return None


@dataclasses.dataclass(frozen=True)
class TypedefType(BaseType):
    alias: str

    @property
    def kind(self):
        return TypeKind.TYPEDEF

    @classmethod
    def from_json(cls, name: str, data: dict, target_game: Game) -> "TypedefType":
        return cls(name, target_game, data["alias"])

    def _find_type_errors(self, __value: typing.Any) -> BaseException | None:
        return self.type_lib.get_type(self.alias, follow_typedef=True)._find_type_errors(__value)


@dataclasses.dataclass(frozen=True)
class PointerType(BaseType):
    target: str

    @property
    def kind(self):
        return TypeKind.POINTER

    @classmethod
    def from_json(cls, name: str, data: dict, target_game: Game) -> "PointerType":
        return cls(name, target_game, data["target"])

    @property
    def pointer_set(self) -> PointerSet:
        return typing.cast(PointerSet, self.construct)

    def _find_type_errors(self, __value: typing.Any) -> BaseException | None:
        names = set(self.pointer_set.type_names)

        type_name = None

        if __value is None:
            if "void" in names:
                return None
            type_name = "void"
        names.discard("void")

        if isinstance(__value, dict):
            type_name = __value.get("@type")
            if "@value" in __value:
                __value = __value["@value"]

        if type_name is not None and type_name not in names:
            return TypeError(f"{type_name} is not a valid target for {self.target}")

        if len(names) == 1:
            return self.type_lib.get_type(next(names))._find_type_errors(__value)

        if type_name is None:
            return TypeError(f"No type specified for {self.target}")

        return self.type_lib.get_type(type_name)._find_type_errors(__value)


@dataclasses.dataclass(frozen=True)
class VectorType(BaseType):
    value_type: str

    @property
    def kind(self):
        return TypeKind.VECTOR

    @classmethod
    def from_json(cls, name: str, data: dict, target_game: Game) -> "VectorType":
        return cls(name, target_game, data["value_type"])

    def _find_type_errors(self, __value: typing.Any) -> BaseException | None:
        if not isinstance(__value, typing.Iterable):
            return TypeError(f"{type(__value)} is not iterable")
        errors = {
            i: self.type_lib.get_type(self.value_type)._find_type_errors(v)
            for i, v in enumerate(__value)
        }
        errors = {i: v for i, v in errors.items() if v is not None}
        if errors:
            return TypeError(errors)
        return None


@dataclasses.dataclass(frozen=True)
class DictionaryType(BaseType):
    key_type: str
    value_type: str

    @property
    def kind(self):
        return TypeKind.DICTIONARY

    @classmethod
    def from_json(cls, name: str, data: dict, target_game: Game) -> "DictionaryType":
        return cls(name, target_game, data["key_type"], data["value_type"])

    def _find_type_errors(self, __value: typing.Any) -> BaseException | None:
        if not isinstance(__value, dict):
            return TypeError(f"Expected dict; got {type(__value)}")

        key_errors = {
            key: self.type_lib.get_type(self.key_type)._find_type_errors(key)
            for key in __value.keys()
        }
        key_errors = {k: v for k, v in key_errors.items() if v is not None}

        value_errors = {
            key: self.type_lib.get_type(self.value_type)._find_type_errors(value)
            for key, value in __value.items()
        }
        value_errors = {k: v for k, v in value_errors.items() if v is not None}

        errors = {}
        if key_errors:
            errors["Keys"] = key_errors
        if value_errors:
            errors["Values"] = value_errors
        if errors:
            return TypeError(errors)

        return None


def decode_type(name: str, data: dict, target_game: Game) -> BaseType:
    kind: TypeKind = TypeKind(data["kind"])
    return kind.type_class.from_json(name, data, target_game)


class TypeLib:
    def __init__(self, types_dict: Dict[str, typing.Any], target_game: Game):
        self.types_dict = types_dict
        self.target_game = target_game

    @functools.lru_cache
    def all_types(self) -> Dict[str, BaseType]:
        return {
            name: decode_type(name, data, self.target_game)
            for name, data in self.types_dict.items()
        }

    @functools.lru_cache
    def all_constructs(self) -> Dict[str, construct.Construct]:
        return {
            name: type.construct
            for name, type in self.all_types().items()
        }


    def get_type(self, type_name: str, *, follow_typedef: bool = True) -> BaseType:
        result = self.all_types()[type_name]

        if follow_typedef and result.kind == TypeKind.TYPEDEF:
            assert isinstance(result, TypedefType)
            return self.get_type(result.alias, follow_typedef=follow_typedef)

        return result


    def GetTypeConstruct(self, keyfunc, follow_typedef: bool = True) -> construct.Construct:
        return construct.FocusedSeq(
            "switch",
            "key" / construct.Computed(keyfunc),
            "type" / construct.Computed(lambda this: self.get_type(this.key, follow_typedef=follow_typedef).name),
            "switch" / construct.Switch(
                lambda this: this.type,
                self.all_constructs(),
                construct.Error
                # ErrorWithMessage(lambda this: f"Unknown type: {this.type}", construct.SwitchError)
            )
        )


    def get_parent_for(self, type_name: str) -> Optional[str]:
        data = self.get_type(type_name)

        if data.kind == TypeKind.STRUCT:
            assert isinstance(data, StructType)
            return data.parent

        return None


    def is_child_of(self, type_name: Optional[str], parent_name: str) -> bool:
        """
        Checks if the type_name is a direct or indirect child of the type parent_name
        """
        if type_name == parent_name:
            return True

        if type_name is None:
            return False

        return self.is_child_of(self.get_parent_for(type_name), parent_name)


    @functools.lru_cache
    def all_direct_children(self) -> Dict[str, Set[str]]:
        """
        Returns a mapping of type names to all their direct children.
        """
        result = collections.defaultdict(set)

        for type_name in self.all_types().keys():
            if (parent := self.get_parent_for(type_name)) is not None:
                result[parent].add(type_name)

        return dict(result)


    def get_all_children_for(self, type_name: str) -> Set[str]:
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

            types_to_check.update(self.all_direct_children().get(next_type, set()))

        return result


@functools.lru_cache
def get_type_lib_dread():
    from mercury_engine_data_structures import dread_data
    return TypeLib(dread_data.get_raw_types(), Game.DREAD)


@functools.lru_cache
def get_type_lib_samus_returns():
    from mercury_engine_data_structures import samus_returns_data
    return TypeLib(samus_returns_data.get_raw_types(), Game.SAMUS_RETURNS)


@functools.lru_cache
def get_type_lib_for_game(game: Game):
    if game == Game.DREAD:
        return get_type_lib_dread()
    if game == Game.SAMUS_RETURNS:
        return get_type_lib_samus_returns()
