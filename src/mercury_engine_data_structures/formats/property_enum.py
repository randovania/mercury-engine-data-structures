import enum
import warnings
from typing import Dict, Tuple

import construct

from mercury_engine_data_structures import crc, dread_data


class HashSet(enum.Enum):
    DREAD_PROPERTY = enum.auto()
    DREAD_FILE_NAME = enum.auto()

    def get_hashes(self) -> Tuple[Dict[str, int], Dict[int, str]]:
        if self == HashSet.DREAD_PROPERTY:
            return dread_data.all_name_to_property_id(), dread_data.all_property_id_to_name()
        elif self == HashSet.DREAD_FILE_NAME:
            return dread_data.all_name_to_asset_id(), dread_data.all_asset_id_to_name()
        else:
            raise ValueError("Unknown")


class CRCAdapter(construct.Adapter):
    known_hashes: Dict[str, int]
    inverted_hashes: Dict[int, str]

    def __init__(self, hash_set: HashSet, allow_unknowns=False, display_warnings=True):
        super().__init__(construct.Hex(construct.Int64ul))
        self._raw_subcon = construct.Int64ul
        self.hash_set = hash_set
        self.known_hashes, self.inverted_hashes = hash_set.get_hashes()
        self.allow_unknowns = allow_unknowns
        self.display_warnings = display_warnings

    def _decode(self, obj: int, context, path):
        try:
            return self.inverted_hashes[obj]
        except KeyError:
            msg = "no mapping for 0x{:8X} ({})".format(obj, obj.to_bytes(8, "little"))
            if self.allow_unknowns:
                if self.display_warnings:
                    warnings.warn(UserWarning(msg))
                return obj
            raise construct.MappingError(
                "parsing failed, " + msg,
                path=path,
            )

    def _encode(self, obj: str | int, context, path):
        try:
            return self.known_hashes[obj]
        except KeyError:
            msg = f"no mapping for {obj}"
            if self.allow_unknowns:
                if self.display_warnings:
                    warnings.warn(UserWarning(msg))
                if isinstance(obj, int):
                    return obj
                else:
                    return crc.crc64(obj)

            raise construct.MappingError(
                "building failed, " + msg,
                path=path
            )

    def _emitparse(self, code: construct.CodeGen):
        n = self.hash_set.name
        code.append("from mercury_engine_data_structures.formats.property_enum import HashSet")
        code.append(f"known_hashes_{n}, inverted_hashes_{n} = HashSet.{n}.get_hashes()")

        if self.allow_unknowns:
            return f"reuse({self.subcon._compileparse(code)}, lambda key: inverted_hashes_{n}.get(key, key))"
        else:
            return f"inverted_hashes_{n}[{self.subcon._compileparse(code)}]"

    def _emitbuild(self, code: construct.CodeGen):
        if self.allow_unknowns:
            raise NotImplementedError

        n = self.hash_set.name
        code.append("from mercury_engine_data_structures.formats.property_enum import HashSet")
        code.append(f"known_hashes_{n}, inverted_hashes_{n} = HashSet.{n}.get_hashes()")

        ret: str = self._raw_subcon._compilebuild(code)
        return ret.replace(".pack(obj)", f".pack(known_hashes_{n}[obj])")


PropertyEnum = CRCAdapter(HashSet.DREAD_PROPERTY)
PropertyEnumUnsafe = CRCAdapter(HashSet.DREAD_PROPERTY, True)

FileNameEnum = CRCAdapter(HashSet.DREAD_FILE_NAME)
FileNameEnumUnsafe = CRCAdapter(HashSet.DREAD_FILE_NAME, True, False)
