from __future__ import annotations

import struct

import construct


class CompressedZSTD(construct.Tunnel):
    def __init__(self, subcon, level: int = 3):
        super().__init__(subcon)
        import zstandard

        self.lib = zstandard
        self.level = level

    def _decode(self, data, context, path):
        return self.lib.decompress(data)

    def _encode(self, data, context, path):
        return self.lib.compress(data, self.level)


class HashesDict(construct.Construct):
    def __init__(self):
        super().__init__()
        self._build_construct = construct.PrefixedArray(
            construct.Int32un,
            construct.Sequence(
                construct.PascalString(construct.Int16un, "ascii"),  # key
                construct.Int64un,  # hash
            ),
        )

    def _parse(self, stream, context, path) -> dict[str, int]:
        key_struct = struct.Struct("=H")
        value_struct = struct.Struct("=Q")

        count = construct.Int32un._parse(stream, None, "")

        result = {}
        for _ in range(count):
            key = stream.read(key_struct.unpack(stream.read(2))[0]).decode()
            value = value_struct.unpack(stream.read(8))[0]
            result[key] = value

        return result

    def _build(self, obj: dict[str, int], stream, context, path):
        return self._build_construct._build(list(obj.items()), stream, context, path)


class VersionedHashesDict(construct.Construct):
    def __init__(self):
        super().__init__()
        self._build_construct = construct.PrefixedArray(
            construct.Int32un,
            construct.Sequence(
                construct.PascalString(construct.Int16un, "ascii"),  # key
                construct.Int64un,  # hash
                construct.Int16un,  # versions
            ),
        )

    def _parse(self, stream, context, path) -> dict[str, int]:
        key_struct = struct.Struct("=H")
        value_struct = struct.Struct("=QH")

        count = construct.Int32un._parse(stream, None, "")

        result = {}
        for _ in range(count):
            key = stream.read(key_struct.unpack(stream.read(2))[0]).decode()
            value, versions = value_struct.unpack(stream.read(10))
            result[key] = {"crc": value, "versions": versions}

        return result

    def _build(self, obj: dict[str, dict], stream, context, path):
        ver_to_val = context.versions
        all_vers = sum([v for v in ver_to_val.values()])
        for a in obj.values():
            vers = a.get("versions")
            if vers is not None:
                a["versions"] = sum([ver_to_val[v] for v in vers])
            else:
                a["versions"] = all_vers

        return self._build_construct._build(
            list([(k, v["crc"], v["versions"]) for k, v in obj.items()]), stream, context, path
        )


KnownHashes = CompressedZSTD(HashesDict(), 15)
VersionedHashes = CompressedZSTD(VersionedHashesDict(), 15)
