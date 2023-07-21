import struct
import typing

import construct


class CompressedZSTD(construct.Tunnel):
    def __init__(self, subcon, level: int = 3):
        super().__init__(subcon)
        import zstd
        self.lib = zstd
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
            )
        )

    def _parse(self, stream, context, path) -> typing.Dict[str, int]:
        key_struct = struct.Struct("=H")
        value_struct = struct.Struct("=Q")

        count = construct.Int32un._parse(stream, None, "")

        result = {}
        for _ in range(count):
            key = stream.read(key_struct.unpack(stream.read(2))[0]).decode()
            value = value_struct.unpack(stream.read(8))[0]
            result[key] = value

        return result

    def _build(self, obj: typing.Dict[str, int], stream, context, path):
        return self._build_construct._build(list(obj.items()), stream, context, path)


KnownHashes = CompressedZSTD(HashesDict(), 15)
