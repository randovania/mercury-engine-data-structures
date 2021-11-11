from construct.core import FixedSized, GreedyBytes, NullStripped, NullTerminated, Prefixed, StringEncoded, StringError, encodingunit


class StringEncodedRobust(StringEncoded):
    def _decode(self, obj, context, path):
        try:
            return super()._decode(obj, context, path)
        except UnicodeDecodeError as e:
            raise StringError(f"string decoding failed: {e}", path=path) from e

def PaddedStringRobust(length, encoding):
    r"""
    Configurable, fixed-length or variable-length string field.

    When parsing, the byte string is stripped of null bytes (per encoding unit), then decoded. Length is an integer or context lambda. When building, the string is encoded and then padded to specified length. If encoded string is larger than the specified length, it fails with PaddingError. Size is same as length parameter.

    .. warning:: PaddedStringRobust only supports encodings explicitly listed in :class:`~construct.core.possiblestringencodings` .

    :param length: integer or context lambda, length in bytes (not unicode characters)
    :param encoding: string like: utf8 utf16 utf32 ascii

    :raises StringError: building a non-unicode string
    :raises StringError: selected encoding is not on supported list
    :raises StringError: unicode decoding failed

    Can propagate any exception from the lambda, possibly non-ConstructError.

    Example::

        >>> d = PaddedStringRobust(10, "utf8")
        >>> d.build(u"Афон")
        b'\xd0\x90\xd1\x84\xd0\xbe\xd0\xbd\x00\x00'
        >>> d.parse(_)
        u'Афон'
    """
    macro = StringEncodedRobust(FixedSized(length, NullStripped(GreedyBytes, pad=encodingunit(encoding))), encoding)
    def _emitfulltype(ksy, bitwise):
        return dict(size=length, type="strz", encoding=encoding)
    macro._emitfulltype = _emitfulltype
    return macro


def PascalStringRobust(lengthfield, encoding):
    r"""
    Length-prefixed string. The length field can be variable length (such as VarInt) or fixed length (such as Int64ub). :class:`~construct.core.VarInt` is recommended when designing new protocols. Stored length is in bytes, not characters. Size is not defined.

    :param lengthfield: Construct instance, field used to parse and build the length (like VarInt Int64ub)
    :param encoding: string like: utf8 utf16 utf32 ascii

    :raises StringError: building a non-unicode string
    :raises StringError: unicode decoding failed
    

    Example::

        >>> d = PascalStringRobust(VarInt, "utf8")
        >>> d.build(u"Афон")
        b'\x08\xd0\x90\xd1\x84\xd0\xbe\xd0\xbd'
        >>> d.parse(_)
        u'Афон'
    """
    macro = StringEncodedRobust(Prefixed(lengthfield, GreedyBytes), encoding)

    def _emitparse(code):
        return f"io.read({lengthfield._compileparse(code)}).decode({repr(encoding)})"
    macro._emitparse = _emitparse

    def _emitseq(ksy, bitwise):
        return [
            dict(id="lengthfield", type=lengthfield._compileprimitivetype(ksy, bitwise)), 
            dict(id="data", size="lengthfield", type="str", encoding=encoding),
        ]
    macro._emitseq = _emitseq

    return macro

def CStringRobust(encoding):
    r"""
    String ending in a terminating null byte (or null bytes in case of UTF16 UTF32).

    .. warning:: CStringRobust only supports encodings explicitly listed in :class:`~construct.core.possiblestringencodings` .

    :param encoding: string like: utf8 utf16 utf32 ascii

    :raises StringError: building a non-unicode string
    :raises StringError: selected encoding is not on supported list
    :raises StringError: unicode decoding failed

    Example::

        >>> d = CStringRobust("utf8")
        >>> d.build(u"Афон")
        b'\xd0\x90\xd1\x84\xd0\xbe\xd0\xbd\x00'
        >>> d.parse(_)
        u'Афон'
    """
    macro = StringEncodedRobust(NullTerminated(GreedyBytes, term=encodingunit(encoding)), encoding)
    def _emitfulltype(ksy, bitwise):
        return dict(type="strz", encoding=encoding)
    macro._emitfulltype = _emitfulltype
    return macro

def GreedyStringRobust(encoding):
    r"""
    String that reads entire stream until EOF, and writes a given string as-is. Analog to :class:`~construct.core.GreedyBytes` but also applies unicode-to-bytes encoding.

    :param encoding: string like: utf8 utf16 utf32 ascii

    :raises StringError: building a non-unicode string
    :raises StreamError: stream failed when reading until EOF
    :raises StringError: unicode decoding failed

    Example::

        >>> d = GreedyStringRobust("utf8")
        >>> d.build(u"Афон")
        b'\xd0\x90\xd1\x84\xd0\xbe\xd0\xbd'
        >>> d.parse(_)
        u'Афон'
    """
    macro = StringEncodedRobust(GreedyBytes, encoding)
    def _emitfulltype(ksy, bitwise):
        return dict(size_eos=True, type="str", encoding=encoding)
    macro._emitfulltype = _emitfulltype
    return macro
