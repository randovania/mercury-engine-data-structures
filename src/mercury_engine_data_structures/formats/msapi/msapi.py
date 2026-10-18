from __future__ import annotations

import construct
from construct.core import (
    Const,
    Construct,
    Int32ul,
    Int64ul,
    Struct,
    Subconstruct,
    stream_size,
)
from construct.lib.containers import Container, ListContainer

from mercury_engine_data_structures.common_types import StrId, VersionAdapter
from mercury_engine_data_structures.game_check import Game


class MsapiPointer(Subconstruct):
    def __init__(self, subcon, nullable=False):
        super().__init__(Int64ul)
        self.nullable = nullable
        self.inner_type = subcon

    def _parse(self, stream, context, path):
        context._root = context._.get("_root", context)

        assert hasattr(context._root, "_structures")
        structures = context._root._structures

        offset = context._root._pointer_subcon._parse(stream, context, path)

        if offset == 0:
            if self.nullable:
                return None
            else:
                raise ValueError(
                    f"MsapiPointer of type {self.inner_type} is not nullable but encountered a null value! {path}"
                )

        if offset not in structures.keys():
            structures[offset] = (construct.evaluate(self.inner_type, context), Container())

        return structures[offset][1]

    def _build(self, obj, stream, context, path):
        context._root = context.get("_root", context)

        assert hasattr(context._root, "_build_order")
        build_order = context._root._build_order

        assert hasattr(context._root, "_pointers")
        pointers = context._root._pointers

        if obj is None:
            if self.nullable:
                context._root._pointer_subcon._build(0, stream, context, path)
                return
            else:
                raise ValueError(
                    f"MsapiPointer of type {self.inner_type} is not nullable but is building a None value!"
                )

        curr = stream.tell()

        if id(obj) not in [id(v[0]) for v in build_order]:
            build_order.append((obj, construct.evaluate(self.inner_type, context)))

        pointers[curr] = obj
        context._root._pointer_subcon._build(0, stream, context, path)

        return curr


class StandardModelMsapi(Subconstruct):
    def __init__(
        self, magic: bytes, version: int | str | tuple[int, int, int] | None, root: Construct, target_game: Game
    ):
        super().__init__(root)
        self.magic = magic
        self.version = version

        if target_game == Game.SAMUS_RETURNS:
            self.padding_byte = b"\x00"
            self.alignment = 4
            self.pointer_subcon = Int32ul
            self.pad_strings = True
        elif target_game == Game.DREAD:
            self.padding_byte = b"\xff"
            self.alignment = 8
            self.pointer_subcon = Int64ul
            self.pad_strings = False

    def _parse(self, stream, context, path):
        context._root = context
        root = context._root
        root._pointer_subcon = self.pointer_subcon
        root._padding_byte = self.padding_byte
        root._alignment = self.alignment

        structures: dict[int, tuple[Construct, Container]] = {}
        root._structures = structures

        size = stream_size(stream)

        Const(self.magic)._parse(stream, context, path)
        ver = VersionAdapter(self.version)._parse(stream, context, path)
        root.version = ver

        # parse header subcon
        root = self.subcon._parse(stream, context, path)
        off = stream.tell()
        remaining = {k: v for k, v in structures.items() if off <= k}

        # keep parsing the structures queue until there are no items remaining
        while remaining:
            if off in structures.keys():
                r = structures[off][0]._parse(stream, context, path)
                if structures[off][0] is StrId:
                    r = Container(val=r)
                structures[off][1].update(r)  # Note: construct.Pass will cause this to fail!
                off = stream.tell()
                remaining = {k: v for k, v in structures.items() if off <= k}

            else:
                if off < size:
                    off += 1
                    stream.read(1)
                else:
                    raise ValueError(f"Structures remain, but reached EOF ({off})")

        return Container(version=ver, root=root)

    def _build(self, obj, stream, context, path):
        context._root = context
        root = context._root
        root._pointer_subcon = self.pointer_subcon
        root._padding_byte = self.padding_byte
        root._alignment = self.alignment

        build_order: list[tuple[Container, Construct]] = []
        root._build_order = build_order

        offsets: dict[int, int] = {}
        root._offsets = offsets

        pointers: dict[int, Container] = {}
        root._pointers = pointers

        Const(self.magic)._build(None, stream, context, path)
        VersionAdapter(self.version)._build(obj.version, stream, context, path)

        # build header subcon
        self.subcon._build(obj.root, stream, context, path)

        # iterate through build order, as items are added by MsapiPointer._build
        current_struct = 0
        while current_struct < len(build_order):
            (val, con) = build_order[current_struct]

            # non-strings are aligned to 8 with padding bytes
            if (cur := stream.tell() % self.alignment) != 0 and (con is not StrId or self.pad_strings):
                Const(self.padding_byte * (self.alignment - cur))._build(None, stream, context, path)

            # add this struct's starting position to offsets
            offsets[id(val)] = stream.tell()
            if con is StrId:
                val = val.val

            con._build(val, stream, context, path)
            current_struct += 1

        # seek to the pointers we have collected and write the final locations
        for off, val in pointers.items():
            stream.seek(off)
            self.pointer_subcon._build(offsets[id(val)], stream, context, path)

        return context


class LinkedList(Construct):
    """
    A linked-list of Int64ul pointers that is frequently used in the msapi formats
    """

    def node(self, subcon):
        return Struct("val" / MsapiPointer(self.el_type), "next" / subcon)

    def __init__(self, element_type):
        super().__init__()
        self.el_type = element_type

    def _parse(self, stream, context, path):
        subcon = self.node(context._root._pointer_subcon)
        res = []

        while True:
            node = subcon._parse(stream, context, path)
            res.append(node["val"])

            if node["next"] == 0:
                return Container(vals=ListContainer(res))
            elif node["next"] != stream.tell():
                # TODO tolerate non-tightly-packed lists
                raise ValueError(f"Linked List goes out of order: expected {node[1]}, got {stream.tell()}")

    def _build(self, obj, stream, context, path):
        subcon = self.node(context._root._pointer_subcon)

        for val in obj.vals[:-1]:
            node = {"val": val, "next": stream.tell() + 2 * context._root._pointer_subcon.sizeof()}
            subcon._build(node, stream, context, path)

        subcon._build({"val": obj.vals[-1], "next": 0}, stream, context, path)


class MsapiAlign(Construct):
    """
    Applies alignment in-line, using the game's standard padding byte and alignment
    """

    def __init__(self):
        super().__init__()
        self.flagbuildnone = True

    def _parse(self, stream, context, path):
        context._root = context._.get("_root", context)
        padding = context._root._padding_byte
        alignment = context._root._alignment

        if (cur := stream.tell() % alignment) != 0:
            Const(padding * (alignment - cur))._parse(stream, context, path)

    def _build(self, obj, stream, context, path):
        context._root = context._.get("_root", context)
        padding = context._root._padding_byte
        alignment = context._root._alignment

        if (cur := stream.tell() % alignment) != 0:
            Const(padding * (alignment - cur))._build(None, stream, context, path)
