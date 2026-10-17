from __future__ import annotations

import construct
from construct.core import (
    Array,
    Bytes,
    Const,
    Construct,
    Flag,
    IfThenElse,
    Int16ul,
    Int32ul,
    Int64ul,
    Pass,
    Peek,
    Rebuild,
    Struct,
)

from mercury_engine_data_structures.base_resource import BaseResource
from mercury_engine_data_structures.common_types import CVectorConstruct, Float, StrId
from mercury_engine_data_structures.formats.msapi.msapi import LinkedList, MsapiPointer, StandardModelMsapi
from mercury_engine_data_structures.game_check import Game


def JointMap(this):
    return Struct("joints" / Array(this.jointmap_count, Int32ul))


Submesh = Struct(
    "skinning_type" / Int32ul,
    "index_offset" / Int32ul,
    "index_count" / Int32ul,
    "jointmap_count" / Int32ul,
    "jointmap" / MsapiPointer(JointMap),
)


def CompressableBuffer(uncompressed, compressed) -> Construct:
    return Struct(
        _gzip_header=Peek(Int32ul),
        buf=IfThenElse(
            construct.this._gzip_header != 559903,  # gzip header
            Bytes(uncompressed),
            Bytes(compressed),
        ),
    )


Transform = Struct(
    "position" / CVectorConstruct(3),
    "rotation" / CVectorConstruct(3),
    "scale" / CVectorConstruct(3),
    "matrix" / Float[16],
)

Joint = Struct(
    "transform" / MsapiPointer(Transform),
    "name" / MsapiPointer(StrId),
    "parent_name" / MsapiPointer(StrId, nullable=True),
    "used_for_skinning" / Flag,
)

VertexInfo = Struct(
    "semantic" / Int32ul,
    "start" / Int32ul,
    "data_type" / Const(3, Int16ul),
    "count" / Int16ul,
    Const(0, Int32ul),
)

IndexData = Struct(
    Const(0, Int64ul),  # pointer?
    Const(2, Int16ul),  # data type?
    Const(1, Int16ul),
    "index_count" / Int32ul,
    "compressed_size" / Int32ul,
    Const(b"\xff\xff\xff\xff"),
    "buffer" / MsapiPointer(lambda this: CompressableBuffer(this.index_count * 2, compressed=this.compressed_size)),
)

VertexData = Struct(
    "ptr1_null" / MsapiPointer(Int64ul, nullable=True),  # always null, seems to be a pointer based on MSR sizes
    "unk1" / Const(0, Int32ul),
    "size" / Int32ul,
    "count" / Int32ul,
    "compressed_size" / Int32ul,
    "buffer" / MsapiPointer(lambda this: CompressableBuffer(this.size, this.compressed_size)),
    "_info_count" / Rebuild(Int32ul, construct.len_(construct.this.infos)),
    Const(b"\xff\xff\xff\xff"),
    "infos" / Array(construct.this._info_count, VertexInfo),
)

MeshData = Struct(
    "spatial_matrix" / Array(16, Float),
    "mesh_size" / CVectorConstruct(3),
    Const(b"\xff\xff\xff\xff"),
    "indices" / MsapiPointer(IndexData),
    "vertices" / MsapiPointer(VertexData),
    "submesh_count" / Int32ul,
    Const(b"\xff\xff\xff\xff"),
    "submeshes" / MsapiPointer(LinkedList(Submesh)),
    "translation" / CVectorConstruct(3),
)

MaterialBin0 = Struct(
    Const(0, Int32ul),
    "unk1" / Int32ul,
    "unk2" / Float[18],
    "unk3" / CVectorConstruct(4)[10],
    Const(0, Int32ul),
    Const(1, Int32ul),
    Const(2, Int32ul),
    Const(3, Int32ul),
    Const(4, Int32ul),
    Const(5, Int32ul),
    Const(6, Int32ul),
    Const(7, Int32ul),
    Const(8, Int32ul),
    Const(9, Int32ul),
)

MaterialBin1 = Struct(
    "unk0" / Flag[9],
    Const(b"\xff\xff\xff"),
    "unk1" / Int32ul[17],
    Const(255, Int32ul),
)

TextureBin = Struct(
    "unk1" / Int64ul,
    "unk2" / Int32ul,
    "unk3" / Float[5],
    "unk4" / Int32ul[2],
    "unk5" / Int64ul[3],
)

Material = Struct(
    "name" / MsapiPointer(StrId),
    "path" / MsapiPointer(StrId),
    "prefix" / MsapiPointer(StrId),
    "bin0" / MaterialBin0,
    "tex1Name" / MsapiPointer(StrId, nullable=True),
    "tex1Data" / MsapiPointer(TextureBin, nullable=True),
    "tex2Name" / MsapiPointer(StrId, nullable=True),
    "tex2Data" / MsapiPointer(TextureBin, nullable=True),
    "tex3Name" / MsapiPointer(StrId, nullable=True),
    "tex3Data" / MsapiPointer(TextureBin, nullable=True),
    "bin1" / MaterialBin1,
)

MeshName = Struct(
    "name" / MsapiPointer(StrId),
    "visible" / Flag,
)

MeshInfo = Struct(
    "mesh" / MsapiPointer(MeshData),
    "material" / MsapiPointer(Material),
    "name" / MsapiPointer(MeshName, nullable=True),
    "visible" / Flag,
    Const(b"\xff\xff\xff\x00\x00\x00\x00"),
)


def JointDeformFlags(this):
    return LinkedList(Struct("_header" / Const(4777532174063007314, Int64ul), "values" / Flag[this.count]))


JointData = Struct(
    "count" / Rebuild(Int32ul, construct.len_(construct.this.joints.vals)),
    Const(b"\xff\xff\xff\xff"),
    "joints" / MsapiPointer(LinkedList(Joint)),
    "deforming_flags" / MsapiPointer(JointDeformFlags, nullable=True),
)


ModelVar = Struct(
    "name" / MsapiPointer(StrId),
    "val" / Float,
)

BcmdlHeader = Struct(
    "vertices" / MsapiPointer(LinkedList(VertexData)),
    "indices" / MsapiPointer(LinkedList(IndexData)),
    "meshes" / MsapiPointer(LinkedList(MeshData)),
    "materials" / MsapiPointer(LinkedList(Material)),
    "meshinfos" / MsapiPointer(LinkedList(MeshInfo)),
    "meshnames" / MsapiPointer(LinkedList(MeshName), nullable=True),
    "transforms" / MsapiPointer(LinkedList(Transform)),
    "joints" / MsapiPointer(JointData),
    "variables" / MsapiPointer(LinkedList(ModelVar), nullable=True),
    "lookup_tables" / MsapiPointer(Pass, nullable=True),  # TODO implement Struct9
)


class Bcmdl(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        if target_game == Game.DREAD:
            return StandardModelMsapi(b"MMDL", "1.58.0", BcmdlHeader, target_game)
        else:
            raise NotImplementedError(f"BCMDL format has not been implemented for game {target_game}")

    def change_material_path(self, mat_name: str, new_path: str) -> None:
        for mat in self.raw.root.materials.vals:
            if mat.name.val == mat_name:
                mat.path.val = new_path
                return

        raise ValueError(
            f"Material name {mat_name} not found in model! "
            "Ensure you are using the material's name rather than its path."
        )
