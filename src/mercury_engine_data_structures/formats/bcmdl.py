import construct
from construct.core import (
    Array,
    Byte,
    Bytes,
    Const,
    Construct,
    Container,
    Flag,
    GreedyBytes,
    Hex,
    If,
    IfThenElse,
    Int16ul,
    Int32sl,
    Int32ul,
    Int64ul,
    ListContainer,
    Peek,
    Pointer,
    RepeatUntil,
    Struct,
    Tell,
    stream_seek,
)

from mercury_engine_data_structures.common_types import Float, StrId
from mercury_engine_data_structures.formats import BaseResource
from mercury_engine_data_structures.game_check import Game

# Partial implementation to generate material variants
# Based off Joschuka's MMDL implementation in Noesis
# https://github.com/Joschuka/fmt_mmdl/blob/main/fmt_mmdl.py

# prints a pointer's hex value in containers, to make finding it in a binary easier
Ptr = Hex(Int64ul)

# pad 0xFF bytes to an offset of 8
PadTo8B = Struct(
    _cur_pos=Tell,
    padding=construct.Padding((8 - construct.this._cur_pos) % 8, pattern=b'\xff')
)

# an entry in a linked-list typically pointed to by TOC.
# next entry should be whats pointed to but in practice all the entries are contiguous
# so we just need to break when next==0
TOC_subentry = Struct(
    ptr=Ptr,
    next=Ptr
)

# info on a section of the decompressed vertex buffer
# example, semantic=0, offset=0x48, count=7 means starting from buffer+0x48, read 7 XYZ positions
# a little complex in context, see below
# https://github.com/Joschuka/fmt_mmdl/blob/c8c2ff9f10d95c6d4eedbbe45abea9dd535cf22e/fmt_mmdl.py#L695
Vertex_Info_entry = Struct(
    semantic=Int32ul,  # 0-8, controls different things (0=vert positions, 1=vert normals, etc)
    offset=Int32ul,  # the offset from the start of decompressed Vert_Buffer
    data_type=Int16ul,  # always 3?
    count=Int16ul,  # number of entries
    unk=Int32ul
).compile()

# vertex buffer
Vert_Buffer = Struct(
    _gzip_header=Peek(Int32ul),
    buf=IfThenElse(
        construct.this._gzip_header != 559903,  # gzip header
        Bytes(construct.this._.buffer_size),
        Bytes(construct.this._.comp_size)  # TODO inflate this and have it correctly deflate
    ),
    _padding=PadTo8B
)

# vertex info and buffer ptr
Vertex_Info = Struct(
    ptr=Hex(Tell),
    unk0=Array(3, Int32ul),
    buffer_size=Int32ul,
    count=Int32ul,
    comp_size=Int32ul,
    buffer_offset=Ptr,
    info_count=Int32ul,
    const0=Const(-1, Int32sl),
    infos=Array(construct.this.info_count, Vertex_Info_entry),
    verts=Pointer(construct.this.buffer_offset, Vert_Buffer)
).compile()

# triangle(?) buffer
Tri_Buffer = Struct(
    _gzip_header=Peek(Int32ul),
    buf=IfThenElse(
        construct.this._gzip_header != 559903,
        Bytes(construct.this._.idx_count * 2),
        Bytes(construct.this._.comp_size)  # TODO inflate and have it correctly deflate
    ),
    _padding=PadTo8B
)

# Triangle info(?) and buffer ptr
Tri_Info = Struct(
    ptr=Tell,
    _const0=Const(0, Int64ul),
    _data_type_maybe=Const(2, Int16ul),
    _count_maybe=Const(1, Int16ul),
    idx_count=Int32ul,  # if uncompressed, buffer size idx_count * 2
    comp_size=Int32ul,  # if compressed, buffer size comp_size
    const1=Const(-1, Int32sl),
    _tri_buffer_offset=Ptr,
    tri_buffer_offset=Pointer(construct.this._tri_buffer_offset, Tri_Buffer)
).compile()

# submesh info(?) pointed to by TOC2_entry._submesh_info_offsets_ptr
submesh_info = Struct(
    ptr=Tell,
    skinning_type=Int32ul,
    index_offset=Int32ul,
    index_count=Int32ul,
    jMapEntryCount=Int32ul,
    jMapOffset=Ptr,
    jMap=Pointer(construct.this.jMapOffset, Array(construct.this.jMapEntryCount, Int32ul))
).compile()

# TOC2 entry, noe plugin thinks its submesh
TOC2_entry = Struct(
    ptr=Hex(Tell),
    unk0=Array(19, Float),
    const0=Const(-1, Int32sl),
    tris=Ptr,  # VertInfo
    verts=Ptr,  # TriInfo
    submesh_count=Int32ul,
    const1=Const(-1, Int32sl),
    _submesh_info_offsets_ptr=Ptr,  # submeshInfoOffsets in noe plugin
    transform=Array(3, Float),
    const2=Const(-1, Int32sl)
).compile()

# string padded with 0xFF bytes until an offset of 8
Padded_String = Struct(
    str=StrId,
    _cur_pos=Tell,
    _padding=construct.Padding((8 - construct.this._cur_pos) % 8, pattern=b'\xff'),
)

# material entry
MAT_entry = Struct(
    ptr=Tell,
    _name_ptr=Ptr,  # material name, "mp_fxhologram_01"
    _path_ptr=Ptr,  # path to material, "actors/props/.../mat.bsmat"
    _unk_ptr=Ptr,  # empty string?
    name=Pointer(construct.this._name_ptr, StrId),
    path=Pointer(construct.this._path_ptr, StrId),
    unk0=Pointer(construct.this._unk_ptr, StrId),
    _unk_region=Bytes(0x118),
    _bc=Ptr,  # FF-padded str
    _bc_datregion=Ptr,  # 64bytes
    _nm=Ptr,  # FF-padded str
    _nm_datregion=Ptr,  # 64bytes
    _at=Ptr,  # FF-padded str
    _at_datregion=Ptr,  # 64bytes
    _unk=Bytes(0x58),
    base_color_tex=Pointer(construct.this._bc, Padded_String),
    normal_tex=Pointer(construct.this._nm, Padded_String),
    attribute_tex=Pointer(construct.this._at, Padded_String),
    _bcdat=Pointer(construct.this._bc_datregion, Array(16, Int32ul)),
    _nmdat=Pointer(construct.this._nm_datregion, Array(16, Int32ul)),
    _atdat=Pointer(construct.this._at_datregion, Array(16, Int32ul)),
).compile()

# mesh entry
MESH_entry = Struct(
    ptr=Tell,
    SUBMESH_ptr=Ptr,  # points to TOC2_entry, the noe plugin thinks its submesh
    MAT_ptr=Ptr,  # points to MAT_entry
    MESHNAME_ptr=Ptr,  # points to MESHNAME_entry
    visible=Flag,
    _remainder=Array(7, Byte)
).compile()

# mesh name, also controls whether mesh is visible
MESHNAME_entry = Struct(
    ptr=Tell,
    _name=Ptr,
    name=Pointer(construct.this._name, Padded_String),
    visible=Flag,
    _remainder=Array(7, Byte),
).compile()

# TOC6 entry, unknown
TOC6_entry = Struct(
    ptr=Tell,
    unk0=Array(25, Float),
    const0=Const(-1, Int32sl),
).compile()

# used in joints
transform = Struct(
    start=Hex(construct.Tell),
    pos=Array(3, Float),
    rot=Array(3, Float),
    scale=Array(3, Float)
).compile()

# joint TOC entry
joint_entry = Struct(
    ptr=Tell,
    _transform=Ptr,
    _name_ptr=Ptr,
    _parent_name_ptr=Ptr,
    _unk=Int64ul,
    name=Pointer(construct.this._name_ptr, Padded_String),
    parent=If(
        construct.this._parent_name_ptr != 0,
        Pointer(construct.this._parent_name_ptr, Padded_String)
    ),
    transform=Pointer(construct.this._transform, transform)
).compile()

# joints TOC since it's not a linked-list
JOINTS = Struct(
    num_joints=Int32ul,
    _const0=Const(-1, Int32sl),
    joints_toc=Ptr,
    joints_toc_2=Ptr,  # only used in a few models, seems to be some sort of flag for each joint
).compile()

# unsure what this is and rarely used :P fortunately easy to parse tho
TOC8_entry = Struct(
    ptr=Tell,
    ptr_name=Ptr,
    name=Pointer(construct.this.ptr_name, Padded_String),
    rest=Int64ul,
).compile()

# pointed to by TOC9_info
toc9_subinfo = Struct(
    unk0=Int32ul,
    unk1=Int32ul,
    unk2=Int32ul,
    unk3=Int32ul,
    unk4=Float,
    const0=Const(-1, Int32sl),
    unk5=Ptr,  # if unk0 != 0 seems to point to something
).compile()

# TOC9 info entry (unsure of name or use).
# BUG: either pointer can be null, and size can be one or two.
TOC9_info = Struct(
    ptr0=Ptr,
    ptr0_ref=If(
        construct.this.ptr0 != 0,
        Pointer(construct.this.ptr0, toc9_subinfo)
    ),
    ptr1=Ptr,
    ptr1_ref=If(
        construct.this.ptr1 != 0,
        Pointer(construct.this.ptr1, toc9_subinfo)
    )
).compile()

# wrapper struct that takes a pointer and parses a TOC9_info if it's nonzero
TOC9_info_ptr = Struct(
    ptr=Ptr,
    ref=If(
        construct.this.ptr != 0,
        Pointer(construct.this.ptr, TOC9_info)
    )
).compile()

# entry for TOC9.
TOC9_entry = Struct(
    ptr=Tell,
    mat_ptr=Ptr,
    unk_ptr=Ptr,
    unk_ptr_contents=Pointer(construct.this.unk_ptr, Padded_String),
    unk0=Int32ul,
    unk1=Int32ul,
    unk2=Float,
    unk3=Int32ul,
    unk4=Int32ul,
    const0=Const(-1, Int32sl),
    toc9_info1=TOC9_info_ptr,
    toc9_info2=TOC9_info_ptr,
    toc9_info3=TOC9_info_ptr,
).compile()

# Linked-list TOC. Always seems to be in sequence so we can use the "hack" of just repeating until next=0.
Sub_TOC = Struct(
    ptr=Tell,
    subtoc_entries=RepeatUntil(construct.obj_.next == 0, TOC_subentry)
).compile()


# Main table of contents, always offset 0x8-0x57
TOC = Struct(
    vertex_info_offset=Ptr,
    tri_info_offset=Ptr,
    submeshes_offset=Ptr,
    materials_offset=Ptr,
    meshes_offset=Ptr,
    mesh_names_offset=Ptr,
    offset_6=Ptr,
    joints_offset=Ptr,
    offset_8=Ptr,
    offset_9=Ptr,
)

Header = Struct(
    _magic=Const(b"MMDL"),
    _ver=Const(0x003A0001, Hex(Int32ul)),

    toc=TOC,
).compile()


class Mdl(Construct):
    # NOTE: Current status of parsing/building
    # - Can parse most assets, but not ones with TOC9 which is... complicated.
    # - Can build with new material files, but the material's path (name) must be
    #   equal or shorter length as its original path.
    # - The above is theoretically true with other fields but may cause unintended behavior
    # - Can rebuild files that it can parse to source without modifications

    # NOTE: data types are stored in order (ie TOCs, then VertexInfos, etc) and pointers point
    # towards each asset (i.e. MESH_entry has a pointer to its MAT_entry).
    # TODO: add a dict of pointers that can be added/updated to allow changes in length of sections

    def _parse(self, stream, context, path):
        # parse header and TOC
        header = Header._parsereport(stream, context, f"{path} -> header")

        sub_tocs = Container()
        for key, val in header.toc.items():
            # skip these two keys, _io breaks this and joints_offset has to be handled differently
            # probably should be for key in [list_of_keys] but those names are *very* up for
            # debate as I learn more about the format - TOC6, TOC8, TOC9 are not understood at all.
            if key in ["_io", "joints_offset"]:
                continue

            if val == 0:
                # mainly for TOC8/TOC9
                continue

            stream_seek(stream, val, 0, path)
            sub_tocs[key] = Sub_TOC._parsereport(stream, context, f"{path} -> {key}")

        # store data in vert buffer entries
        vertex_info = ListContainer()
        for cont in sub_tocs.vertex_info_offset.subtoc_entries:
            stream_seek(stream, cont.ptr, 0, path)
            vertex_info.append(Vertex_Info._parsereport(stream, context, f"{path} -> vertex_info"))

        # vertex buffers
        for cont in vertex_info:
            stream_seek(stream, cont.buffer_offset, 0, f"{path} -> vertex_buffer")
            buf_header = Peek(Int64ul)._parsereport(stream, context, path)
            if buf_header != 559903:
                cont._buffer = Bytes(cont.buffer_size)
            else:
                cont._buffer = Bytes(cont.comp_size)
                # TODO add proper compress/decompress for vert editing
                # parsing and building changes the number of bytes

                # FixedSized(
                #     cont.comp_size,
                #     Compressed(
                #         FixedSized(cont.buffer_size, GreedyBytes),
                #         "gzip",
                #         level=9
                #     )
                # )._parsereport(stream, context, f"{path} -> vertex_bufs")

        # store data in vert tri entries
        tri_info = ListContainer()
        for cont in sub_tocs.tri_info_offset.subtoc_entries:
            stream_seek(stream, cont.ptr, 0, path)
            tri_info.append(Tri_Info._parsereport(stream, context, f"{path} -> tri_info"))

        # tri buffers
        tri_buffers = ListContainer()
        for cont in tri_info:
            stream_seek(stream, cont._tri_buffer_offset, 0, path)
            buf_header = Peek(Int64ul)._parsereport(stream, context, path)
            if buf_header != 559903:
                cont._buffer = Bytes(cont.idx_count * 2)
            else:
                cont._buffer = Bytes(cont.comp_size)

        # submeshes? TOC3
        submeshes = ListContainer()
        for cont in sub_tocs.submeshes_offset.subtoc_entries:
            stream_seek(stream, cont.ptr, 0, path)
            submeshes.append(TOC2_entry._parsereport(stream, context, f"{path} -> submeshes"))

        submesh_info_tocs = ListContainer()
        for cont in submeshes:
            stream_seek(stream, cont._submesh_info_offsets_ptr, 0, path)
            submesh_info_tocs.append(Sub_TOC._parsereport(stream, context, f"{path} -> submeshes -> TOC"))

        for smit in submesh_info_tocs:
            smit.submesh_infos = ListContainer()
            for cont in smit.subtoc_entries:
                stream_seek(stream, cont.ptr, 0, path)
                smit.submesh_infos.append(submesh_info._parsereport(stream, context,
                                                                    f"{path} -> submeshes -> TOC -> infos"))

        # materials
        materials = ListContainer()
        for cont in sub_tocs.materials_offset.subtoc_entries:
            stream_seek(stream, cont.ptr, 0, path)
            materials.append(MAT_entry._parsereport(stream, context, f"{path} -> materials"))

        # meshes
        meshes = ListContainer()
        for cont in sub_tocs.meshes_offset.subtoc_entries:
            stream_seek(stream, cont.ptr, 0, path)
            meshes.append(MESH_entry._parsereport(stream, context, f"{path} -> meshes"))

        # mesh names
        mesh_names = ListContainer()
        if header.toc.mesh_names_offset != 0:
            for cont in sub_tocs.mesh_names_offset.subtoc_entries:
                stream_seek(stream, cont.ptr, 0, path)
                mesh_names.append(MESHNAME_entry._parsereport(stream, context, f"{path} -> mesh_names"))

        # toc6
        toc6 = ListContainer()
        for cont in sub_tocs.offset_6.subtoc_entries:
            stream_seek(stream, cont.ptr, 0, path)
            toc6.append(TOC6_entry._parsereport(stream, context, f"{path} -> TOC6"))

        # toc8
        toc8 = ListContainer()
        if header.toc.offset_8 != 0:
            for cont in sub_tocs.offset_8.subtoc_entries:
                stream_seek(stream, cont.ptr, 0, path)
                toc8.append(TOC8_entry._parse(stream, context, f"{path} -> TOC8"))

        # toc9
        toc9 = ListContainer()
        # if header.toc.offset_9 != 0:
        #     for cont in sub_tocs.offset_9.subtoc_entries:
        #         stream_seek(stream, cont.ptr, 0, path)
        #         toc9.append(TOC9_entry._parse(stream, context, f"{path} -> TOC9"))

        # joints
        stream_seek(stream, header.toc.joints_offset, 0, path)
        joints_info = JOINTS._parsereport(stream, context, f"{path} -> joints_info")
        stream_seek(stream, joints_info.joints_toc, 0, path)
        joints_toc = Sub_TOC._parsereport(stream, context, f"{path} -> joints -> TOC")

        joint_data_struct = Struct(
            header=Const(4777532174063007314, Int64ul),
            data=Array(joints_info.num_joints, Flag),
            _padding=PadTo8B,
        )

        if joints_info.joints_toc_2 != 0:
            stream_seek(stream, joints_info.joints_toc_2, 0, path)
            joints_toc_2 = Sub_TOC._parsereport(stream, context, f"{path} -> joints -> TOC2")

            for joint in joints_toc_2.subtoc_entries:
                stream_seek(stream, joint.ptr, 0, path)
                joint.data = joint_data_struct._parse(stream, context, f"{path} -> joints -> joint")
        else:
            joints_toc_2 = 0

        for joint in joints_toc.subtoc_entries:
            stream_seek(stream, joint.ptr, 0, path)
            joint.data = joint_entry._parse(stream, context, f"{path} -> joints -> joint")

        # HACK: this padding is really weird, should be understood/fixed.
        # seems to pad to 0x8 offset between entries, except for the final one.
        jMap_head_ptr = submesh_info_tocs[0].submesh_infos[0].jMapOffset
        stream_seek(stream, jMap_head_ptr, 0, path)
        jmap_data = Struct(ptr=Tell, data=GreedyBytes)._parse(stream, context, f"{path} -> joints -> jmap")

        return Container(
            header=header,
            sub_tocs=sub_tocs,
            vertex_info=vertex_info,
            tri_info=tri_info,
            _tri_bufs=tri_buffers,
            submeshes=submeshes,
            submesh_info_tocs=submesh_info_tocs,
            materials=materials,
            meshes=meshes,
            mesh_names=mesh_names,
            toc6=toc6,
            joints_info=joints_info,
            joints_toc=joints_toc,
            joints_toc_2=joints_toc_2,
            jmap_data=jmap_data,
            toc8=toc8,
            toc9=toc9,
        )

    def _build(self, obj, stream, context, path):
        # build header/main toc
        Header._build(obj.header, stream, context, f"{path} -> header")

        # build all sub tocs
        for key, val in obj.sub_tocs.items():
            if key in ["_io", "joints_offset", "offset_8", "offset_9"]:
                continue
            Sub_TOC._build(val, stream, context, f"{path} -> {key}_TOC")

        JOINTS._build(obj.joints_info, stream, context, f"{path} -> joints_TOC")

        # if offset8 is there build it
        if obj.header.toc.offset_8:
            Sub_TOC._build(obj.sub_tocs.offset_8, stream, context, f"{path} -> offset_8_TOC")

        if obj.header.toc.offset_9:
            Sub_TOC._build(obj.sub_tocs.offset_9, stream, context, f"{path} -> offset_9_TOC")

        # build vert_info entries
        for vi in obj.vertex_info:
            Vertex_Info._build(vi, stream, context, f"{path} -> vertex_info")

        # build tri_info entries
        for ti in obj.tri_info:
            Tri_Info._build(ti, stream, context, f"{path} -> tri_info")

        # build submesh/toc2 entries
        for t2 in obj.submeshes:
            TOC2_entry._build(t2, stream, context, f"{path} -> submeshes")

        # build mat entries
        for mat in obj.materials:
            MAT_entry._build(mat, stream, context, f"{path} -> materials")

        # build meshes entries
        for mesh in obj.meshes:
            MESH_entry._build(mesh, stream, context, f"{path} -> meshes")

        # build meshname entries
        for meshname in obj.mesh_names:
            MESHNAME_entry._build(meshname, stream, context, f"{path} -> mesh_names")

        # build toc6 entries
        for toc6 in obj.toc6:
            TOC6_entry._build(toc6, stream, context, f"{path} -> toc6")

        # build joints entry
        curr = Tell._build(obj, stream, context, path)
        stream_seek(stream, obj.joints_info.joints_toc, 0, path)
        Sub_TOC._build(obj.joints_toc, stream, context, f"{path} -> joints -> TOC")
        if obj.joints_info.joints_toc_2 != 0:
            stream_seek(stream, obj.joints_info.joints_toc_2, 0, path)
            Sub_TOC._build(obj.joints_toc_2, stream, context, f"{path} -> joints -> TOC2")
        stream_seek(stream, curr, 0, path)

        # build joint_infos
        for joint in obj.joints_toc.subtoc_entries:
            stream_seek(stream, joint.ptr, 0, path)
            joint_entry._build(joint.data, stream, context, f"{path} -> joints -> TOC -> entry")
        if obj.joints_info.joints_toc_2 != 0:
            for joint in obj.joints_toc_2.subtoc_entries:
                stream_seek(stream, joint.ptr, 0, path)
                Struct(
                    header=Const(4777532174063007314, Int64ul),
                    data=Array(obj.joints_info.num_joints, Flag),
                    _padding=PadTo8B,
                )._build(joint.data, stream, context, f"{path} -> joints -> TOC2 -> entry")

        # build toc8
        for t8 in obj.toc8:
            stream_seek(stream, t8.ptr, 0, path)
            TOC8_entry._build(t8, stream, context, f"{path} -> toc8 -> entry")

        # build toc9
        for t9 in obj.toc9:
            stream_seek(stream, t9.ptr, 0, path)
            TOC9_entry._build(t9, stream, context, f"{path} -> toc9 -> entry")

        # build submesh_info
        curr = Tell._build(obj, stream, context, path)
        for sub in obj.submesh_info_tocs:
            stream_seek(stream, sub.ptr, 0, path)
            Sub_TOC._build(sub, stream, context, f"{path} -> submeshes -> TOCs")

            for subinfo in sub.submesh_infos:
                stream_seek(stream, subinfo.ptr, 0, path)
                submesh_info._build(subinfo, stream, context, f"{path} -> submeshes -> infos")
        stream_seek(stream, curr, 0, path)

        # correct jmap
        stream_seek(stream, obj.jmap_data.ptr, 0, path)
        GreedyBytes._build(obj.jmap_data.data, stream, context, f"{path} -> jMap")


BCMDL = Mdl()


class Bcmdl(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BCMDL

    def change_material_path(self, mat_name: str, new_path: str) -> None:
        for mat in self.raw.materials:
            if mat.name == mat_name:
                if len(new_path) <= len(mat.path):
                    mat.path = new_path
                    return
                else:
                    raise ValueError(f"Material path {new_path} is longer than original path {mat.path}!")
        raise ValueError(f"Material name {mat_name} not found in model! "
                         "Ensure you are using the material's name rather than its path.")
