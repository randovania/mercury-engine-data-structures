from __future__ import annotations

from construct.core import (
    BitsInteger,
    BitStruct,
    Byte,
    ByteSwapped,
    Const,
    Construct,
    Flag,
    Int32ul,
    PrefixedArray,
    Struct,
    Terminated,
)

from mercury_engine_data_structures.base_resource import BaseResource
from mercury_engine_data_structures.common_types import (
    CVector2D,
    CVector3D,
    Float,
    StrId,
    VersionAdapter,
    make_dict,
    make_vector,
)
from mercury_engine_data_structures.game_check import Game

### A ton of barely-understood structs :]
###
### Lots of notes here because being able to regenerate with added or
### moved assets would likely reduce bugginess and lag spikes,
### as well as allow custom level geometry

### quick glossary:
### Point / Valid Point: A vertex, basically.
### Area: A navigable area defined by 3-4 Points. Prefers to be rectangles.
### Edge: The line between consecutive vertices in an Area. Areas sharing an Edge each have their own.
### Zone: A group of Areas. usually contiguous unless another actor exists there
###       i.e. each door has a Zone, each shield has a Zone, morph tunnels are Zones, rooms are Zones

# A specific edge for a specific area
# Edge i of Area a is the line between a.vertices[i] and a.vertices[i+1]
AreaEdge = Struct(
    "area" / Int32ul,
    "edge" / Int32ul,
)

# a region where the player can move and enemies can pathfind
# verts are counterclockwise and the first edge is usually the "floor"
# adjacent_edges[n] represents the nth edge's EdgeData from the other area's side
DreadArea = Struct(
    "vertices" / make_vector(Int32ul),
    "adjacent_edges" / make_dict(AreaEdge, Int32ul),
)

MSRArea = Struct(
    "unk0" / Byte,
    "unk1" / Byte,
    "unk2" / Byte,  # 0?
    "area" / DreadArea,
)

# A node in the search tree
# if the point is inside the box defined by (min, max) it goes to the next entry
# if the point is outside the box it goes to the fail_index
# leaves always correspond with the bounds of an Area and have inverse behavior,
# i.e. if it is in the bounds it accesses navmesh.areas[fail_index]
# and if it outside the bounds it goes to the next index
# TODO research how the divisions are made so we can regenerate a navmesh
SearchTreeNode = Struct(
    "test"
    / ByteSwapped(
        BitStruct(
            "on_pass" / Flag,
            "goto" / BitsInteger(31),
        )
    ),
    "min" / CVector2D,
    "max" / CVector2D,
)

# a list of aNavmeshGeos within a LogicShape from the level data
LogicShapeValidPoints = Struct(
    "points" / make_vector(Int32ul),
)

LogicShapesEdges_Area = Struct(
    "index" / Int32ul,
    "included_edges" / make_vector(Int32ul),
)

# a list of Edges within a LogicShape from the level data
# typically used for emmi zone and LS_Forbidden
LogicShapesEdges = Struct(
    "num_edges" / Int32ul,  # TODO adapter to rebuild this
    "areas" / make_vector(LogicShapesEdges_Area),
)

# a specific traversal (ie "emmi can swing across this gap"/"yamplot can jump down here")
# naming maybe wrong, essentially a dynamic smart link rule applied to an explicit location on the mesh.
StaticSmartLink = Struct(
    "unk0" / Int32ul,  # doesn't seem to be an area/edge
    "unk1" / Int32ul,
    "end_edge" / AreaEdge,
    "initial_position" / CVector2D,
    "final_position" / CVector2D,
    "initial_rotation" / CVector3D,
    "final_rotation" / CVector3D,
    "unk12" / StrId,
    "unk13" / StrId,
    "action_name" / StrId,  # specific action in the bmslink
    "unk14" / Flag,
    "unk15" / Float,
    "unk16" / Float,
    "areas_in_link" / make_vector(Int32ul),  # all areas it passes through
    "edges_in_link" / make_vector(AreaEdge),  # same as the above, but with edges (possibly an unk instead)
    "start_areas" / make_vector(AreaEdge),  # empty or first half of above list
    "end_areas" / make_vector(AreaEdge),  # empty or second half of above list
    "unk21" / Flag,
    "unk22" / Flag,
    "unk23_maybe_weight" / Float,
)

# another prefixed array with an unknown parameter. I think maybe this is done based on the area/room the emmy is in?
SmartLinksFromArea = Struct(
    "start_area" / Int32ul,
    "links" / PrefixedArray(Int32ul, StaticSmartLink),
)

# Actor-specific SmartLink paths
DynamicSmartLinkRule = Struct(
    "source_bmslink" / StrId,  # source SmartLink file?
    "smartlinks" / make_vector(SmartLinksFromArea),
)

ZoneSmartLinkAction = Struct(
    "area" / Int32ul,
    "action" / StaticSmartLink,
)

SmartLinkRule = Struct(
    "name" / StrId,
    "bmslink" / StrId,
    "actions" / PrefixedArray(Int32ul, ZoneSmartLinkAction),
)

# actions around certain props like water
Prop = Struct(
    "actions" / PrefixedArray(Int32ul, PrefixedArray(Int32ul, SmartLinkRule)),
)

# a parameter for actor. seems to be sublayers of the navmesh.
ActorStage = Struct(
    "actor_name" / StrId,  # sometimes raw actor sometimes actor_sname_st01
    "stage_idx" / Int32ul,  # likely something to do with the collider stage stuff in bmsad?
)

# info on an actor
ZoneData = Struct(
    # guess, typically true for "small" areas where you'd be expected to morph
    # like "hidey holes" in emmi zones, or regular tunnels. though some things
    # like the "cross bomb" areas above crumbles aren't.
    "is_morph_tunnel" / Flag,
    "actor_stages" / make_vector(ActorStage),
    "tile_group_id" / Byte,  # 00 for non-tiles
    "unk3" / Const(b"\x00"),
    "tile_group_index" / Byte,  # FF for non-tiles
    "center" / CVector2D,
    "areas" / make_vector(Int32ul),
)

ZoneEdgeData = Struct(
    "zone" / Int32ul,  # "destination" zone index, the one connected to the edges
    "main_edge" / AreaEdge,  # zone the pos is in?
    "pos" / CVector2D,  # center of edge
    "all_edges" / make_vector(AreaEdge),  # all edges, including main_edge
)

ZoneEdges = Struct(
    "zone" / Int32ul,  # "source" zone, i.e. where the areas are
    "edges" / make_vector(ZoneEdgeData),
)

sr_unk_struct = Struct(
    "bound_start" / CVector2D,
    "bound_end" / CVector2D,
    "unk1" / Int32ul,
    "const0" / Int32ul,  # TODO what const?
    "unk2" / Int32ul,
    "unk3" / Int32ul,
)

BMSNAV_SR = Struct(
    "_magic" / Const(b"MNAV"),
    "version" / VersionAdapter("1.12.0"),
    "aNavmeshGeos" / PrefixedArray(Int32ul, CVector2D),
    "areas" / PrefixedArray(Int32ul, MSRArea),
    "search_tree" / PrefixedArray(Int32ul, SearchTreeNode),
    "logic_shapes" / make_dict(LogicShapeValidPoints),  # vertices in certain LS's
    "unk2" / make_dict(PrefixedArray(Int32ul, sr_unk_struct)),
    Terminated,
)

BMSNAV_DREAD = Struct(
    "_magic" / Const(b"MNAV"),
    "version" / VersionAdapter("2.3.0"),
    "points" / make_vector(CVector2D),
    "areas" / make_vector(DreadArea),
    "search_tree" / make_vector(SearchTreeNode),
    "logic_shapes_valid_points" / make_dict(LogicShapeValidPoints),  # vertices in certain LS's
    "logic_shapes_edges" / make_dict(LogicShapesEdges),  # edges in certain LS's
    "unk_arr" / make_vector(Int32ul),
    "dynamic_smartlink_rules" / make_dict(DynamicSmartLinkRule),  # likely converted from bmslink format
    "props" / make_dict(Prop),  # seems to change emmi animations around specific zones (like water)
    "zones" / make_dict(ZoneData),
    "zone_edges" / make_vector(ZoneEdges),
    Terminated,
).compile()


class Bmsnav(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return {
            Game.SAMUS_RETURNS: BMSNAV_SR,
            Game.DREAD: BMSNAV_DREAD,
        }[target_game]
