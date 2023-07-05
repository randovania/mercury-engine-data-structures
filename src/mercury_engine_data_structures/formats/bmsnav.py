import construct
from construct.core import (
    Array, Byte, Const, Construct, Flag, Hex, Int32ul, PrefixedArray, Struct, 
)

from mercury_engine_data_structures.formats import BaseResource
from mercury_engine_data_structures.game_check import Game
from mercury_engine_data_structures.common_types import make_vector, make_dict, CVector2D, CVector3D, Float, StrId

### A ton of barely-understood structs :]

# a connection from a geo's direction to another geo's
geo_connection = Struct(
    initial_direction = Int32ul, # 0-4, up-right-down-left typically. i.e. geo(0.0, 0.0).direction(1) = geo(100.0, 0.0)
    destination_geo = Int32ul,
    destination_direction = Int32ul  # see initial_direction
)

# a list of connections for a geo (essentially, the allowed directions of travel)
geo_connections = Struct(
    directions = PrefixedArray(Int32ul, Int32ul),
    connections = PrefixedArray(Int32ul, geo_connection),
)

# idk
Struct1 = Struct(
    unk0 = Int32ul,
    unk1 = CVector2D,
    unk2 = CVector2D
)

# special paths entities can take that ignore default connections (i.e. chozo robot jumps or wall-traveling enemies).
# emmi's are in a separate structure.
# hard-coded to specific entity's sName
NavigablePath = Struct(
    path = PrefixedArray(Int32ul, Int32ul)
)

EZ_Element = Struct(
    el = Int32ul,
    unk1 = PrefixedArray(Int32ul, Int32ul)
)

EmmyZone_inner = Struct(
    elements = PrefixedArray(Int32ul, EZ_Element)
)

# reference to an "LS_EmmyZone" typically
EmmyZone = Struct(
    elements = Int32ul,
    el1 = EmmyZone_inner,
)

# a specific traversal (ie "emmi can swing across this gap")
Traversal = Struct(
    unk0 = Array(4, Int32ul), # weird shit
    initial_position = CVector2D, 
    final_position = CVector2D,
    initial_rotation = CVector3D, 
    final_rotation = CVector3D,
    unk12 = StrId,
    unk13 = StrId,
    action_name = StrId, # specific action in the bmslink
    unk14 = Flag,
    unk15 = Float,
    unk16 = Float,
    _unk17 = PrefixedArray(Int32ul, Int32ul), # i think this is geos?
    _unk18 = PrefixedArray(Int32ul, CVector2D), # these might also be geos but i just used vectors since its easier
    _unk19 = PrefixedArray(Int32ul, CVector2D),
    _unk20 = PrefixedArray(Int32ul, CVector2D),
    unk21 = Flag,
    unk22 = Flag,
    unk23 = Float,
)

# another prefixed array with an unknown parameter. I think maybe this is done based on the area/room the emmy is in?
EmmyAreaTraversal = Struct(
    actions = PrefixedArray(Int32ul, Traversal)
)

# emmy-specific traversal (ie where they can hop up on ceilings). includes a bmslink reference and refers to specific actions. 
EmmyTraversals = Struct(
    bmslink = StrId,
    traversals = make_dict(EmmyAreaTraversal, Int32ul)
)

PAction = Struct(
    unk0 = Int32ul,
    action = Traversal
)

PropActions = Struct(
    name = StrId,
    bmslink = StrId,
    actions = PrefixedArray(Int32ul, PAction)
)

# actions around certain props like buttons
Prop = Struct(
    actions = PrefixedArray(Int32ul, PrefixedArray(Int32ul, PropActions))
)

# a parameter for actor. seems to be sublayers of the navmesh. 
Actor_unk1_param = Struct(
    sName = StrId,
    unk = Int32ul
)

# info on an actor
Actor = Struct(
    unk0 = Byte,
    unk1 = PrefixedArray(Int32ul, Actor_unk1_param),
    unk2 = Byte, # these three are either 00 00 FF or XX 00 YY, where the actor is TILEGROUP.uGroupId XX as TILEGROUP.aGridTiles[YY]
    unk3 = Byte,
    unk4 = Byte,
    coordinates = CVector2D,
    geos = PrefixedArray(Int32ul, Int32ul),
)

IntIntStruct = Struct(
    unk1 = Int32ul,
    unk2 = Int32ul,
)

Struct3 = Struct(
    unk1 = Int32ul,
    unk2 = Int32ul,
    unk3 = Int32ul,
    pos = CVector2D,
    unk4 = PrefixedArray(Int32ul, IntIntStruct), # seems to be a geo and an enum
)

Struct2 = Struct(
    unk0 = Int32ul,
    unk1 = PrefixedArray(Int32ul, Struct3),
)


BMSNAV = Struct(
    _magic = Const(b'MNAV'),
    version = Const(0x00030002, Hex(Int32ul)),
    aNavmeshGeos = PrefixedArray(Int32ul, CVector2D), # giant list of all of the navmesh geos in the scenario. referenced by index all over the rest of the format. 
    geo_connections = PrefixedArray(Int32ul, geo_connections), # maybe mapping the geo connections?
    unk1 = PrefixedArray(Int32ul, Struct1), # seems like these contain bounding boxes of some sort, antidote thought maybe octants
    navigable_paths = make_dict(NavigablePath), # contains additional paths for certain enemies (ie chozo soldiers)
    emmy_zones = make_dict(EmmyZone), # references "LS_EmmyZone" and maybe other logicshapes
    unk_arr = PrefixedArray(Int32ul, Int32ul), # i suspect this is an array but not used anywhere.
    emmy_actions = make_dict(EmmyTraversals), # seems to contain additional emmi navigation methods, and links to bmslink.
    props = make_dict(Prop), # seems to change emmi animations around specific props (ie water button)
    actors = make_dict(Actor), # info on actors' navmeshes
    unk2 = PrefixedArray(Int32ul, Struct2) # idk on this one
)

class Bmsnav(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BMSNAV