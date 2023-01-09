import construct
from construct import Construct, Container
from construct.core import (
    Array, Byte, Const, Construct, Flag, Float32l, Hex, Int16ul, Int32ul, Int64ul, PrefixedArray, Struct, Switch, If, IfThenElse
)

from mercury_engine_data_structures.formats import BaseResource, standard_format
from mercury_engine_data_structures.game_check import Game
from mercury_engine_data_structures.common_types import make_vector, CVector2D, CVector4D, Float, StrId

### A ton of barely-understood structs :]

Struct0_inner = Struct(
    unk0 = Int32ul, # 0-4
    unk1 = Int32ul, # any
    unk2 = Int32ul  # 0-4
)

# ???
Struct0 = Struct(
    unk0 = PrefixedArray(Int32ul, Int32ul),
    unk1 = PrefixedArray(Int32ul, Struct0_inner),
)

# ?
Struct1 = Struct(
    unk0 = Int32ul,
    unk1 = CVector2D,
    unk2 = CVector2D
)

# a path that an entity can take... i think
NavigablePath = Struct(
    name = StrId,
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
    name = StrId,
    elements = Int32ul,
    el1 = EmmyZone_inner,
)

# a specific traversal (ie "emmi can swing across this gap")
Traversal = Struct(
    unk0 = Array(4, Int32ul), # weird shit
    unk4 = Array(4, Float), # seem to be positions
    unk6 = Array(6, Float), # seem to be angles
    unk12 = StrId,
    unk13 = StrId,
    action_name = StrId, # specific action in the bmslink
    unk14 = Flag,
    unk15 = Float,
    unk16 = Float,
    _unk17 = PrefixedArray(Int32ul, Int32ul), # i think this is nodes?
    _unk18 = PrefixedArray(Int32ul, CVector2D), # these might also be nodes but i just used vectors since its easier
    _unk19 = PrefixedArray(Int32ul, CVector2D),
    _unk20 = PrefixedArray(Int32ul, CVector2D),
    unk21 = Flag,
    unk22 = Flag,
    unk23 = Float,
)

# another prefixed array with an unknown parameter. I think maybe this is done based on the area/room the emmy is in?
EmmyAreaTraversal = Struct(
    unk0 = Int32ul,
    actions = PrefixedArray(Int32ul, Traversal)
)

# emmy-specific traversal (ie where they can hop up on ceilings). includes a bmslink reference and refers to specific actions. 
EmmyTraversals = Struct(
    name = StrId,
    bmslink = StrId,
    traversals = PrefixedArray(Int32ul, EmmyAreaTraversal)
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
    sName = StrId,
    actions = PrefixedArray(Int32ul, PrefixedArray(Int32ul, PropActions))
)

# a parameter for actor. seems to be sublayers of the navmesh. 
Actor_unk1_param = Struct(
    sName = StrId,
    unk = Int32ul
)

# info on an actor
Actor = Struct(
    name = StrId,
    unk0 = Byte,
    unk1 = PrefixedArray(Int32ul, Actor_unk1_param),
    unk2 = Byte, # these three are either 00 00 FF or XX 00 YY, where the actor is in tile group XX as the YYth entry
    unk3 = Byte,
    unk4 = Byte,
    coordinates = CVector2D,
    nodes = PrefixedArray(Int32ul, Int32ul),
)

BMSNAV = Struct(
    _magic = Const(b'MNAV'),
    version = Const(0x00030002, Hex(Int32ul)),
    navmesh_nodes = make_vector(CVector2D), # giant list of all of the navmesh nodes in the scenario. referenced by index all over the rest of the format. 
    unk0 = PrefixedArray(Int32ul, Struct0), # maybe mapping the node connections?
    unk1 = PrefixedArray(Int32ul, Struct1), # seems like these contain bounding boxes of some sort
    navigable_paths = PrefixedArray(Int32ul, NavigablePath), # contains additional paths for certain enemies (ie chozo soldiers)
    emmy_zones = PrefixedArray(Int32ul, EmmyZone), # references "LS_EmmyZone"
    unk_arr = PrefixedArray(Int32ul, Int32ul), # i suspect this is an array but not sure
    emmy_actions = PrefixedArray(Int32ul, EmmyTraversals), # seems to contain additional emmi navigation methods, and links to bmslink.
    props = PrefixedArray(Int32ul, Prop), # seems to change emmi animations around specific props (ie water button)
    actors = PrefixedArray(Int32ul, Actor) # info on actors' navmeshes
    # there's more stuff at the end that i havent finished yet :upside_down:
)

class Bmsnav(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BMSNAV