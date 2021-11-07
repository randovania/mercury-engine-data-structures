import construct
from construct import Hex, Int64ul
from construct.lib import HexDisplayedInteger

from mercury_engine_data_structures.dread_data import all_property_id_to_name

PropertyEnum = construct.Enum(Hex(Int64ul), **{
    name: HexDisplayedInteger.new(property_id, "0%sX" % (2 * 8))
    for property_id, name in all_property_id_to_name().items()
})
