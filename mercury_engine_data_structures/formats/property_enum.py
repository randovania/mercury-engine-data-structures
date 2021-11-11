from typing import Dict

import construct

from mercury_engine_data_structures import dread_data


class CRCAdapter(construct.Adapter):
    def __init__(self, subcon, known_hashes: Dict[str, int]):
        super().__init__(subcon)
        self.known_hashes = known_hashes
        self.inverted_hashes = {value: name for name, value in known_hashes.items()}

    def _decode(self, obj, context, path):
        try:
            return self.inverted_hashes[obj]
        except KeyError:
            raise construct.MappingError("parsing failed, no mapping for %r" % (hex(obj),), path=path)

    def _encode(self, obj, context, path):
        try:
            return self.known_hashes[obj]
        except KeyError:
            raise construct.MappingError("building failed, no mapping for %r" % (obj,), path=path)


PropertyEnum = CRCAdapter(construct.Hex(construct.Int64ul), dread_data.all_name_to_property_id())
