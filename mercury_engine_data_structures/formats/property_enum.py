from typing import Dict
import warnings

import construct

from mercury_engine_data_structures import dread_data, crc


class CRCAdapter(construct.Adapter):
    def __init__(self, subcon, known_hashes: Dict[str, int], allow_unknowns=False, display_warnings=True):
        super().__init__(subcon)
        self.known_hashes = known_hashes
        self.inverted_hashes = {value: name for name, value in known_hashes.items()}
        self.allow_unknowns = allow_unknowns
        self.display_warnings = display_warnings

    def _decode(self, obj, context, path):
        try:
            return self.inverted_hashes[obj]
        except KeyError:
            msg = "no mapping for 0x{:8X} ({})".format(obj, obj.to_bytes(8, "little"))
            if self.allow_unknowns:
                if self.display_warnings:
                    warnings.warn(UserWarning(msg))
                return obj
            raise construct.MappingError(
                "parsing failed, "+msg,
                path=path,
            )

    def _encode(self, obj, context, path):
        try:
            return self.known_hashes[obj]
        except KeyError:
            msg = f"no mapping for {obj}"
            if self.allow_unknowns:
                if self.display_warnings:
                    warnings.warn(UserWarning(msg))
                if isinstance(obj, int):
                    return obj
                else:
                    return crc.crc64(obj)

            raise construct.MappingError(
                "building failed, "+msg,
                path=path
            )


PropertyEnum = CRCAdapter(construct.Hex(construct.Int64ul), dread_data.all_name_to_property_id())
PropertyEnumUnsafe = CRCAdapter(construct.Hex(construct.Int64ul), dread_data.all_name_to_property_id(), True)

FileNameEnum = CRCAdapter(construct.Hex(construct.Int64ul), dread_data.all_name_to_asset_id())
FileNameEnumUnsafe = CRCAdapter(construct.Hex(construct.Int64ul), dread_data.all_name_to_asset_id(), True, False)
