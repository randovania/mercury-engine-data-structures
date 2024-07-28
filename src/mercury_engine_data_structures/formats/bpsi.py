from construct.core import Const, Construct, Int32ul, PrefixedArray, Struct, Terminated

from mercury_engine_data_structures import game_check
from mercury_engine_data_structures.common_types import VersionAdapter
from mercury_engine_data_structures.construct_extensions.strings import PascalStringRobust
from mercury_engine_data_structures.formats.base_resource import BaseResource

BPSI = Struct(
    _magic = Const(b"MPSI"),
    version = game_check.is_sr_or_else(
        VersionAdapter("1.2.0"),
        VersionAdapter("1.3.0")
    ),
    files = PrefixedArray(Int32ul, Struct(
        file = PascalStringRobust(Int32ul, "utf-8"),
        in_packages = PrefixedArray(Int32ul, PascalStringRobust(Int32ul, "utf-8"))
    )),
    _eof=Terminated,
)

class Bpsi(BaseResource):
    @classmethod
    def construct_class(cls, target_game: game_check.Game) -> Construct:
        return BPSI
