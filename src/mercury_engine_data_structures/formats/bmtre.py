import construct
from construct.core import (
    Array, Byte, Const, Construct, Container, Flag, Float32l, Hex, If, Int16ul, Int32ul, Int32sl, Int64ul, LazyBound, PrefixedArray, Select, Struct, Switch, IfThenElse
)

from mercury_engine_data_structures import common_types, type_lib
from mercury_engine_data_structures import game_check
from mercury_engine_data_structures.common_types import Float, StrId, make_dict, make_vector
from mercury_engine_data_structures.construct_extensions.alignment import PrefixedAllowZeroLen
from mercury_engine_data_structures.construct_extensions.misc import ErrorWithMessage
from mercury_engine_data_structures.formats import BaseResource, dread_types
from mercury_engine_data_structures.formats.property_enum import PropertyEnum
from mercury_engine_data_structures.game_check import Game

ArgumentCases = {
    'b': Flag,
    's': StrId,
    'f': Float,
    'u': Int32ul,
    'i': Int32sl,
    'e': StrId,
    'o': Int32ul,
    'v': Array(3, Float)
}

StrKeyArgument = Struct(
    key = StrId,
    val = Switch(
        construct.this.key[0],
        ArgumentCases,
        construct.Error
    )
)

CrcKeyArgument = Struct(
    key = PropertyEnum,
    val = Switch(
        construct.this.key[0],
        ArgumentCases,
        construct.Error
    )
)

Behavior = Struct(
    type = Select(PropertyEnum, Hex(Int64ul)),
    args = PrefixedArray(Int32ul, CrcKeyArgument),
    children = PrefixedArray(Int32ul, LazyBound(lambda: Behavior)),
)

BMTRE = Struct(
    _magic = Const(b"BTRE"),
    version = Const(0x00050001, Hex(Int32ul)), # for dread, unsure if it exists in SR
    args = PrefixedArray(Int32ul, StrKeyArgument),
    behavior = Behavior,
)



class Bmtre(BaseResource):
    @classmethod
    def construct_class(cls, target_game: Game) -> Construct:
        return BMTRE
    
    # private func to print a line in the pretty printer
    def _pretty_print_line(self, text: str, depth: int) -> None:
        print('    ' * depth + text)

    # private func to print a string's type and args
    def _type_and_args_string(self, behavior: Container) -> str:
        res: str = behavior.type
        if len(behavior.args) > 0:
            res += " ("
            for arg in behavior.args:
                res += f"{arg.key}={arg.val}, "
            res = res[:-2] # remove the last comma
            res += ")"
        res = res[14:] # remove "behaviortree::" from start
        return res

    # private func to pretty-print a behaviortree element
    def _pretty_print_behavior(self, behavior: Container, depth: int) -> None:
        # Repeats the behavior of its child regardless of success or failure
        if behavior.type == "behaviortree::CRepeat":
            self._pretty_print_line(f"Repeat behavior:", depth)
            self._pretty_print_behavior(behavior.children[0], depth+1)
        
        # if the first child returns success, runs the second child. otherwise runs the third child. 
        elif behavior.type ==  "behaviortree::CIf":
            self._pretty_print_line(f"If:", depth)
            self._pretty_print_behavior(behavior.children[0], depth+1)
            self._pretty_print_line("Then:", depth)
            self._pretty_print_behavior(behavior.children[1], depth+1)
            self._pretty_print_line("Else:", depth)
            self._pretty_print_behavior(behavior.children[2], depth+1)
        
        # runs children in sequence until one fails, then returns to parent
        elif behavior.type ==  "behaviortree::CSequence":
            self._pretty_print_line("Sequence:", depth)
            for child in behavior.children:
                self._pretty_print_behavior(child, depth+1)
        
        # runs children in sequence until one succeeds, then returns to parent
        elif behavior.type ==  "behaviortree::CSelector":
            self._pretty_print_line("Selector:", depth)
            for child in behavior.children:
                self._pretty_print_behavior(child, depth+1)
        
        # runs *all* children in parallel until all succeed or one fails. if one fails, it terminates all other children and returns to parent
        elif behavior.type ==  "behaviortree::CParallel":
            self._pretty_print_line("Parallel:", depth)
            for child in behavior.children:
                self._pretty_print_behavior(child, depth+1)

        else:
            self._pretty_print_line(self._type_and_args_string(behavior), depth)

    # pretty-prints the tree in a more human-readable format
    def print_tree(self) -> None:
        # print global arguments
        if len(self.raw.args) > 0:
            for arg in self.raw.args:
                self._pretty_print_line(f"{arg.key} = {arg.val}", 0)

        # print behaviors
        self._pretty_print_behavior(self.raw.behavior, 0)