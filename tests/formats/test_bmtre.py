import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data
from mercury_engine_data_structures.formats.bmtre import Bmtre


@pytest.mark.parametrize("bmtre_path", dread_data.all_files_ending_with(".bmtre"))
def test_bmtre(dread_tree_100, bmtre_path):
    parse_build_compare_editor(Bmtre, dread_tree_100, bmtre_path)
