import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data
from mercury_engine_data_structures.formats.bfstm import Bfstm


@pytest.mark.parametrize("bfstm_path", dread_data.all_files_ending_with(".bfstm"))
def test_bgsnds(dread_file_tree, bfstm_path):
    parse_build_compare_editor(Bfstm, dread_file_tree, bfstm_path)
