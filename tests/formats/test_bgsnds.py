from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures.formats.bgsnds import Bgsnds


def test_bgsnds(dread_file_tree):
    parse_build_compare_editor(Bgsnds, dread_file_tree, "system/snd/guisoundevents.bgsnds")
