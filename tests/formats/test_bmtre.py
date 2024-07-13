import pytest
from tests.test_lib import parse_build_compare_editor

from mercury_engine_data_structures import dread_data, samus_returns_data
from mercury_engine_data_structures.formats.bmtre import Bmtre

all_sr_bmtre = [[name for name in samus_returns_data.all_name_to_asset_id().keys()
                   if name.endswith(".bmtre")][0]]

all_dread_bmtre = [name for name in dread_data.all_name_to_asset_id().keys()
                   if name.endswith(".bmtre")]

# Uncomment when they parse
#@pytest.mark.parametrize("bmtre_path", all_sr_bmtre)
#def test_bmtre(samus_returns_tree, bmtre_path):
#    parse_build_compare_editor(Bmtre, samus_returns_tree, bmtre_path)

@pytest.mark.parametrize("bmtre_path", all_dread_bmtre)
def test_bmtre_dread(dread_file_tree, bmtre_path):
    parse_build_compare_editor(Bmtre, dread_file_tree, bmtre_path)
