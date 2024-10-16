from __future__ import annotations

import pytest

from mercury_engine_data_structures.game_check import GameVersion
from mercury_engine_data_structures.romfs import ExtractedRomFs
from mercury_engine_data_structures.version_validation import identify_version

# ignores unsupported dread versions
GAME_VERSIONS_TESTS = [
    ("samus_returns_path", GameVersion.MSR),
    ("dread_path_100", GameVersion.DREAD_1_0_0),
    # ("dread_path_101", GameVersion.DREAD_1_0_1),
    # ("dread_path_200", GameVersion.DREAD_2_0_0),
    ("dread_path_210", GameVersion.DREAD_2_1_0),
]


@pytest.mark.parametrize(("path_fixture_name", "version"), GAME_VERSIONS_TESTS)
def test_identify_version(path_fixture_name: str, version: GameVersion, request: pytest.FixtureRequest):
    # finds correct version after creating an editor
    path = request.getfixturevalue(path_fixture_name)
    romfs = ExtractedRomFs(path)
    assert identify_version(romfs) == version
