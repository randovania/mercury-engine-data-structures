from __future__ import annotations

import pytest

from mercury_engine_data_structures.file_tree_editor import FileTreeEditor, GameVersion
from mercury_engine_data_structures.romfs import ExtractedRomFs
from mercury_engine_data_structures.version_validation import verify_file_integrity, verify_file_structure

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
    editor = FileTreeEditor(ExtractedRomFs(path), version.game)
    assert editor.version == version


@pytest.mark.parametrize(("path_fixture_name", "version"), GAME_VERSIONS_TESTS)
def test_verify_structure(path_fixture_name: str, version: GameVersion, request: pytest.FixtureRequest):
    path = request.getfixturevalue(path_fixture_name)
    editor = FileTreeEditor(ExtractedRomFs(path), version.game)
    assert verify_file_structure(editor) == version


@pytest.mark.parametrize(("path_fixture_name", "version"), GAME_VERSIONS_TESTS)
def test_verify_data(path_fixture_name: str, version: GameVersion, request: pytest.FixtureRequest):
    path = request.getfixturevalue(path_fixture_name)
    editor = FileTreeEditor(ExtractedRomFs(path), version.game)
    assert verify_file_integrity(editor) == version
