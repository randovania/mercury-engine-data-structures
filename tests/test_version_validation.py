from mercury_engine_data_structures.file_tree_editor import FileTreeEditor, Game, GameVersion
from mercury_engine_data_structures.version_validation import check_file_integrity, check_file_structure


def test_validate_dread_100(dread_path_100):
    # finds correct version after creating an editor
    editor = FileTreeEditor(dread_path_100, Game.DREAD)
    assert editor.version == GameVersion.DREAD_1_0_0

    # validates the file structure
    res, ver = check_file_structure(editor)
    assert res and ver == GameVersion.DREAD_1_0_0

    # validates file integrity
    res, ver = check_file_integrity(editor)
    assert res and ver == GameVersion.DREAD_1_0_0


def test_validate_dread_210(dread_path_210):
    # finds correct version after creating an editor
    editor = FileTreeEditor(dread_path_210, Game.DREAD)
    assert editor.version == GameVersion.DREAD_2_1_0

    # validates the file structure
    res, ver = check_file_structure(editor)
    assert res and ver == GameVersion.DREAD_2_1_0

    # validates file integrity
    res, ver = check_file_integrity(editor)
    assert res and ver == GameVersion.DREAD_2_1_0


def test_validate_samus_returns(samus_returns_path):
    # finds correct version after creating an editor
    editor = FileTreeEditor(samus_returns_path, Game.SAMUS_RETURNS)
    assert editor.version == GameVersion.MSR

    # validates the file structure
    res, ver = check_file_structure(editor)
    assert res and ver == GameVersion.MSR

    # validates file integrity
    res, ver = check_file_integrity(editor)
    assert res and ver == GameVersion.MSR
