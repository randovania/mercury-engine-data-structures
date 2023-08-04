import os
from pathlib import Path

import pytest

from mercury_engine_data_structures.file_tree_editor import FileTreeEditor
from mercury_engine_data_structures.game_check import Game

_FAIL_INSTEAD_OF_SKIP = False


def get_env_or_skip(env_name):
    if env_name not in os.environ:
        if _FAIL_INSTEAD_OF_SKIP:
            pytest.fail(f"Missing environment variable {env_name}")
        else:
            pytest.skip(f"Skipped due to missing environment variable {env_name}")
    return os.environ[env_name]


@pytest.fixture(scope="session")
def samus_returns_path():
    return Path(get_env_or_skip("SAMUS_RETURNS_PATH"))


@pytest.fixture(scope="session")
def dread_path():
    return Path(get_env_or_skip("DREAD_PATH"))


@pytest.fixture(scope="session")
def samus_returns_tree(samus_returns_path):
    return FileTreeEditor(samus_returns_path, Game.SAMUS_RETURNS)


@pytest.fixture(scope="session")
def dread_file_tree(dread_path):
    return FileTreeEditor(dread_path, Game.DREAD)


def pytest_addoption(parser):
    parser.addoption('--fail-if-missing', action='store_true', dest="fail_if_missing",
                     default=False, help="Fails tests instead of skipping, in case any asset is missing")


def pytest_configure(config: pytest.Config):
    global _FAIL_INSTEAD_OF_SKIP
    _FAIL_INSTEAD_OF_SKIP = config.option.fail_if_missing
