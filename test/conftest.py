import os
from pathlib import Path

import pytest


def get_env_or_skip(env_name):
    if env_name not in os.environ:
        pytest.skip(f"Skipped due to missing environment variable {env_name}")
    return os.environ[env_name]


@pytest.fixture()
def samus_returns_path():
    return Path(get_env_or_skip("SAMUS_RETURNS_PATH"))


@pytest.fixture()
def dread_path():
    return Path(get_env_or_skip("DREAD_PATH"))

