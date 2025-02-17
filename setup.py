from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py


def generate_property_templates():
    subprocess.run(
        [
            sys.executable,
            os.fspath(Path(__file__).parent.joinpath("tools", "create_class_definitions.py")),
            "dread",
        ],
        check=True,
    )
    subprocess.run(
        [
            sys.executable,
            os.fspath(Path(__file__).parent.joinpath("tools", "create_class_definitions.py")),
            "sr",
        ],
        check=True,
    )


class BuildPyCommand(build_py):
    """
    Generate script templates code before building the package.
    """

    def run(self):
        generate_property_templates()
        build_py.run(self)


setup(
    cmdclass={
        "build_py": BuildPyCommand,
    },
)
