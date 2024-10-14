from __future__ import annotations

import io
from abc import ABC, abstractmethod
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


class RomFs(ABC):
    @contextmanager
    @abstractmethod
    def get_pkg_stream(self, file_path: str) -> Iterator[io.BufferedIOBase]:
        """Returns a package file stream which should be used in a "with" context.

        :param file_path: File path to the pkg file
        """
        pass

    @abstractmethod
    def read_file_with_entry(self, file_path: str, entry) -> bytes:
        """Reads and returns a file within a pkg file.

        :param file_path: File path to the pkg file
        :param entry: An entry object containing the end_offset and start_offset within the pkg
        """
        pass

    @abstractmethod
    def get_file(self, file_path: str) -> bytes:
        """Reads and returns a file.

        :param file_path: Path to the file
        """
        pass

    @abstractmethod
    def all_files(self) -> Iterator[str]:
        """Returns an Iterator for all files within the RomFS"""
        pass


class ExtractedRomFs(RomFs):
    def __init__(self, root: Path):
        self.root = root

    @contextmanager
    def get_pkg_stream(self, file_path: str) -> Iterator[io.BufferedReader]:
        file_stream = self.root.joinpath(file_path).open("rb")
        try:
            yield file_stream
        finally:
            file_stream.close()

    def read_file_with_entry(self, file_path: str, entry) -> bytes:
        with self.root.joinpath(file_path).open("rb") as f:
            f.seek(entry.start_offset)
            return f.read(entry.end_offset - entry.start_offset)

    def get_file(self, file_path: str) -> bytes:
        return self.root.joinpath(file_path).read_bytes()

    def all_files(self) -> Iterator[str]:
        for f in self.root.rglob("*.*"):
            name = f.relative_to(self.root).as_posix()
            yield name
