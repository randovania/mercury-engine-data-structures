import io
from abc import ABC, abstractmethod
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from mercury_engine_data_structures.formats.Rom3ds import Rom3DS


class RomFs(ABC):
    @contextmanager
    @abstractmethod
    def get_pkg_stream(self, file_path: str) -> Iterator[io.BufferedIOBase]:
        pass

    @abstractmethod
    def read_file_with_entry(self, file_path: str, entry) -> bytes:
        pass

    @abstractmethod
    def get_file(self, path_as_str: str) -> bytes:
        pass

    @abstractmethod
    def all_files(self) -> Iterator[str]:
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


class PackedRomFs(RomFs):
    def __init__(self, root: Path):
        self.root = root
        self._file_stream = self.root.open("rb")
        self.parsed_rom = Rom3DS(self.root.as_posix(), self._file_stream)

    def __del__(self):
        self._file_stream.close()

    @contextmanager
    def get_pkg_stream(self, file_path: str) -> Iterator[io.BytesIO]:
        file_stream = io.BytesIO(self.parsed_rom.get_file_binary(file_path))
        try:
            yield file_stream
        finally:
            file_stream.close()

    def read_file_with_entry(self, file_path: str, entry) -> bytes:
        with io.BytesIO(self.parsed_rom.get_file_binary(file_path)) as f:
            f.seek(entry.start_offset)
            return f.read(entry.end_offset - entry.start_offset)

    def get_file(self, file_path: str) -> bytes:
        return self.parsed_rom.get_file_binary(file_path)

    def all_files(self) -> Iterator[str]:
        yield from self.parsed_rom.file_name_to_entry.keys()
