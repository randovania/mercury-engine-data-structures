import io
from abc import ABC, abstractmethod
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from mercury_engine_data_structures.formats.Rom3ds import Rom3DS


class RomFsWrapper(ABC):
    @contextmanager
    @abstractmethod
    def get_pkg_stream(self, file_path: str):
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


class RomFsAsDir(RomFsWrapper):
    def __init__(self, root: Path):
        self.root = root

    @contextmanager
    def get_pkg_stream(self, file_path: str):
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


class RomFsFromFile(RomFsWrapper):
    def __init__(self, root: Path):
        self.root = root
        self._file_stream = self.root.open("rb")
        self.parsed_rom = Rom3DS(self._file_stream)

    def __del__(self):
        self._file_stream.close()

    # meds to romfs name (needs leading /)
    def _to_romfs_name(self, file_path: str):
        if not file_path.startswith("/"):
            return "/" + file_path
        return file_path

    # romfs name to meds (remove leading /)
    def _from_romfs_name(self, file_path: str):
        if file_path.startswith("/"):
            return file_path[1:]
        return file_path

    @contextmanager
    def get_pkg_stream(self, file_path: str):
        romfs_path = self._to_romfs_name(file_path)
        file_stream = io.BytesIO(self.parsed_rom.get_file_binary(romfs_path))
        try:
            yield file_stream
        finally:
            file_stream.close()

    def read_file_with_entry(self, file_path: str, entry) -> bytes:
        romfs_path = self._to_romfs_name(file_path)
        with io.BytesIO(self.parsed_rom.get_file_binary(romfs_path)) as f:
            f.seek(entry.start_offset)
            return f.read(entry.end_offset - entry.start_offset)

    def get_file(self, file_path: str) -> bytes:
        romfs_path = self._to_romfs_name(file_path)
        return self.parsed_rom.get_file_binary(romfs_path)

    def all_files(self) -> Iterator[str]:
        for name in self.parsed_rom.file_name_to_entry.keys():
            yield self._from_romfs_name(name)
