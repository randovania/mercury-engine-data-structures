import pytest

from mercury_engine_data_structures.formats.rom3ds import Rom3DS, parse_rom_file


@pytest.mark.parametrize("rom_ending", [".cxi", ".cia", ".3ds"])
def test_compare_pkg_sr(samus_returns_roms_path, rom_ending):
    file_path = samus_returns_roms_path.joinpath("MSR" + rom_ending)
    with open(file_path, "rb") as file_stream:
        rom = Rom3DS(parse_rom_file(file_path, file_stream), file_stream)
        # deactivated to not let other users tests fail when they use a NTSC version
        # assert rom.get_title_id() == "00040000001BFB00"
        # assert rom.is_pal()
        assert rom.get_file_binary("gui/scripts/loadingscreen.lc")[:6] == b"\x1bLuaQ\x00"
        assert rom.get_code_binary()[:6] == b"\x07\x00\x00\xeb\x92#"
        assert rom.exheader()[:8] == b"MATADORA"
