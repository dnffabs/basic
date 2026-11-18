"""M1 loader capabilities and regressions; no fixture compilation here."""

import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

from bpa.loader import ELFLoadError, load_elf, open_elf
from bpa.model import BinaryInfo


BINARIES = Path(__file__).resolve().parent / "fixtures" / "binaries"


def symbol(info, name):
    return next(s for s in info.symbols if s.name == name and s.mapped_address is not None)


class ExtendedLoaderTests(unittest.TestCase):
    def test_symbols_imports_dependencies_and_plt(self):
        for bits in (64, 32):
            with self.subTest(bits=bits):
                info = load_elf(BINARIES / f"test_{bits}")
                self.assertTrue(symbol(info, "add").is_function)
                self.assertTrue(symbol(info, "main").is_function)
                self.assertEqual(symbol(info, "operations").size, 2 * bits // 8)
                imports = {entry.name: entry for entry in info.imports}
                self.assertTrue({"malloc", "free", "printf"} <= imports.keys())
                self.assertIn("libc.so.6", info.dependencies)
                self.assertTrue({"malloc", "free", "printf"} <= {p.name for p in info.plt})
                self.assertTrue({"malloc", "free", "printf"} <= {r.symbol for r in info.relocations})
                self.assertTrue(imports["malloc"].resolved)
                self.assertTrue(imports["malloc"].target_is_extern)
                self.assertFalse(info.auto_load_libs)
                self.assertEqual(info.loader_backend, "cle")
                self.assertEqual(info.loader_version, "9.2.173")
                self.assertEqual(info.mapped_entry, info.entry + info.load_bias)

    def test_initial_memory_pointer_table_data_bss_and_import_slot(self):
        for bits in (64, 32):
            with self.subTest(bits=bits):
                loaded = open_elf(BINARIES / f"test_{bits}")
                info = loaded.info
                operations = symbol(info, "operations")
                raw = loaded.read_memory(operations.mapped_address, operations.size)
                word = bits // 8
                pointers = [int.from_bytes(raw[i:i + word], info.endianness) for i in (0, word)]
                self.assertEqual(pointers, [symbol(info, name).mapped_address for name in ("add", "subtract")])
                value = loaded.read_memory(symbol(info, "initialized_value").mapped_address, 4)
                self.assertEqual(int.from_bytes(value, info.endianness), 7)
                bss = symbol(info, "zero_buffer")
                self.assertEqual(loaded.read_memory(bss.mapped_address, bss.size), bytes(256))
                message = symbol(info, "message")
                self.assertEqual(loaded.read_memory(message.mapped_address, message.size), b"bpa-test\0")
                malloc = next(entry for entry in info.imports if entry.name == "malloc")
                pointer = loaded.read_memory(malloc.slot_mapped_address, word)
                self.assertEqual(int.from_bytes(pointer, info.endianness), malloc.target_mapped_address)
                self.assertEqual(loaded.to_elf(loaded.to_mapped(info.entry)), info.entry)
                with self.assertRaises(ValueError):
                    loaded.read_memory((1 << bits) - 4096, 8)
                with self.assertRaises(ValueError):
                    loaded.read_memory(info.mapped_entry, -1)

    def test_region_contract_and_json_roundtrip(self):
        info = load_elf(BINARIES / "test_64")
        restored = BinaryInfo.from_dict(json.loads(json.dumps(info.to_dict())))
        self.assertEqual(info, restored)
        self.assertTrue(any(r.name == ".text" and r.start < r.end for r in info.executable_regions))
        self.assertTrue({".data", ".rodata", ".bss"} <= {r.name for r in info.global_regions})
        for region in info.executable_regions + info.global_regions:
            section = next(s for s in info.sections if s.name == region.name)
            self.assertEqual(region.end - region.start, section.size)
        bad = info.to_dict()
        bad["schema_version"] = 1
        with self.assertRaises(ValueError):
            BinaryInfo.from_dict(bad)

    def test_hardlink_and_symlink_output_cannot_overwrite_input(self):
        data = (BINARIES / "test_64").read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for kind in ("hardlink", "symlink"):
                with self.subTest(kind=kind):
                    source, output = root / f"{kind}.elf", root / f"{kind}.json"
                    source.write_bytes(data)
                    if kind == "hardlink":
                        os.link(source, output)
                    else:
                        output.symlink_to(source)
                    result = subprocess.run([sys.executable, "-m", "bpa", str(source), "-o", str(output)],
                                            capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("must not overwrite", result.stderr)
                    self.assertEqual(source.read_bytes(), data)

    def test_section_payload_beyond_file_is_rejected(self):
        data = bytearray((BINARIES / "test_64").read_bytes())
        section_table = struct.unpack_from("<Q", data, 40)[0]
        # Section 1 is the file-backed .interp in this fixed GCC executable.
        struct.pack_into("<Q", data, section_table + 64 + 24, len(data) + 4096)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.elf"
            path.write_bytes(data)
            with self.assertRaisesRegex(ELFLoadError, "beyond the ELF file"):
                load_elf(path)


if __name__ == "__main__":
    unittest.main()
