"""Integration checks against the fixed, locally compiled ELF fixtures."""

import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

from bpa.loader import ELFLoadError, load_elf


FIXTURES = Path(__file__).resolve().parent / "fixtures"
BASE_BINARY = FIXTURES / "binaries" / "test_64"


class LoaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        manifest = FIXTURES / "manifest.json"
        if not manifest.exists():
            raise RuntimeError("Build fixtures first: bash tests/fixtures/build.sh")
        cls.samples = json.loads(manifest.read_text())["samples"]

    def test_fixture_integrity(self):
        self.assertTrue(self.samples)
        for sample in self.samples:
            with self.subTest(sample=sample["id"]):
                for path_key, hash_key in (("binary", "sha256"), ("source", "source_sha256")):
                    data = (FIXTURES / sample[path_key]).read_bytes()
                    self.assertEqual(hashlib.sha256(data).hexdigest(), sample[hash_key])

    def test_real_elf_matches_raw_header(self):
        for sample in self.samples:
            with self.subTest(sample=sample["id"]):
                binary = FIXTURES / sample["binary"]
                data = binary.read_bytes()
                info = load_elf(binary)
                self.assertEqual(data[:4], b"\x7fELF")
                self.assertEqual(info.bits, {1: 32, 2: 64}[data[4]])
                byte_order = "<" if data[5] == 1 else ">"
                entry_format = "I" if data[4] == 1 else "Q"
                self.assertEqual(info.entry, struct.unpack_from(byte_order + entry_format, data, 24)[0])
                self.assertEqual(info.file_size, len(data))
                self.assertTrue(any(s.executable and s.virtual_address <= info.entry <
                                    s.virtual_address + s.memory_size for s in info.segments))
                self.assertTrue(any(s.name == ".text" and s.executable for s in info.sections))
                self.assertTrue(any(s.memory_size > s.file_size for s in info.segments))
                document = json.loads(json.dumps(info.to_dict()))
                self.assertEqual(document["schema_version"], 2)
                self.assertEqual(document["address_space"], "elf-va")

    def test_compilation_variants(self):
        for sample in self.samples:
            with self.subTest(sample=sample["id"]):
                info = load_elf(FIXTURES / sample["binary"])
                expected = sample["expected"]
                for field in ("bits", "machine", "elf_type", "endianness"):
                    self.assertEqual(getattr(info, field), expected[field])
                sections = {section.name for section in info.sections}
                self.assertEqual(".debug_info" in sections, expected["has_debug_info"])
                self.assertEqual(".symtab" in sections, expected["has_symtab"])
                self.assertTrue(any(s.name == ".bss" and s.type == "SHT_NOBITS" for s in info.sections))

    def test_native_execution(self):
        for sample in self.samples:
            with self.subTest(sample=sample["id"]):
                result = subprocess.run([str(FIXTURES / sample["binary"])],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, sample["expected"]["exit_code"], result.stderr)
                self.assertEqual(result.stdout, sample["expected"]["stdout"])

    def test_invalid_and_truncated_input(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "bad.elf"
            for data in (b"not an ELF", b"\x7fELF"):
                with self.subTest(data=data):
                    binary.write_bytes(data)
                    with self.assertRaises(ELFLoadError):
                        load_elf(binary)

    def test_cli_saves_json_and_rejects_input_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "m1" / "binary.json"
            result = subprocess.run(
                [sys.executable, "-m", "bpa", str(BASE_BINARY), "-o", str(output)],
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(output.read_text())["path"], str(BASE_BINARY))
            binary = Path(directory) / "input.elf"
            data = BASE_BINARY.read_bytes()
            binary.write_bytes(data)
            result = subprocess.run(
                [sys.executable, "-m", "bpa", str(binary), "-o", str(binary)],
                capture_output=True, text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(binary.read_bytes(), data)


if __name__ == "__main__":
    unittest.main()
