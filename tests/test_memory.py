"""M4 artifact contract, independent of block numbering and install paths."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from bpa.memory import run_m4
from bpa.memory.partition import read_rows

ROOT = Path(__file__).resolve().parents[1]
BINARIES = ROOT / "tests/fixtures/binaries"
SOURCE = ROOT / "tests/fixtures/sources/test.c"


@unittest.skipUnless(shutil.which("souffle") and shutil.which("objdump"), "requires Souffle and objdump")
class MemoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(tmp.cleanup)
        cls.root = Path(tmp.name)
        cls.runs = {}
        for bits in (32, 64):
            output = cls.root / str(bits)
            manifest = run_m4(BINARIES / f"test_{bits}", output)
            cls.runs[bits] = (output, output / "m4" / manifest["facts_dir"], manifest)

    def test_manifest_and_access_coverage(self):
        for output, facts, manifest in self.runs.values():
            with self.subTest(arch=manifest["arch"]):
                self.assertEqual(manifest, json.loads((output / "m4/manifest.json").read_text()))
                for name, columns in manifest["columns"].items():
                    data = (facts / f"{name}.facts").read_bytes()
                    self.assertEqual(hashlib.sha256(data).hexdigest(), manifest["files"][f"{name}.facts"])
                    rows = list(read_rows(facts, name))
                    self.assertEqual(len(rows), manifest["counts"][name])
                    self.assertTrue(all(len(row) == len(columns) for row in rows))
                accesses = {(kind, row[0]) for kind in ("load", "store", "guarded_load", "guarded_store")
                            for row in read_rows(output / "m3", kind)}
                unknown = {(kind, ident) for kind, ident, _, _ in read_rows(facts, "unmapped_access")}
                links = list(read_rows(facts, "memory_access_block"))
                mapped = {tuple(row[:2]) for row in links}
                self.assertFalse(mapped & unknown)
                self.assertEqual(mapped | unknown, accesses)
                self.assertEqual(len(unknown), manifest["unmapped_accesses"])
                blocks = {("global", row[0]) for row in read_rows(facts, "mloc_gblk")}
                blocks.update(("stack", row[0]) for row in read_rows(facts, "mloc_sblk"))
                self.assertTrue(all(tuple(row[2:4]) in blocks for row in links))

    def test_malloc_site_and_global_symbol(self):
        for output, facts, _ in self.runs.values():
            info = json.loads((output / "m1/binary.json").read_text())
            transfers = json.loads((output / "m2/cfg.json").read_text())["transfers"]
            malloc = next(p["elf_address"] for p in info["plt"] if p["name"] == "malloc")
            sites = {t["address"] for t in transfers if t["direct_target"] == malloc}
            self.assertEqual(len(sites), 1)
            self.assertEqual(sites, {int(site) for _, site in read_rows(facts, "mloc_hblk")})
            var = next(s["elf_address"] for s in info["symbols"] if s["name"] == "initialized_value")
            self.assertIn(var, {int(row[1]) for row in read_rows(facts, "mloc_gblk")})

    def test_stack_open_bounds_and_call_contexts(self):
        _, facts, _ = self.runs[32]
        rows = list(read_rows(facts, "mloc_sblk"))
        main = next(row[3] for row in read_rows(facts, "local_block_boundary") if row[2] == "main")
        frame = [row for row in rows if row[1] == main and row[6] == "0"]
        self.assertEqual(sum(row[4] == "0" for row in frame), 1)
        self.assertEqual(sum(row[5] == "0" for row in frame), 1)
        self.assertTrue(any(row[6] != "0" for row in rows))

    def test_reuse_and_input_checks(self):
        output, _, manifest = self.runs[64]
        stage = output / "m3"
        target = self.root / "reuse"
        with patch("bpa.pipeline.run_m3", side_effect=AssertionError("unexpected re-extraction")):
            rerun = run_m4(BINARIES / "test_64", target, m3_path=stage)
            self.assertEqual(rerun["files"], manifest["files"])
            with self.assertRaisesRegex(ValueError, "identity"):
                run_m4(BINARIES / "test_32", target, m3_path=stage)
        self.assertEqual(rerun, json.loads((target / "m4/manifest.json").read_text()))

    def test_refuses_partial_or_mixed_upstream_artifacts(self):
        output, _, _ = self.runs[64]
        upstream = self.root / "mixed"
        for stage in ("m1", "m2", "m3"):
            shutil.copytree(output / stage, upstream / stage)
        manifest_path = upstream / "m3/manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest_path.write_text(json.dumps(dict(manifest, status="partial")))
        with self.assertRaisesRegex(ValueError, "complete M3"):
            run_m4(BINARIES / "test_64", upstream, m3_path=upstream / "m3")
        manifest_path.write_text(json.dumps(manifest))
        cfg = upstream / "m2/cfg.json"
        cfg.write_text(cfg.read_text() + "\n")
        with self.assertRaisesRegex(ValueError, "upstream checksum"):
            run_m4(BINARIES / "test_64", upstream, m3_path=upstream / "m3")
        self.assertFalse((upstream / "m4/manifest.json").exists())

    @unittest.skipUnless(shutil.which("gcc"), "requires GCC")
    def test_pie_rebase_preserves_elf_sites_and_boundaries(self):
        binary = self.root / "pie"
        subprocess.run(["gcc", "-O0", "-fPIE", "-pie", SOURCE, "-o", binary], check=True)
        layouts = []
        for base in (0x400000, 0x600000):
            output = self.root / f"pie-{base:x}"
            manifest = run_m4(binary, output, mapped_base=base)
            facts = output / "m4" / manifest["facts_dir"]
            names = ("mloc_sblk", "mloc_gblk", "mloc_hblk")
            layouts.append([{tuple(row[1:]) for row in read_rows(facts, name)} for name in names])
            self.assertTrue(all(layouts[-1]))
            info = json.loads((output / "m1/binary.json").read_text())
            var = next(s["elf_address"] for s in info["symbols"] if s["name"] == "initialized_value")
            self.assertIn(var, {int(row[1]) for row in read_rows(facts, "global_block_boundary")})
        self.assertEqual(*layouts)
