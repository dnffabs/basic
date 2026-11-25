"""The M7 output must contain the targets exercised by these small programs."""

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from bpa.calls import run_m7


SOURCES = Path(__file__).resolve().parent / "fixtures/sources"


@unittest.skipUnless(all(shutil.which(tool) for tool in ("gcc", "objdump", "souffle")),
                     "requires GCC, objdump and Souffle")
class CallResolutionTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def analyze(self, source, *options):
        binary, output = self.root / "program", self.root / "analysis"
        build = subprocess.run(["gcc", "-g", *options, str(SOURCES / source), "-o", str(binary)],
                               text=True, capture_output=True)
        if "-m32" in options and build.returncode and any(
                marker in build.stderr for marker in ("cannot find", "skipping incompatible")):
            self.skipTest("the installed GCC lacks 32-bit linker inputs")
        self.assertEqual(build.returncode, 0, build.stderr)
        manifest = run_m7(binary, output)
        self.assertTrue(manifest["converged"])
        directory = output / "m7" / manifest["results_dir"]
        rounds = json.loads((directory / "iterations.json").read_text())["rounds"]
        self.assertEqual(len(rounds), manifest["iterations"])
        for field in ("new_call_edges", "new_tail_edges", "new_opaque_sites"):
            self.assertEqual(rounds[-1][field], [])
        graph = json.loads((directory / "call_graph.json").read_text())
        sites = json.loads((directory / "indirect_calls.json").read_text())["sites"]
        symbols = {s["name"]: s["elf_address"] for s in json.loads((output / "m1/binary.json").read_text())["symbols"]}
        return binary, graph, sites, symbols

    def assert_callbacks(self, *options):
        binary, graph, sites, symbols = self.analyze("m7_callbacks.c", "-O0", "-fPIE", "-pie", *options)
        self.assertEqual(subprocess.run([binary]).returncode, 20)
        self.assertEqual(subprocess.run([binary, "left"]).returncode, 18)
        indirect = [e for e in graph["edges"] if e["kind"] == "call" and e["indirect"]]
        cascade = [e for e in indirect if symbols["cascade"] in e["callers"]]
        self.assertEqual([(e["target_name"], e["first_seen_round"]) for e in cascade],
                         [("make_callback", 1), ("result", 2)])
        dispatch = [e for e in indirect if symbols["dispatch"] in e["callers"]]
        self.assertEqual({e["target_name"] for e in dispatch}, {"left", "right"})
        dispatch_site, = {e["site"] for e in dispatch}
        info = next(site for site in sites if site["site"] == dispatch_site)
        self.assertEqual(set(info["targets"]), {symbols["left"], symbols["right"]})

    def test_pie_callbacks_x64(self):
        self.assert_callbacks()

    def test_pie_callbacks_x86(self):
        self.assert_callbacks("-m32")

    def test_tail_return_reaches_original_caller(self):
        binary, graph, sites, symbols = self.analyze("m7_tail.S", "-nostdlib", "-no-pie")
        self.assertEqual(subprocess.run([binary]).returncode, 9)
        tails = {(e["site"], e["target_name"], e["first_seen_round"])
                 for e in graph["edges"] if e["kind"] == "tail_call"}
        self.assertEqual(tails, {(symbols["direct_tail"], "indirect_tail", 0),
                                 (symbols["indirect_tail"], "make_result", 1)})
        final_call = next(site for site in sites if site["site"] == symbols["after_tail"])
        self.assertEqual(final_call["targets"], [symbols["tail_result"]])
        self.assertTrue(any(row["continuation"] == symbols["after_tail"]
                            and row["return_block"] == symbols["make_result"] for row in graph["return_links"]))


if __name__ == "__main__":
    unittest.main()
