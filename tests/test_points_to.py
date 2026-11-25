"""M6 regression checks on a small PIE with function pointers."""

from collections import defaultdict
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from bpa.points_to import run_m6


SOURCE = """
#include <stdlib.h>
typedef int (*callback)(void);
struct fields { callback volatile first; callback volatile second; };
static callback volatile slot, branch_slot;
int first(void) { return 1; }
int second(void) { return 2; }
static callback volatile initialized = second;
callback identity(callback p) { return p; }
int from_image(void) { return initialized(); }
int overwrite(void) {
    slot = first;
    int a = slot();
    slot = second;
    return a + slot();
}
int fields(void) {
    struct fields *p = malloc(sizeof *p);
    if (!p) return 0;
    p->first = first;
    p->second = second;
    return p->second();
}
int branch(int choose) {
    if (choose) branch_slot = first;
    else branch_slot = second;
    return branch_slot();
}
int contexts(void) {
    int left = identity(first)();
    return left + identity(second)();
}
int main(int argc, char **argv) {
    return from_image() + overwrite() + fields() + branch(argc > 1) + contexts();
}
"""


@unittest.skipUnless(all(shutil.which(program) for program in ("gcc", "objdump", "souffle")),
                     "requires GCC, objdump and Souffle")
class PointsToTests(unittest.TestCase):
    def test_pointer_values_and_memory_order(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            source, binary, output = root / "sample.c", root / "sample", root / "analysis"
            source.write_text(SOURCE)
            subprocess.run(["gcc", "-O0", "-g", "-fPIE", "-pie", str(source), "-o", str(binary)], check=True)
            manifest = run_m6(binary, output)
            directory = output / "m6" / manifest["facts_dir"]
            functions = json.loads((output / "m2/functions.json").read_text())["functions"]
            by_entry = {f["entry"]: f["name"] for f in functions}
            by_function = defaultdict(lambda: defaultdict(set))
            for line in (directory / "call_operand_value.facts").read_text().splitlines():
                _, site, _, kind, target = line.split("\t")
                site = int(site)
                for f in functions:
                    if any(low <= site < high for low, high in f["code_ranges"]):
                        name = by_entry.get(int(target), target) if kind == "function" else kind
                        by_function[f["name"]][site].add(name)

            def candidates(name):
                return [targets for _, targets in sorted(by_function[name].items())]

            self.assertEqual(candidates("from_image"), [{"second"}])
            self.assertEqual(candidates("overwrite"), [{"first"}, {"second"}])
            self.assertEqual(candidates("branch"), [{"first", "second"}])
            self.assertEqual(candidates("contexts"), [{"first"}, {"second"}])
            self.assertEqual(candidates("fields"), [{"second", "unknown"}])

            with patch("bpa.pipeline.run_m3", side_effect=AssertionError("unexpected M3 rerun")), \
                 patch("bpa.memory.run_m4", side_effect=AssertionError("unexpected M4 rerun")), \
                 patch("bpa.registers.run_m5", side_effect=AssertionError("unexpected M5 rerun")):
                reused = run_m6(binary, root / "reuse", m3_path=output / "m3", m4_path=output / "m4",
                                m5_path=output / "m5")
            self.assertEqual(reused["files"], manifest["files"])


if __name__ == "__main__":
    unittest.main()
