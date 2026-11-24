"""M2 integration checks use only the two existing fixed test executables."""

from dataclasses import replace
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from capstone import CS_ARCH_X86, CS_GRP_CALL, CS_MODE_32, CS_MODE_64, Cs
from capstone.x86_const import X86_OP_IMM

from bpa.cfg import CFGError, build_cfg
from bpa.loader import load_elf


ROOT = Path(__file__).resolve().parents[1]
BINARIES = ROOT / "tests/fixtures/binaries"
USER_FUNCTIONS = ("main", "add", "subtract", "apply", "invoke")


class CFGTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.infos = {bits: load_elf(BINARIES / f"test_{bits}") for bits in (64, 32)}
        cls.results = {bits: build_cfg(info) for bits, info in cls.infos.items()}

    def test_functions_and_recovered_code_ranges(self):
        for bits, result in self.results.items():
            with self.subTest(bits=bits):
                by_name = {f.name: f for f in result.functions}
                for name in USER_FUNCTIONS:
                    function = by_name[name]
                    self.assertEqual(function.source, "elf-symbol")
                    self.assertTrue(function.blocks)
                    symbol = next(s for s in self.infos[bits].symbols if s.name == name)
                    self.assertEqual(function.entry, symbol.elf_address)
                    self.assertEqual(function.symbol_end, symbol.elf_address + symbol.size)
                    self.assertTrue(all(function.entry <= a < b
                                        for a, b in function.code_ranges))
                    # BPA-X ends a function at the next function entry (which
                    # can include trailing alignment padding past symbol_end).
                    next_entry = min((s.elf_address for s in self.infos[bits].symbols
                                      if s.is_function and s.elf_address is not None
                                      and s.elf_address > symbol.elf_address),
                                     default=None)
                    if next_entry is not None:
                        self.assertEqual(function.code_ranges[-1][1], next_entry)

    def test_exports_only_bpax_user_defined_functions(self):
        expected = {
            64: {"main", "add", "subtract", "apply", "invoke"},
            32: {"main", "add", "subtract", "apply", "invoke", "__wrap_main"},
        }
        for bits, result in self.results.items():
            with self.subTest(bits=bits):
                names = {function.name for function in result.functions}
                self.assertEqual(names, expected[bits])
                for function in result.functions:
                    self.assertFalse(function.name.startswith("sub_"))
                    self.assertFalse(function.is_plt)
                for block in result.blocks:
                    self.assertTrue(set(block.function_entries) <=
                                    {function.entry for function in result.functions})

    def test_graph_and_instruction_integrity(self):
        for bits, result in self.results.items():
            with self.subTest(bits=bits):
                blocks = {b.address: b for b in result.blocks}
                functions = {f.entry: f for f in result.functions}
                self.assertIn(result.entry, blocks)
                self.assertEqual(len(blocks), len(result.blocks))
                for block in result.blocks:
                    self.assertTrue(block.instructions)
                    cursor = block.address
                    for instruction in block.instructions:
                        self.assertEqual(instruction.address, cursor)
                        cursor += instruction.size
                    self.assertEqual(cursor, block.address + block.size)
                    for owner in block.function_entries:
                        self.assertIn(block.address, functions[owner].blocks)
                for edge in result.edges:
                    self.assertIn(edge.source, blocks)
                    if edge.target is None:
                        self.assertIsNotNone(edge.external_symbol)
                    else:
                        self.assertIn(edge.target, blocks)
                    if edge.kind == "fake_return":
                        self.assertEqual(edge.provenance, "assumed-return")
                    if edge.kind == "return":
                        self.assertEqual(edge.provenance, "cfgfast-return")
                for function in result.functions:
                    for address in function.blocks:
                        self.assertIn(function.entry, blocks[address].function_entries)

    def test_call_inventory_matches_independent_linear_decode(self):
        for bits, info in self.infos.items():
            raw_file = Path(info.path).read_bytes()
            decoder = Cs(CS_ARCH_X86, CS_MODE_64 if bits == 64 else CS_MODE_32)
            decoder.detail = True
            functions = {f.name: f for f in self.results[bits].functions}
            for name in USER_FUNCTIONS:
                with self.subTest(bits=bits, function=name):
                    symbol = next(s for s in info.symbols if s.name == name)
                    segment = next(s for s in info.segments if s.virtual_address <= symbol.elf_address <
                                   s.virtual_address + s.file_size)
                    offset = segment.offset + symbol.elf_address - segment.virtual_address
                    expected = {}
                    for instruction in decoder.disasm(raw_file[offset:offset + symbol.size], symbol.elf_address):
                        if instruction.group(CS_GRP_CALL):
                            indirect = instruction.operands[0].type != X86_OP_IMM
                            expected[instruction.address] = (indirect, None if indirect else instruction.operands[0].imm)
                    actual = {t.address: (t.indirect, t.direct_target) for t in self.results[bits].transfers
                              if t.kind == "call" and functions[name].entry in t.function_entries}
                    self.assertEqual(actual, expected)
                    if name == "main":
                        self.assertEqual(len(actual), 7)

    def test_user_indirect_calls_remain_unresolved_with_continuations(self):
        for bits, result in self.results.items():
            functions = {f.name: f for f in result.functions}
            for name in ("apply", "invoke"):
                with self.subTest(bits=bits, function=name):
                    calls = [t for t in result.transfers if t.kind == "call" and
                             functions[name].entry in t.function_entries]
                    self.assertEqual(len(calls), 1)
                    call = calls[0]
                    self.assertTrue(call.indirect)
                    self.assertEqual(call.status, "unresolved")
                    self.assertFalse(call.targets)
                    self.assertFalse(call.external_targets)
                    self.assertIsNotNone(call.continuation)
                    self.assertIn(call.address, result.cfg_document()["unresolved_transfers"])

    def test_address_taken_evidence_excludes_direct_calls(self):
        for bits, result in self.results.items():
            with self.subTest(bits=bits):
                functions = {f.name: f for f in result.functions}
                table = next(s for s in self.infos[bits].symbols if s.name == "operations")
                for index, name in enumerate(("add", "subtract")):
                    self.assertTrue(functions[name].address_taken)
                    self.assertTrue(any(e.source == "global-initializer" and
                                        e.address == table.elf_address + index * bits // 8
                                        for e in functions[name].at_evidence))
                for name in ("apply", "invoke"):
                    self.assertFalse(functions[name].address_taken)

    def test_m1_identity_and_address_contract_are_checked(self):
        info = self.infos[64]
        for altered in (replace(info, sha256="0" * 64), replace(info, schema_version=1),
                        replace(info, entry=info.entry + 1), replace(info, bits=32)):
            with self.subTest(altered=altered.sha256, entry=altered.entry, bits=altered.bits):
                with self.assertRaises(CFGError):
                    build_cfg(altered)

    def test_export_is_json_serializable_and_deterministic(self):
        result = self.results[64]
        rebuilt = build_cfg(self.infos[64])
        for method in ("functions_document", "cfg_document"):
            document = getattr(result, method)()
            self.assertEqual(json.loads(json.dumps(document))["address_space"], "elf-va")
            self.assertEqual(document["binary_sha256"], self.infos[64].sha256)
            self.assertEqual(json.dumps(document, sort_keys=True),
                             json.dumps(getattr(rebuilt, method)(), sort_keys=True))

    def test_cli_consumes_m1_and_exports_both_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            m1 = root / "input_m1.json"
            m1.write_text(json.dumps(self.infos[64].to_dict()))
            before = m1.read_bytes()
            command = [sys.executable, "-m", "bpa", self.infos[64].path, "--stage", "m2",
                       "--m1", str(m1), "-o", str(root / "result")]
            completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=30)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(m1.read_bytes(), before)
            functions = json.loads((root / "result/m2/functions.json").read_text())
            cfg = json.loads((root / "result/m2/cfg.json").read_text())
            self.assertEqual(functions["binary_sha256"], cfg["binary_sha256"])
            self.assertEqual(functions["kind"], "functions")
            self.assertEqual(cfg["kind"], "cfg")
            self.assertEqual(cfg["statistics"]["blocks"], len(cfg["blocks"]))
