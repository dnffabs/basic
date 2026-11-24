"""M3 contract checks, fixed 32/64-bit fixtures, and precise synthetic VEX cases."""

from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import archinfo
import pyvex

from bpa.cfg import build_cfg
from bpa.loader import load_elf
from bpa.pipeline import run_m3
from bpa.vex import FactResult, read_facts, write_facts
from bpa.vex.compat import Projection, short_binop
from bpa.vex.extractor import VEXError, VexExtractor, extract_vex


ROOT = Path(__file__).resolve().parents[1]
BINARIES = ROOT / "tests/fixtures/binaries"


def synthetic(statements, types=()):
    arch = archinfo.ArchAMD64()
    irsb = pyvex.IRSB.empty_block(arch, 0x401000)
    for ty in types:
        irsb.tyenv.add(ty)
    irsb.statements = [pyvex.IRStmt.IMark(0x401000, 1, 0), *statements]
    irsb.next = pyvex.IRExpr.Const(pyvex.const.U64(0x401001))
    irsb.jumpkind = "Ijk_Boring"
    raw = FactResult.empty(dict(arch="AMD64", status="complete", binary_sha256="test"))
    raw.add("block", 0x401000, 1, 1, "Ijk_Boring")
    raw.add("instruction", 0x401000, 0x401000, 1, "test", "")
    VexExtractor(raw, arch, 0).extract(irsb, dict(address=0x401000, instructions=[dict(address=0x401000)]))
    raw.validate()
    return raw


def const(value, bits=64):
    cls = pyvex.const.V128 if bits == 128 else getattr(pyvex.const, f"U{bits}")
    return pyvex.IRExpr.Const(cls(value))


class VexSemanticsTests(unittest.TestCase):
    def test_ite_preserves_condition_and_true_false_order(self):
        ite = pyvex.IRExpr.ITE(const(1, 1), const(3, 32), const(7, 32))
        raw = synthetic([pyvex.IRStmt.WrTmp(0, ite)], ["Ity_I32"])
        ite_id = next(eid for eid, opcode in raw.rows["operation"] if opcode == "ITE")
        values = {eid: int(value, 16) for eid, _, value in raw.rows["constant"]}
        args = {index: values[value] for eid, index, value in raw.rows["operand"] if eid == ite_id}
        self.assertEqual(args, {0: 1, 1: 7, 2: 3})
        projected = Projection(raw).project()
        self.assertEqual(projected["if_vex_exp"][0][1], 0)
        self.assertEqual(len(raw.rows["operand"]), 3)

    def test_register_access_widths_and_alias_names_remain_distinct(self):
        offset = archinfo.ArchAMD64().registers["rax"][0]
        stmts = [pyvex.IRStmt.WrTmp(index, pyvex.IRExpr.Get(offset, ty))
                 for index, ty in enumerate(("Ity_I8", "Ity_I32", "Ity_I64"))]
        raw = synthetic(stmts, ["Ity_I8", "Ity_I32", "Ity_I64"])
        self.assertEqual(set(raw.rows["register"]), {(offset, 8, "al"), (offset, 32, "eax"), (offset, 64, "rax")})
        projected = Projection(raw).project()
        self.assertEqual({name for _, name in projected["get_loc_vex_exp"]}, {"rax"})

    def test_guarded_accesses_preserve_guard_conversion_width_and_endness(self):
        raw = synthetic([
            pyvex.IRStmt.LoadG("Iend_LE", "ILGop_8Uto32", 0, const(0x500000), const(17, 32), const(1, 1)),
            pyvex.IRStmt.StoreG("Iend_BE", const(0x500004), const(29, 32), const(0, 1)),
        ], ["Ity_I32"])
        load = raw.rows["guarded_load"][0]
        self.assertEqual(load[6:], (8, 32, "ILGop_8Uto32", "Iend_LE"))
        self.assertEqual(raw.rows["guarded_store"][0][4:], (32, "Iend_BE"))
        values = {eid: int(value, 16) for eid, _, value in raw.rows["constant"]}
        self.assertEqual(values[load[4]], 17)
        self.assertEqual(values[load[5]], 1)
        self.assertEqual(values[raw.rows["guarded_store"][0][3]], 0)
        self.assertFalse(Projection(raw).project()["set_mem_vex"])

    def test_wide_constants_and_vector_sized_stores_are_not_truncated(self):
        value = (1 << 127) + 0x123456789abcdef0
        raw = synthetic([pyvex.IRStmt.Store(const(0x500000), const(value, 128), "Iend_LE")])
        self.assertEqual(raw.rows["store"][0][3], 128)
        self.assertTrue(any(bits == 128 and int(hexadecimal, 16) == value
                            for _, bits, hexadecimal in raw.rows["constant"]))

    def test_signed_unsigned_opcodes_and_casts_remain_in_raw_facts(self):
        raw = synthetic([
            pyvex.IRStmt.WrTmp(0, pyvex.IRExpr.Binop("Iop_CmpLT64S", [const(2**64 - 1), const(0)])),
            pyvex.IRStmt.WrTmp(1, pyvex.IRExpr.Binop("Iop_CmpLT64U", [const(2**64 - 1), const(0)])),
            pyvex.IRStmt.WrTmp(2, pyvex.IRExpr.Unop("Iop_32Uto64", [const(2**32 - 1, 32)])),
        ], ["Ity_I1", "Ity_I1", "Ity_I64"])
        self.assertEqual({op for _, op in raw.rows["operation"]}, {"Iop_CmpLT64S", "Iop_CmpLT64U", "Iop_32Uto64"})
        projected = Projection(raw).project()
        self.assertEqual([row[2] for row in projected["binop_dl_exp"]], ["<", "<"])
        self.assertEqual(projected["cast_u_dl_exp"][0][1:3], (32, 64))
        self.assertEqual(short_binop("Iop_ExpCmpNE64"), ("CmpNE", 64))

    def test_unmodeled_operations_are_marked_without_invented_effects(self):
        expr = pyvex.IRExpr.GetI(pyvex.IRRegArray(0, "Ity_I64", 2), const(0, 32), 0)
        raw = synthetic([pyvex.IRStmt.WrTmp(0, expr), pyvex.IRStmt.MBE("Imbe_Fence")], ["Ity_I64"])
        self.assertEqual(raw.rows["unmodeled_expression"][0][1], "Iex_GetI")
        self.assertEqual(raw.rows["unmodeled_statement"][0][1], "Ist_MBE")
        self.assertFalse(Projection(raw).project()["set_tmp_reg_vex"])

    def test_projection_expands_composite_operations_and_keeps_origins(self):
        raw = synthetic([
            pyvex.IRStmt.WrTmp(0, pyvex.IRExpr.Unop("Iop_64HIto32", [const(0x123456789abcdef0)])),
            pyvex.IRStmt.WrTmp(1, pyvex.IRExpr.Binop("Iop_32HLto64", [const(0x1234, 32), const(0x5678, 32)])),
            pyvex.IRStmt.WrTmp(2, pyvex.IRExpr.Binop("Iop_DivModU64to32", [const(13), const(5, 32)])),
        ], ["Ity_I32", "Ity_I64", "Ity_I64"])
        projected = Projection(raw).project()
        self.assertEqual({row[2] for row in projected["binop_dl_exp"]}, {"bshru", "bshl", "bor", "/", "%"})
        origins = dict(projected["expression_origin"])
        raw_ids = {row[0] for row in raw.rows["expression"]}
        new_operations = {row[0] for row in projected["binop_dl_exp"] if row[0] not in raw_ids}
        self.assertTrue(new_operations)
        self.assertTrue(all(origins[eid] in raw_ids for eid in new_operations))


class VexIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.infos = {bits: load_elf(BINARIES / f"test_{bits}") for bits in (64, 32)}
        cls.cfgs = {bits: build_cfg(info).cfg_document() for bits, info in cls.infos.items()}
        cls.results = {bits: extract_vex(info, cls.cfgs[bits]) for bits, info in cls.infos.items()}

    def test_all_m2_blocks_and_owners_are_retained_without_cfgfast(self):
        for bits, result in self.results.items():
            with self.subTest(bits=bits):
                self.assertEqual(result.metadata["status"], "complete")
                self.assertEqual({r[0] for r in result.rows["block_exit"]}, {b["address"] for b in self.cfgs[bits]["blocks"]})
                self.assertEqual(set(result.rows["block_function"]),
                                 {(b["address"], owner) for b in self.cfgs[bits]["blocks"] for owner in b["function_entries"]})
                self.assertTrue(any(not b["function_entries"] for b in self.cfgs[bits]["blocks"]))
        cfg = deepcopy(self.cfgs[64])
        cfg["blocks"][0]["function_entries"] = [0x1000, 0x2000]
        with patch("angr.analyses.cfg.cfg_fast.CFGFast.__init__", side_effect=AssertionError("CFGFast rerun")):
            result = extract_vex(self.infos[64], cfg)
        self.assertIn((cfg["blocks"][0]["address"], 0x1000), result.rows["block_function"])
        self.assertIn((cfg["blocks"][0]["address"], 0x2000), result.rows["block_function"])

    def test_calls_and_returns_keep_stack_effects_and_unresolved_status(self):
        for bits, result in self.results.items():
            with self.subTest(bits=bits):
                cfg_calls = {t["address"]: t for t in self.cfgs[bits]["transfers"] if t["kind"] == "call"}
                self.assertTrue(cfg_calls)
                links = {sid: (site, kind) for sid, site, kind in result.rows["transfer_statement"]}
                call_stores = {links[sid][0] for sid, *_ in result.rows["store"]
                               if sid in links and links[sid][1] == "call"}
                self.assertEqual(call_stores, set(cfg_calls))
                registers = {(offset, width): name for offset, width, name in result.rows["register"]}
                return_sp = [sid for sid, offset, width, _ in result.rows["register_write"]
                             if sid in links and links[sid][1] == "return" and registers[(offset, width)] in ("rsp", "esp")]
                self.assertTrue(return_sp)
                self.assertEqual({site for _, site, kind, indirect, status in result.rows["control_transfer"]
                                  if kind == "call" and indirect and status == "unresolved"},
                                 {t["address"] for t in cfg_calls.values() if t["indirect"] and t["status"] == "unresolved"})

    def test_initial_memory_contains_function_table_and_zero_bss(self):
        for bits, result in self.results.items():
            info = self.infos[bits]
            chunks = [(a, bytes.fromhex(h)) for a, _, h in result.rows["initial_memory"]]

            def read(address, size):
                return next(data[address - base:address - base + size] for base, data in chunks
                            if base <= address and address + size <= base + len(data))

            symbols = {s.name: s for s in info.symbols}
            word = bits // 8
            for index, name in enumerate(("add", "subtract")):
                value = int.from_bytes(read(symbols["operations"].elf_address + index * word, word), "little")
                self.assertEqual(value, symbols[name].mapped_address)
            self.assertEqual(read(symbols["zero_buffer"].elf_address, 256), bytes(256))

    def test_identity_and_lifting_options_are_checked(self):
        for bad_info in (replace(self.infos[64], sha256="0" * 64), replace(self.infos[64], mapped_entry=0)):
            with self.assertRaises(VEXError):
                extract_vex(bad_info, self.cfgs[64])
        for field, value in (("binary_sha256", "wrong"), ("address_space", "rva"), ("arch", "X86")):
            cfg = deepcopy(self.cfgs[64])
            cfg[field] = value
            with self.assertRaises(VEXError):
                extract_vex(self.infos[64], cfg)
        cfg = deepcopy(self.cfgs[64])
        cfg["options"]["vex_lift_options"]["opt_level"] = 0
        with self.assertRaises(VEXError):
            extract_vex(self.infos[64], cfg)

    def test_roundtrip_determinism_and_corruption_detection(self):
        result = self.results[64]
        self.assertEqual(result.rows, extract_vex(self.infos[64], self.cfgs[64]).rows)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_facts(result, root)
            self.assertEqual(read_facts(root).rows, result.rows)
            (root / "constant.facts").write_text("corrupt\n")
            with self.assertRaisesRegex(ValueError, "checksum"):
                read_facts(root)

    def test_downstream_fact_reader_does_not_import_angr(self):
        completed = subprocess.run([sys.executable, "-c",
                                    "import sys; from bpa.vex import read_facts; assert 'angr' not in sys.modules"],
                                   cwd=ROOT, capture_output=True, text=True, timeout=10)
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_validator_rejects_dangling_references_and_overlapping_ids(self):
        raw = deepcopy(self.results[64])
        raw.rows["load"][0] = (raw.rows["load"][0][0], 2**63, 64, "Iend_LE")
        with self.assertRaisesRegex(ValueError, "Dangling"):
            raw.validate()
        raw = deepcopy(self.results[64])
        row = raw.rows["expression"][0]
        raw.rows["expression"].append((raw.rows["statement"][0][0], *row[1:]))
        with self.assertRaisesRegex(ValueError, "disjoint"):
            raw.validate()

    def test_output_guards_and_symbol_escaping(self):
        raw = deepcopy(self.results[64])
        raw.add("diagnostic", "warning", "escape", 0, 0, 0, 'a\tb\nc\\t"d')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input"
            source.write_bytes(b"keep")
            (root / "constant.facts").symlink_to(source)
            with self.assertRaisesRegex(ValueError, "overwrite"):
                write_facts(raw, root, protected=[source])
            self.assertEqual(source.read_bytes(), b"keep")
            (root / "constant.facts").unlink()
            write_facts(raw, root)
            self.assertEqual(read_facts(root).rows["diagnostic"][-1][-1], 'a\tb\nc\\t"d')

    def test_existing_artifacts_cli_and_pipeline_do_not_rebuild_cfg(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_m3(self.infos[64].path, root / "source")
            m1, m2 = root / "source/m1/binary.json", root / "source/m2/cfg.json"
            before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in (m1, m2)}
            with patch("bpa.pipeline.build_cfg", side_effect=AssertionError("CFG rebuilt")):
                result = run_m3(self.infos[64].path, root / "reused", m1_path=m1, m2_path=m2)
            self.assertEqual(result.rows, self.results[64].rows)
            completed = subprocess.run([sys.executable, "-m", "bpa", self.infos[32].path,
                                        "--stage", "m3", "-o", str(root / "cli32")],
                                       cwd=ROOT, capture_output=True, text=True, timeout=30)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(read_facts(root / "cli32/m3").metadata["bits"], 32)
            self.assertEqual(before, {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in before})

    def test_lift_failures_are_partial_not_silent_success(self):
        import angr
        with patch("angr.factory.AngrObjectFactory.block", side_effect=angr.errors.SimEngineError("test failure")):
            raw = extract_vex(self.infos[64], self.cfgs[64])
        self.assertEqual(raw.metadata["status"], "partial")
        self.assertEqual(raw.metadata["lifted_blocks"], 0)
        self.assertEqual(len(raw.rows["block"]), len(self.cfgs[64]["blocks"]))
        self.assertTrue(all(row[0] == "error" for row in raw.rows["diagnostic"]))

    def test_pie_elf_locations_stay_stable_and_relocated_pointers_remain_mapped(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "test_pie"
            subprocess.run(["gcc", "-g", "-O0", "-fPIE", "-pie", str(ROOT / "tests/fixtures/sources/test.c"), "-o", str(binary)],
                           check=True, capture_output=True, text=True)
            block_sets = []
            for base in (0x400000, 0x600000):
                info = load_elf(binary, mapped_base=base)
                cfg = build_cfg(info).cfg_document()
                raw = extract_vex(info, cfg)
                self.assertEqual(raw.metadata["status"], "complete")
                block_sets.append({row[0] for row in raw.rows["block"]})
                symbols = {s.name: s for s in info.symbols}
                table = symbols["operations"].elf_address
                address, _, hexadecimal = next(row for row in raw.rows["initial_memory"] if row[0] <= table < row[0] + row[1])
                data = bytes.fromhex(hexadecimal)
                pointer = int.from_bytes(data[table - address:table - address + 8], "little")
                self.assertEqual(pointer, symbols["add"].elf_address + info.load_bias)
                self.assertNotEqual(pointer, symbols["add"].elf_address)
                self.assertTrue(any(int(value, 16) == symbols["add"].mapped_address
                                    for _, _, value in raw.rows["constant"]))
            self.assertEqual(block_sets[0], block_sets[1])
