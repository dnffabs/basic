"""Lift M2 blocks, never discover a replacement CFG or evaluate program values."""

import hashlib
from io import BytesIO
from pathlib import Path

import angr
import cle
import pyvex

from bpa.lifting import VEX_LIFT_OPTIONS
from bpa.model import BinaryInfo
from .facts import FactResult


class VEXError(ValueError):
    """M1/M2 inputs do not describe the same supported binary and address layout."""


class VexExtractor:
    """Per-extraction IDs and per-block temporary identity; no global mutable state."""

    def __init__(self, result, arch, load_bias):
        self.result, self.arch, self.bias = result, arch, load_bias
        self.next_id = 1
        self.registers = set()

    def fresh(self):
        identity = self.next_id
        self.next_id += 1
        return identity

    def diagnostic(self, code, detail, severity="warning"):
        self.result.add("diagnostic", severity, code, self.bb, self.instruction, self.position, str(detail))

    def register(self, offset, bits):
        key = (offset, bits)
        if key not in self.registers:
            self.registers.add(key)
            name = self.arch.translate_register_name(offset, max(1, bits // 8))
            self.result.add("register", offset, bits, name)

    def temporary(self, index):
        if index not in self.temporaries:
            self.temporaries.add(index)
            self.result.add("temporary", self.bb, index, pyvex.get_type_size(self.tyenv.lookup(index)))

    def expr(self, expression):
        eid = self.fresh()
        bits = expression.result_size(self.tyenv)
        self.result.add("expression", eid, self.sid, bits, expression.tag)
        if isinstance(expression, pyvex.IRExpr.RdTmp):
            self.temporary(expression.tmp)
            self.result.add("temporary_read", eid, self.bb, expression.tmp)
        elif isinstance(expression, pyvex.IRExpr.Const) and type(expression.con.value) is int:
            value = expression.con.value & ((1 << bits) - 1)
            self.result.add("constant", eid, bits, f"0x{value:0{(bits + 3) // 4}x}")
        elif isinstance(expression, pyvex.IRExpr.Get):
            self.register(expression.offset, bits)
            self.result.add("register_read", eid, expression.offset, bits)
        elif isinstance(expression, pyvex.IRExpr.Load):
            self.result.add("load", eid, self.expr(expression.addr), bits, expression.end)
        elif isinstance(expression, (pyvex.IRExpr.Unop, pyvex.IRExpr.Binop)):
            self.result.add("operation", eid, expression.op)
            for index, argument in enumerate(expression.args):
                self.result.add("operand", eid, index, self.expr(argument))
        elif isinstance(expression, pyvex.IRExpr.ITE):
            self.result.add("operation", eid, "ITE")
            # pyvex's constructor takes (cond, iffalse, iftrue); use named attributes.
            for index, argument in enumerate((expression.cond, expression.iftrue, expression.iffalse)):
                self.result.add("operand", eid, index, self.expr(argument))
        elif isinstance(expression, pyvex.IRExpr.CCall):
            # Conditions can depend on lazy flag helpers; retain structure, not a new helper model.
            self.result.add("operation", eid, "CCall:" + expression.cee.name)
            for index, argument in enumerate(expression.args):
                self.result.add("operand", eid, index, self.expr(argument))
            self.result.add("unmodeled_expression", eid, expression.tag, str(expression))
            self.diagnostic("helper_requires_model", expression.cee.name)
        else:
            # BPA-X does not model GetI/Triop/Qop or non-integer constants.
            self.result.add("unmodeled_expression", eid, expression.tag, str(expression))
            self.diagnostic("unmodeled_expression", expression.tag)
        return eid

    def extract(self, irsb, block):
        self.bb = block["address"]
        self.instruction = self.bb
        self.tyenv, self.temporaries = irsb.tyenv, set()
        order = 0
        for self.position, stmt in enumerate(irsb.statements):
            if isinstance(stmt, pyvex.IRStmt.IMark):
                self.instruction = stmt.addr + stmt.delta - self.bias
                order = 0
            else:
                order += 1
            self.sid = self.fresh()
            self.result.add("statement", self.sid, self.bb, self.position, self.instruction, order, stmt.tag)
            if isinstance(stmt, pyvex.IRStmt.WrTmp):
                self.temporary(stmt.tmp)
                self.result.add("temporary_write", self.sid, self.bb, stmt.tmp, self.expr(stmt.data))
            elif isinstance(stmt, pyvex.IRStmt.Put):
                bits = stmt.data.result_size(self.tyenv)
                self.register(stmt.offset, bits)
                self.result.add("register_write", self.sid, stmt.offset, bits, self.expr(stmt.data))
            elif isinstance(stmt, pyvex.IRStmt.Store):
                self.result.add("store", self.sid, self.expr(stmt.addr), self.expr(stmt.data),
                                stmt.data.result_size(self.tyenv), stmt.end)
            elif isinstance(stmt, pyvex.IRStmt.Exit):
                self.result.add("branch", self.sid, self.expr(stmt.guard),
                                self.expr(pyvex.IRExpr.Const(stmt.dst)), stmt.jumpkind)
            elif isinstance(stmt, pyvex.IRStmt.StoreG):
                self.result.add("guarded_store", self.sid, self.expr(stmt.addr), self.expr(stmt.data),
                                self.expr(stmt.guard), stmt.data.result_size(self.tyenv), stmt.end)
            elif isinstance(stmt, pyvex.IRStmt.LoadG):
                self.temporary(stmt.dst)
                self.result.add("guarded_load", self.sid, self.bb, stmt.dst, self.expr(stmt.addr),
                                self.expr(stmt.alt), self.expr(stmt.guard),
                                pyvex.get_type_size(stmt.cvt_types[0]),
                                pyvex.get_type_size(stmt.cvt_types[1]), stmt.cvt, stmt.end)
            elif isinstance(stmt, (pyvex.IRStmt.IMark, pyvex.IRStmt.NoOp, pyvex.IRStmt.AbiHint)):
                pass
            else:
                # As in BPA-X, no semantics for Dirty/PutI/CAS/LLSC/MBE.
                self.result.add("unmodeled_statement", self.sid, stmt.tag, str(stmt))
                self.diagnostic("unmodeled_statement", stmt.tag)
        self.position = len(irsb.statements)
        self.instruction = block["instructions"][-1]["address"]
        self.sid = self.fresh()
        self.result.add("statement", self.sid, self.bb, self.position, self.instruction, order + 1, "Terminator")
        self.result.add("block_exit", self.bb, self.sid, self.expr(irsb.next), irsb.jumpkind)


def _validate_inputs(info, cfg, data):
    if info.schema_version != 2 or info.address_space != "elf-va":
        raise VEXError("M3 requires M1 schema 2 with address_space=elf-va")
    if info.arch not in ("AMD64", "X86") or info.bits != {"AMD64": 64, "X86": 32}.get(info.arch) or info.endianness != "little":
        raise VEXError("M3 currently supports little-endian AMD64/X86")
    if info.auto_load_libs or info.loader_backend != "cle" or info.loader_version != cle.__version__:
        raise VEXError("M1 loader policy/version differs; regenerate M1")
    if hashlib.sha256(data).hexdigest() != info.sha256:
        raise VEXError("ELF SHA256 does not match M1")
    expected = dict(schema_version=1, stage="M2", kind="cfg", address_space="elf-va",
                    binary_sha256=info.sha256, arch=info.arch, bits=info.bits, entry=info.entry,
                    backend="angr.CFGFast", backend_version=angr.__version__)
    if any(cfg.get(key) != value for key, value in expected.items()):
        raise VEXError("M2 identity, schema, address space or backend does not match M1/M3")
    # Older M2 artifacts used these pinned defaults implicitly; verify their decode below.
    options = cfg.get("options", {}).get("vex_lift_options")
    if options is not None and options != VEX_LIFT_OPTIONS:
        raise VEXError("M2 VEX lifting configuration differs from M3")
    blocks = cfg["blocks"]
    addresses = {b["address"] for b in blocks}
    if not blocks or len(addresses) != len(blocks):
        raise VEXError("M2 requires nonempty blocks with unique addresses")
    for block in blocks:
        if type(block["address"]) is not int or block["address"] < 0 or block["size"] <= 0:
            raise VEXError("Invalid M2 block range")
        cursor = block["address"]
        for instruction in block["instructions"]:
            if instruction["address"] != cursor or instruction["size"] <= 0:
                raise VEXError("M2 instruction ranges are inconsistent")
            cursor += instruction["size"]
        if cursor != block["address"] + block["size"]:
            raise VEXError("M2 block size does not match its instructions")
        if not any(r.start <= block["address"] and cursor <= r.end for r in info.executable_regions):
            raise VEXError("M2 block is outside M1 executable regions")
    by_address = {b["address"]: b for b in blocks}
    for transfer in cfg["transfers"]:
        block = by_address.get(transfer["block"])
        if block is None or transfer["address"] != block["instructions"][-1]["address"]:
            raise VEXError("M2 transfer is not at the end of its block")


def extract_vex(info: BinaryInfo, cfg: dict) -> FactResult:
    """Consume M1 and the M2 cfg document; return serializable raw facts, never run CFGFast."""
    data = Path(info.path).read_bytes()
    _validate_inputs(info, cfg, data)
    project = angr.Project(BytesIO(data), auto_load_libs=False, main_opts={"base_addr": info.mapped_base})
    obj = project.loader.main_object
    if (obj.arch.name, obj.linked_base, obj.mapped_base, obj.entry) != (
            info.arch, info.linked_base, info.mapped_base, info.mapped_entry) or info.entry + info.load_bias != info.mapped_entry:
        raise VEXError("M3 loaded architecture, bases or entry differs from M1")
    result = FactResult.empty(dict(binary_path=info.path, binary_sha256=info.sha256,
                                  arch=info.arch, bits=info.bits, endianness=info.endianness,
                                  linked_base=info.linked_base, mapped_base=info.mapped_base,
                                  load_bias=info.load_bias,
                                  versions=dict(angr=angr.__version__, cle=cle.__version__, pyvex=pyvex.__version__),
                                  lift_options=dict(VEX_LIFT_OPTIONS),
                                  m2_lift_options_explicit="vex_lift_options" in cfg.get("options", {}),
                                  constant_semantics="raw VEX bitvectors; no address rebasing",
                                  initial_memory_semantics="CLE relocated bytes; locations are ELF VA, embedded pointers may be mapped VA"))
    extractor = VexExtractor(result, project.arch, info.load_bias)
    for block in sorted(cfg["blocks"], key=lambda b: b["address"]):
        address, size = block["address"], block["size"]
        for owner in sorted(set(block["function_entries"])):
            result.add("block_function", address, owner)
        for instruction in block["instructions"]:
            result.add("instruction", address, instruction["address"], instruction["size"],
                       instruction["mnemonic"], instruction["operands"])
        try:
            irsb = project.factory.block(address + info.load_bias, size=size, **VEX_LIFT_OPTIONS).vex
        except (angr.errors.AngrError, angr.errors.SimError, pyvex.PyVEXError) as error:
            result.add("block", address, size, 0, block["jumpkind"])
            result.add("diagnostic", "error", "lift_failed", address, address, 0, str(error))
            continue
        result.add("block", address, size, irsb.size, irsb.jumpkind)
        marks = [(stmt.addr + stmt.delta - info.load_bias, stmt.len)
                 for stmt in irsb.statements if isinstance(stmt, pyvex.IRStmt.IMark)]
        expected = [(i["address"], i["size"]) for i in block["instructions"]]
        if irsb.size != size or marks != expected or irsb.jumpkind != block["jumpkind"]:
            result.add("diagnostic", "error", "lift_range_mismatch", address, address, 0,
                       f"M2 size/kind={size}/{block['jumpkind']}; VEX={irsb.size}/{irsb.jumpkind}; IMarks match={marks == expected}")
            continue
        extractor.extract(irsb, block)
    for edge in cfg["edges"]:
        if edge["target"] is not None:
            result.add("cfg_edge", edge["source"], edge["target"], edge["kind"], edge["provenance"])
        elif edge["external_symbol"] is not None:
            result.add("cfg_external_edge", edge["source"], edge["external_symbol"], edge["kind"], edge["provenance"])
    for transfer in sorted(cfg["transfers"], key=lambda t: (t["block"], t["address"])):
        site = transfer["address"]
        result.add("control_transfer", transfer["block"], site, transfer["kind"], int(transfer["indirect"]), transfer["status"])
        if transfer["continuation"] is not None:
            result.add("continuation", site, transfer["continuation"])
        for target in transfer["targets"]:
            result.add("known_target", site, target)
        for target in transfer["external_targets"]:
            result.add("external_target", site, target)
    transfers = {(t["block"], t["address"]): t for t in cfg["transfers"] if t["kind"] in ("call", "return")}
    for sid, block, _, instruction, _, tag in result.rows["statement"]:
        transfer = transfers.get((block, instruction))
        if transfer and tag not in ("Ist_IMark", "Terminator"):
            result.add("transfer_statement", sid, instruction, transfer["kind"])
    # Snapshot only M1's global regions, not the whole address space or extern memory.
    for region in info.global_regions:
        for address in range(region.start, region.end, 4096):
            size = min(4096, region.end - address)
            raw = project.loader.memory.load(address + info.load_bias, size)
            result.add("initial_memory", address, size, raw.hex())
    errors = sum(row[0] == "error" for row in result.rows["diagnostic"])
    result.metadata.update(status="partial" if errors else "complete",
                           input_blocks=len(cfg["blocks"]), lifted_blocks=len(result.rows["block_exit"]),
                           unmodeled_expressions=len(result.rows["unmodeled_expression"]),
                           unmodeled_statements=len(result.rows["unmodeled_statement"]))
    result.validate()
    return result
