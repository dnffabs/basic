"""Adapt M3–M5 artifacts to the M6 Soufflé solver and publish its results."""

from bisect import bisect_right
from collections import defaultdict
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from networkx import DiGraph, strongly_connected_components

from bpa.artifacts import write_json
from bpa.model import BinaryInfo
from bpa.vex import read_facts


RULES = Path(__file__).with_name("values.dl")
COLUMNS = {
    "expr_value": "context expression kind base frame offset offset_known",
    "access_target": "context kind access block_kind block frame offset offset_known bits",
    "load_source": "context kind access source_context source_kind source",
    "call_operand_value": "context call_site expression kind target",
}
INPUTS = """seed def_seed def_rhs read_def partial copy cast select_value arithmetic numeric
    number_value pointer_size limits alias displacement flow root load_at store_at access_seed
    seeded strong havoc stack_transfer image indirect_operand readonly_global guarded_result expression
    global_start comparison""".split()
UNKNOWN = ("unknown", 0, 0, 0, 0)
LIMIT = 1 << 60
CAST = re.compile(r"Iop_(\d+)(HI|U|S)?to(\d+)$")
BINARY = re.compile(r"Iop_(Add|Sub|Mul|And|Or|Xor|Shl|Shr|Sar|CmpEQ|CmpNE)(\d+)$")


def _digest(data):
    return hashlib.sha256(data).hexdigest()


class StageFacts:
    def __init__(self, path, stage, m3_hash, binary_hash):
        manifest = (path / "manifest.json").read_bytes()
        self.digest = _digest(manifest)
        self.meta = json.loads(manifest)
        expected = dict(schema=f"bpa.{stage}.v1", address_space="elf-va",
                        m3_manifest_sha256=m3_hash, binary_sha256=binary_hash)
        if any(self.meta.get(key) != val for key, val in expected.items()):
            raise ValueError(f"M6 {stage.upper()} artifacts do not match the M3 input")
        self.directory = path / self.meta["facts_dir"]

    def read(self, name):
        return list(self.iter_rows(name))

    def iter_rows(self, name):
        """Stream a large relation and validate it when the reader reaches EOF."""
        filename = f"{name}.facts"
        path = self.directory / filename
        digest = hashlib.sha256()
        count, columns = 0, len(self.meta["columns"][name])
        with path.open("rb") as stream:
            for line in stream:
                digest.update(line)
                row = line.decode().rstrip("\r\n").split("\t")
                if len(row) != columns:
                    raise ValueError(f"Invalid relation row: {path}")
                count += 1
                yield row
        if count != self.meta["counts"].get(name) or digest.hexdigest() != self.meta["files"].get(filename):
            raise ValueError(f"Upstream relation checksum or count mismatch: {path}")


def _signed(value, bits):
    return (value ^ (1 << (bits - 1))) - (1 << (bits - 1))


def _cast_shape(op):
    match = CAST.fullmatch(op)
    if match:
        source, mode, result = match.groups()
        source, result = int(source), int(result)
        if source <= 64 and result <= 64:
            return (source - result if mode == "HI" else 0), result, source if mode == "S" else 0
    return None


def _constants(rows, operands, ops, bits):
    """Fold the literal-only VEX expression trees before entering the finite solver."""
    constants = {eid: int(hexadecimal, 16) for eid, width, hexadecimal in rows["constant"] if width <= 64}
    for eid in sorted(ops, reverse=True):  # M3 allocates the parent ID before its operands.
        op, args = ops[eid], operands[eid]
        if bits[eid] > 64 or any(arg not in constants for arg in args):
            continue
        values = [constants[arg] for arg in args]
        shape = _cast_shape(op)
        match = BINARY.fullmatch(op)
        if op == "ITE":
            result = values[1] if values[0] else values[2]
        elif shape:
            low, _, sign = shape
            result = _signed(values[0], sign) if sign else values[0] >> low
        elif match:
            name, width = match.groups()
            a, b = values
            width = int(width)
            if name == "CmpEQ":
                result = int(a == b)
            elif name == "CmpNE":
                result = int(a != b)
            elif name == "Shl":
                result = a << b if b < width else 0
            elif name == "Shr":
                result = a >> b if b < width else 0
            elif name == "Sar":
                result = _signed(a, width) >> min(b, width - 1)
            else:
                result = {"Add": a + b, "Sub": a - b, "Mul": a * b,
                          "And": a & b, "Or": a | b, "Xor": a ^ b}[name]
        else:
            continue
        constants[eid] = result & ((1 << bits[eid]) - 1)
    return constants


class Inputs:
    def __init__(self, rows, info, m4, m5, functions):
        self.rows, self.info, self.m4, self.m5 = rows, info, m4, m5
        self.facts = defaultdict(set)
        self.functions = {f["entry"] for f in functions} | {stub.elf_address for stub in info.plt}
        self.facts["pointer_size"].add((info.bits,))
        self.bits = {eid: width for eid, _, width, _ in rows["expression"]}
        self.stmts = {sid: (block, pos, pc) for sid, block, pos, pc, _, _ in rows["statement"]}
        self.expr_stmt = {eid: sid for eid, sid, _, _ in rows["expression"]}
        self.contexts = {int(c): (int(entry), int(site), kind) for c, entry, site, kind in m5.read("context")}
        self.active = defaultdict(set)
        for ctx, block in m5.read("context_block"):
            self.active[int(block)].add(int(ctx))
        self.call_links = [tuple(map(int, row)) for row in m5.read("call_link")]
        self.tail_links = [tuple(map(int, row)) for row in m5.read("tail_link")] if "tail_link" in m5.meta["columns"] else []
        self.return_links = [tuple(map(int, row)) for row in m5.read("return_link")]
        self.opaques = [(ctx, block, site, ctx, dest) for ctx, block, site, dest in
                        (tuple(map(int, row)) for row in m5.read("opaque_return"))]
        if "opaque_tail_return" in m5.meta["columns"]:
            self.opaques.extend(tuple(map(int, row)) for row in m5.read("opaque_tail_return"))
        jump_blocks = {site: block for block, site, kind, _, _ in rows["control_transfer"] if kind == "jump"}
        self.tail_edges = {(jump_blocks[site], target) for site, target in m5.meta.get("additional_tail_targets", [])}
        self.owners = defaultdict(set)
        for block, owner in rows["block_function"]:
            self.owners[block].add(owner)
        self.globals = sorted((int(lo), int(hi), int(bid)) for bid, lo, hi, lf, hf in m4.read("mloc_gblk")
                              if int(lf) and int(hf) and int(lo) < int(hi))
        self.global_starts = [lo for lo, _, _ in self.globals]
        self.global_bounds = {bid: (lo, hi) for lo, hi, bid in self.globals}
        self.regions = sorted((r.start, r.end) for r in info.global_regions)
        self.region_starts = [lo for lo, _ in self.regions]
        self.stacks = {}
        self.frame_blocks = defaultdict(list)
        for bid, owner, lo, hi, lf, hf, site in m4.read("mloc_sblk"):
            bid, owner, site = int(bid), int(owner), int(site)
            low, high = int(lo) if int(lf) else -LIMIT, int(hi) if int(hf) else LIMIT
            self.stacks[bid] = (owner, low, high, site)
            if not site:
                self.frame_blocks[owner].append((low, high, bid))
        self.heaps = {int(site): int(bid) for bid, site in m4.read("mloc_hblk")}
        self.ops = dict(rows["operation"])
        args = defaultdict(list)
        for expr, index, child in rows["operand"]:
            args[expr].append((index, child))
        self.args = {eid: [child for _, child in sorted(ordered)] for eid, ordered in args.items()}
        self.args = defaultdict(list, self.args)
        self.constants = _constants(rows, self.args, self.ops, self.bits)
        self.numbers = {0, 1, *self.constants.values()}
        self.temporary_sources = {(block, tmp): expr for _, block, tmp, expr in rows["temporary_write"]}
        self.temporary_reads = {expr: (block, tmp) for expr, block, tmp in rows["temporary_read"]}
        self.register_names = {int(reg): name for reg, _, name in m5.read("register_bank")}
        frame_regs = {reg for reg, name in self.register_names.items() if name in ("rsp", "rbp", "esp", "ebp")}
        self.read_ranges = {int(e): (int(reg), int(low), int(bits)) for e, reg, low, bits in m5.read("register_read")}
        self.frame_reads = {e for e, (reg, low, bits) in self.read_ranges.items()
                            if reg in frame_regs and not low and bits == info.bits}
        self.read_defs = defaultdict(set)
        for c, e, o, d in m5.read("register_read_def"):
            self.read_defs[int(c), int(e)].add((int(o), int(d)))
        self.definitions = {int(d): (int(block), int(stmt), int(reg), int(low), int(bits), int(expr), kind, int(site))
                            for d, block, stmt, reg, low, bits, expr, kind, site in m5.read("register_def")}
        self.pc_values = self._x86_pc_values() if info.arch == "X86" else {}
        self.numbers.update(self.pc_values.values())

    def _x86_pc_values(self):
        """Fold addresses derived from a verified mov reg,[esp]; ret PC thunk."""
        instructions = defaultdict(list)
        sizes = {}
        for block, pc, size, mnemonic, operands in self.rows["instruction"]:
            instructions[block].append((pc, mnemonic, operands))
            sizes[pc] = size
        loads = {expr for expr, _, bits, _ in self.rows["load"] if bits == 32}
        defs_by_block = defaultdict(list)
        for block, stmt, reg, _, width, rhs, kind, _ in self.definitions.values():
            source = self.temporary_sources.get(self.temporary_reads.get(rhs), rhs)
            if kind == "write" and width == 32 and source in loads:
                defs_by_block[block].append((self.stmts[stmt][2], self.register_names[reg], source))
        seeds = {}
        for _, _, site, callee, entry in self.call_links:
            body = sorted(instructions[entry])
            if len(body) != 2 or body[0][1] != "mov" or body[1][1:] != ("ret", ""):
                continue
            destination, sep, source = body[0][2].partition(", ")
            if sep and source == "dword ptr [esp]":
                for pc, reg, rhs in defs_by_block[entry]:
                    if pc == body[0][0] and reg == destination:
                        seeds[callee, rhs] = (site + sizes[site] + self.info.load_bias, True)
        if not seeds:
            return {}

        @lru_cache(maxsize=None)
        def evaluate(ctx, expr, depth):
            if not depth:
                return None
            if (ctx, expr) in seeds:
                return seeds[ctx, expr]
            if expr in self.constants:
                return self.constants[expr], False
            source = self.temporary_sources.get(self.temporary_reads.get(expr))
            if source is not None:
                return evaluate(ctx, source, depth - 1)
            reaching = self.read_defs.get((ctx, expr))
            if reaching and self.bits[expr] == 32:
                values = {evaluate(origin, self.definitions[d][5], depth - 1)
                          if self.definitions[d][6] == "write" else None for origin, d in reaching}
                if None not in values and len({value for value, _ in values}) == 1:
                    return next(iter(values))[0], any(pc_relative for _, pc_relative in values)
                return None
            op = self.ops.get(expr)
            if op in ("Iop_Add32", "Iop_Sub32"):
                left, right = (evaluate(ctx, child, depth - 1) for child in self.args[expr])
                if left is not None and right is not None:
                    delta = right[0] if op == "Iop_Add32" else -right[0]
                    return (left[0] + delta) & 0xffffffff, left[1] or right[1]
            return None

        values = {}
        for expr, bits in self.bits.items():
            if bits == 32 and expr not in self.constants:
                for ctx in self.expression_ctx(expr):
                    folded = evaluate(ctx, expr, 32)
                    if folded is not None and folded[1]:
                        values[ctx, expr] = folded[0]
        return values

    @lru_cache(maxsize=None)
    def frame_address(self, expr, depth=32):
        if expr in self.frame_reads:
            return True
        if not depth:
            return False
        source = self.temporary_sources.get(self.temporary_reads.get(expr))
        if source is not None:
            return self.frame_address(source, depth - 1)
        op = self.ops.get(expr)
        if op in (f"Iop_Add{self.info.bits}", f"Iop_Sub{self.info.bits}"):
            lhs, rhs = self.args[expr]
            if rhs in self.constants:
                return self.frame_address(lhs, depth - 1)
            if op.startswith("Iop_Add") and lhs in self.constants:
                return self.frame_address(rhs, depth - 1)
        return False

    def global_at(self, address, size=1):
        index = bisect_right(self.global_starts, address) - 1
        region = bisect_right(self.region_starts, address) - 1
        if index >= 0 and region >= 0:
            lo, hi, bid = self.globals[index]
            if address < hi and address + size <= self.regions[region][1]:
                return "global", bid, 0, address - lo, 1
        return None

    def number(self, raw, bits):
        if bits == self.info.bits:
            va = raw - self.info.load_bias
            if va in self.functions:
                return "function", va, 0, 0, 1
            loc = self.global_at(va)
            if loc:
                return loc
        return "integer", raw, 0, 0, 1

    def stack_at(self, ctx, owner, off):
        for lo, hi, bid in self.frame_blocks[owner]:
            if lo <= off < hi:
                return "stack", bid, ctx, off, 1
        return None

    def expression_ctx(self, expr):
        return self.active[self.stmts[self.expr_stmt[expr]][0]]

    def prepare_values(self):
        r, f = self.rows, self.facts
        temps = {(block, index): expr for _, block, index, expr in r["temporary_write"]}
        temps.update({(block, tmp): sid for sid, block, tmp, *_ in r["guarded_load"]})
        tmp_reads = {eid: (block, tmp) for eid, block, tmp in r["temporary_read"]}
        for key, reaching in self.read_defs.items():
            f["read_def"].update((*key, origin, definition, *self.read_ranges[key[1]][1:])
                                 for origin, definition in reaching if key not in self.pc_values)

        handled_loads = {expr for expr, *_ in r["load"]}
        stack_offsets = defaultdict(set)
        for key, offset in self.m4.read("tmp_reg_offset"):
            stack_offsets[key].add(int(offset))
        tmp_blocks = defaultdict(set)
        for key, bid in self.m4.read("tmp_reg_sblk_id"):
            tmp_blocks[key].add(int(bid))

        for eid, sid, bits, _ in r["expression"]:
            op, args = self.ops.get(eid, ""), self.args[eid]
            cast = _cast_shape(op)
            arithmetic = {f"Iop_Add{self.info.bits}": "add", f"Iop_Sub{self.info.bits}": "sub"}.get(op)
            comparison = re.fullmatch(r"Iop_Cmp(EQ|NE)(?:8|16|32|64)", op)
            for ctx in self.expression_ctx(eid):
                f["expression"].add((ctx, eid))
                stack_hints = set()
                if eid in tmp_reads:
                    block, index = tmp_reads[eid]
                    key = f"{block}_{index}"
                    entry, site, _ = self.contexts[ctx]
                    for bid in tmp_blocks[key]:
                        owner, lo, hi, tag = self.stacks[bid]
                        if (tag and tag != site and tag not in self.block_call_sites[block]) or (
                                owner != entry and owner not in self.owners[block]):
                            continue
                        for off in stack_offsets[key]:
                            loc = self.stack_at(ctx, owner, off)
                            if lo <= off < hi and loc:
                                stack_hints.add(loc)
                f["seed"].update((ctx, eid, loc) for loc in stack_hints)
                if len(stack_hints) == 1 and self.frame_address(eid):
                    continue
                constant = self.pc_values.get((ctx, eid), self.constants.get(eid))
                if constant is not None:
                    val = self.number(constant, bits)
                    f["seed"].add((ctx, eid, val))
                    f["numeric"].add((val, constant))
                elif eid in tmp_reads and tmp_reads[eid] in temps:
                    f["copy"].add((ctx, eid, temps[tmp_reads[eid]]))
                elif (ctx, eid) in self.read_defs or eid in handled_loads:
                    pass
                elif op == "ITE":
                    f["select_value"].add((ctx, eid, *args))
                elif cast:
                    f["cast"].add((ctx, eid, args[0], *cast))
                elif arithmetic:
                    f["arithmetic"].add((ctx, eid, arithmetic, *args))
                elif comparison:
                    f["comparison"].add((ctx, eid, int(comparison[1] == "EQ"), *args))
                else:
                    f["seed"].add((ctx, eid, UNKNOWN))

        definitions, names = self.definitions, self.register_names
        for d, (block, _, reg, _, _, expr, kind, site) in definitions.items():
            for ctx in self.active[block]:
                if kind == "write":
                    f["def_rhs"].add((ctx, d, expr))
                elif kind == "entry" and self.contexts[ctx] == (block, 0, "root"):
                    loc = self.stack_at(ctx, block, 0) if names[reg] in ("rsp", "esp") else None
                    f["def_seed"].add((ctx, d, loc or UNKNOWN))
                elif kind == "clobber":
                    heap = self.heaps.get(site) if names[reg] in ("rax", "eax") else None
                    val = ("heap", heap, 0, 0, 1) if heap is not None else UNKNOWN
                    f["def_seed"].add((ctx, d, val))
                    if heap is not None:
                        f["def_seed"].add((ctx, d, ("integer", 0, 0, 0, 1)))
        for c, d, o, prev in self.m5.read("partial_input"):
            c, d, o, prev = map(int, (c, d, o, prev))
            _, _, _, low, bits, expr, _, _ = definitions[d]
            f["partial"].add((c, d, o, prev, expr, low, bits))
            old_expr = definitions[prev][5]
            if expr in self.constants and old_expr in self.constants:
                mask = (1 << bits) - 1
                self.numbers.add((self.constants[old_expr] & ~(mask << low)) | ((self.constants[expr] & mask) << low))

    def prepare_accesses(self):
        r, f = self.rows, self.facts
        candidates = defaultdict(list)
        for kind, access, area, bid, off, _, basis in self.m4.read("memory_access_block"):
            candidates[kind, int(access)].append((area, int(bid), int(off), basis))
        self.events = defaultdict(set)
        self.block_call_sites = defaultdict(set)
        self.allocators = {}
        allocator_names = {s.elf_address: s.name for s in self.info.plt}
        allocator_names.update({s.elf_address: s.name for s in self.info.symbols if s.is_function and s.elf_address is not None})
        for site, target in r["known_target"]:
            if site in self.heaps:
                self.allocators[site] = allocator_names.get(target, "malloc").split("@")[0]
        for site, name in r["external_target"]:
            if site in self.heaps:
                self.allocators[site] = name.split("@")[0]
        for block, site, kind, *_ in r["control_transfer"]:
            if kind == "call":
                self.block_call_sites[block].add(site)

        transfer = {sid for sid, _, kind in r["transfer_statement"] if kind == "call"}
        call_graph = DiGraph((caller, callee) for caller, _, _, callee, _ in self.call_links + self.tail_links)
        recursive = {ctx for group in strongly_connected_components(call_graph) for ctx in group
                     if len(group) > 1 or call_graph.has_edge(ctx, ctx)}
        self.accesses = []
        for kind, access_rows in (("load", r["load"]), ("store", r["store"]),
                                  ("guarded_load", r["guarded_load"]), ("guarded_store", r["guarded_store"])):
            for row in access_rows:
                access = row[0]
                guard = 0
                if kind == "load":
                    _, addr, width, end = row
                    sid, rhs = self.expr_stmt[access], None
                elif kind == "store":
                    sid, addr, rhs, width, end = row
                elif kind == "guarded_load":
                    sid, _, _, addr, alt, guard, width, result, op, end = row
                    rhs = None
                else:
                    sid, addr, rhs, guard, width, end = row
                block = self.stmts[sid][0]
                self.events[block].add(sid)
                size = (width + 7) // 8
                self.accesses.append((kind, access, sid, size, end))
                for ctx in self.active[block]:
                    if rhs is None:
                        f["load_at"].add((ctx, kind, access, sid, addr, size, end, guard))
                        if kind == "guarded_load":
                            convert = 0 if width == result else 1 if re.search(r"[US]to", op) else 2
                            sign = width if "Sto" in op else 0
                            f["guarded_result"].add((ctx, access, guard, alt, result, sign, convert))
                    else:
                        f["store_at"].add((ctx, kind, access, sid, addr, rhs, size, end, guard))
                    if sid in transfer:
                        f["stack_transfer"].add((ctx, access))
                    # The concrete VEX address is the proof for a strong global write.
                    address = self.pc_values.get((ctx, addr), self.constants.get(addr))
                    direct = self.global_at(address - self.info.load_bias, size) if address is not None else None
                    if direct:
                        f["access_seed"].add((ctx, kind, access, direct))
                        f["seeded"].add((ctx, kind, access))
                        if rhs is not None and not guard and width == size * 8:
                            f["strong"].add((ctx, sid, direct, size))
                    stack_hints = set()
                    for area, bid, off, basis in candidates[kind, access]:
                        if area != "stack":
                            continue
                        owner, lo, _, tag = self.stacks[bid]
                        if tag and tag != self.contexts[ctx][1] and tag not in self.block_call_sites[block]:
                            continue
                        if owner != self.contexts[ctx][0] and owner not in self.owners[block]:
                            continue
                        absolute = off if basis == "entry_sp" else lo + off
                        loc = self.stack_at(ctx, owner, absolute)
                        if loc:
                            stack_hints.add(loc)
                    f["access_seed"].update((ctx, kind, access, loc) for loc in stack_hints)
                    if len(stack_hints) == 1 and self.frame_address(addr):
                        loc, = stack_hints
                        f["seeded"].add((ctx, kind, access))
                        owner, _, hi, _ = self.stacks[loc[1]]
                        if (rhs is not None and not guard and width == size * 8 and ctx not in recursive
                                and owner == self.contexts[ctx][0] and loc[3] + size <= min(hi, 0)):
                            f["strong"].add((ctx, sid, loc, size))

    def prepare_flow(self):
        f, r = self.facts, self.rows
        max_id = max(self.stmts)
        blocks = sorted(self.active)
        endpoints = {b: (max_id + 2*i + 1, max_id + 2*i + 2) for i, b in enumerate(blocks)}
        branches = defaultdict(set)
        for sid, _, target, _ in r["branch"]:
            block = self.stmts[sid][0]
            if target in self.constants and block in endpoints:
                addr = self.constants[target] - self.info.load_bias
                if addr in endpoints:
                    self.events[block].add(sid)
                    branches[block, addr].add(sid)
        for block, (entry, exit_) in endpoints.items():
            points = [entry, *sorted(self.events[block], key=lambda sid: self.stmts[sid][1]), exit_]
            for ctx in self.active[block]:
                f["flow"].update((ctx, a, ctx, b) for a, b in zip(points, points[1:]))
        for source, dest, kind, _ in r["cfg_edge"]:
            if (kind not in ("call", "return", "fake_return") and (source, dest) not in self.tail_edges
                    and dest in endpoints and source in endpoints):
                for ctx in self.active[source] & self.active[dest]:
                    for point in branches.get((source, dest), (endpoints[source][1],)):
                        f["flow"].add((ctx, point, ctx, endpoints[dest][0]))
        exits = {block: target for block, _, target, _ in r["block_exit"]}
        for block, site, kind, indirect, _ in r["control_transfer"]:
            if kind == "call" and indirect:
                f["indirect_operand"].update((ctx, site, exits[block]) for ctx in self.active[block])
        for ctx, (entry, _, kind) in self.contexts.items():
            if kind == "root":
                f["root"].add((ctx, endpoints[entry][0]))
        for caller, block, _, callee, entry in self.call_links + self.tail_links:
            f["flow"].add((caller, endpoints[block][1], callee, endpoints[entry][0]))
        for caller, _, callee, source, dest in self.return_links:
            f["flow"].add((callee, endpoints[source][1], caller, endpoints[dest][0]))
        for index, (ctx, block, site, target_ctx, dest) in enumerate(self.opaques, start=max_id + 2*len(blocks) + 1):
            if site in self.heaps and self.allocators.get(site) != "realloc":
                f["flow"].add((ctx, endpoints[block][1], target_ctx, endpoints[dest][0]))
            else:
                f["flow"].add((ctx, endpoints[block][1], ctx, index))
                f["flow"].add((ctx, index, target_ctx, endpoints[dest][0]))
                f["havoc"].add((ctx, index, site, "heap" if site in self.heaps else "mutable"))

        # Match callee stack arguments to their physical slots in the calling frame.
        sp_offsets = defaultdict(set)
        sp = "rsp" if self.info.bits == 64 else "esp"
        writes = defaultdict(set)
        for instruction, order, _, _, reg, offset in self.m4.read("set_loc_vex_offset"):
            if reg == sp:
                sp_offsets[int(instruction)].add(int(offset))
                writes[int(instruction), int(order)].add(int(offset))
        stack_locations = {v for _, _, _, v in f["access_seed"] if v[0] == "stack"}
        stack_locations.update(v for _, _, v in f["seed"] if v[0] == "stack")
        by_frame = defaultdict(set)
        for loc in stack_locations:
            by_frame[loc[2]].add(loc)
        # Tail jumps use the SP at the end of the block, without a call push.
        if self.tail_links:
            by_block = defaultdict(set)
            tail_blocks = {block: site for _, block, site, _, _ in self.tail_links}
            instructions = {pc: block for block, pc, *_ in r["instruction"] if block in tail_blocks}
            for pc, order in writes:
                if pc in instructions:
                    by_block[instructions[pc]].add((pc, order))
            block_sp = defaultdict(set)
            for block, reg, offset in self.m4.read("bb_reg_offset"):
                if reg == sp:
                    block_sp[int(block)].add(int(offset))
            for block, site in tail_blocks.items():
                sp_offsets[site] = writes[max(by_block[block])] if by_block[block] else block_sp[block]
        for caller, _, site, callee, _ in self.call_links + self.tail_links:
            for loc in by_frame[callee]:
                if loc[3] < self.info.bits // 8:
                    continue
                for delta in sp_offsets[site]:
                    parent = self.stack_at(caller, self.contexts[caller][0], delta + loc[3])
                    if parent and parent != loc:
                        f["alias"].add((loc, parent))

    def prepare_image(self):
        f = self.facts
        for lo, hi, bid in self.globals:
            f["limits"].add(("global", bid, 0, hi - lo))
            f["global_start"].add((bid, lo))
            if any(not s.writable and s.virtual_address <= lo and hi <= s.virtual_address + s.memory_size
                   for s in self.info.segments):
                f["readonly_global"].add((bid,))
        for bid, (_, lo, hi, _) in self.stacks.items():
            f["limits"].add(("stack", bid, lo, hi))
        for bid in self.heaps.values():
            f["limits"].add(("heap", bid, 0, LIMIT))

        chunks = sorted((a, bytes.fromhex(value)) for a, _, value in self.rows["initial_memory"])
        starts = [start for start, _ in chunks]

        def decode(address, size):
            index = bisect_right(starts, address) - 1
            if index < 0:
                return None
            start, data = chunks[index]
            offset = address - start
            word = data[offset:offset + size]
            if not word:
                return None
            if len(word) < size and index + 1 < len(chunks) and starts[index + 1] == start + len(data):
                word += chunks[index + 1][1][:size - len(word)]
            return word if len(word) == size else None

        loads = {(kind, access): (size, end) for kind, access, _, size, end in self.accesses
                 if kind in ("load", "guarded_load") and size <= 8}
        for _, kind, access, loc in f["access_seed"]:
            if loc[0] != "global" or (kind, access) not in loads:
                continue
            size, end = loads[kind, access]
            address = self.global_bounds[loc[1]][0] + loc[3]
            word = decode(address, size)
            if word is not None:
                raw = int.from_bytes(word, "big" if end == "Iend_BE" else "little")
                f["image"].add((loc, size, end, self.number(raw, size * 8)))
                self.numbers.add(raw)

        size = self.info.bits // 8
        # Aligned image pointers cover initialized pointer tables, including computed loads.
        # Explicit unaligned loads were decoded above.
        for address, data in chunks:
            for offset in range((-address) % size, len(data) - size + 1, size):
                raw = int.from_bytes(data[offset:offset + size], "little")
                val = self.number(raw, self.info.bits)
                if val[0] == "integer":
                    continue
                loc = self.global_at(address + offset, size)
                if loc:
                    f["image"].add((loc, size, "Iend_LE", val))
                    self.numbers.add(raw)
        for n in tuple(self.numbers):
            self.numbers.update(n & ((1 << bits) - 1) for bits in (1, 8, 16, 32))
        for n in self.numbers:
            val = self.number(n, self.info.bits) if n < (1 << self.info.bits) else ("integer", n, 0, 0, 1)
            f["number_value"].add((n, val))
            f["numeric"].add((val, n))
            if n < (1 << self.info.bits):
                displacement = _signed(n, self.info.bits)
                if -LIMIT < displacement < LIMIT:
                    f["displacement"].add((n, displacement))

    def prepare(self):
        try:
            self.prepare_accesses()
            self.prepare_values()
            self.prepare_flow()
            self.prepare_image()
            return self.facts
        finally:
            self.frame_address.cache_clear()


def _write_facts(path, rows):
    def cell(value):
        if isinstance(value, tuple):
            return "[" + ", ".join(str(field) for field in value) + "]"
        return str(value)

    with path.open("w", encoding="utf-8") as stream:
        for row in sorted(rows):
            stream.write("\t".join(cell(value) for value in row) + "\n")


def run_m6(binary: str | Path, output: str | Path, *, m3_path: str | Path | None = None,
           m4_path: str | Path | None = None, m5_path: str | Path | None = None,
           mapped_base: int | None = None, souffle: str = "souffle") -> dict:
    """Run points-to analysis on the current call graph and publish M6 relations."""
    from bpa.memory import run_m4
    from bpa.pipeline import run_m3
    from bpa.registers import run_m5

    binary, output = Path(binary).resolve(), Path(output).resolve()
    executable = shutil.which(souffle)
    if not executable:
        raise ValueError(f"Souffle executable unavailable: {souffle}")
    if m3_path is None:
        run_m3(binary, output, mapped_base=mapped_base)
    m3 = Path(m3_path or output / "m3").resolve()
    m3_hash = _digest((m3 / "manifest.json").read_bytes())
    raw = read_facts(m3)
    if raw.metadata.get("status") != "complete":
        raise ValueError("M6 requires complete M3 facts")
    metadata = {}
    for name in ("m1/binary.json", "m2/functions.json"):
        data = (m3.parent / name).read_bytes()
        if _digest(data) != raw.metadata["inputs"].get(name):
            raise ValueError(f"M6 upstream checksum mismatch: {name}")
        metadata[name] = json.loads(data)
    info = BinaryInfo.from_dict(metadata["m1/binary.json"])
    if _digest(binary.read_bytes()) != info.sha256 or raw.metadata["binary_sha256"] != info.sha256:
        raise ValueError("M6 input ELF identity mismatch")
    if mapped_base is not None and mapped_base != info.mapped_base:
        raise ValueError("mapped_base conflicts with M3 artifacts")
    if m4_path is None:
        run_m4(binary, output, m3_path=m3, souffle=executable)
    if m5_path is None:
        run_m5(binary, output, m3_path=m3, souffle=executable)
    m4 = StageFacts(Path(m4_path or output / "m4"), "m4", m3_hash, info.sha256)
    m5 = StageFacts(Path(m5_path or output / "m5"), "m5", m3_hash, info.sha256)
    facts = Inputs(raw.rows, info, m4, m5, metadata["m2/functions.json"]["functions"]).prepare()
    dest = output / "m6"
    dest.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".m6-", dir=dest) as scratch:
        work = Path(scratch)
        published = work / "facts"
        published.mkdir()
        for name in INPUTS:
            _write_facts(work / f"{name}.facts", facts[name])
        proc = subprocess.run([executable, "-j", "1", "-I", str(RULES.parent), "-F", str(work),
                               "-D", str(published), str(RULES)], text=True, capture_output=True)
        if proc.returncode:
            raise ValueError(f"M6 Souffle failed: {proc.stderr or proc.stdout}")
        hashes, counts = {}, {}
        for name in COLUMNS:
            path = published / f"{name}.facts"
            content = path.read_bytes()
            hashes[path.name], counts[name] = _digest(content), content.count(b"\n")
        generation = "facts-" + _digest(json.dumps(hashes, sort_keys=True).encode())
        if _digest((m3 / "manifest.json").read_bytes()) != m3_hash:
            raise ValueError("M3 input changed during M6 analysis")
        try:
            published.rename(dest / generation)
        except OSError:
            if not all((dest / generation / n).is_file() and _digest((dest / generation / n).read_bytes()) == h
                       for n, h in hashes.items()):
                raise
        result = dict(stage="M6", schema="bpa.m6.v1", address_space="elf-va", arch=info.arch,
                      binary_sha256=info.sha256, m3_manifest_sha256=m3_hash, m4_manifest_sha256=m4.digest,
                      m5_manifest_sha256=m5.digest, context_depth=1, offset_abstraction="0-base",
                      offset_origin={"stack": "frame-entry-sp", "global": "block-start", "heap": "allocation-start"},
                      facts_dir=generation, columns={name: fields.split() for name, fields in COLUMNS.items()},
                      files=hashes, counts=counts)
        write_json(dest / "manifest.json", result, binary=binary)
    return result
