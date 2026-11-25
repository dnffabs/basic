"""Prepare M3 register operations and publish M5 reaching-definition facts."""

from collections import defaultdict
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

import archinfo

from bpa.artifacts import write_json
from bpa.model import BinaryInfo
from bpa.vex import read_facts


RULES = Path(__file__).with_name("reaching_definitions.dl")
COLUMNS = {
    "register_bank": "register bits name",
    "context": "context entry call_site kind",
    "context_block": "context block",
    "register_def": "definition block statement register low_bit bits value kind call_site",
    "register_read": "expression register low_bit bits",
    "register_read_def": "context expression definition_context definition",
    "partial_input": "context definition previous_context previous_definition",
    "call_link": "caller_context block call_site callee_context entry",
    "tail_link": "caller_context block call_site callee_context entry",
    "return_link": "caller_context call_site callee_context return_block continuation",
    "opaque_return": "context block call_site continuation",
    "opaque_tail_return": "tail_context block tail_site caller_context continuation",
}
PYTHON_OUTPUTS = ("register_bank", "context", "register_def", "register_read")
GPRS = {
    "X86": "eax ebx ecx edx esi edi ebp esp",
    "AMD64": "rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15",
}
# Unknown calls may clobber volatile registers. Model SP as unknown on this path
# too, since the block exit includes the call push and no return IR is available.
OPAQUE_REGS = {"X86": "eax ecx edx esp", "AMD64": "rax rcx rdx rsi rdi rsp r8 r9 r10 r11"}


def _digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_rows(path, rows):
    with path.open("w", encoding="utf-8") as stream:
        for row in rows:
            stream.write("\t".join(map(str, row)) + "\n")


def _register_operations(rows, arch, facts):
    bank = sorted((arch.registers[name][0], arch.registers[name][1] * 8, name)
                  for name in GPRS[arch.name].split())
    facts["register_bank"].extend(bank)
    aliases = {}
    for offset, bits, _ in rows["register"]:
        for reg, width, _ in bank:
            low_bit = (offset - reg) * 8
            if 0 <= low_bit < width and low_bit + bits <= width:
                aliases[offset, bits] = reg, low_bit, width
                break

    expression_stmts = {expr: stmt for expr, stmt, _, _ in rows["expression"]}
    reads = defaultdict(list)
    for expr, offset, bits in rows["register_read"]:
        access = aliases.get((offset, bits))
        if access is not None:
            reg, low_bit, _ = access
            reads[expression_stmts[expr]].append((expr, reg))
            facts["register_read"].append((expr, reg, low_bit, bits))

    writes = {stmt: (offset, bits, value) for stmt, offset, bits, value in rows["register_write"]}
    last = {}

    def add_use(block, use, reg):
        previous = last.get((block, reg))
        if previous is None:
            facts["entry_use"].append((block, use, reg))
        else:
            facts["local_use"].append((block, use, previous))

    for stmt, block, *_ in sorted(rows["statement"], key=lambda row: (row[1], row[2])):
        for expr, reg in reads.get(stmt, ()):
            add_use(block, expr, reg)
        if stmt in writes:
            offset, bits, value = writes[stmt]
            access = aliases.get((offset, bits))
            if access is None:
                continue
            reg, low_bit, width = access
            kind = "write" if bits == width else "partial"
            if kind == "partial":
                add_use(block, stmt, reg)
                facts["partial_definition"].append((stmt,))
            facts["register_def"].append((stmt, block, stmt, reg, low_bit, bits, value, kind, 0))
            last[block, reg] = stmt
    facts["last_write"].extend((block, reg, stmt) for (block, reg), stmt in last.items())
    return bank


def _roots(blocks, entry, owners, local_edges, targets, continuations):
    """Prefer natural roots and add roots for disconnected CFG regions."""
    successors = defaultdict(set)
    for source, target in (*local_edges, *continuations):
        successors[source].add(target)
    called = set()
    for block, callees in targets.items():
        successors[block].update(callees)
        called.update(callees)

    entries = (owners | called | {entry}) & blocks
    roots = (entries - called) | ({entry} & blocks)
    seen = set(roots)

    def visit(pending):
        while pending:
            for target in successors[pending.pop()] - seen:
                seen.add(target)
                pending.append(target)

    visit(sorted(roots))
    for block in (*sorted(entries), *sorted(blocks)):
        if block not in seen:
            roots.add(block)
            seen.add(block)
            visit([block])
    return roots


def _control_flow(rows, info, extra_targets, tail_targets, opaque_sites, added_continuations, bank, facts):
    blocks = {row[0] for row in rows["block"]}
    plts = {stub.elf_address for stub in info.plt}
    internal_blocks = blocks - plts
    calls = {site: (block, status) for block, site, kind, _, status in rows["control_transfer"]
             if kind == "call"}
    jumps = {site: (block, status) for block, site, kind, _, status in rows["control_transfer"]
             if kind == "jump"}
    known = defaultdict(set)
    for site, target in rows["known_target"]:
        if site in calls:
            known[site].add(target)
    for site, target in extra_targets:
        if site not in calls or (target not in blocks and target not in plts):
            raise ValueError(f"Invalid M5 call target: {site:#x} -> {target:#x}")
        known[site].add(target)
    tails = defaultdict(set)
    for site, target in tail_targets:
        if site not in jumps or (target not in blocks and target not in plts):
            raise ValueError(f"Invalid M5 tail target: {site:#x} -> {target:#x}")
        tails[site].add(target)
    if opaque_sites - (calls.keys() | tails.keys()):
        raise ValueError("M5 opaque sites must be calls or recognized tail calls")
    external = {site for site, _ in rows["external_target"]}
    continuations = {site: target for site, target in rows["continuation"]
                     if site in calls and target in blocks}
    call_end = {pc: pc + size for _, pc, size, _, _ in rows["instruction"] if pc in calls}
    for site, target in added_continuations:
        if call_end.get(site) != target or target not in blocks or continuations.get(site, target) != target:
            raise ValueError(f"Invalid M5 continuation: {site:#x} -> {target:#x}")
        continuations[site] = target
    tail_edges = {(jumps[site][0], target) for site, targets in tails.items() for target in targets}
    local_edges = {(source, target) for source, target, kind, _ in rows["cfg_edge"]
                   if kind not in ("call", "return", "fake_return")} - tail_edges
    facts["local_edge"].extend(sorted(local_edges))
    facts["return_block"].extend((block,) for block, _, kind, _, _ in rows["control_transfer"]
                                 if kind == "return")
    facts["continuation"].extend(sorted(continuations.items()))

    targets_by_block = defaultdict(set)
    internal = []
    for site, (block, status) in sorted(calls.items()):
        targets = known[site]
        callees = targets & internal_blocks
        targets_by_block[block].update(callees)
        internal.extend((block, site, target) for target in sorted(callees))
        if site in continuations and (site in opaque_sites or status == "unresolved"
                                      or site in external or not callees or targets - callees):
            facts["opaque_call"].append((block, site, continuations[site]))
    for site, targets in sorted(tails.items()):
        block, status = jumps[site]
        callees = targets & internal_blocks
        targets_by_block[block].update(callees)
        if site in opaque_sites or status == "unresolved" or site in external or targets - callees:
            facts["opaque_tail"].append((block, site))

    roots = _roots(blocks, info.entry, {owner for _, owner in rows["block_function"]},
                   local_edges, targets_by_block,
                   [(calls[site][0], target) for site, target in continuations.items()])
    # Explicit definitions use M3 statement IDs. Reserve synthetic IDs by block
    # and call site so adding an edge does not renumber surviving definitions.
    first_id = 1 + max(row[0] for name in ("statement", "expression") for row in rows[name])
    block_order = {block: i for i, block in enumerate(sorted(blocks))}
    call_order = {site: i for i, site in enumerate((*sorted(calls), *sorted(jumps)))}
    for ctx, block in enumerate(sorted(roots), start=1):
        facts["context"].append((ctx, block, 0, "root"))
        facts["root"].append((ctx, block))
        for index, (reg, bits, _) in enumerate(bank):
            definition = first_id + block_order[block] * len(bank) + index
            facts["entry_def"].append((ctx, block, reg, definition))
            facts["register_def"].append((definition, block, 0, reg, 0, bits, 0, "entry", 0))

    for ctx, (block, site, target) in enumerate(internal, start=len(roots) + 1):
        facts["context"].append((ctx, target, site, "call"))
        facts["internal_call"].append((block, site, target, ctx))
    ctx = len(roots) + len(internal)
    for site, targets in sorted(tails.items()):
        for target in sorted(targets & internal_blocks):
            ctx += 1
            facts["context"].append((ctx, target, site, "tail"))
            facts["internal_tail"].append((jumps[site][0], site, target, ctx))
    volatile = set(OPAQUE_REGS[info.arch].split())
    for block, site, *_ in (*facts["opaque_call"], *facts["opaque_tail"]):
        for index, (reg, bits, name) in enumerate(bank):
            if name in volatile:
                definition = first_id + (len(blocks) + call_order[site]) * len(bank) + index
                facts["clobber"].append((site, reg, definition))
                facts["register_def"].append((definition, block, 0, reg, 0, bits, 0, "clobber", site))


def run_m5(binary: str | Path, output: str | Path, *, m3_path: str | Path | None = None,
           mapped_base: int | None = None, souffle: str = "souffle", additional_call_targets=(),
           additional_tail_targets=(), opaque_sites=(), additional_continuations=()) -> dict:
    """Run register analysis. Extra edges are (instruction, target) ELF VAs."""
    from bpa.pipeline import run_m3

    binary, output = Path(binary).resolve(), Path(output).resolve()
    executable = shutil.which(souffle)
    if not executable:
        raise ValueError(f"Souffle executable unavailable: {souffle}")
    if m3_path is None:
        run_m3(binary, output, mapped_base=mapped_base)
        m3_path = output / "m3"
    m3 = Path(m3_path).resolve()
    m3_digest = _digest(m3 / "manifest.json")
    raw = read_facts(m3)
    if raw.metadata.get("status") != "complete":
        raise ValueError("M5 requires complete M3 facts")
    m1_data = (m3.parent / "m1/binary.json").read_bytes()
    if raw.metadata["inputs"].get("m1/binary.json") != hashlib.sha256(m1_data).hexdigest():
        raise ValueError("M5 M1 checksum differs from the M3 manifest")
    info = BinaryInfo.from_dict(json.loads(m1_data))
    if info.arch not in GPRS:
        raise ValueError(f"Unsupported M5 architecture: {info.arch}")
    if _digest(binary) != info.sha256 or raw.metadata["binary_sha256"] != info.sha256:
        raise ValueError("M5 input ELF identity mismatch")
    if mapped_base is not None and mapped_base != info.mapped_base:
        raise ValueError("mapped_base conflicts with M3 artifacts")

    facts = defaultdict(list)
    bank = _register_operations(raw.rows, archinfo.arch_from_id(info.arch), facts)
    extra_targets = sorted(set(additional_call_targets))
    tail_targets = sorted(set(additional_tail_targets))
    opaque_sites = set(opaque_sites)
    added_continuations = sorted(set(additional_continuations))
    _control_flow(raw.rows, info, extra_targets, tail_targets, opaque_sites, added_continuations, bank, facts)
    dest = output / "m5"
    dest.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".m5-", dir=dest) as scratch:
        work = Path(scratch)
        published = work / "facts"
        published.mkdir()
        for name in ("root", "entry_def", "local_edge", "internal_call", "internal_tail", "continuation", "return_block",
                     "opaque_call", "opaque_tail", "clobber", "last_write", "local_use", "entry_use", "register_read",
                     "partial_definition"):
            _write_rows(work / f"{name}.facts", facts[name])
        for name in PYTHON_OUTPUTS:
            _write_rows(published / f"{name}.facts", facts[name])
        proc = subprocess.run([executable, "-j", "1", "-F", str(work), "-D", str(published), str(RULES)],
                              text=True, capture_output=True)
        if proc.returncode:
            raise ValueError(f"M5 Souffle failed: {proc.stderr or proc.stdout}")
        hashes, counts = {}, {}
        for name in COLUMNS:
            path = published / f"{name}.facts"
            hashes[path.name] = _digest(path)
            with path.open("rb") as stream:
                counts[name] = sum(1 for _ in stream)
        generation = "facts-" + hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()
        if _digest(m3 / "manifest.json") != m3_digest:
            raise ValueError("M3 input changed during M5 analysis")
        try:
            published.rename(dest / generation)
        except OSError:
            if not all((dest / generation / n).is_file() and _digest(dest / generation / n) == h
                       for n, h in hashes.items()):
                raise
        result = dict(stage="M5", schema="bpa.m5.v1", address_space="elf-va", arch=info.arch,
                      binary_sha256=info.sha256, m3_manifest_sha256=m3_digest, context_depth=1,
                      register_state="whole-gpr-with-partial-updates", additional_call_targets=extra_targets,
                      additional_tail_targets=tail_targets, opaque_sites=sorted(opaque_sites),
                      additional_continuations=added_continuations,
                      facts_dir=generation, columns={name: fields.split() for name, fields in COLUMNS.items()},
                      files=hashes, counts=counts)
        write_json(dest / "manifest.json", result, binary=binary)
    return result
