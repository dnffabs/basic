"""Adapt M1–M3 observations to the bundled Soufflé baseline and publish M4."""
from bisect import bisect_right
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from bpa.artifacts import write_json
from bpa.model import BinaryInfo
from bpa.vex import read_facts
from bpa.vex.compat import write_projection

BASELINE = Path(__file__).parent / "baseline"
BASELINE_REVISION = "0fb0a5152074495e8227f936aa694a3c83e3884e"
# Column order in the published TSV files, including the upstream relations.
COLUMNS = {
    "mloc_sblk": "id function lower upper has_lower has_upper call_site",
    "mloc_gblk": "id lower upper has_lower has_upper",
    "mloc_gchk": "id lower upper has_lower has_upper",
    "mloc_gcoarser": "id lower upper has_lower has_upper",
    "mloc_hblk": "id allocation_site",
    "local_block_boundary": "instruction order function_name function offset",
    "global_chunk_boundary": "instruction address",
    "global_block_boundary": "instruction address",
    "heap_block": "allocation_site",
    "bb_reg_offset": "block register offset",
    "bb_last_reg_def": "block instruction order register",
    "set_loc_vex_offset": "instruction order bits expression register offset",
    "get_loc_vex_exp_offset": "expression register offset",
    "tmp_reg_offset": "temporary offset",
    "tmp_reg_sblk_id": "temporary stack_id",
    "set_loc_vex_sblk_id": "instruction order bits expression register stack_id",
    "get_loc_vex_exp_sblk_id": "expression register stack_id",
    "tmp_reg_func_arg_passing": "temporary function offset call_site",
    "memory_access_block": "kind access_id block_kind block_id offset bits basis",
    "unmapped_access": "kind access_id address_expression bits",
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_rows(directory, name, rows):
    with (directory / (name + ".facts")).open("w", encoding="utf-8") as stream:
        for row in rows:
            stream.write("\t".join(map(str, row)) + "\n")


def read_rows(directory, name):
    with (directory / (name + ".facts")).open(encoding="utf-8") as stream:
        for line in stream:
            yield line.rstrip("\n").split("\t")


def invoke(command):
    proc = subprocess.run(command, text=True, capture_output=True)
    if proc.returncode:
        raise ValueError(f"M4 {Path(command[0]).name} failed: {proc.stderr or proc.stdout}")


def prepare_inputs(directory, raw, info, functions):
    write_projection(raw, directory)
    rows = raw.rows
    users = [(f["name"], f["entry"], f["code_ranges"][-1][1]) for f in functions if f["code_ranges"]]
    # M2 exports user functions. Include PLT and defined ELF functions for named
    # allocator targets and function starts relevant to reversed tail calls.
    addr_func = {start: (name, start, stop) for name, start, stop in users}
    for sym in info.symbols:
        if sym.is_function and sym.elf_address is not None:
            start = sym.elf_address
            addr_func.setdefault(start, (sym.name, start, start + max(1, sym.size)))
    for plt in info.plt:
        addr_func.setdefault(plt.elf_address, (plt.name, plt.elf_address, plt.elf_address + 1))
    write_rows(directory, "addr_func", addr_func.values())
    write_rows(directory, "user_defined_addr_func", users)
    taken = {f["entry"] for f in functions if f["address_taken"]}
    write_rows(directory, "addr_AT_func", (row for row in users if row[1] in taken))
    # Default to the block start when no machine instruction was decoded.
    last = {b[0]: (b[0], "", "") for b in rows["block"]}
    for block, site, _, mnemonic, operands in rows["instruction"]:
        if site >= last[block][0]:
            last[block] = (site, mnemonic, operands)
    write_rows(directory, "bb_addr_bound", ((b, i[0]) for b, i in last.items()))
    write_rows(directory, "bb_addr_bound_instr", (r[:2] for r in rows["instruction"]))
    write_rows(directory, "edge", ((last[b][0], dest) for b, dest, kind, _ in rows["cfg_edge"]
                                   if kind != "fake_return"))
    write_rows(directory, "inter_succ", rows["continuation"])
    constants = {eid: int(value, 16) for eid, _, value in rows["constant"]}
    tmp = {eid: index for eid, _, index in rows["temporary_read"]}
    jumps = []
    for block, _, target, kind in rows["block_exit"]:
        site, mnemonic, operands = last[block]
        if kind == "Ijk_Boring":
            if mnemonic.startswith("j"):
                kind = "Jump_Table" if "[" in operands and "*" in operands else "Jump"
            else:
                kind = "Fall"
        else:
            kind = {"Ijk_Call": "Call", "Ijk_Ret": "Ret"}.get(kind, kind)
        if target in constants:
            dest = constants[target] - info.load_bias
            typ, value = ("imm", dest) if dest >= 0 else ("other", 0)
        elif target in tmp:
            typ, value = "tmp_reg", tmp[target]
        else:
            typ, value = "other", 0
        jumps.append((site, kind, typ, value))
    write_rows(directory, "jumps", jumps)
    write_rows(directory, "push_instr_addr", ((site,) for _, site, _, op, _ in rows["instruction"]
                                              if op.startswith("push")))
    for name in ("sblk_dwarf_func", "sblk_dwarf_var"):
        write_rows(directory, name, ())
    return constants


def partition(directory, binary, info, souffle):
    def rule(group, name):
        invoke([souffle, "-j", "1", "-F", directory, "-D", directory, "--macro=" + info.arch,
                BASELINE / "rules" / group / (name + ".dl")])

    def helper(name, *args):
        invoke([sys.executable, BASELINE / "helpers" / (name + ".py"), *args])

    for name in ("reverse-tail-call-opt", "remove-exit-inter-succ", "filter-instr",
                 "addr_func_instr", "remove-unreachable-func"):
        rule("pre-process", name)
    helper("get_func_arg_pass_instr_addr", binary, info.arch, directory)
    rule("mem-alloc", "preprocess")
    helper("stack-analysis-preprocess", directory, binary)
    rule("mem-alloc", "local-mem-block")
    # Match the bitvectors in the image's mapped coordinate system. Convert
    # only the inferred global-address column back to ELF VA afterwards.
    bias = info.load_bias
    def regions(delta):
        return [(r.name, r.start + delta, r.end - 1 + delta) for r in info.global_regions]
    write_rows(directory, "global_rgn", regions(bias))
    rule("mem-alloc", "global-mem-block")
    if bias:
        for name in ("global_block_boundary", "global_chunk_boundary", "global_coarser_boundary"):
            converted = [(*row[:-1], int(row[-1]) - bias) for row in read_rows(directory, name)]
            write_rows(directory, name, converted)
        write_rows(directory, "global_rgn", regions(0))
    rule("mem-alloc", "heap-mem-block")
    helper("mloc-gen", directory, "normal")
    rule("mem-alloc", "postprocess")


def link_accesses(directory, raw, info, constants):
    """Connect M3 access IDs to directly supported block candidates, with provenance."""
    globals_ = sorted((int(lo), int(hi), int(bid)) for bid, lo, hi, _, _ in read_rows(directory, "mloc_gblk"))
    starts = [lo for lo, _, _ in globals_]
    offsets = defaultdict(set)
    for tmp, off in read_rows(directory, "tmp_reg_offset"):
        offsets[tmp].add(int(off))
    matched = defaultdict(set)
    for tmp, bid in read_rows(directory, "tmp_reg_sblk_id"):
        matched[tmp].add(int(bid))
    # A temporary can have multiple offsets; match each offset only to blocks containing it.
    bounds = {int(bid): (int(lo) if int(lf) else None, int(hi) if int(hf) else None, site)
              for bid, _, lo, hi, lf, hf, site in read_rows(directory, "mloc_sblk")}
    contexts = defaultdict(set)
    for tmp, _, off, site in read_rows(directory, "tmp_reg_func_arg_passing"):
        contexts[tmp, int(off)].add(site)
    temps = {eid: f"{block}_{index}" for eid, block, index in raw.rows["temporary_read"]}
    accesses = []
    for name, addr_col, bits_col in (("load", 1, 2), ("store", 1, 3),
                                    ("guarded_load", 3, 6), ("guarded_store", 1, 4)):
        accesses.extend((name, row[0], row[addr_col], row[bits_col]) for row in raw.rows[name])
    links, unknown = [], []
    for kind, ident, address, bits in accesses:
        before = len(links)
        if address in constants:
            va = constants[address] - info.load_bias
            i = bisect_right(starts, va) - 1
            if i >= 0 and va < globals_[i][1] and any(r.start <= va < r.end for r in info.global_regions):
                lo, _, bid = globals_[i]
                links.append((kind, ident, "global", bid, va - lo, bits, "direct"))
        if address in temps:
            tmp = temps[address]
            for bid in sorted(matched[tmp]):
                lo, hi, site = bounds[bid]
                for off in sorted(offsets[tmp]):
                    sites = contexts.get((tmp, off))
                    if sites and site not in sites:
                        continue
                    if (lo is None or off >= lo) and (hi is None or off < hi):
                        # Open-low blocks have no displacement origin; keep the frame offset.
                        origin = "entry_sp" if lo is None else "block_start"
                        links.append((kind, ident, "stack", bid, off if lo is None else off - lo, bits, origin))
        if before == len(links):
            unknown.append((kind, ident, address, bits))
    write_rows(directory, "memory_access_block", links)
    write_rows(directory, "unmapped_access", unknown)
    return len(accesses), len(unknown)


def run_m4(binary: str | Path, output: str | Path, *, m3_path: str | Path | None = None,
           mapped_base: int | None = None, souffle: str = "souffle") -> dict:
    """Partition x86 ELF memory and return the manifest identifying the published facts."""
    from bpa.pipeline import run_m3

    binary, output = Path(binary).resolve(), Path(output).resolve()
    executable = shutil.which(souffle)
    if not executable:
        raise ValueError(f"Souffle executable unavailable: {souffle}")
    if m3_path is None:
        run_m3(binary, output, mapped_base=mapped_base)
        m3_path = output / "m3"
    m3 = Path(m3_path).resolve()
    m3_hash = digest(m3 / "manifest.json")
    raw = read_facts(m3)
    if raw.metadata.get("status") != "complete":
        raise ValueError("M4 requires complete M3 facts")
    upstream = m3.parent
    expected_inputs = ("m1/binary.json", "m2/cfg.json", "m2/functions.json")
    for name in expected_inputs:
        if raw.metadata["inputs"].get(name) != digest(upstream / name):
            raise ValueError(f"M4 upstream checksum mismatch: {name}")
    info = BinaryInfo.from_dict(json.loads((upstream / expected_inputs[0]).read_text()))
    if info.arch not in ("X86", "AMD64"):
        raise ValueError(f"Unsupported M4 architecture: {info.arch}")
    if digest(binary) != info.sha256 or raw.metadata["binary_sha256"] != info.sha256:
        raise ValueError("M4 input ELF identity mismatch")
    if mapped_base is not None and mapped_base != info.mapped_base:
        raise ValueError("mapped_base conflicts with M3 artifacts")
    functions = json.loads((upstream / expected_inputs[2]).read_text())["functions"]
    dest = output / "m4"
    dest.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=dest) as scratch:
        work = Path(scratch)
        constants = prepare_inputs(work, raw, info, functions)
        partition(work, binary, info, executable)
        total, unresolved = link_accesses(work, raw, info, constants)
        published = work / "facts"
        published.mkdir()
        hashes = {}
        counts = {}
        for name in COLUMNS:
            src = work / (name + ".facts")
            hashes[src.name] = digest(src)
            counts[name] = sum(1 for _ in read_rows(work, name))
            src.rename(published / src.name)
        generation = "facts-" + hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()
        try:
            published.rename(dest / generation)
        except OSError:
            if not all((dest / generation / n).is_file() and digest(dest / generation / n) == h for n, h in hashes.items()):
                raise
        if digest(m3 / "manifest.json") != m3_hash:
            raise ValueError("M3 input changed during M4 analysis")
        result = dict(stage="M4", schema="bpa.m4.v1", mode="normal", address_space="elf-va",
                      arch=info.arch, binary_sha256=info.sha256, load_bias=info.load_bias,
                      m3_manifest_sha256=m3_hash, facts_dir=generation,
                      baseline_revision=BASELINE_REVISION, columns={k: v.split() for k, v in COLUMNS.items()},
                      files=hashes, counts=counts, accesses=total, unmapped_accesses=unresolved)
        write_json(dest / "manifest.json", result, binary=binary)
    return result
