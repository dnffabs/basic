"""Resolve indirect calls and tail calls by feeding new edges back into M5/M6."""

from collections import defaultdict
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import shutil
import tempfile

from bpa.artifacts import write_json
from bpa.memory import run_m4
from bpa.pipeline import run_m3
from bpa.points_to import run_m6
from bpa.points_to.analysis import StageFacts
from bpa.registers import run_m5
from bpa.vex import read_facts


@dataclass(frozen=True)
class Transfer:
    block: int
    kind: str
    indirect: bool
    status: str


def _digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class CallGraph:
    def __init__(self, rows, functions, binary_info):
        self.sites = {site: Transfer(block, kind, bool(indirect), status)
                      for block, site, kind, indirect, status in rows["control_transfer"]}
        self.blocks = {a for a, *_ in rows["block"]}
        self.names = {f["entry"]: f["name"] for f in functions}
        self.plt = {stub["elf_address"]: stub["name"] for stub in binary_info["plt"]}
        self.entries = (self.names.keys() & self.blocks) | self.plt.keys()
        self.owners = defaultdict(set)
        for block, owner in rows["block_function"]:
            self.owners[block].add(owner)
        known = defaultdict(set)
        self.external = defaultdict(set)
        for site, target in rows["known_target"]:
            known[site].add(target)
        for site, symbol in rows["external_target"]:
            self.external[site].add(symbol)

        instructions = {(block, pc): mnemonic for block, pc, _, mnemonic, _ in rows["instruction"]}
        self.calls = {site: transfer for site, transfer in self.sites.items() if transfer.kind == "call"}
        self.tail_owners = {}
        for site, transfer in self.sites.items():
            owners = self.owners[transfer.block]
            if transfer.kind != "jump" or instructions.get((transfer.block, site)) != "jmp" or len(owners) != 1:
                continue
            owner, = owners
            # A recovered intra-function destination is evidence of a local jump.
            if owner not in self.plt and all(t in self.entries and t != owner for t in known[site]):
                self.tail_owners[site] = owner

        exits = {block: expr for block, _, expr, _ in rows["block_exit"]}
        self.tail_operands = defaultdict(set)
        for site in self.tail_owners:
            transfer = self.sites[site]
            if transfer.indirect:
                self.tail_operands[exits[transfer.block]].add(site)
        self.call_edges = {(site, target): 0 for site in self.calls for target in known[site]}
        self.tail_edges = {(site, target): 0 for site in self.tail_owners for target in known[site]}
        self.opaque_sites = {site for site, transfer in self.calls.items()
                             if transfer.indirect and transfer.status == "unresolved"}
        recovered = dict(rows["continuation"])
        extents = sorted((s["elf_address"], s["elf_address"] + s["size"]) for s in binary_info["symbols"]
                         if s["is_function"] and s["elf_address"] is not None and s["size"] > 0)
        self.resume = {}
        for block, site, size, _, _ in rows["instruction"]:
            target = site + size
            if site not in self.calls or site in recovered or target not in self.blocks:
                continue
            if self.owners[block] & self.owners[target] or any(lo <= site < target < hi for lo, hi in extents):
                self.resume[site] = target

    def additional_continuations(self):
        # A decoded successor can be absent from the CFG when the initial
        # callee looked non-returning. M5 still requires a real return or an opaque path.
        sites = {site for site, target in self.call_edges if target in self.blocks and target not in self.plt}
        return [(site, self.resume[site]) for site in sites & self.resume.keys()]

    def observations(self, m6):
        values = defaultdict(lambda: defaultdict(set))
        for ctx, site, _, kind, target in m6.read("call_operand_value"):
            site, ctx, target = int(site), int(ctx), int(target)
            values[site][ctx].add(target if kind == "function" and target in self.entries else None)
        if self.tail_operands:
            for ctx, expr, kind, base, *_ in m6.iter_rows("expr_value"):
                for site in self.tail_operands.get(int(expr), ()):
                    address = int(base)
                    valid = kind == "function" and address in self.entries and address != self.tail_owners[site]
                    values[site][int(ctx)].add(address if valid else None)
        return values

    def extend(self, values, iteration):
        new_calls, new_tails = [], []
        new_opaque = set()
        tail_sites = {s for s, _ in self.tail_edges}
        for site, contexts in sorted(values.items()):
            pairs, unknown = set(), False
            for evidence in contexts.values():
                pairs.update((site, address) for address in evidence if address is not None)
                unknown |= None in evidence
            if site in self.calls:
                new_calls.extend(sorted(pairs - self.call_edges.keys()))
            else:
                new_tails.extend(sorted(pairs - self.tail_edges.keys()))
            if unknown and (site in self.calls or site in tail_sites or pairs) and site not in self.opaque_sites:
                new_opaque.add(site)
        self.call_edges.update(dict.fromkeys(new_calls, iteration))
        self.tail_edges.update(dict.fromkeys(new_tails, iteration))
        self.opaque_sites.update(new_opaque)
        return dict(iteration=iteration, new_call_edges=new_calls, new_tail_edges=new_tails,
                    new_opaque_sites=sorted(new_opaque), call_edges=len(self.call_edges), tail_edges=len(self.tail_edges))

    def call_graph(self, m5):
        edges = []
        for kind, pairs in (("call", self.call_edges), ("tail_call", self.tail_edges)):
            for (site, target), iteration in sorted(pairs.items()):
                edges.append(dict(site=site, kind=kind, indirect=self.sites[site].indirect,
                                  callers=sorted(self.owners[self.sites[site].block]), target=target,
                                  target_name=self.plt.get(target, self.names.get(target)),
                                  target_kind="external" if target in self.plt else "internal",
                                  first_seen_round=iteration, source="m6" if iteration else "m2"))
        covered_external = {(edge["site"], edge["target_name"]) for edge in edges if edge["target_kind"] == "external"}
        for site, names in sorted(self.external.items()):
            if site in self.calls:
                edges.extend(dict(site=site, kind="call", indirect=self.sites[site].indirect,
                                  callers=sorted(self.owners[self.sites[site].block]), target=None,
                                  target_name=name, target_kind="external", first_seen_round=0, source="m2")
                             for name in sorted(names) if (site, name) not in covered_external)
        returns = [dict(zip(("caller_context", "call_site", "return_context", "return_block", "continuation"), map(int, row)))
                   for row in m5.read("return_link")]
        edges.sort(key=lambda edge: (edge["site"], edge["target"] is None, edge["target"] or 0, edge["target_name"] or ""))
        return dict(edges=edges, return_links=returns,
                    additional_continuations=sorted(self.additional_continuations()))

    def indirect_calls(self, values, m5):
        incoming = {int(c): (int(e), int(s), k) for c, e, s, k in m5.read("context")}
        retained_opaque = {int(row[2]) for row in m5.read("opaque_return") + m5.read("opaque_tail_return")}
        targets = defaultdict(set)
        for site, target in self.call_edges.keys() | self.tail_edges.keys():
            targets[site].add(target)
        call_sites = self.calls.keys() | {s for s, _ in self.tail_edges}
        sites = []
        for site in sorted(s for s in call_sites if self.sites[s].indirect):
            contexts = []
            for ctx, evidence in sorted(values.get(site, {}).items()):
                entry, recent, kind = incoming[ctx]
                contexts.append(dict(context=ctx, entry=entry, recent_call_site=recent, context_kind=kind,
                                     targets=sorted(t for t in evidence if t is not None), unknown=None in evidence))
            known = bool(targets[site] or self.external[site])
            unknown = any(context["unknown"] for context in contexts)
            status = "unreachable" if not contexts else "unresolved" if not known else "partial" if unknown else "resolved"
            sites.append(dict(site=site, block=self.sites[site].block,
                              kind="call" if site in self.calls else "tail_call", status=status,
                              targets=sorted(targets[site]), external_targets=sorted(self.external[site]),
                              unknown=unknown, opaque_path_retained=site in retained_opaque, contexts=contexts))
        return sites


def run_m7(binary: str | Path, output: str | Path, *, m3_path: str | Path | None = None,
           m4_path: str | Path | None = None, mapped_base: int | None = None, souffle: str = "souffle") -> dict:
    """Publish a fixed point of accepted call edges and the final M5/M6 evidence."""
    binary, output = Path(binary).resolve(), Path(output).resolve()
    if m3_path is None:
        run_m3(binary, output, mapped_base=mapped_base)
    m3 = Path(m3_path or output / "m3").resolve()
    m3_hash = _digest(m3 / "manifest.json")
    raw = read_facts(m3)
    if raw.metadata.get("status") != "complete":
        raise ValueError("M7 requires complete M3 facts")
    binary_hash = _digest(binary)
    if raw.metadata["binary_sha256"] != binary_hash:
        raise ValueError("M7 input ELF identity mismatch")

    def upstream(name):
        path = m3.parent / name
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != raw.metadata["inputs"].get(name):
            raise ValueError(f"M7 upstream checksum mismatch: {name}")
        return json.loads(data)

    functions = upstream("m2/functions.json")["functions"]
    binary_info = upstream("m1/binary.json")
    if mapped_base is not None and mapped_base != binary_info["mapped_base"]:
        raise ValueError("mapped_base conflicts with M3 artifacts")
    if m4_path is None:
        run_m4(binary, output, m3_path=m3, souffle=souffle)
    m4 = Path(m4_path or output / "m4").resolve()
    m4_input = StageFacts(m4, "m4", m3_hash, binary_hash)
    graph = CallGraph(raw.rows, functions, binary_info)
    del raw
    dest = output / "m7"
    dest.mkdir(parents=True, exist_ok=True)
    iterations = []
    with tempfile.TemporaryDirectory(prefix=".m7-", dir=dest) as scratch:
        while True:
            with tempfile.TemporaryDirectory(prefix="round-", dir=scratch) as directory:
                work = Path(directory)
                run_m5(binary, work, m3_path=m3, souffle=souffle,
                       additional_call_targets=[pair for pair, found in graph.call_edges.items() if found],
                       additional_tail_targets=graph.tail_edges, opaque_sites=graph.opaque_sites,
                       additional_continuations=graph.additional_continuations())
                run_m6(binary, work, m3_path=m3, m4_path=m4, m5_path=work / "m5", souffle=souffle)
                m5 = StageFacts(work / "m5", "m5", m3_hash, binary_hash)
                m6 = StageFacts(work / "m6", "m6", m3_hash, binary_hash)
                if m6.meta["m4_manifest_sha256"] != m4_input.digest or m6.meta["m5_manifest_sha256"] != m5.digest:
                    raise ValueError("M7 analysis inputs changed during iteration")
                values = graph.observations(m6)
                round_result = graph.extend(values, len(iterations) + 1)
                iterations.append(round_result)
                if any(round_result[key] for key in ("new_call_edges", "new_tail_edges", "new_opaque_sites")):
                    continue

                sites = graph.indirect_calls(values, m5)
                reports = {"call_graph.json": graph.call_graph(m5), "indirect_calls.json": {"sites": sites},
                           "iterations.json": {"rounds": iterations}}
                for name, data in reports.items():
                    write_json(work / name, data, binary=binary)
                hashes = {name: _digest(work / name) for name in reports}
                hashes.update({"m5/manifest.json": m5.digest, "m6/manifest.json": m6.digest})
                generation = "analysis-" + hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()
                if _digest(m3 / "manifest.json") != m3_hash or _digest(m4 / "manifest.json") != m4_input.digest:
                    raise ValueError("M7 inputs changed before publication")
                try:
                    work.rename(dest / generation)
                except OSError:
                    if not all((dest / generation / name).is_file() and _digest(dest / generation / name) == digest
                               for name, digest in hashes.items()):
                        raise
                counts = dict(call_edges=len(reports["call_graph.json"]["edges"]), indirect_sites=len(sites),
                              new_call_edges=sum(found > 0 for found in graph.call_edges.values()),
                              tail_edges=len(graph.tail_edges), new_tail_edges=sum(found > 0 for found in graph.tail_edges.values()))
                for status in ("resolved", "partial", "unresolved", "unreachable"):
                    counts[status] = sum(site["status"] == status for site in sites)
                result = dict(stage="M7", schema="bpa.m7.v1", address_space="elf-va", binary_sha256=binary_hash,
                              m3_manifest_sha256=m3_hash, m4_manifest_sha256=m4_input.digest, converged=True,
                              iterations=len(iterations), results_dir=generation, files=hashes, counts=counts)
                write_json(dest / "manifest.json", result, binary=binary)
                return result
