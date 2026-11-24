"""Initial CFG and function observations behind an angr-independent interface."""

from collections import defaultdict
from dataclasses import replace
import hashlib
from io import BytesIO
from pathlib import Path

import angr
import cle
from capstone import CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_REG_EIP, X86_REG_RIP

from bpa.model import BinaryInfo
from bpa.model.cfg import ATEvidence, BasicBlock, CFGResult, Edge, Function, Instruction, Transfer


class CFGError(ValueError):
    """The supplied M1 artifact cannot produce a consistent initial CFG."""


# Mirrors BPA-X's pre-process/user_defined_addr_func.dl list.
_COMPILER_BUILTINS = frozenset({
    "deregister_tm_clones", "register_tm_clones", "frame_dummy",
    "__libc_csu_init", "__libc_csu_fini", "__libc_start_main",
    "__do_global_dtors_aux", "_fini", "__x86.get_pc_thunk.bx",
    "__x86.get_pc_thunk.dx", "_start", "_start_c", "__errno_location",
    "__stack_chk_fail", "_dl_relocate_static_pie", "__plt_dispatcher",
    "_init", "__divsc3", "__mulsc3", "__umoddi3", "__udivdi3",
    "__moddi3", "__divdi3",
})


def _is_user_defined(function: Function, text_ranges) -> bool:
    """Apply BPA-X's user-defined function filter to an exported function."""
    if (function.name.startswith("sub_") or function.is_plt
            or function.name in _COMPILER_BUILTINS):
        return False
    # BPA-X requires the entry to be inside .text. Fall back to the executable
    # regions when a section table is unavailable.
    return (not text_ranges
            or any(start <= function.entry < end for start, end in text_ranges))


def _export_user_defined(functions, blocks, transfers, diagnostics, text_ranges):
    """Mirror BPA-X's sub_* merge and user_defined_addr_func filtering.

    CFGFast emits one-block sub_* entries for alignment padding and jump
    thunks on bzip2. BPA-X merges them into the preceding function before
    filtering compiler built-ins and PLT; do the same for the exported view.
    Blocks that lose their only owner remain in the graph and are diagnosed.
    """
    ordered = sorted(functions, key=lambda function: function.entry)
    predecessors = {}
    previous = None
    for function in ordered:
        if function.name.startswith("sub_"):
            predecessors[function.entry] = previous
        else:
            previous = function.entry

    # BPA-X's addr_func upper bound is the next raw function start, and
    # func-bound-merge absorbs consecutive sub_* functions into the preceding
    # one. The merged upper of an exported function is therefore the first
    # following non-sub_* entry; using it keeps code_ranges end addresses
    # aligned with BPA-X, including trailing alignment padding.
    merged_upper = {}
    for index, function in enumerate(ordered):
        following = index + 1
        while following < len(ordered) and ordered[following].name.startswith("sub_"):
            following += 1
        merged_upper[function.entry] = (
            ordered[following].entry if following < len(ordered) else None)

    kept = {function.entry for function in ordered if _is_user_defined(function, text_ranges)}
    owner_map = {}
    for function in ordered:
        if function.entry in kept:
            owner_map[function.entry] = function.entry
        elif function.name.startswith("sub_"):
            target = predecessors[function.entry]
            owner_map[function.entry] = target if target in kept else None
        else:
            owner_map[function.entry] = None

    def remap(entries):
        return tuple(sorted({owner_map[entry] for entry in entries
                             if owner_map.get(entry) is not None}))

    exported_blocks = []
    diagnostics = list(diagnostics)
    diagnostic_set = set(diagnostics)
    for block in blocks:
        owners = remap(block.function_entries)
        if block.function_entries and not owners:
            message = f"Block has no user-defined function owner: {block.address:#x}"
            if message not in diagnostic_set:
                diagnostics.append(message)
                diagnostic_set.add(message)
        exported_blocks.append(replace(block, function_entries=owners))

    blocks_by_owner = defaultdict(list)
    for block in exported_blocks:
        for entry in block.function_entries:
            blocks_by_owner[entry].append(block)
    exported_functions = []
    for function in ordered:
        if function.entry not in kept:
            continue
        owned = blocks_by_owner[function.entry]
        ranges = list(_ranges((block.address, block.address + block.size) for block in owned))
        upper = merged_upper.get(function.entry)
        if ranges and upper is not None and upper > ranges[-1][1]:
            ranges[-1] = (ranges[-1][0], upper)
        exported_functions.append(replace(
            function,
            blocks=tuple(block.address for block in owned),
            code_ranges=tuple(ranges),
        ))

    exported_transfers = [
        replace(transfer, function_entries=remap(transfer.function_entries))
        for transfer in transfers
    ]
    return (tuple(exported_functions), tuple(exported_blocks),
            tuple(exported_transfers), tuple(diagnostics))


def _ranges(intervals):
    result = []
    for start, end in sorted(intervals):
        if result and start <= result[-1][1]:
            result[-1] = (result[-1][0], max(result[-1][1], end))
        else:
            result.append((start, end))
    return tuple(result)


def build_cfg(info: BinaryInfo) -> CFGResult:
    """Consume M1 observations and return functions, blocks and initial edges.

    Addresses in the result are ELF VAs. Synthetic extern nodes and angr's
    UnresolvableCallTarget are not exported as real program functions/targets.
    """
    if info.schema_version != 2 or info.address_space != "elf-va":
        raise CFGError("M2 requires M1 schema 2 with address_space=elf-va")
    if info.arch not in ("AMD64", "X86"):
        raise CFGError(f"M2 currently supports AMD64/X86, got {info.arch}")
    if info.bits != {"AMD64": 64, "X86": 32}[info.arch] or info.endianness != "little":
        raise CFGError("M1 bit width/endianness does not match its X86 architecture")
    if info.mapped_entry != info.entry + info.load_bias:
        raise CFGError("M1 ELF entry and mapped entry are inconsistent")
    if info.auto_load_libs or info.loader_backend != "cle" or info.loader_version != cle.__version__:
        raise CFGError("M1 loader policy/version does not match M2; regenerate M1")
    data = Path(info.path).read_bytes()
    if hashlib.sha256(data).hexdigest() != info.sha256:
        raise CFGError("ELF SHA256 does not match the M1 artifact")
    project = angr.Project(BytesIO(data), auto_load_libs=False, main_opts={"base_addr": info.mapped_base})
    obj = project.loader.main_object
    if (obj.arch.name, obj.linked_base, obj.mapped_base, obj.entry) != (
        info.arch, info.linked_base, info.mapped_base, info.mapped_entry
    ):
        raise CFGError("M2 loaded addresses/architecture do not match the M1 artifact")
    bias = info.load_bias

    def valid(address):
        return any(r.start <= address - bias < r.end for r in info.executable_regions)

    symbols = defaultdict(list)
    for symbol in info.symbols:
        if symbol.is_function and symbol.elf_address is not None and valid(symbol.elf_address + bias):
            symbols[symbol.elf_address + bias].append(symbol)
    options = dict(normalize=True, resolve_indirect_jumps=True, detect_tail_calls=False)
    cfg = project.analyses.CFGFast(**options, function_starts=sorted(symbols),
                                   regions=[(r.start + bias, r.end + bias) for r in info.executable_regions])
    functions = {f.addr: f for f in cfg.kb.functions.values() if valid(f.addr) and not f.is_simprocedure}
    nodes = {}
    diagnostics = []
    for node in cfg.graph.nodes():
        if not node.size or not valid(node.addr):
            continue
        if node.addr in nodes:
            raise CFGError(f"Duplicate CFG nodes at {node.addr - bias:#x}")
        nodes[node.addr] = node
    owners = defaultdict(set)
    for entry, function in functions.items():
        for address in function.block_addrs_set & nodes.keys():
            owners[address].add(entry - bias)
    blocks, machine = {}, {}
    for address, node in sorted(nodes.items()):
        block = project.factory.block(address, size=node.size)
        jumpkind = block.vex.jumpkind
        decoded = [wrapped.insn for wrapped in block.capstone.insns]
        if not decoded:
            raise CFGError(f"No decoded instructions for CFG block {address - bias:#x}")
        if sum(i.size for i in decoded) != block.size:
            diagnostics.append(f"Incomplete disassembly at {address - bias:#x}")
        if not owners[address]:
            diagnostics.append(f"Block has no recovered function owner: {address - bias:#x}")
        blocks[address] = BasicBlock(address - bias, block.size, tuple(sorted(owners[address])),
                                     tuple(Instruction(i.address - bias, i.size, i.mnemonic, i.op_str) for i in decoded),
                                     jumpkind)
        machine[address] = decoded

    def transfer_kind(address):
        last = machine[address][-1]
        if last.group(CS_GRP_CALL):
            return "call"
        if last.group(CS_GRP_RET):
            return "return"
        if last.group(CS_GRP_JUMP):
            return "jump"
        return "fallthrough" if blocks[address].jumpkind == "Ijk_Boring" else "other"

    def indirect(address):
        last = machine[address][-1]
        return transfer_kind(address) in ("call", "jump") and (
            not last.operands or last.operands[0].type != X86_OP_IMM)

    external = {i.target_mapped_address: i.name for i in info.imports if i.target_mapped_address is not None}
    edges = set()
    for source, target, attributes in cfg.graph.edges(data=True):
        if source.addr not in blocks:
            continue
        external_name = external.get(target.addr) if target.addr not in blocks else None
        if target.addr not in blocks and external_name is None:
            # This includes the unresolved indirect-call placeholder, not a real target.
            continue
        jumpkind = attributes.get("jumpkind", "unknown")
        kind = {"Ijk_Call": "call", "Ijk_Ret": "return", "Ijk_FakeRet": "fake_return"}.get(jumpkind, "other")
        if jumpkind == "Ijk_Boring":
            if transfer_kind(source.addr) == "jump" and machine[source.addr][-1].mnemonic in ("jmp", "ljmp"):
                kind = "jump"
            else:
                kind = "fallthrough" if target.addr == source.addr + blocks[source.addr].size else "branch"
        provenance = ("assumed-return" if kind == "fake_return" else "cfgfast-return" if kind == "return"
                      else "cfgfast-indirect" if indirect(source.addr) else "machine-cfgfast")
        edges.add(Edge(source.addr - bias, target.addr - bias if target.addr in blocks else None,
                       kind, jumpkind, provenance, external_name))
    ordered_edges = tuple(sorted(edges, key=lambda e: (e.source, e.target is None, e.target or 0,
                                                      e.kind, e.external_symbol or "")))
    outgoing = defaultdict(list)
    for edge in ordered_edges:
        outgoing[edge.source].append(edge)
    transfers = []
    for address, block in blocks.items():
        last = machine[address][-1]
        kind, is_indirect = transfer_kind(address), indirect(address)
        relevant = [e for e in outgoing[block.address] if e.kind != "fake_return"]
        direct = None
        if kind in ("call", "jump") and not is_indirect and last.operands:
            target = last.operands[0].imm & ((1 << info.bits) - 1)
            if valid(target):
                direct = target - bias
        targets = {e.target for e in relevant if e.target is not None}
        if direct is not None:
            targets.add(direct)
        external_targets = tuple(sorted({e.external_symbol for e in relevant if e.external_symbol is not None}))
        continuation = next((e.target for e in outgoing[block.address]
                             if e.kind == "fake_return" and e.target == last.address + last.size - bias), None)
        if is_indirect:
            status = "resolved" if targets or external_targets else "unresolved"
            target_source = ("cfgfast-jump-table" if address in cfg.jump_tables or last.address in cfg.jump_tables
                             else "cfgfast-indirect") if status == "resolved" else "unresolved"
        else:
            status = "direct" if kind in ("call", "jump") else kind
            target_source = "machine" if status == "direct" else "cfgfast-return" if kind == "return" else "cfgfast"
        transfers.append(Transfer(last.address - bias, block.address, block.function_entries, kind, is_indirect,
                                  direct, tuple(sorted(targets)), external_targets, continuation, status, target_source))

    evidence = defaultdict(set)
    mask = (1 << info.bits) - 1

    def address_taken(value, source, address):
        if value in functions:
            evidence[value].add((source, address))

    for decoded in machine.values():
        for instruction in decoded:
            # A direct CALL/JMP destination alone is not AT evidence.
            if instruction.group(CS_GRP_CALL) or instruction.group(CS_GRP_JUMP):
                continue
            for operand in instruction.operands:
                if operand.type == X86_OP_IMM:
                    address_taken(operand.imm & mask, "instruction-immediate", instruction.address - bias)
                elif instruction.mnemonic == "lea" and operand.type == X86_OP_MEM:
                    if operand.mem.base in (X86_REG_RIP, X86_REG_EIP) and not operand.mem.index:
                        address_taken((instruction.address + instruction.size + operand.mem.disp) & mask,
                                      "instruction-address", instruction.address - bias)
                    elif not operand.mem.base and not operand.mem.index:
                        address_taken(operand.mem.disp & mask, "instruction-address", instruction.address - bias)
    word = info.bits // 8
    for region in info.global_regions:
        raw = project.loader.memory.load(region.start + bias, region.end - region.start)
        for offset in range(0, len(raw) - word + 1, word):
            address_taken(int.from_bytes(raw[offset:offset + word], info.endianness),
                          "global-initializer", region.start + offset)
    plt = {p.mapped_address for p in info.plt}
    records = []
    for entry, function in sorted(functions.items()):
        names = {s.name for s in symbols[entry]}
        name = function.name
        addresses = tuple(sorted(a for a in function.block_addrs_set if a in blocks))
        sizes = [s.size for s in symbols[entry] if s.size > 0]
        records.append(Function(
            entry=entry - bias, name=name, aliases=tuple(sorted(names - {name})),
            source="plt" if entry in plt else "elf-symbol" if names else "cfgfast",
            symbol_end=entry - bias + max(sizes) if sizes else None,
            blocks=tuple(a - bias for a in addresses),
            code_ranges=_ranges((a - bias, a - bias + blocks[a].size) for a in addresses),
            is_plt=entry in plt, address_taken=bool(evidence[entry]),
            at_evidence=tuple(ATEvidence(source, address) for source, address in sorted(evidence[entry])),
        ))
    text_ranges = tuple((section.virtual_address, section.virtual_address + section.size)
                        for section in info.sections if section.name == ".text" and section.size)
    exported_functions, exported_blocks, exported_transfers, diagnostics = _export_user_defined(
        records, blocks.values(), transfers, diagnostics, text_ranges
    )
    return CFGResult(info.path, info.sha256, info.arch, info.bits, info.entry, angr.__version__,
                     dict(options, function_starts="M1 defined function symbols"), exported_functions,
                     exported_blocks, ordered_edges, exported_transfers, diagnostics)
