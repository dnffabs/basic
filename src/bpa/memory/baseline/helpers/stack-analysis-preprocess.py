# Executed before stack analysis (finding local memory blocks)
# Use python instead of Datalog for some rules having aggregation functions

import os
import sys
import re
import subprocess
import bisect


# last_def_before_use_local.facts
# Within the same BB, the last def instruction before the use registers
def last_def_before_use_local(
    get_loc_vex_exp, set_tmp_reg_vex, set_loc_vex, bb_addr_bound
):
    # uses
    use_loc_eid = {}
    for line in get_loc_vex_exp:
        loc = line[1]
        eid = line[0]
        use_loc_eid[eid] = loc
    use_addr_order_loc = []
    for line in set_tmp_reg_vex:
        eid = line[3]
        if eid in use_loc_eid:
            addr = int(line[0])
            order = int(line[1])
            use_addr_order_loc.append((addr, order, use_loc_eid[eid]))

    # defs
    bb_bounds = []
    for line in bb_addr_bound:
        start = int(line[0])
        end = int(line[1])
        bb_bounds.append((start, end))
    bb_bounds.sort(key=lambda x: x[0])
    bb_starts = [start for start, _ in bb_bounds]
    def_bb_addr_order_loc = {}
    for line in set_loc_vex:
        loc = line[4]
        addr = int(line[0])
        order = int(line[1])
        bb = find_bb_containing_addr(addr, bb_bounds, bb_starts)
        if bb not in def_bb_addr_order_loc:
            def_bb_addr_order_loc[bb] = []
        def_bb_addr_order_loc[bb].append((addr, order, loc))

    # lookup
    result = []
    for use_addr, use_order, use_loc in use_addr_order_loc:
        bb = find_bb_containing_addr(use_addr, bb_bounds, bb_starts)
        if bb in def_bb_addr_order_loc:
            defs = def_bb_addr_order_loc[bb]
            valid_defs = []
            for def_addr, def_order, def_loc in defs:
                if def_loc == use_loc:
                    if def_addr < use_addr or (
                        def_addr == use_addr and def_order < use_order
                    ):
                        valid_defs.append((def_addr, def_order, def_loc))
            last_def = max(valid_defs, key=lambda x: (x[0], x[1]), default=None)
            if last_def:
                result.append((last_def[0], last_def[1], use_addr, use_order, use_loc))
    return result


def find_bb_containing_addr(addr, bb_bounds, bb_starts):
    # bb_bounds is sorted by start, bb_starts is its parallel list of starts;
    # binary-search for the rightmost BB whose start is <= addr.
    i = bisect.bisect_right(bb_starts, addr) - 1
    if i >= 0:
        start, end = bb_bounds[i]
        if start <= addr <= end:  # the BB bound ends are inclusive
            return start
    return None


# From roots, perform BFS and only keep one edge which is first explored to each node
def get_spanning_tree(edges, roots):
    from collections import deque

    graph = {}
    for src, dst in edges:
        if src not in graph:
            graph[src] = []
        graph[src].append(dst)

    visited = set()
    tree_edges = []
    queue = deque()

    # init
    for r in roots:
        if r not in visited:
            visited.add(r)
            queue.append(r)

    while queue:
        node = queue.popleft()
        if node in graph:
            for neighbor in graph[node]:
                if neighbor not in visited:
                    visited.add(neighbor)
                    tree_edges.append((node, neighbor))
                    queue.append(neighbor)

    return tree_edges


# return the instruction address where lea instruction is saving an offset + stack-related register to a register
# e.g. lea -0x10(%ebp), %eax
LEA_ADDR_REG = re.compile(
    r"(?i)([0-9a-f]+):\s*(?:[0-9a-f]{2}\s+)*\s*lea[^v]?\s+[-]?0x[0-9a-f]+\(\%(?:ebp|esp|rbp|rsp)\)"
)


def lea_addr_reg(binary_file):
    objdump_cmd = ["objdump", "-d", "-w", "-M", "att", binary_file]
    result = subprocess.run(objdump_cmd, capture_output=True, text=True, check=True)
    asm_lines = result.stdout.splitlines()

    instr_addrs = set()
    for line in asm_lines:
        match = LEA_ADDR_REG.search(line)
        if match:
            instr_addrs.add((int(match.group(1), 16),))
    return instr_addrs


def read_facts(file_path):
    facts = []
    with open(file_path, "r") as f:
        for line in f.readlines():
            words = line.split()
            facts.append(words)
    return facts


def write_facts(content, file_path):
    with open(file_path, "w") as f:
        for line in content:
            f.write("\t".join(map(str, line)) + "\n")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python stack-analysis-preprocess.py <facts_dir> <binary_file>")
        sys.exit(1)

    get_loc_vex_exp = read_facts(os.path.join(sys.argv[1], "get_loc_vex_exp.facts"))
    set_tmp_reg_vex = read_facts(os.path.join(sys.argv[1], "set_tmp_reg_vex.facts"))
    set_loc_vex = read_facts(os.path.join(sys.argv[1], "set_loc_vex.facts"))
    bb_addr_bound = read_facts(os.path.join(sys.argv[1], "bb_addr_bound.facts"))
    edge_cfg_intra_w_inter_succ = read_facts(
        os.path.join(sys.argv[1], "edge_cfg_intra_w_inter_succ.facts")
    )
    first_bbs = read_facts(os.path.join(sys.argv[1], "first_bbs.facts"))

    write_facts(
        last_def_before_use_local(
            get_loc_vex_exp, set_tmp_reg_vex, set_loc_vex, bb_addr_bound
        ),
        os.path.join(sys.argv[1], "last_def_before_use_local.facts"),
    )

    # sort edge_cfg_intra_w_inter_succ to make output deterministic
    edge_cfg_intra_w_inter_succ.sort(key=lambda x: (int(x[0]), int(x[1])))
    first_bbs.sort(key=lambda x: int(x[0]))

    write_facts(
        get_spanning_tree(edge_cfg_intra_w_inter_succ, [i[0] for i in first_bbs]),
        os.path.join(sys.argv[1], "edge_cfg_intra_w_inter_succ_spanning_tree.facts"),
    )

    write_facts(
        lea_addr_reg(sys.argv[2]),
        os.path.join(sys.argv[1], "lea_addr_reg.facts"),
    )
