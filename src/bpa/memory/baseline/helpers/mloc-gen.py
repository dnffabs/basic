# Putting all memory blocks in one fact file
import sys
import os


def mloc_sblk():
    fact_dir = sys.argv[1]
    output_file = os.path.join(fact_dir, "mloc_sblk.facts")

    output_lines = []
    counter = 1

    # process sblk: local_block_boundary.facts
    local_dict = {}
    with open(os.path.join(fact_dir, "local_block_boundary.facts"), "r") as f:
        for line in f:
            words = line.split()
            func_addr = int(words[3])
            offset = int(words[4])
            if func_addr not in local_dict:
                local_dict[func_addr] = set()
            local_dict[func_addr].add(offset)

    arg_passing_blocks_map = {}
    with open(os.path.join(fact_dir, "tmp_reg_func_arg_passing.facts"), "r") as f:
        for line in f:
            words = line.split()
            func_addr = int(words[1])
            offset = int(words[2])
            call_site = int(words[3])
            if (func_addr, offset) not in arg_passing_blocks_map:
                arg_passing_blocks_map[(func_addr, offset)] = set()
            arg_passing_blocks_map[(func_addr, offset)].add(call_site)

    for func_addr in local_dict:
        sorted_offset = sorted(local_dict[func_addr])
        # add the lowest
        output_lines.append(f"{counter}\t{func_addr}\t0\t{sorted_offset[0]}\t0\t1\t0")
        counter += 1
        if (func_addr, sorted_offset[0]) in arg_passing_blocks_map:
            for call_site in arg_passing_blocks_map[(func_addr, sorted_offset[0])]:
                output_lines.append(
                    f"{counter}\t{func_addr}\t0\t{sorted_offset[0]}\t0\t1\t{call_site}"
                )
                counter += 1
        i = 0
        while i < len(sorted_offset) - 1:
            output_lines.append(
                f"{counter}\t{func_addr}\t{sorted_offset[i]}\t{sorted_offset[i + 1]}\t1\t1\t0"
            )
            counter += 1
            if (func_addr, sorted_offset[i]) in arg_passing_blocks_map:
                for call_site in arg_passing_blocks_map[(func_addr, sorted_offset[i])]:
                    output_lines.append(
                        f"{counter}\t{func_addr}\t{sorted_offset[i]}\t{sorted_offset[i + 1]}\t1\t1\t{call_site}"
                    )
                    counter += 1
            i += 1
        # add the highest
        output_lines.append(f"{counter}\t{func_addr}\t{sorted_offset[i]}\t0\t1\t0\t0")
        counter += 1
        if (func_addr, sorted_offset[i]) in arg_passing_blocks_map:
            for call_site in arg_passing_blocks_map[(func_addr, sorted_offset[i])]:
                output_lines.append(
                    f"{counter}\t{func_addr}\t{sorted_offset[i]}\t0\t1\t0\t{call_site}"
                )
                counter += 1

    with open(output_file, "w") as f:
        for line in output_lines:
            f.write(line + "\n")


# def mloc_sblk_old():
#     fact_dir = sys.argv[1]
#     output_file = os.path.join(fact_dir, "mloc_sblk.facts")

#     output_lines = []
#     counter = 1

#     # process sblk: local_block_boundary.facts
#     local_dict = {}
#     with open(os.path.join(fact_dir, "local_block_boundary.facts"), "r") as f:
#         for line in f:
#             words = line.split()
#             func_addr = int(words[3])
#             offset = int(words[4])
#             if func_addr not in local_dict:
#                 local_dict[func_addr] = set()
#             local_dict[func_addr].add(offset)
#     for func_addr in local_dict:
#         sorted_offset = sorted(local_dict[func_addr])
#         # add the lowest
#         output_lines.append(f"{counter}\t{func_addr}\t0\t{sorted_offset[0]}\t0\t1")
#         counter += 1
#         i = 0
#         while i < len(sorted_offset) - 1:
#             output_lines.append(
#                 f"{counter}\t{func_addr}\t{sorted_offset[i]}\t{sorted_offset[i + 1]}\t1\t1"
#             )
#             counter += 1
#             i += 1
#         # add the highest
#         output_lines.append(f"{counter}\t{func_addr}\t{sorted_offset[i]}\t0\t1\t0")
#         counter += 1

#     with open(output_file, "w") as f:
#         for line in output_lines:
#             f.write(line + "\n")


def global_mode():
    # normal: boundaries from referenced immediates (default)
    # coarser: same, plus a coarser tier spanning indexed objects
    # symtbl:  boundaries from global variables in the ELF symbol table
    return sys.argv[2] if len(sys.argv) > 2 else "normal"


def mloc_gblk():
    fact_dir = sys.argv[1]
    output_file = os.path.join(fact_dir, "mloc_gblk.facts")

    output_lines = []
    counter = 1

    # process gblk: global_block_boundary.facts (or the symbol table)
    global_block_set = set()
    if global_mode() == "symtbl":
        with open(os.path.join(fact_dir, "global_symbol_boundary.facts"), "r") as f:
            for line in f:
                words = line.split()
                global_block_set.add(int(words[0]))
                global_block_set.add(int(words[1]))
    else:
        with open(os.path.join(fact_dir, "global_block_boundary.facts"), "r") as f:
            for line in f:
                words = line.split()
                start_addr = int(words[1])
                global_block_set.add(start_addr)

    add_default_global_rgn(global_block_set)

    sorted_global_blocks = sorted(global_block_set)
    if len(sorted_global_blocks) > 0:
        # Only the closed blocks between consecutive boundaries, none below the
        # lowest boundary or above the highest: every region edge is a boundary
        # (add_default_global_rgn), so no address inside a global region lies
        # there, and those two open-ended blocks only ever collected the NULL
        # words, integers and code addresses the fixed point's seed used to map
        # into them. Their former ids (the first and the last) stay unused, so
        # every other block, and every coarser block numbered after these, keeps
        # its id.
        counter += 1
        i = 0
        while i < len(sorted_global_blocks) - 1:
            output_lines.append(
                f"{counter}\t{sorted_global_blocks[i]}\t{sorted_global_blocks[i + 1]}\t1\t1"
            )
            counter += 1
            i += 1
        counter += 1

    with open(output_file, "w") as f:
        for line in output_lines:
            f.write(line + "\n")

    return counter


def mloc_gcoarser(counter):
    fact_dir = sys.argv[1]
    output_file = os.path.join(fact_dir, "mloc_gcoarser.facts")

    output_lines = []

    # process gcoarser: global_coarser_boundary.facts
    # The IDs continue mloc_gblk's, since both tiers share the global block ID
    # space. The file is written empty unless the mode asks for a coarser tier.
    if global_mode() == "coarser":
        global_coarser_set = set()
        with open(os.path.join(fact_dir, "global_coarser_boundary.facts"), "r") as f:
            for line in f:
                words = line.split()
                global_coarser_set.add(int(words[0]))

        add_default_global_rgn(global_coarser_set)

        sorted_global_coarser = sorted(global_coarser_set)
        if len(sorted_global_coarser) > 0:
            # Closed blocks only, as in mloc_gblk; the first id stays unused so
            # the others keep theirs.
            counter += 1
            i = 0
            while i < len(sorted_global_coarser) - 1:
                output_lines.append(
                    f"{counter}\t{sorted_global_coarser[i]}\t{sorted_global_coarser[i + 1]}\t1\t1"
                )
                counter += 1
                i += 1

    with open(output_file, "w") as f:
        for line in output_lines:
            f.write(line + "\n")


def mloc_gchk():
    fact_dir = sys.argv[1]
    output_file = os.path.join(fact_dir, "mloc_gchk.facts")

    output_lines = []
    counter = 1

    # process gchk: global_chunk_boundary.facts
    global_chunk_set = set()
    with open(os.path.join(fact_dir, "global_chunk_boundary.facts"), "r") as f:
        for line in f:
            words = line.split()
            start_addr = int(words[1])
            global_chunk_set.add(start_addr)

    add_default_global_rgn(global_chunk_set)

    sorted_global_chunks = sorted(global_chunk_set)
    if len(sorted_global_chunks) > 0:
        # Closed blocks only, as in mloc_gblk; the first id stays unused so the
        # others keep theirs.
        counter += 1
        i = 0
        while i < len(sorted_global_chunks) - 1:
            output_lines.append(
                f"{counter}\t{sorted_global_chunks[i]}\t{sorted_global_chunks[i + 1]}\t1\t1"
            )
            counter += 1
            i += 1

    with open(output_file, "w") as f:
        for line in output_lines:
            f.write(line + "\n")


def mloc_hblk():
    fact_dir = sys.argv[1]
    output_file = os.path.join(fact_dir, "mloc_hblk.facts")

    output_lines = []
    counter = 1

    # process hblk: heap_block.facts
    with open(os.path.join(fact_dir, "heap_block.facts"), "r") as f:
        for line in f:
            alloc_instr_addr = int(line)
            output_lines.append(f"{counter}\t{alloc_instr_addr}")
            counter += 1

    with open(output_file, "w") as f:
        for line in output_lines:
            f.write(line + "\n")


def add_default_global_rgn(global_set):
    fact_dir = sys.argv[1]
    with open(os.path.join(fact_dir, "global_rgn.facts"), "r") as f:
        for line in f:
            words = line.split()
            start_addr = int(words[1])
            end_addr = int(words[2]) + 1  # make it exclusive
            global_set.add(start_addr)
            global_set.add(end_addr)


if __name__ == "__main__":
    mloc_sblk()
    mloc_gcoarser(mloc_gblk())
    mloc_gchk()
    mloc_hblk()
