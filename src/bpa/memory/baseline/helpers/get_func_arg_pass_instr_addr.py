# In x86, argument passed via stack can be identified by:
# (1) push instructions
# in the same BB with call instructions and after (if any) sub-esp instruction
# (2) mov instructions that store into [esp + offset]
# in the same BB with call instructions and after (if any) sub-esp instruction,
# limited to the contiguous run of slots starting at the call's stack pointer,
# see stack_arg_movs
#
# Call sites are direct (call <addr>), indirect (call *%reg), and the jmp sites
# that reverse-tail-call-opt.dl marked as reversed tail calls; all three pass
# stack arguments, a tail call one slot higher because it inherits its caller's
# return address. Pushes that belong to a function prologue rather than to
# argument setup are excluded, see FP_SETUP_RE and CALLEE_SAVED_PUSH_RE.

# Output format in func_arg_pass_instr_addr.facts:
# <instr_addr> <call_site_addr> <max_total_arg_size>
# max_total_arg_size is the maximum total size of stack-passed arguments at this call site (in bytes)
#
# Known limitations of this detection
# -----------------------------------
# Detection is basic-block scoped. Arguments set up in a predecessor block are
# invisible. In test_52 only 181 of 513 reversed tail-call sites received any
# argument row; the rest either pass arguments in registers or set them up
# earlier. This is the largest remaining gap in argument coverage.
#
# Stack pointer adjustments other than push/pop/sub/add are not modelled.
# SP_SUB_RE and SP_ADD_RE match only "sub/add $imm,%sp", so register-operand
# adjustments, "lea -imm(%esp),%esp" and alloca-style variable adjustments are
# missed and sp_cursor drifts, placing stores at wrong slots. Stack realignment
# ("and $0xfffffff0,%esp") is likewise unmodelled; the prologue rules hide it in
# the common case but not in general.
#
# Push width is assumed to be one word. PUSH_RE matches pushw/pushf, which move
# the stack pointer by other amounts, but they are charged a full word. No such
# mnemonic occurs in the current benchmarks, so this is latent.
#
# The scan assumes monotonic, non-overlapping basic blocks. bb_index only moves
# forward, so overlapping or out-of-order blocks silently skip instructions, and
# the loop can fall through with stale bounds once bb_bounds is exhausted. No
# overlap occurs in the current benchmarks.
#
# objdump and angr can disagree. This reads an objdump linear sweep while the
# block bounds come from angr's recursive descent, so data decoded as code can
# produce phantom pushes or calls.
#
# MPX-prefixed calls are not matched. objdump prints "bnd call ...", which no
# pattern here matches. Not present in the current benchmarks.
#
# The mov run heuristic is an approximation, see stack_arg_movs. A call whose
# slot 0 is written in another block, or whose arguments are non-contiguous, is
# under-approximated; a local spill that happens to land on slot 0 is wrongly
# accepted (observed before a pow@plt call in test_48). It fails safe towards
# under-approximation, losing connections rather than inventing them.
#
# Evidence for the two most recent additions. Both are correct at fact level:
# the mov-store detection adds 101 to 291 covered sites per test at -O2/-O3
# while rejecting 327 to 864 spills, and exactly 0 at -O0 where everything is
# pushed; the prologue register-save suppression removes 999 argument pairs in
# test_55. Neither changed icall_target.facts anywhere in SPEC tests 2-53.
# Single-change ablation on lighttpd -O2 32-bit (test_92) attributes the output
# there: dropping the mov-store detection costs 208 of 4316 targets, while
# dropping the prologue register-save suppression costs none. So the mov-store
# detection is demonstrated on lighttpd; the prologue suppression still has no
# measured effect on any analysis output.

import re
import sys
import subprocess
import os

# Matches any push-like mnemonic (push, pushq, pushl, pushf, etc.)
PUSH_RE = re.compile(r"(?i)(?:[0-9a-f]+):\s*(?:[0-9a-f]{2}\s+)*\s*push[\w]*")
# Matches any pop-like mnemonic
POP_RE = re.compile(r"(?i)(?:[0-9a-f]+):\s*(?:[0-9a-f]{2}\s+)*\s*pop[\w]*")
# Matches a push of a callee-saved register, i.e. a register save rather than
# an argument. Only used while still inside a function prologue.
CALLEE_SAVED_PUSH_RE = re.compile(
    r"(?i)(?:[0-9a-f]+):\s*(?:[0-9a-f]{2}\s+)*\s*push[\w]*\s+"
    r"%(?:ebx|esi|edi|ebp|rbx|rsi|rdi|rbp|r1[2-5])\s*$"
)
# Matches instructions a prologue may contain before its register saves
PROLOGUE_FILLER_RE = re.compile(
    r"(?i)(?:[0-9a-f]+):\s*(?:[0-9a-f]{2}\s+)*\s*(?:endbr32|endbr64|nop|xchg\s+%ax,%ax)"
)
# Matches add sp instructions, e.g. the epilogue that precedes a tail call
SP_ADD_RE = re.compile(
    r"(?i)(?:[0-9a-f]+):\s*(?:[0-9a-f]{2}\s+)*\s*add[\w]*\s+\$(0x[0-9a-f]+),\s*(?:%esp|%rsp)"
)
# Matches mov instructions that store into [sp + offset], capturing the offset.
# Only sp-relative stores can be outgoing arguments; a bp-relative store is a
# local. The pattern is anchored so that indexed forms such as
# mov %eax,0x4(%esp,%edx,4), which are array writes, do not match.
MOV_STACK_ARG_RE = re.compile(
    r"(?i)(?:[0-9a-f]+):\s*(?:[0-9a-f]{2}\s+)*\s*mov[\w]*\s+[^,]+,\s*(-?0x[0-9a-f]+)?\((?:%esp|%rsp)\)\s*$"
)
# Matches sub sp instructions
SP_SUB_RE = re.compile(
    r"(?i)(?:[0-9a-f]+):\s*(?:[0-9a-f]{2}\s+)*\s*sub[\w]*\s+\$(0x[0-9a-f]+),\s*(?:%esp|%rsp)"
)
# Matches the frame pointer setup that ends a function prologue. A push seen
# before it saves a register (e.g. push %ebp, push %ebx) and is not an outgoing
# argument of a call that comes later in the same BB.
FP_SETUP_RE = re.compile(
    r"(?i)(?:[0-9a-f]+):\s*(?:[0-9a-f]{2}\s+)*\s*mov[\w]*\s+(?:%esp,\s*%ebp|%rsp,\s*%rbp)"
)
# Matches any call, direct (call 8048400) or indirect (call *%eax)
CALL_RE = re.compile(
    r"(?i)(?:[0-9a-f]+):\s*(?:[0-9a-f]{2}\s+)*\s*call[\w]*\s"
)
INSTR_ADDR_RE = re.compile(r"(?i)([0-9a-f]+):")


def read_bb_bounds_from_facts(fact_dir):
    bb_bounds = []
    with open(os.path.join(fact_dir, "bb_addr_bound.facts"), "r") as f:
        for line in f:
            words = line.split()
            if len(words) == 2:
                bb_first_instr = int(words[0])
                bb_last_instr = int(words[1])
                bb_bounds.append((bb_first_instr, bb_last_instr))
    return bb_bounds


def read_addrs_from_facts(fact_dir, name, column=0):
    addrs = set()
    path = os.path.join(fact_dir, name)
    if not os.path.isfile(path):
        return addrs
    with open(path, "r") as f:
        for line in f:
            words = line.split()
            if len(words) > column:
                addrs.add(int(words[column]))
    return addrs


def get_word_size(arch):
    if arch == "X86":
        return 4
    elif arch == "AMD64":
        return 8
    else:
        sys.exit(f"Unsupported architecture: {arch}")


def stack_arg_movs(cur_movs, sp_cursor, word_size, first_slot):
    # Outgoing arguments occupy a contiguous run of slots starting at the stack
    # pointer as it stands at the call site, so keep only the stores covering
    # that run. Without this, register spills into the frame (common once
    # -fomit-frame-pointer makes locals sp-relative) would be recorded as
    # arguments.
    #
    # A store is placed at the slot it occupies at the call site, which means
    # rebasing it by however far the stack pointer moved in between. first_slot
    # is 0 for a call, whose return address is pushed by the call itself, and
    # one word for a tail call, which inherits the return address of its caller
    # and therefore keeps its arguments one slot higher.
    slots = {}
    for instr_addr, offset, cursor_at_store in cur_movs:
        slots.setdefault(offset + cursor_at_store - sp_cursor, instr_addr)
    run = []
    while first_slot + len(run) * word_size in slots:
        run.append(slots[first_slot + len(run) * word_size])
    return run


def write_to_facts(fact_dir, args_info):
    with open(os.path.join(fact_dir, "func_arg_pass_instr_addr.facts"), "w") as f:
        for call_site in args_info:
            arg_instrs, max_size = args_info[call_site]
            for arg_instr in arg_instrs:
                f.write(f"{arg_instr}\t{call_site}\t{max_size}\n")


def main():
    if len(sys.argv) != 4:
        print(
            "Usage: python get_func_arg_pass_instr_addr.py <binary> <arch> <fact_dir>"
        )
        sys.exit(1)

    binary = sys.argv[1]
    word_size = get_word_size(sys.argv[2])
    fact_dir = sys.argv[3]

    bb_bounds = read_bb_bounds_from_facts(fact_dir)
    bb_bounds.sort(key=lambda x: x[0])
    # reverse-tail-call-opt.dl runs before this script, so the reversed tail
    # calls are already known. They are jmp sites, so CALL_RE never sees them.
    tail_call_addrs = read_addrs_from_facts(fact_dir, "tail_call_addr.facts")
    func_starts = read_addrs_from_facts(fact_dir, "addr_func.facts", column=1)

    objdump_cmd = ["objdump", "-d", "-w", "-M", "att", binary]
    result = subprocess.run(objdump_cmd, capture_output=True, text=True, check=True)
    asm_lines = result.stdout.splitlines()

    # The scan walks the disassembly once, in address order, carrying the state
    # below. Everything except args_info describes the argument setup seen so
    # far for the next call site, and is cleared both when a call site consumes
    # it and when the scan moves to another basic block, since argument setup
    # never spans blocks.

    # the result: call_site_addr -> (arg instr addrs, max_total_arg_size)
    args_info = {}
    # position in bb_bounds, which is sorted by address and walked forwards only
    bb_index = 0
    # bytes the stack pointer has moved since the last reset, negative when it
    # has been lowered. Recorded stores are rebased through it.
    sp_cursor = 0
    # size of the most recent sub-sp, i.e. the outgoing argument area a call
    # reached this way was given. None when no sub-sp has been seen.
    cur_sub_sp_size = None
    # push instructions taken to be arguments, in the order encountered
    cur_args = []
    # sp-relative stores seen so far, as (instr addr, offset, sp_cursor at the
    # store). Which of them are arguments is only decided at the call site, by
    # stack_arg_movs, because that needs the stack pointer as it stands there.
    cur_movs = []
    # whether the scan is still inside a function prologue, where a push of a
    # callee-saved register saves it rather than passing it
    in_prologue = False
    for line in asm_lines:
        line = line.strip()
        instr_addr_match = INSTR_ADDR_RE.match(line)
        if not instr_addr_match:
            continue  # not an instruction line
        instr_addr = int(instr_addr_match.group(1), 16)

        if bb_index >= len(bb_bounds):
            break
        bb_first, bb_last = bb_bounds[bb_index]
        if instr_addr < bb_first:
            continue  # instructions we don't care about
        while bb_last < instr_addr:
            # move to the next BB where this instruction belongs
            bb_index += 1
            sp_cursor = 0
            cur_sub_sp_size = None
            cur_args = []
            cur_movs = []
            if bb_index >= len(bb_bounds):
                break
            bb_first, bb_last = bb_bounds[bb_index]

        if instr_addr in func_starts:
            in_prologue = True

        sp_sub_match = SP_SUB_RE.match(line)
        if sp_sub_match:
            # if there is a sub sp instruction, reset
            # the recorded stores are dropped too, their offsets were taken
            # against the old stack pointer
            cur_args = []
            cur_movs = []
            sp_cursor = 0
            cur_sub_sp_size = int(sp_sub_match.group(1), 16)
            in_prologue = False
            continue
        fp_setup_match = FP_SETUP_RE.match(line)
        if fp_setup_match:
            # the prologue ends here, nothing before it is argument setup
            cur_args = []
            cur_movs = []
            sp_cursor = 0
            cur_sub_sp_size = None
            in_prologue = False
            continue
        sp_add_match = SP_ADD_RE.match(line)
        if sp_add_match:
            # an epilogue raising the stack pointer, e.g. right before a tail
            # call. It does not start a new outgoing argument area, so the
            # recorded stores are kept and only rebased.
            sp_cursor += int(sp_add_match.group(1), 16)
            in_prologue = False
            continue
        push_match = PUSH_RE.match(line)
        if push_match:
            # a callee-saved register pushed in the prologue is a register
            # save, not an argument, even when no frame pointer is set up
            if not (in_prologue and CALLEE_SAVED_PUSH_RE.match(line)):
                cur_args.append(instr_addr)
                in_prologue = False
            sp_cursor -= word_size
            continue
        pop_match = POP_RE.match(line)
        if pop_match:
            sp_cursor += word_size
            in_prologue = False
            continue
        mov_stack_arg_match = MOV_STACK_ARG_RE.match(line)
        if mov_stack_arg_match:
            offset = mov_stack_arg_match.group(1)
            cur_movs.append((instr_addr, int(offset, 16) if offset else 0, sp_cursor))
            in_prologue = False
            continue
        if not PROLOGUE_FILLER_RE.match(line):
            in_prologue = False
        is_tail_call = instr_addr in tail_call_addrs
        if CALL_RE.match(line) or is_tail_call:
            if is_tail_call:
                # a tail call inherits its caller's return address, so its
                # arguments start one slot above the stack pointer and no push
                # of its own can reach the callee
                mov_args = stack_arg_movs(cur_movs, sp_cursor, word_size, word_size)
                max_total_arg_size = len(mov_args) * word_size
                arg_instrs = mov_args
            else:
                mov_args = stack_arg_movs(cur_movs, sp_cursor, word_size, 0)
                max_total_arg_size = 0
                if cur_sub_sp_size is not None:
                    max_total_arg_size = cur_sub_sp_size
                max_total_arg_size += len(cur_args) * word_size
                max_total_arg_size = max(
                    max_total_arg_size, len(mov_args) * word_size
                )
                arg_instrs = cur_args + mov_args
            args_info[instr_addr] = (arg_instrs, max_total_arg_size)
            # reset
            sp_cursor = 0
            cur_sub_sp_size = None
            cur_args = []
            cur_movs = []

    write_to_facts(fact_dir, args_info)


if __name__ == "__main__":
    main()
