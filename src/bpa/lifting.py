"""Explicit defaults shared by M2 and M3 for the pinned angr/pyvex version."""

VEX_LIFT_OPTIONS = dict(opt_level=1, cross_insn_opt=True, strict_block_end=False,
                        load_from_ro_regions=False, const_prop=False,
                        collect_data_refs=False, skip_stmts=False, traceflags=0)
