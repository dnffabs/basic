# M5 调研：寄存器定义、调用点上下文与 BinPointer

## BPA-X 的子寄存器行为

在 BPA-X 提交 `0fb0a51` 上，用默认 VEX 提升和 BPA-X facts 提取器验证了以下指令。`Get` 和 `Put` 按 guest-state 偏移查询寄存器名，查询时省略位宽，再按白名单筛选。`set_loc_vex` 记录写入位宽，但到达定义的覆盖规则按 `loc` 匹配。[寄存器白名单](/home/qc/Desktop/rebuild/bpa_x/vex_fact_gen/instr.py:53) · [按偏移取名](/home/qc/Desktop/rebuild/bpa_x/vex_fact_gen/instr.py:120) · [Get](/home/qc/Desktop/rebuild/bpa_x/vex_fact_gen/instr.py:221) · [Put](/home/qc/Desktop/rebuild/bpa_x/vex_fact_gen/instr.py:307) · [到达定义规则](/home/qc/Desktop/rebuild/bpa_x/logic/souffle/fixed-point/reaching_def.dl:24)

| 指令 | 默认 VEX 与 BPA-X 提取结果 |
| --- | --- |
| `mov ah, 1`、`movzx eax, ah` | VEX 保留 `ah` 的 8 位写入和读取。偏移在 AMD64 上为 17，在 x86 上为 9。BPA-X 的无位宽名称查询返回 `17` 或 `9`，白名单过滤了这两种 `ah` 访问。`movzx` 写回的目的寄存器仍有写入事实。 |
| `mov al, 1`、`mov ax, 1` | VEX 写入 8 或 16 位。两者与完整寄存器起始偏移相同，在 BPA-X 写入事实里都归到 `rax`（AMD64）或 `eax`（x86）。后续到达定义按这个名称覆盖。 |
| `mov eax, 1` | 默认 VEX 在 AMD64 上产生零扩展的 64 位写入，在 x86 上产生 32 位写入。 |

## M5 的建议接口

- **按寄存器访问范围连接定义和读取。** 使用 M3 原始 facts 中的 guest-state 偏移、位宽和语句顺序。每次写入只覆盖它写到的位段。整寄存器读取可同时依赖多个定义，例如 `al` 写入提供低 8 位，原 `rax` 定义仍提供高 56 位。到达定义关系可记录读取表达式、来源定义、重叠位段和调用点上下文。指针值能否由这些位段恢复留给 M6。[M3 facts](../src/bpa/vex/facts.py#L18-L26) · [M3 寄存器语义](M3.md#4-关系与语义)
- **分支汇合时保留多条来源。** M6 可以直接消费每次读取的到达定义，显式 `φ` 可作为按需导出的表示。BinPointer 的论文以显式 `φ` 表示汇合，图 4 的 `Phi` 规则合并输入寄存器的值集。BPA-X 论文也描述了 `φ`，而核对的代码直接把读取连到块内前序定义或块入口到达定义，显式 `φ` 规则处于注释状态。[BinPointer §5.2，图 3–4](https://www.cse.psu.edu/~gxt29/papers/BinPointerCC22.pdf#page=5) · [BPA-X §IV.C](https://www.cse.psu.edu/~gxt29/papers/NDSS_BAR_BPAX_26.pdf#page=5) · [BPA-X 读取规则](/home/qc/Desktop/rebuild/bpa_x/logic/souffle/fixed-point/get_locs_ssa.dl:2)
- **为已知调用边提供一层寄存器调用点上下文。** 用最近的调用点区分被调函数中的寄存器来源，把参数寄存器连到对应的调用点，把返回寄存器连到同一调用关系记录的调用方续点。仅给入口参数记录调用点会丢失返回值的区分。若同一个内层调用点在多个外层上下文中执行，内层上下文仍会合并。BPA-X 按调用点建立的栈实参与形参块连接是局部处理，寄存器到达定义关系本身没有调用点维度。BinPointer §4 则明确将其跨过程分析描述为上下文不敏感。[BPA-X 栈参数连接](/home/qc/Desktop/rebuild/bpa_x/logic/souffle/fixed-point/sblk_arg_pass_conn.dl:74) · [BPA-X 寄存器到达定义](/home/qc/Desktop/rebuild/bpa_x/logic/souffle/fixed-point/reaching_def.dl:2) · [BinPointer §4](https://www.cse.psu.edu/~gxt29/papers/BinPointerCC22.pdf#page=4)

## BinPointer 对 M6 和 M7 的启发

- **M6 求指针值集。** M6 消费 M5 的寄存器来源和 M4 的栈、全局、堆分块，处理地址表达式、加载、存储和已知调用上的值传播。BinPointer 追踪函数入口和块内地址。其 `0-base` 抽象把块内地址表示为 `b[o]`，例如 `b[0] + 4` 得到 `b[4]`，`b[4] + 4` 则放宽为覆盖块内任意偏移的 `b[⊤]`。同一块的两个已知偏移可以区分，每个内存位置跨程序点共享值集，因此内存是流不敏感的。寄存器经 SSA 具有流敏感性。块内偏移是 M6 可评估的精度选项，依赖 M4 分块满足块内指针运算假设。BinPointer 采用更保守的栈分块，并优先使用符号表确定全局块边界。[M4 产物](M4.md#读取产物) · [BinPointer §4–5](https://www.cse.psu.edu/~gxt29/papers/BinPointerCC22.pdf#page=4) · [BinPointer 表 2、定义 5.1](https://www.cse.psu.edu/~gxt29/papers/BinPointerCC22.pdf#page=6) · [BinPointer §6 分块](https://www.cse.psu.edu/~gxt29/papers/BinPointerCC22.pdf#page=7)
- **M7 管理新边和外层迭代。** 从间接调用操作数的值集提取候选函数地址，建立调用、返回及尾调用相关边，再用新增边更新 M5 的定义关系和 M6 的值集，直到图和值集稳定。BinPointer §4 把寄存器 SSA、值传播和间接边发现放进同一个 Datalog 固定点，也处理间接跳转。[项目阶段划分](STAGES.md) · [BinPointer §4](https://www.cse.psu.edu/~gxt29/papers/BinPointerCC22.pdf#page=4)
