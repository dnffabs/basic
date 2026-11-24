# 查看一个简单程序的 M3 产物

`m3_demo.c` 通过函数指针调用 `add_one`，读取全局 `source=3`，将结果 `4` 写入全局 `result`。正常执行返回 0。

在项目根目录运行：

```bash
mkdir -p outputs/m3_demo
gcc -g -O0 -fno-pie -no-pie -fno-stack-protector \
  examples/m3_demo.c -o outputs/m3_demo/m3_demo
outputs/m3_demo/m3_demo
PYTHONPATH=src uv run --locked python -m bpa \
  outputs/m3_demo/m3_demo --stage m3 -o outputs/m3_demo
```

二进制和分析产物均位于被 Git 忽略的 `outputs/`；仓库仅保存示例源码和说明。

本机本次运行提升全部 32 个块，输出 481 条语句、566 个表达式、23 次普通读取和 16 次普通写入。统计包含启动代码；`m2/functions.json` 中的用户函数为 `add_one`、`invoke` 和 `main`。

以下是从本次真实 facts 中摘录的内容，用关系调用形式展示，实际文件为制表符分列。编译器或构建选项变化时，地址和 ID 也可能变化。

## 加法

`add_one` 中的 `add eax, 1` 位于 ELF VA `0x401114`（十进制 4198676）：

```text
statement(630, 4198662, 23, 4198676, 2, "Ist_WrTmp")
expression(631, 630, 32, "Iex_Binop")
operation(631, "Iop_Add32")
operand(631, 0, 632)
operand(631, 1, 633)
temporary_read(632, 4198662, 23)
constant(633, 32, "0x00000001")
temporary_write(630, 4198662, 4, 631)
```

含义：语句 630 在该指令内部进行一次 32 位加法，左值来自本块的临时变量 23，右值为常量 1；结果表达式 631 被写到本块的临时变量 4。语句 ID、表达式 ID 和临时变量编号属于不同概念。

## 全局变量读写

`source` 位于 `0x404010`，`result` 位于 `0x404018`：

```text
load(855, 856, 32, "Iend_LE")
constant(856, 64, "0x0000000000404010")

store(901, 902, 903, 32, "Iend_LE")
constant(902, 64, "0x0000000000404018")
```

第一组表示从 `source` 读取 32 位值，读取结果为表达式 855；第二组表示语句 901 将表达式 903 的值写入 `result`。读写均为小端。这里地址常量的位宽是 64，实际数据访问宽度是 32。

## 函数指针调用

`invoke` 内部在 `0x401135` 执行 `call rdx`：

```text
control_transfer(4198681, 4198709, "call", 1, "unresolved")
block_exit(4198681, 794, 795, "Ijk_Call")
temporary_read(795, 4198681, 28)
```

含义：这是一个间接调用，块出口目标来自本块临时变量 28。M3 保留调用位置、目标表达式和原始栈效果；它尚未通过指针传播求出 `add_one`，所以状态仍为 `unresolved`。

完整关系定义见 `outputs/m3_demo/m3/schema.json`，逐关系计数见 `manifest.json`。阶段说明见 [docs/M3.md](../docs/M3.md)。
