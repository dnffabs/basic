.text
.globl _start
.type _start, @function
_start:
    lea make_result(%rip), %rax
    mov %rax, tail_target(%rip)
    call direct_tail
after_tail:
    call *%rax
    mov %eax, %edi
    mov $60, %eax
    syscall
.size _start, .-_start

.type direct_tail, @function
direct_tail:
    jmp indirect_tail
.size direct_tail, .-direct_tail

.type indirect_tail, @function
indirect_tail:
    jmp *tail_target(%rip)
.size indirect_tail, .-indirect_tail

.type make_result, @function
make_result:
    lea tail_result(%rip), %rax
result_return:
    ret
.size make_result, .-make_result

.type tail_result, @function
tail_result:
    mov $9, %eax
    ret
.size tail_result, .-tail_result

.bss
.align 8
.type tail_target, @object
tail_target:
    .zero 8
.size tail_target, .-tail_target
.section .note.GNU-stack,"",@progbits
