;;! target = "x86_64"
;;! test = "winch"

(module
  (memory 1 1 shared)
  (func (export "_start") (result i64)
        (i64.atomic.rmw32.sub_u (i32.const 0) (i64.const 42))))
;; wasm[0]::function[0]:
;;       pushq   %rbp
;;       movq    %rsp, %rbp
;;       movq    8(%rdi), %r11
;;       movq    0x10(%r11), %r11
;;       addq    $0x10, %r11
;;       cmpq    %rsp, %r11
;;       ja      0x68
;;   1c: movq    %rdi, %r14
;;       subq    $0x10, %rsp
;;       movq    %rdi, 8(%rsp)
;;       movq    %rsi, (%rsp)
;;       movq    $0x2a, %rax
;;       movl    $0, %ecx
;;       andl    $3, %ecx
;;       cmpl    $0, %ecx
;;       jne     0x6a
;;   4a: movl    $0, %ecx
;;       movq    0x30(%r14), %r11
;;       movq    (%r11), %rdx
;;       addq    %rcx, %rdx
;;       negl    %eax
;;       lock xaddl %eax, (%rdx)
;;       addq    $0x10, %rsp
;;       popq    %rbp
;;       retq
;;   68: ud2
;;   6a: ud2
