;;! target = "x86_64"
;;! test = "compile"
;;! flags = " -C cranelift-enable-heap-access-spectre-mitigation -W memory64 -O static-memory-maximum-size=0 -O static-memory-guard-size=0 -O dynamic-memory-guard-size=0"

;; !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
;; !!! GENERATED BY 'make-load-store-tests.sh' DO NOT EDIT !!!
;; !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

(module
  (memory i64 1)

  (func (export "do_store") (param i64 i32)
    local.get 0
    local.get 1
    i32.store8 offset=0xffff0000)

  (func (export "do_load") (param i64) (result i32)
    local.get 0
    i32.load8_u offset=0xffff0000))

;; wasm[0]::function[0]:
;;       pushq   %rbp
;;       movq    %rsp, %rbp
;;       movq    %rdx, %rax
;;       addq    0x2a(%rip), %rax
;;       jb      0x36
;;   14: movq    0x40(%rdi), %r9
;;       xorq    %r8, %r8
;;       addq    0x38(%rdi), %rdx
;;       movl    $0xffff0000, %r10d
;;       addq    %r10, %rdx
;;       cmpq    %r9, %rax
;;       cmovaq  %r8, %rdx
;;       movb    %cl, (%rdx)
;;       movq    %rbp, %rsp
;;       popq    %rbp
;;       retq
;;   36: ud2
;;   38: addl    %eax, (%rax)
;;
;; wasm[0]::function[1]:
;;       pushq   %rbp
;;       movq    %rsp, %rbp
;;       movq    %rdx, %rax
;;       addq    0x32(%rip), %rax
;;       jb      0x78
;;   54: movq    0x40(%rdi), %r8
;;       xorq    %rcx, %rcx
;;       addq    0x38(%rdi), %rdx
;;       movl    $0xffff0000, %r9d
;;       addq    %r9, %rdx
;;       cmpq    %r8, %rax
;;       cmovaq  %rcx, %rdx
;;       movzbq  (%rdx), %rax
;;       movq    %rbp, %rsp
;;       popq    %rbp
;;       retq
;;   78: ud2
;;   7a: addb    %al, (%rax)
;;   7c: addb    %al, (%rax)
;;   7e: addb    %al, (%rax)
;;   80: addl    %eax, (%rax)
