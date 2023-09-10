[BITS 64]
NULL equ 0x00
O_RDONLY equ 0x00
SYS_READ equ 0x00
SYS_OPEN equ 0x02
SYS_MMAP equ 0x09
SYS_CLOSE equ 0x03
PROT_READ equ 0x01
PROT_EXEC equ 0x04
PROT_WRITE equ 0x02
MAP_SHARED equ 0x01
MAP_ANONYMOUS equ 0x20

mov rax, SYS_MMAP
mov rdi, NULL
mov rsi, [rel $ + (alloc_size - $)]
mov rdx, PROT_READ | PROT_WRITE | PROT_EXEC
mov r10, MAP_ANONYMOUS | MAP_SHARED
mov r8, -1
mov r9, 0
syscall

mov [rel $ + (out_ptr - $)], rax

mov rax, SYS_OPEN
lea rdi, [rel $ + (devpath - $)]
mov rsi, O_RDONLY
mov rdx, NULL
syscall

mov rdi, rax
mov rax, SYS_READ
mov rsi, NULL
mov rdx, 1
syscall

mov rax, SYS_CLOSE
syscall
jmp $

device_fd: dq 0
devpath: db "/dev/raminspect", 0
out_ptr: db 2, 2, 2, 2, 2, 2, 2, 2
alloc_size: db 1, 1, 1, 1, 1, 1, 1, 1