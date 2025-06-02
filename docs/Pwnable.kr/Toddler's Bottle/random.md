---
custom_edit_url: null
sidebar_position: 5
---

> Daddy, teach me how to use random value in programming!

## File properties

```
random@ubuntu:~$ file ./random
./random: setgid ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=04c4d602c054138d2b75d9b8d1f00a53165be033, for GNU/Linux 3.2.0, not stripped
```

## Source code

```c title="random.c"
#include <stdio.h>

int main(){
    unsigned int random;
    random = rand();	// random value!

    unsigned int key=0;
    scanf("%d", &key);

    if( (key ^ random) == 0xcafebabe ){
        printf("Good!\n");
        setregid(getegid(), getegid());
        system("/bin/cat flag");
        return 0;
    }

    printf("Wrong, maybe you should try 2^32 cases.\n");
    return 0;
}
```

As we can see the program generates a pseudo-random number (it isn't exactly random because no `seed` has been set).

The it takes in a `key` from the user.

If the XOR of the `key` and `random` results in `0xdeadbeef`, the flag is printed.

## Disassembly

```
pwndbg> disassemble main
Dump of assembler code for function main:
   0x0000000000001209 <+0>:	endbr64
   0x000000000000120d <+4>:	push   rbp
   0x000000000000120e <+5>:	mov    rbp,rsp
   0x0000000000001211 <+8>:	push   rbx
   0x0000000000001212 <+9>:	sub    rsp,0x18
   0x0000000000001216 <+13>:	mov    rax,QWORD PTR fs:0x28
   0x000000000000121f <+22>:	mov    QWORD PTR [rbp-0x18],rax
   0x0000000000001223 <+26>:	xor    eax,eax
   0x0000000000001225 <+28>:	mov    eax,0x0
   0x000000000000122a <+33>:	call   0x1110 <rand@plt>
   0x000000000000122f <+38>:	mov    DWORD PTR [rbp-0x1c],eax
   0x0000000000001232 <+41>:	mov    DWORD PTR [rbp-0x20],0x0
   0x0000000000001239 <+48>:	lea    rax,[rbp-0x20]
   0x000000000000123d <+52>:	mov    rsi,rax
   0x0000000000001240 <+55>:	lea    rax,[rip+0xdc1]        # 0x2008
   0x0000000000001247 <+62>:	mov    rdi,rax
   0x000000000000124a <+65>:	mov    eax,0x0
   0x000000000000124f <+70>:	call   0x1100 <__isoc99_scanf@plt>
   0x0000000000001254 <+75>:	mov    eax,DWORD PTR [rbp-0x20]
   0x0000000000001257 <+78>:	xor    eax,DWORD PTR [rbp-0x1c]
   0x000000000000125a <+81>:	cmp    eax,0xcafebabe
   0x000000000000125f <+86>:	jne    0x12af <main+166>
   0x0000000000001261 <+88>:	lea    rax,[rip+0xda3]        # 0x200b
   0x0000000000001268 <+95>:	mov    rdi,rax
   0x000000000000126b <+98>:	call   0x10b0 <puts@plt>
   0x0000000000001270 <+103>:	mov    eax,0x0
   0x0000000000001275 <+108>:	call   0x10e0 <getegid@plt>
   0x000000000000127a <+113>:	mov    ebx,eax
   0x000000000000127c <+115>:	mov    eax,0x0
   0x0000000000001281 <+120>:	call   0x10e0 <getegid@plt>
   0x0000000000001286 <+125>:	mov    esi,ebx
   0x0000000000001288 <+127>:	mov    edi,eax
   0x000000000000128a <+129>:	mov    eax,0x0
   0x000000000000128f <+134>:	call   0x10f0 <setregid@plt>
   0x0000000000001294 <+139>:	lea    rax,[rip+0xd76]        # 0x2011
   0x000000000000129b <+146>:	mov    rdi,rax
   0x000000000000129e <+149>:	mov    eax,0x0
   0x00000000000012a3 <+154>:	call   0x10d0 <system@plt>
   0x00000000000012a8 <+159>:	mov    eax,0x0
   0x00000000000012ad <+164>:	jmp    0x12c3 <main+186>
   0x00000000000012af <+166>:	lea    rax,[rip+0xd6a]        # 0x2020
   0x00000000000012b6 <+173>:	mov    rdi,rax
   0x00000000000012b9 <+176>:	call   0x10b0 <puts@plt>
   0x00000000000012be <+181>:	mov    eax,0x0
   0x00000000000012c3 <+186>:	mov    rdx,QWORD PTR [rbp-0x18]
   0x00000000000012c7 <+190>:	sub    rdx,QWORD PTR fs:0x28
   0x00000000000012d0 <+199>:	je     0x12d7 <main+206>
   0x00000000000012d2 <+201>:	call   0x10c0 <__stack_chk_fail@plt>
   0x00000000000012d7 <+206>:	mov    rbx,QWORD PTR [rbp-0x8]
   0x00000000000012db <+210>:	leave
   0x00000000000012dc <+211>:	ret
End of assembler dump.
```

```python
random@ubuntu:~$ python
Python 3.10.12 (main, Feb  4 2025, 14:57:36) [GCC 11.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> a = 0x6b8b4567
>>> b = 0xcafebabe
>>> result = a ^ b
>>> print(result)
2708864985
```

```
random@ubuntu:~$ ./random
2708864985
Good!
m0mmy_I_can_predict_rand0m_v4lue!
```
