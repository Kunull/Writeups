---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 6
---

:::note
The `syscall` instruction invokes an OS system-call handler at privilege level 0, and is used to make system calls.
It will be used in every level in this module.
:::

## level 1

> In this challenge you will exit a program.

### Syscall calling convention

In order to make an exit syscall, we need to first set it up properly.

[This](https://www.chromium.org/chromium-os/developer-library/reference/linux-constants/syscalls/) documentaion tells us what the calling convention is for x86_64.

![image](https://github.com/Kunull/Write-ups/assets/110326359/b9f4db11-eb71-4cdf-9266-890bf718dbfc)

### Exit syscall

```c
void _exit(int _status_);
```

The Exit syscall does not return anything and takes one argument:

1. `status`: Status of the process' exit. 0 - for success / OK, 1 - non success / error.

Let's look at how everything would be set up.

| Register | Argument | Value | 
|:-:|:-:|:-:|
| rax | syscall id | 0x3c |
| rdi | status | 0 |

Let's move the required values in the relevant registers.

```txt title="Exit syscall"
mov rdi, 0
mov rax, 0x3c        
syscall
```

Once the setup is completed, we can use the `syscall` instruction.

```asm title="webserver1.s"
.intel_syntax noprefix
.globl _start

.section .text

_start:
    # Exit syscall
    mov rdi, 0
    mov rax, 0x3c        
    syscall

.section .data
```

```
hacker@building-a-web-server~level1:~$ as -o webserver1.o webserver1.s && ld -o webserver1 webserver1.o
```

```
hacker@building-a-web-server~level1:~$ /challenge/run ./webserver1
```

&nbsp;

## level 2

> In this challenge you will create a socket.

### Socket syscall

```c
int socket(int _domain_, int _type_, int _protocol_);
```

The Socket syscall returns a file descriptor and takes three arguments:

1. `domain`: Specifies a communication domain; this selects the protocol family which will be used for communication.
2. `type`: Specifies the communication semantics.
3. `protocol`: Specifies a particular protocol to be used with the socket.

In order to set up the Socket system call, we need to first find out the value of it's relevant arguments.

```python
>>> import pwn 
>>> pwn.constants.AF_INET
Constant('AF_INET', 0x2)
```

```python
>>> import pwn 
>>> pwn.constants.SOCK_STREAM
Constant('SOCK_STREAM', 0x1)
```

OR

```
grep -r "#define AF_INET" /usr/include
grep -r "#define SOCK_STREAM" /usr/include
grep -r "IPPROTO_IP" /usr/include
```

| Register | Argument | Value | 
|:-:|:-:|:-:|
| rax | syscall id | 0x29 |
| rdi | domain | 2 (AF_INET) |
| rsi | type | 1 (SOCK_STREAM) |
| rdx | protocol | 0 (IPPROTO_IP) |

Now, we can move the required values in the relevant registers. 

```txt title="Socket syscall"
mov rdi, 2
mov rsi, 1
mov rdx, 0
mov rax, 0x29
syscall
```

```asm title="webserver2.s"
.intel_syntax noprefix
.globl _start

.section .text

_start:
    # Socket syscall
    mov rdi, 2
    mov rsi, 1
    mov rdx, 0
    mov rax, 0x29
    syscall

    # Exit syscall
    mov rdi, 0
    mov rax, 0x3c        
    syscall

.section .data
```

```
hacker@building-a-web-server~level2:~$ as -o webserver2.o webserver2.s && ld -o webserver2 webserver2.o
```

```
hacker@building-a-web-server~level2:~$ /challenge/run ./webserver2
```

&nbsp;

## level 3

> In this challenge you will bind an address to a socket.

### Bind syscall

```c
int bind(int _sockfd_, const struct sockaddr _*addr_, socklen_t _addrlen_);
```

The Bind syscall returns a file descriptor and takes three arguments:

1. `sockfd`: Refers to a socket by it's file descriptor.
2. `*addr`: Points to the address to be assigned to the socket. Requires a `struct` to be created for the socket.
3. `addrlen`: Specifies the size, in bytes, of the address structure pointed to by `addr`.

In order to fill up the arguments, we need to know the file descriptor of the socket required for the `sockfd` argument.
For that we need to trace all the syscalls using the `strace` command.

```
hacker@building-a-web-server~level3:~/server$ strace ./webserver2
execve("./server", ["./server"], 0x7ffd3e044280 /* 25 vars */) = 0
socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3
exit(0)                                 = ?
+++ exited with 0 +++
```

As we can see, the Socket syscall returns a file descriptor `3`. This makes sense because the first three file descriptors, `0`, `1` and `2`, are mapped to STDIN, STDOUT, and STDERR respectively.

Next, for the `sockaddr` argument, we need to create a `struct` and create a pointer to that `struct`.

If we check the Expected processes, we get more information.

```
===== Expected: Parent Process =====
[ ] execve(<execve_args>) = 0
[ ] socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3
[ ] bind(3, {sa_family=AF_INET, sin_port=htons(<bind_port>), sin_addr=inet_addr("<bind_address>")}, 16) = 0
    - Bind to port 80
    - Bind to address 0.0.0.0
[ ] exit(0) = ?
```

For the `bind` process, `{sa_family=AF_INET, sin_port=htons(<bind_port>), sin_addr=inet_addr("<bind_address>")}` is the `struct` required for `sockaddr`.

In order to create the `sruct`, we need to use the `.data` section.

```asm
.section .data
sockaddr:
    .2byte 2	# AF_INET
    .2byte 0x5000	# Port 80
    .4byte 0	# Address 0.0.0.0
    .8byte 0	# Additional 8 bytes
```

We can now load the address of this `struct` into `rsi` using the `lea` instruction.

```
lea rsi, [rip+sockaddr]
```

The value of the `addlen` argument will be 16, as the `struct` is 16 bytes in length.

The final Bind syscall will look as follows:

```txt title="Bind syscall"
mov rdi, 3
lea rsi, [rip+sockaddr]
mov rdx, 16
mov rax, 0x31
syscall

.section .data
sockaddr:
    .2byte 2
    .2byte 0x5000
    .4byte 0
    .8byte 0
```

```asm title="webserver3.s"
.intel_syntax noprefix
.globl _start

.section .text

_start:
    # Socket syscall
    mov rdi, 2
    mov rsi, 1
    mov rdx, 0
    mov rax, 0x29
    syscall

    # Bind syscall
    mov rdi, 3
    lea rsi, [rip+sockaddr]
    mov rdx, 16
    mov rax, 0x31
    syscall

    # Exit syscall
    mov rdi, 0
    mov rax, 0x3c        
    syscall

.section .data
sockaddr:
    .2byte 2
    .2byte 0x5000
    .4byte 0
    .8byte 0
```

```
hacker@building-a-web-server~level3:~$ as -o webserver3.o webserver3.s && ld -o webserver3 webserver3.o
```

```
hacker@building-a-web-server~level3:~$ /challenge/run ./webserver3
```

&nbsp;

## level 4

```Assembly
.intel_syntax noprefix
.globl _start

.section .text

_start:
    # Socket syscall
    mov rdi, 2
    mov rsi, 1
    mov rdx, 0
    mov rax, 0x29
    syscall

    # Bind syscall
    mov rdi, 3
    lea rsi, [rip+sockaddr]
    mov rdx, 16
    mov rax, 0x31
    syscall

    # Listen syscall
    mov rdi, 3
    mov rsi, 0
    mov rax, 0x32
    syscall

    # Exit syscall
    mov rdi, 0
    mov rax, 0x3c        
    syscall

.section .data
sockaddr:
    .2byte 2
    .2byte 0x5000
    .4byte 0
    .8byte 0
```

&nbsp;

## level 5

```Assembly
.intel_syntax noprefix
.globl _start

.section .text

_start:
    # Socket syscall
    mov rdi, 2
    mov rsi, 1
    mov rdx, 0
    mov rax, 0x29
    syscall

    # Bind syscall
    mov rdi, 3
    lea rsi, [rip+sockaddr]
    mov rdx, 16
    mov rax, 0x31
    syscall

    # Listen syscall
    mov rdi, 3
    mov rsi, 0
    mov rax, 0x32
    syscall

    # Accept syscall
    mov rdi, 3
    mov rsi, 0
    mov rdx, 0
    mov rax, 0x2b
    syscall

    # Exit syscall
    mov rdi, 0
    mov rax, 0x3c        
    syscall

.section .data
sockaddr:
    .2byte 2
    .2byte 0x5000
    .4byte 0
    .8byte 0
```

&nbsp;

## level 6

```Assembly
.intel_syntax noprefix
.globl _start

.section .text

_start:
    # Socket syscall
    mov rdi, 2
    mov rsi, 1
    mov rdx, 0
    mov rax, 0x29
    syscall

    # Bind syscall
    mov rdi, 3
    lea rsi, [rip+sockaddr]
    mov rdx, 16
    mov rax, 0x31
    syscall

    # Listen syscall
    mov rdi, 3
    mov rsi, 0
    mov rax, 0x32
    syscall

    # Accept syscall
    mov rdi, 3
    mov rsi, 0
    mov rdx, 0
    mov rax, 0x2b
    syscall

    # Read syscall
    mov rdi, 4
    mov rsi, rsp
    mov rdx, 140
    mov rax, 0x00
    syscall

    # Write syscall
    mov rdi, 4
    lea rsi, [rip+response]
    mov rdx, 19
    mov rax, 0x01
    syscall

    # Close syscall
    mov rdi, 4
    mov rax, 0x03
    syscall

    # Exit syscall
    mov rdi, 0
    mov rax, 0x3c        
    syscall

.section .data
sockaddr:
    .2byte 2
    .2byte 0x5000
    .4byte 0
    .8byte 0

response: 
    .string "HTTP/1.0 200 OK\r\n\r\n"
```

&nbsp;

## level 7

```Assembly
.intel_syntax noprefix
.globl _start

.section .text

_start:
    # Socket syscall
    mov rdi, 2
    mov rsi, 1
    mov rdx, 0
    mov rax, 0x29
    syscall

    # Bind syscall
    mov rdi, 3
    lea rsi, [rip+sockaddr]
    mov rdx, 16
    mov rax, 0x31
    syscall

    # Listen syscall
    mov rdi, 3
    mov rsi, 0
    mov rax, 0x32
    syscall

    # Accept syscall
    mov rdi, 3
    mov rsi, 0
    mov rdx, 0
    mov rax, 0x2b
    syscall

    # Read syscall
    mov rdi, 4
    mov rsi, rsp
    mov rdx, 155
    mov rax, 0x00
    syscall

    mov r10, rsp
	
loop1:
    mov al, [r10]
    cmp al, ' '
    je done1
    add r10, 1
    jmp loop1

done1:
	add r10, 1
	mov r11, r10
	mov r12, 0

loop2:
    mov al, [r11]
    cmp al, ' '
    je done2
    add r11, 1
    add r12, 1
    jmp loop2

done2:
    mov byte ptr [r12], 0

    # Open syscall
    mov rdi, r11
    mov rsi, 0
    mov rdx, 0
    mov rax, 0x02
    syscall

    # Read syscall
    mov rdi, 5
    mov rsi, rsp
    mov rdx, 256
    mov rax, 0x00
    syscall

    # Close syscall
    mov rdi, 4
    mov rax, 0x03
    syscall

    # Write syscall
    mov rdi, 4
    lea rsi, [rip+response]
    mov rdx, 19
    mov rax, 0x01
    syscall

    # Write syscall
    mov rdi, 1
    mov rsi, r10
    mov rdx, r12
    mov rax, 0x01
    syscall

    # Close syscall
    mov rdi, 4
    mov rax, 0x03
    syscall

    # Exit syscall
    mov rdi, 0
    mov rax, 0x3c        
    syscall

.section .data
sockaddr:
    .2byte 2
    .2byte 0x5000
    .4byte 0
    .8byte 0

response: 
    .string "HTTP/1.0 200 OK\r\n\r\n"
```

&nbsp;

## level 8

```Assembly
.intel_syntax noprefix
.globl _start

.section .text

_start:
    # Socket syscall
    mov rdi, 2
    mov rsi, 1
    mov rdx, 0
    mov rax, 0x29
    syscall

    # Bind syscall
    mov rdi, 3
    lea rsi, [rip+sockaddr]
    mov rdx, 16
    mov rax, 0x31
    syscall

    # Listen syscall
    mov rdi, 3
    mov rsi, 0
    mov rax, 0x32
    syscall

    # Accept syscall
    mov rdi, 3
    mov rsi, 0
    mov rdx, 0
    mov rax, 0x2b
    syscall

    # Read syscall
    mov rdi, 4
    mov rsi, rsp
    mov rdx, 155
    mov rax, 0x00
    syscall

    mov r10, rsp
	
loop1:
    mov al, [r10]
    cmp al, ' '
    je done1
    add r10, 1
    jmp loop1

done1:
    add r10, 1
    mov r11, r10
    mov r12, 0

loop2:
    mov al, [r11]
    cmp al, ' '
    je done2
    add r11, 1
    add r12, 1
    jmp loop2

done2:
    mov byte ptr [r12], 0

    # Open syscall
    mov rdi, r11
    mov rsi, 0
    mov rdx, 0
    mov rax, 0x02
    syscall

    # Read syscall
    mov rdi, 5
    mov rsi, rsp
    mov rdx, 256
    mov rax, 0x00
    syscall

    # Close syscall
    mov rdi, 4
    mov rax, 0x03
    syscall

    # Write syscall
    mov rdi, 4
    lea rsi, [rip+response]
    mov rdx, 19
    mov rax, 0x01
    syscall

    # Write syscall
    mov rdi, 1
    mov rsi, r10
    mov rdx, r12
    mov rax, 0x01
    syscall

    # Close syscall
    mov rdi, 4
    mov rax, 0x03
    syscall

    # Exit syscall
    mov rdi, 0
    mov rax, 0x3c        
    syscall

.section .data
sockaddr:
    .2byte 2
    .2byte 0x5000
    .4byte 0
    .8byte 0

response: 
    .string "HTTP/1.0 200 OK\r\n\r\n"
```
