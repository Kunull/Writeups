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
void _exit(int status);
```

The Exit syscall takes one argument:

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
int socket(int domain, int type, int protocol);
```

The Socket syscall takes three arguments:

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

```c
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
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
