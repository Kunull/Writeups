---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 6
---

## level 1

```
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

&nbsp;

## level 2

```Python
import pwn

pwn.constants.AF_INET
pwn.constants.SOCK_STREAM
```

OR

```
grep -r "#define AF_INET" /usr/include
grep -r "#define SOCK_STREAM" /usr/include
grep -r "IPPROTO_IP" /usr/include
```



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

  # Exit syscall
  mov rdi, 0
  mov rax, 0x3c    
  syscall

.section .data
```

&nbsp;

## level 3

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

### level 8

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
