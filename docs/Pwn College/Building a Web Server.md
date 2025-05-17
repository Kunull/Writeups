---
custom_edit_url: null
sidebar_position: 6
---

:::note
The `syscall` instruction invokes an OS system-call handler at privilege level 0, and is used to make system calls.
It will be used in every level in this module.
:::

## level 1

> Your first task is to create the simplest possible program—one that immediately terminates when run. In this challenge, you will use the exit syscall, which is responsible for ending a process and returning an exit status to the operating system. This syscall takes a single argument: the exit status (with 0 typically indicating success). Understanding how to cleanly exit a program is crucial because it ensures your process communicates its completion state properly.

> ```
> ===== Expected: Parent Process =====[ ] execve(<execve_args>) = 0
> [ ] exit(0) = ?
> ```

### Syscall calling convention

In order to make an exit syscall, we need to first set it up properly.

[This](https://www.chromium.org/chromium-os/developer-library/reference/linux-constants/syscalls/) documentaion tells us what the calling convention is for x86_64.

![image](https://github.com/Kunull/Write-ups/assets/110326359/b9f4db11-eb71-4cdf-9266-890bf718dbfc)

### Exit syscall

```c
void _exit(int status);
```

```
RETURN VALUE
       These functions do not return.
```

The Exit syscall does not return anything and takes one argument:

1. `status`: Status of the process' exit. 0 - for success / OK, 1 - non success / error.

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

> In this challenge, you’ll begin your journey into networking by creating a socket using the socket syscall. A socket is the basic building block for network communication; it serves as an endpoint for sending and receiving data. When you invoke socket, you provide three key arguments: the domain (for example, AF_INET for IPv4), the type (such as SOCK_STREAM for TCP), and the protocol (usually set to 0 to choose the default). Mastering this syscall is important because it lays the foundation for all subsequent network interactions.

> ```
> ===== Expected: Parent Process =====
> [ ] execve(<execve_args>) = 0
> [ ] socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3
> [ ] exit(0) = ?
> ```

### Socket syscall

```c
int socket(int domain, int type, int protocol);
```

```
socket() creates an endpoint for communication and returns a file
       descriptor that refers to that endpoint.  The file descriptor
       returned by a successful call will be the lowest-numbered file
       descriptor not currently open for the process.
```

```
RETURN VALUE
       On success, a file descriptor for the new socket is returned.  On
       error, -1 is returned, and errno is set to indicate the error.
```

The Socket syscall returns a file descriptor and takes three arguments:

1. `domain`: Specifies a communication domain; this selects the protocol family which will be used for communication.
2. `type`: Specifies the communication semantics.
3. `protocol`: Specifies a particular protocol to be used with the socket.

Looking at the expected processes dump, we can see that the program expects `AF_INET` as domain, `SOCK_STREAM` as type, and `IPPROTO_IP` as protocol.

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

Now, we can move the required values in the relevant registers. 

```asm title="Socket syscall"
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

> After creating a socket, the next step is to assign it a network identity. In this challenge, you will use the bind syscall to connect your socket to a specific IP address and port number. The call requires you to provide the socket file descriptor, a pointer to a struct sockaddr (specifically a struct sockaddr_in for IPv4 that holds fields like the address family, port, and IP address), and the size of that structure. Binding is essential because it ensures your server listens on a known address, making it reachable by clients.

> ```
> ===== Expected: Parent Process =====
> [ ] execve(<execve_args>) = 0
> [ ] socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3
> [ ] bind(3, {sa_family=AF_INET, sin_port=htons(<bind_port>), sin_addr=inet_addr("<bind_address>")}, 16) = 0
>     - Bind to port 80
>     - Bind to address 0.0.0.0
> [ ] exit(0) = ?
> ```

### Bind syscall

```c
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
```

```
RETURN VALUE
       On success, zero is returned.  On error, -1 is returned, and
       errno is set to indicate the error.
```

The Bind syscall returns a file descriptor and takes three arguments:

1. `sockfd`: File descriptor that refers to the socket.
2. `*addr`: Points to the address to be assigned to the socket. Requires a `struct` to be created for the socket.
3. `addrlen`: Specifies the size, in bytes, of the address structure pointed to by `addr`.

#### `sockfd` argument
For the `sockfd` argument, we need to know the file descriptor of the socket created using the Socket syscall.

```
===== Trace: Parent Process =====
[✓] execve("/proc/self/fd/3", ["/proc/self/fd/3"], 0x7f56f63cd980 /* 0 vars */) = 0
[✓] socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3
```

As we can see, the Socket syscall returns a file descriptor `3`. This makes sense because the first three file descriptors, `0`, `1` and `2`, are mapped to STDIN, STDOUT, and STDERR respectively.

One thing to note from the [calling convention](#syscall-calling-convention) is that the result of a syscall is stored in the `$rax` register. So the file descriptor, which is the result of the Socket syscall would be found in the `$rax` register.

We can move this value in the `$rdi` register. Doing so, we do not have to specifiy a fixed file descriptor value (`3`), making our program more dynamic.

```
mov rdi, 3
```

#### `*addr` argument
Next, for the `*addr` argument, we need to create a `sockaddr` struct and create a pointer to that struct.

```c title="struct"
struct sockaddr {
    sa_family_t     sa_family;      /* Address family */
    char            sa_data[];      /* Socket address */
};
```

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

In the Bind syscall, `{sa_family=AF_INET, sin_port=htons(<bind_port>), sin_addr=inet_addr("<bind_address>")}` is the struct required for `*addr`.

In order to create the struct, we need to use the `.data` section.

```asm
.section .data
sockaddr:
    .2byte 2		# AF_INET
    .2byte 0x5000	# Port 80
    .4byte 0    	# Address 0.0.0.0
    .8byte 0		# Additional 8 bytes of padding
```

We can now load the address of this struct into `$rsi` using the `lea` instruction.

```asm
lea rsi, [rip+sockaddr]
```

#### `addrlen` argument

The value of the `addlen` argument will be 16, as the `sockaddr` struct is 16 bytes in length.

```
mov rdx, 16
```

The final Bind syscall will look as follows:

```asm title="Bind syscall"
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
    mov rdi, rax		# 3 for the fd of socket
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

> With your socket bound to an address, you now need to prepare it to accept incoming connections. The listen syscall transforms your socket into a passive one that awaits client connection requests. It requires the socket’s file descriptor and a backlog parameter, which sets the maximum number of queued connections. This step is vital because without marking the socket as listening, your server wouldn’t be able to receive any connection attempts.

> ```
> ===== Expected: Parent Process =====
> [ ] execve(<execve_args>) = 0
> [ ] socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3
> [ ] bind(3, {sa_family=AF_INET, sin_port=htons(<bind_port>), sin_addr=inet_addr("<bind_address>")}, 16) = 0
>     - Bind to port 80
>     - Bind to address 0.0.0.0
> [ ] listen(3, 0) = 0
> [ ] exit(0) = ?
> ```

### Listen syscall

```c
int listen(int sockfd, int backlog);
```

```
RETURN VALUE
       On success, zero is returned.  On error, -1 is returned, and
       errno is set to indicate the error.
```

The Listen syscall returns a file descriptor and takes two arguments:

1. `sockfd`: File descriptor that refers to the socket.
2. `backlog`: Defines the maximum length to which the queue of pending connections for sockfd may grow.

#### `sockfd` argument
The file descriptor is `3`.

We already saw that the file descriptor of the any syscall is returned in the `$rax` register. So the resultant file descriptor of Socket stored in `$rax` is being overwritten by the result of the Bind syscall.

In order to preserve it, we can push the value of `$rax` onto the stack before making the Bind syscall and then pop it into `$rdi` to set up the first argument of the Listen syscall.

```
# Socket syscall
mov rdi, 2
mov rsi, 1
mov rdx, 0
mov rax, 0x29
syscall

push rax

# Listen syscall
pop rdi
```

#### `backlog` argument
As for the `backlog`, we'll set it to zero, because we do not want a queue.

```asm title="Listen syscall"
# Listen syscall
pop rdi
mov rsi, 0
mov rax, 0x32
syscall
```

```asm title="webserver4.s"
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

    push rax		# To be used in the Listen syscall

    # Bind syscall
    mov rdi, rax
    lea rsi, [rip+sockaddr]
    mov rdx, 16
    mov rax, 0x31
    syscall

    # Listen syscall
    pop rdi
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

```
hacker@building-a-web-server~level4:~$ as -o webserver4.o webserver4.s && ld -o webserver4 webserver4.o
```

```
hacker@building-a-web-server~level4:~$ /challenge/run ./webserver4
```

&nbsp;

## level 5

> Once your socket is listening, it’s time to actively accept incoming connections. In this challenge, you will use the accept syscall, which waits for a client to connect. When a connection is established, it returns a new socket file descriptor dedicated to communication with that client and fills in a provided address structure (such as a struct sockaddr_in) with the client’s details. This process is a critical step in transforming your server from a passive listener into an active communicator.

> ```
> ===== Expected: Parent Process =====
> [ ] execve(<execve_args>) = 0
> [ ] socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3
> [ ] bind(3, {sa_family=AF_INET, sin_port=htons(<bind_port>), sin_addr=inet_addr("<bind_address>")}, 16) = 0
>     - Bind to port 80
>     - Bind to address 0.0.0.0
> [ ] listen(3, 0) = 0
> [ ] accept(3, NULL, NULL) = 4
> [ ] exit(0) = ?
> ```

### Accept syscall

```c
int accept(int sockfd, struct sockaddr *_Nullable restrict addr, socklen_t *_Nullable restrict addrlen);
```

```
RETURN VALUE
       On success, these system calls return a file descriptor for the
       accepted socket (a nonnegative integer).  On error, -1 is
       returned, errno is set to indicate the error, and addrlen is left
       unchanged.
```

The Accept syscall returns a file descriptor and takes two arguments:

1. `sockfd`: Socket that has been created with [socket(2)](https://man7.org/linux/man-pages/man2/socket.2.html), bound to a local address with [bind(2)](https://man7.org/linux/man-pages/man2/bind.2.html), and is listening for connections after a [listen(2)](https://man7.org/linux/man-pages/man2/listen.2.html).
2. `addr`: Pointer to a `sockaddr` structure.
3. `addrlen`: Contain the size (in bytes) of the structure pointed to by `addr`.

#### `sockfd` argument
For the `sockfd` argument, we have to set value to the file descriptor that we created. Again, we will `push` the value onto the stack so that it is not over-written when the Listen syscall is made. Then we `pop` it into the `$rdi` register.

```
# Listen syscall
pop rdi
push rdi
mov rsi, 0
mov rax, 0x32
syscall

# Accept syscall
pop rdi
```

#### `addr` argumet
The `addr` argument will be zero, because we do not want any information about the remote address of the connected socket is returned.

#### `addrlen` argument
Thus, the `addrlen` argument will also be zero.

```asm title="Accept syscall"
pop rdi
mov rsi, 0
mov rdx, 0
mov rax, 0x2b
syscall
```

```asm title="webserver5.s"
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

    push rax		# To be used in the Listen syscall

    # Bind syscall
    mov rdi, rax
    lea rsi, [rip+sockaddr]
    mov rdx, 16
    mov rax, 0x31
    syscall

    # Listen syscall
    pop rdi
    push rdi		# To be used in the Accept syscall
    mov rsi, 0
    mov rax, 0x32
    syscall

    # Accept syscall
    pop rdi
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

```
hacker@building-a-web-server~level5:~$ as -o webserver5.o webserver5.s && ld -o webserver5 webserver5.o
```

```
hacker@building-a-web-server~level5:~$ /challenge/run ./webserver5
```

&nbsp;

## level 6

> In this challenge you will respond to an http request.

For this level, we are expected to perform multiple new syscalls.

```
===== Expected: Parent Process =====
[ ] execve(<execve_args>) = 0
[ ] socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3
[ ] bind(3, {sa_family=AF_INET, sin_port=htons(<bind_port>), sin_addr=inet_addr("<bind_address>")}, 16) = 0
    - Bind to port 80
    - Bind to address 0.0.0.0
[ ] listen(3, 0) = 0
[ ] accept(3, NULL, NULL) = 4
[ ] read(4, <read_request>, <read_request_count>) = <read_request_result>
[ ] write(4, "HTTP/1.0 200 OK\r\n\r\n", 19) = 19
[ ] close(4) = 0
[ ] exit(0) = ?
```

### Read syscall

```c
ssize_t read(int fd, void buf[.count], size_t count);
```

```
RETURN VALUE
       On success, the number of bytes read is returned (zero indicates
       end of file), and the file position is advanced by this number.
       It is not an error if this number is smaller than the number of
       bytes requested; this may happen for example because fewer bytes
       are actually available right now (maybe because we were close to
       end-of-file, or because we are reading from a pipe, or from a
       terminal), or because read() was interrupted by a signal.  See
       also NOTES.

       On error, -1 is returned, and errno is set to indicate the error.
       In this case, it is left unspecified whether the file position
       (if any) changes.
```

The Read syscall returns the number of bytes that are read and takes three arguments:

1. `fd`: Specifies file descriptor from which bytes are to be read.
2. `buf[.count]`: Specifies the location of buffer into which bytes are to be read.
3. `count`: Specifies the number of bytes to be read.

#### `fd` argument
For the `fd` argument we have to use the file descriptor of the connection that we accepted using the Accept syscall.

```
===== Trace: Parent Process =====
[✓] execve("/proc/self/fd/3", ["/proc/self/fd/3"], 0x7f56f63cd980 /* 0 vars */) = 0
[✓] socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3
[✓] bind(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("0.0.0.0")}, 16) = 0
[✓] listen(3, 0)                            = 0
[✓] accept(3, NULL, NULL)                   = 4
```

As we can see the file descriptor for the accepted connection is `4`, which is stored in `rax`.

#### `buf[.count]` argument
For the `buf[.count]` argument, we have to set the location of the buffer. 
We can set the location to the stack using the stack pointer `rsp` register.

#### `count` argument
For the `count` argument, we have to set it to the length of the message to be received which is `146` bytes. 
Reading more bytes than necessay can use up unnecessary space and also allow the client to insert malicious data.

```asm title="Read syscall"
mov rdi, 4
mov rsi, rsp
mov rdx, 146
mov rax, 0x00
syscall
```

### Write syscall

```c
ssize_t write(int fd, const void buf[.count], size_t count);
```

```
RETURN VALUE
       On success, the number of bytes written is returned.  On error,
       -1 is returned, and errno is set to indicate the error.

       Note that a successful write() may transfer fewer than count
       bytes.  Such partial writes can occur for various reasons; for
       example, because there was insufficient space on the disk device
       to write all of the requested bytes, or because a blocked write()
       to a socket, pipe, or similar was interrupted by a signal handler
       after it had transferred some, but before it had transferred all
       of the requested bytes.  In the event of a partial write, the
       caller can make another write() call to transfer the remaining
       bytes.  The subsequent call will either transfer further bytes or
       may result in an error (e.g., if the disk is now full).

       If count is zero and fd refers to a regular file, then write()
       may return a failure status if one of the errors below is
       detected.  If no errors are detected, or error detection is not
       performed, 0 is returned without causing any other effect.  If
       count is zero and fd refers to a file other than a regular file,
       the results are not specified.
```
The Read syscall returns the number of bytes that are written and takes three arguments:

1. `fd`: Specifies file descriptor to which bytes are to be written.
2. `buf[.count]`: Specifies the location of buffer from which bytes are to be written.
3. `count`: Specifies the number of bytes to be written.

#### `fd` argument
For the `fd` argument we have to use the file descriptor of the connection that we accepted using the Accept syscall.
We know that it is `4`.

#### `buf[.count]` argument
For this argument, we have to first store the response in the `.data` section. and 

```asm
.section .data
response: 
    .string "HTTP/1.0 200 OK\r\n\r\n"
```

We can now load the address of this `struct` into `rsi` using the `lea` instruction.

```asm
lea rsi, [rip+response]
```

#### `count` argument
For the count argument, we have to set it to the length of the response to be written which is 19 bytes.

```asm title="Write syscall"
mov rdi, 4
lea rsi, [rip+response]
mov rdx, 19
mov rax, 0x01
syscall

.section .data
response: 
    .string "HTTP/1.0 200 OK\r\n\r\n"
```

### Close syscall

```c
int close(int fd);
```

```
RETURN VALUE
       close() returns zero on success.  On error, -1 is returned, and
       errno is set to indicate the error.
```

The Close syscall returns a code and takes one argument:

1. `fd`: Specidfies the file descriptor to be closed.

#### `fd` argument

The file descriptor that we want to close is `4` whic is the file descriptor of the accepted connection.

```asm title="Close syscall"
mov rdi, 4
mov rax, 0x03
syscall
```

```asm title="webserver6.s"
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
    mov rdx, 146
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

> In this challenge you will respond to a GET request for the contents of a specified file.

For this level, we are expected to take the 

```
===== Expected: Parent Process =====
[ ] execve(<execve_args>) = 0
[ ] socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3
[ ] bind(3, {sa_family=AF_INET, sin_port=htons(<bind_port>), sin_addr=inet_addr("<bind_address>")}, 16) = 0
    - Bind to port 80
    - Bind to address 0.0.0.0
[ ] listen(3, 0) = 0
[ ] accept(3, NULL, NULL) = 4
[ ] read(4, <read_request>, <read_request_count>) = <read_request_result>
[ ] open("<open_path>", O_RDONLY) = 5
[ ] read(5, <read_file>, <read_file_count>) = <read_file_result>
[ ] close(5) = 0
[ ] write(4, "HTTP/1.0 200 OK\r\n\r\n", 19) = 19
[ ] write(4, <write_file>, <write_file_count>) = <write_file_result>
[ ] close(4) = 0
[ ] exit(0) = ?
```

### Extracting the filename specified in the response

If we run the last program for this level, we can see that the response includes a filename.

```
===== Trace: Parent Process =====
[✓] execve("/proc/self/fd/3", ["/proc/self/fd/3"], 0x7fd87944e980 /* 0 vars */) = 0
[✓] socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3
[✓] bind(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("0.0.0.0")}, 16) = 0
[✓] listen(3, 0)                            = 0
[✓] accept(3, NULL, NULL)                   = 4
[✓] read(4, "GET /tmp/tmpmslfupz4 HTTP/1.1\r\nHost: localhost\r\nUser-Agent: python-requests/2.32.3\r\nAccept-Encoding: gzip, deflate, zstd\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n", 256) = 161
```

We can see that the response include the `/tmp/tmpmslfupz4` filename, which seems to be a random name.

In the Read syscall, we stored the data to be read onto the stack.
So the `rsp` register currently acts a pointer to `GET /tmp/tmpmslfupz4 HTTP/1.1\r\nHost: localhost\r\nUser-Agent: python-requests/2.32.3\r\nAccept-Encoding: gzip, deflate, zstd\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n`.

Let's move the pointer into `r10` so that we can perform further operations with it.

```asm
mov r10, rsp       # r10 also points to the response 
```

#### Parsing through `GET`
Now, we need a loop that parses through the respones and removes the `GET` part.

```asm
Parse_GET:
    mov al, [r10]       # Move one byte from the stack into al
    cmp al, ' '         # Compare if the byte is an empty space ' '
                        # If equal:
    je Done_1                  # Jump out of the loop
                        # Else:
    add r10, 1                 # Make r10 point to the next byte
    jmp Parse_GET       # Repeat loop 
```

Once this loop is done executing, this is how the relevant registers will look:

```
rsp
|  r10
v  v
GET /tmp/tmpmslfupz4 HTTP/1.1\r\nHost: localhost\r\nUser-Agent: python-requests/2.32.3\r\nAccept-Encoding: gzip, deflate, zstd\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n
```

Next, we need to create a setup first before we parse the actual filename.

```asm
done1:
    add r10, 1         # Make r10 point to the first character of filename (/)
    mov r11, r10       # Make r11 point to the same byte
    mov r12, 0         # Set r12 to 0, to use as a counter
```

#### Parsing through filename
Now, we are ready to parse through the filename.

```asm
Parse_filename:
    mov al, byte ptr [r11]       # Move one byte from the stack into al
    cmp al, ' '                  # Compare if the byte is an empty space ' '
                                 # If equal:
    je Done_2                           # Jump out of the loop     
                                 # Else:
    add r11, 1                          # Make r11 point to the next byte
    jmp Parse_filename           # Repeat loop 
```

Once this loop is done executing, this is how the relevant registers will look:

```
rsp
|   r10             r11
v   v               v
GET /tmp/tmpmslfupz4 HTTP/1.1\r\nHost: localhost\r\nUser-Agent: python-requests/2.32.3\r\nAccept-Encoding: gzip, deflate, zstd\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n
```

Let's set a NULL byte at r11 is pointing. This will terminate the string while reading the filename.

```asm
Done_2:
    mov byte ptr [r11], 0
```

#### Final pointer locations

```
rsp
|   r10             r11
v   v               v
GET /tmp/tmpmslfupz40HTTP/1.1\r\nHost: localhost\r\nUser-Agent: python-requests/2.32.3\r\nAccept-Encoding: gzip, deflate, zstd\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n
```

### Open syscall

```c
int open(const char *pathname, int flags, .../* mode_t mode */ );
```

```
RETURN VALUE
       On success, open(), openat(), and creat() return the new file
       descriptor (a nonnegative integer).  On error, -1 is returned and
       errno is set to indicate the error.
```

The Open syscall returns a file descriptor and takes three arguemnts:

1. `*pathname`: Points to the filename to be opened.
2. `flags`: Must include one of the following access modes: O_RDONLY, O_WRONLY, or O_RDWR. Other access modes also exist.
3. `mode`: Specifies file permissions if file is being created.

#### `*pathname` argument
If we look at the [this](#final-pointer-values) diagram, we can see that `r10` already points to the start of the filename.
We can just move it into the `rdi` register.

```asm
mov rdi, r10
```

#### `flags` argument
Since we are only reading from the file, we need to set the flag to `O_RDONLY`.

```
hacker@building-a-web-server~level10:~/server$ grep -r "#define O_RDONLY" /usr/include/
/usr/include/x86_64-linux-gnu/bits/fcntl-linux.h:#define O_RDONLY            00
/usr/include/asm-generic/fcntl.h:#define O_RDONLY       00000000
```

The Octal value for `O_RDONLY` is `00000000` which is `0` in Decimal.

#### `mode` argument
Since we are not creating a new file, we have to set the `mode` to `0`.

```asm title="Open syscall"
mov rdi, r10
mov rsi, 0
mov rdx, 0
mov rax, 0x02
syscall
```

### Reading file content

The file descriptor of the Open syscall is `5`. That will be where we will read from.

We want to read to the stack. So we will point to the location using `rsp`.

```asm title="Reading file content"
mov rdi, 5
mov rsi, rsp
mov rdx, 256
mov rax, 0x00
syscall
```

```
[✓] read(5, "pM6ypGMUwpKdFw94HsUXn5woBxkD2hk2pViNTbWMSpaEVx8SBHH0CMYnSQj", 256) = 59
```

As we can see, we read 59 bytes from the file.

#### File content
```
rsp
v
pM6ypGMUwpKdFw94HsUXn5woBxkD2hk2pViNTbWMSpaEVx8SBHH0CMYnSQj
```

### Writing file content

The connection we want to write to has the file descriptor `4`.

We are again going to write from the stack pointed to by `rsp`. 

We have to write the exact number of bytes that we read from the file. This is the result of the Read syscall and is stored in the `rax` register. 
We can preserve the reult by moving it into another register.

```asm
mov r12, rax
```

```asm title="Writing file content"
mov rdi, 4
mov rsi, rsp
mov rdx, r12
mov rax, 0x01
syscall
```

```asm title="webserver7.asm"
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
    mov rdx, 256
    mov rax, 0x00
    syscall

    mov r10, rsp

Parse_GET:
    mov al, byte ptr [r10]
    cmp al, ' '
    je Done_1
    add r10, 1
    jmp Parse_GET

Done_1:
    add r10, 1
    mov r11, r10

Parse_filename:
    mov al, byte ptr [r11]
    cmp al, ' '
    je Done_2
    add r11, 1
    jmp Parse_filename

Done_2:
    mov byte ptr [r11], 0

    # Open syscall
    mov rdi, r10
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

    mov r12, rax

    # Close syscall
    mov rdi, 5
    mov rax, 0x03
    syscall

    # Write syscall
    mov rdi, 4
    lea rsi, [rip+response]
    mov rdx, 19
    mov rax, 0x01
    syscall

    # Write syscall
    mov rdi, 4
    mov rsi, rsp
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

```
hacker@building-a-web-server~level7:~$ as -o webserver7.o webserver7.s && ld -o webserver7 webserver7.o
```

```
hacker@building-a-web-server~level7:~$ /challenge/run ./webserver7
```

&nbsp;

## level 8

> In this challenge you will accept multiple requests.

```asm title="webserver8.asm"
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
    mov rdx, 256
    mov rax, 0x00
    syscall

    mov r10, rsp

Parse_GET:
    mov al, byte ptr [r10]
    cmp al, ' '
    je Done_1
    add r10, 1
    jmp Parse_GET

Done_1:
    add r10, 1
    mov r11, r10

Parse_filename:
    mov al, byte ptr [r11]
    cmp al, ' '
    je Done_2
    add r11, 1
    jmp Parse_filename

Done_2:
    mov byte ptr [r11], 0

    # Open syscall
    mov rdi, r10
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

    mov r12, rax

    # Close syscall
    mov rdi, 5
    mov rax, 0x03
    syscall

    # Write syscall
    mov rdi, 4
    lea rsi, [rip+response]
    mov rdx, 19
    mov rax, 0x01
    syscall

    # Write syscall
    mov rdi, 4
    mov rsi, rsp
    mov rdx, r12
    mov rax, 0x01
    syscall

    # Close syscall
    mov rdi, 4
    mov rax, 0x03
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

response: 
    .string "HTTP/1.0 200 OK\r\n\r\n"
```

```
hacker@building-a-web-server~level:~$ as -o webserver8.o webserver8.s && ld -o webserver8 webserver8.o
```

```
hacker@building-a-web-server~level8:~$ /challenge/run ./webserver8
```

&nbsp;

## level 9

> In this challenge you will accept multiple requests.

### Fork syscall

```c
pid_t fork(void);
```

```
RETURN VALUE
       On success, the PID of the child process is returned in the
       parent, and 0 is returned in the child.  On failure, -1 is
       returned in the parent, no child process is created, and errno is
       set to indicate the error.
```

The Fork syscall returns the PID of the child process and takes zero arguments.

If we execute the code, we can check the PID that is returned.

```asm title="Fork syscall"
mov rax, 0x39
syscall
```

```
[✓] fork()                                  = 7
```

As we can see, it is `7`, which means we are within the parent process.

```
===== Expected: Parent Process =====
[ ] execve(<execve_args>) = 0
[ ] socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3
[ ] bind(3, {sa_family=AF_INET, sin_port=htons(<bind_port>), sin_addr=inet_addr("<bind_address>")}, 16) = 0
    - Bind to port 80
    - Bind to address 0.0.0.0
[ ] listen(3, 0) = 0
[ ] accept(3, NULL, NULL) = 4
[ ] fork() = <fork_result>
[ ] close(4) = 0
[ ] accept(3, NULL, NULL) = ?
```

```
===== Expected: Child Process =====
[ ] close(3) = 0
[ ] read(4, <read_request>, <read_request_count>) = <read_request_result>
[ ] open("<open_path>", O_RDONLY) = 3
[ ] read(3, <read_file>, <read_file_count>) = <read_file_result>
[ ] close(3) = 0
[ ] write(4, "HTTP/1.0 200 OK\r\n\r\n", 19) = 19
[ ] write(4, <write_file>, <write_file_count>) = <write_file_result>
[ ] exit(0) = ?
```

After the Fork is done, we need to execute two syscalls in the parent process and then move onto the child process.
In order to separate our control flow, we need to create a simple check to check if we are in a parent process or the child process.

```
cmp rax, 0		# Check if return value of Fork is zero
			# If equal:
je Child_process		# Move onto child process

```

Once this check is performed, we can separate the code using labels:

```
Parent_process:
	# Code for parent process

Child_process:
	# Code for child process
```

```asm title="webserver9.asm" 
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

    # Fork syscall
    mov rax, 0x39
    syscall

    cmp rax, 0
    je Child_process

Parent_process:
    # Close syscall
    mov rdi, 4		# Close the accepted connection
    mov rax, 0x03
    syscall

    # Accept syscall
    mov rdi, 3
    mov rsi, 0
    mov rdx, 0
    mov rax, 0x2b
    syscall

Child_process:
    # Close syscall 
    mov rdi, 3		# Close the Socket listener
    mov rax, 0x03
    syscall

    # Read syscall
    mov rdi, 4
    mov rsi, rsp
    mov rdx, 256
    mov rax, 0x00
    syscall

    mov r10, rsp

Parse_GET:
    mov al, byte ptr [r10]
    cmp al, ' '
    je Done_1
    add r10, 1
    jmp Parse_GET

Done_1:
    add r10, 1
    mov r11, r10

Parse_filename:
    mov al, byte ptr [r11]
    cmp al, ' '
    je Done_2
    add r11, 1
    jmp Parse_filename

Done_2:
    mov byte ptr [r11], 0

    # Open syscall
    mov rdi, r10
    mov rsi, 0
    mov rdx, 0
    mov rax, 0x02
    syscall

    # Read syscall
    mov rdi, 3
    mov rsi, rsp
    mov rdx, 256
    mov rax, 0x00
    syscall

    mov r12, rax

    # Close syscall
    mov rdi, 3
    mov rax, 0x03
    syscall

    # Write syscall
    mov rdi, 4
    lea rsi, [rip+response]
    mov rdx, 19
    mov rax, 0x01
    syscall

    # Write syscall
    mov rdi, 4
    mov rsi, rsp
    mov rdx, r12
    mov rax, 0x01
    syscall

    # Close syscall
    mov rdi, 4
    mov rax, 0x03
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

response: 
    .string "HTTP/1.0 200 OK\r\n\r\n"
```

```
hacker@building-a-web-server~level9:~$ as -o webserver9.o webserver9.s && ld -o webserver9 webserver9.o
```

```
hacker@building-a-web-server~level9:~$ /challenge/run ./webserver9
```

&nbsp;

## level 10

> In this challenge you will respond to a POST request with a specified file and update its contents.

### Open syscall
In this level, we have to modify the Open syscall slightly.

```
[ ] open("<open_path>", O_WRONLY|O_CREAT, 0777) = 3
```

#### `flag` argument
Since we have to set the `O_WRONLY` or the `O_CREAT` flag, we need to perform a bitwise OR of both values.

```
hacker@building-a-web-server~level10:~/server$ grep -r "#define O_WRONLY" /usr/include/
/usr/include/x86_64-linux-gnu/bits/fcntl-linux.h:#define O_WRONLY            01
/usr/include/asm-generic/fcntl.h:#define O_WRONLY       00000001
```

The Octal value of `O_WRONLY` is `00000001` which is `1` in Decimal.

```
hacker@building-a-web-server~level10:~/server$ grep -r "#define O_CREAT" /usr/include/
/usr/include/asm-generic/fcntl.h:#define O_CREAT                00000100        /* not fcntl */
```

The Octal value of `O_WRONLY` is `00000100` which is `64` in Decimal.

```
Flag			Octal		Decimal

O_WRONLY		00000001	1
O_CREAT			00000100	64
------------------------------------------------
Bitwise OR
------------------------------------------------
O_WRONLY | O_CREAT	00000101	65
```

Set the `flag` argument to `65`.

#### `mode` argument
Since we are creating the filw, we have to specifiy the `mode`
We also have to set the `mode` argument to `0777`.

For this level, after the first parsing loop, our pointer will look as follows:

### Final pointer locations
```
rsp
|    r10             r11
v    v               v
POST /tmp/tmp4iy_qvbx0HTTP/1.1\r\nHost: localhost\r\nUser-Agent: python-requests/2.32.3\r\nAccept-Encoding: gzip, deflate, zstd\r\nAccept: */*\r\nConnection: keep-alive\r\nContent-Length: 215\r\n\r\nR15W1AHO2JHSZtB7k9A1LVbfUdHKw8c4mbCV9PjHhIAI5S715T2DltqVlaSONngT8OvACdzhp2tmD1WjTAttBKBpgU0FMEHGJh4NFPyzCTXmAFkUJZ7xyo5sHSWY46mM7ts2vgBmoO6smGMgvA3J4ciu14UIlWi4vM2O7ZryHHi8fiuSu3YQxRiLFZ4CXHCb75vR2LSsT5pXOkVwTa7rxj6
```

We need to create two more parsers that do the following:

- Parses through the POST header till it finds `/r/n/r/n`.
- Parses through the content after `/r/n/r/n`.


### Extracting POST content
#### Parsing through POST header

```
rsp
|                    r10
v                    v
                                 r11
                                 v
POST /tmp/tmp4iy_qvbx0HTTP/1.1\r\nHost: localhost\r\nUser-Agent: python-requests/2.32.3\r\nAccept-Encoding: gzip, deflate, zstd\r\nAccept: */*\r\nConnection: keep-alive\r\nContent-Length: 215\r\n\r\nR15W1AHO2JHSZtB7k9A1LVbfUdHKw8c4mbCV9PjHhIAI5S715T2DltqVlaSONngT8OvACdzhp2tmD1WjTAttBKBpgU0FMEHGJh4NFPyzCTXmAFkUJZ7xyo5sHSWY46mM7ts2vgBmoO6smGMgvA3J4ciu14UIlWi4vM2O7ZryHHi8fiuSu3YQxRiLFZ4CXHCb75vR2LSsT5pXOkVwTa7rxj6
```
