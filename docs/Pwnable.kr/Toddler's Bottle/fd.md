---
custom_edit_url: null
sidebar_position: 1
---

> Mommy! what is a file descriptor in Linux?
>
> * try to play the wargame your self but if you are ABSOLUTE beginner, follow this tutorial link:
> https://youtu.be/971eZhMHQQw
>
> ssh fd@pwnable.kr -p2222 (pw:guest)

## File properties

```
fd@ubuntu:~$ file ./fd
fd: setgid ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=156ca9c174df927ecd7833a27d18d0dd5e413656, for GNU/Linux 3.2.0, not stripped
```

## Source code

```c title="fd.c"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
char buf[32];
int main(int argc, char* argv[], char* envp[]){
    if(argc<2){
        printf("pass argv[1] a number\n");
        return 0;
    }
    int fd = atoi( argv[1] ) - 0x1234;
    int len = 0;
    len = read(fd, buf, 32);
    if(!strcmp("LETMEWIN\n", buf)){
        printf("good job :)\n");
        setregid(getegid(), getegid());
        system("/bin/cat flag");
        exit(0);
    }
    printf("learn about Linux file IO\n");
    return 0;

}
```

The program checks to see if we have passed to arguments or not.

It the converts our second argument into an integer using [atoi](https://man7.org/linux/man-pages/man3/atoi.3.html), subtracts `0x1234` from it and then stores the value in the `fd` variable.

### [`read()`](https://man7.org/linux/man-pages/man2/read.2.html)

```c
ssize_t read(int fd, void buf[.count], size_t count);
```
```
DESCRIPTION         
       read() attempts to read up to count bytes from file descriptor fd
       into the buffer starting at buf.

       On files that support seeking, the read operation commences at the
       file offset, and the file offset is incremented by the number of
       bytes read.  If the file offset is at or past the end of file, no
       bytes are read, and read() returns zero.

       If count is zero, read() may detect the errors described below.
       In the absence of any errors, or if read() does not check for
       errors, a read() with a count of 0 returns zero and has no other
       effects.

       According to POSIX.1, if count is greater than SSIZE_MAX, the
       result is implementation-defined; see NOTES for the upper limit on
       Linux.

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
       In this case, it is left unspecified whether the file position (if
       any) changes.
```


It then reads 32 bytes from the file descriptor `fd` into the buffer buf.

If the string that is read is "LETMEWIN", it cats out the flag.

Knowing all this, we have to provide the second argument such that when subtracted by `0x1234` the answer is `0`, which is the file descriptor for STDIN.
That way, the program will read from STDIN, and we can provide the string "LETMEWIN".

`0x1234` in decimal is `4660`.

```
fd@ubuntu:~$ ./fd 4660
LETMEWIN
good job :)
Mama! Now_I_understand_what_file_descriptors_are!
```


