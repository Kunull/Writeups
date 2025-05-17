---
custom_edit_url: null
---

## level 1

```
hacker@data-dealings~whats-the-password:/$ /challenge/runme
Enter the password:
npknegwx              
Read 8 bytes.
Congrats! Here is your flag:
pwn.college{kQMMfnfgzYwYvTHUEbPNyVaGwSJ.QX5QjN0EDL4ITM0EzW}
```

&nbsp;

## level 2

```
hacker@data-dealings~-and-again:/$ /challenge/runme 
Enter the password:
fbharpsp
Read 8 bytes.
Congrats! Here is your flag:
pwn.college{E0dk8pfSQBwE13ZE790cjercb0t.QXwUjN0EDL4ITM0EzW}
```

&nbsp;

## level 3

In this level, we have to have to pass the input without using Newline, so we cannot use `Enter`.
There are a few ways of working around this.

```
hacker@data-dealings~newline-troubles:/$ /challenge/runme 
Enter the password:
bzvrlubuRead 8 bytes.
Congrats! Here is your flag:
pwn.college{83Yfzwc1-_dx46U81fdAkHxh-s4.QXxUjN0EDL4ITM0EzW}
```

```
hacker@data-dealings~newline-troubles:/$ echo -n "bzvrlubu" | /challenge/runme 
Enter the password:
Read 8 bytes.
Congrats! Here is your flag:
pwn.college{83Yfzwc1-_dx46U81fdAkHxh-s4.QXxUjN0EDL4ITM0EzW}
```

```
hacker@data-dealings~newline-troubles:/$ echo -n "bzvrlubu" > ~/no-newline
hacker@data-dealings~newline-troubles:/$ cat ~/no-newline | /challenge/runme 
Enter the password:
Read 8 bytes.
Congrats! Here is your flag:
pwn.college{83Yfzwc1-_dx46U81fdAkHxh-s4.QXxUjN0EDL4ITM0EzW}
```

&nbsp;

## level 4

```python title="/challenge/runme"
#!/usr/bin/exec-suid -- /bin/python3 -I

import sys


try:
    entered_password = open("dlvd", "rb").read()
except FileNotFoundError:
    print("Input file not found...")
    sys.exit(1)
if b"\n" in entered_password:
    print("Password has newlines /")
    print("Editors add them sometimes /")
    print("Learn to remove them.")

correct_password = b"agnhodts"

print(f"Read {len(entered_password)} bytes.")


if entered_password == correct_password:
    print("Congrats! Here is your flag:")
    print(open("/flag").read().strip())
else:
    print("Incorrect!")
    sys.exit(1)
```

```
hacker@data-dealings~reasoning-about-files:~$ echo -n "agnhodts" > dlvd
hacker@data-dealings~reasoning-about-files:~$ /challenge/runme
Read 8 bytes.
Congrats! Here is your flag:
pwn.college{khRH24VG9yLRmIyub5UOP_O_xOp.QXyUjN0EDL4ITM0EzW}
```

&nbsp;

## level 5

```python title="/challenge/runme"
#!/usr/bin/exec-suid -- /bin/python3 -I

import sys


try:
    entered_password = open(sys.argv[1], "rb").read()
except FileNotFoundError:
    print("Input file not found...")
    sys.exit(1)
if b"\n" in entered_password:
    print("Password has newlines /")
    print("Editors add them sometimes /")
    print("Learn to remove them.")

correct_password = b"yhmspqfn"

print(f"Read {len(entered_password)} bytes.")


if entered_password == correct_password:
    print("Congrats! Here is your flag:")
    print(open("/flag").read().strip())
else:
    print("Incorrect!")
    sys.exit(1)
```

```
hacker@data-dealings~specifying-filenames:~$ /challenge/runme dlvd
Read 8 bytes.
Congrats! Here is your flag:
pwn.college{4Mop728hBfbp6sWoiV9TKBoXL3q.QXzUjN0EDL4ITM0EzW}
```

&nbsp;

## level 6

```python title="/challenge/runme"
#!/usr/bin/exec-suid -- /bin/python3 -I

import sys


print("Enter the password:")
entered_password = sys.stdin.buffer.read1()
correct_password = b"\x87"

print(f"Read {len(entered_password)} bytes.")


entered_password = bytes.fromhex(entered_password.decode("l1"))


if entered_password == correct_password:
    print("Congrats! Here is your flag:")
    print(open("/flag").read().strip())
else:
    print("Incorrect!")
    sys.exit(1)
```

```
hacker@data-dealings~binary-and-hex-encoding:/$ echo -n "87" | /challenge/runme 
Enter the password:
Read 2 bytes.
Congrats! Here is your flag:
pwn.college{ktfk2rTkhXqeMR0AkX32xPNdJyQ.QX0UjN0EDL4ITM0EzW}
```

&nbsp;

## level 7

```python title="/challenge/runme"
#!/usr/bin/exec-suid -- /bin/python3 -I

import sys


print("Enter the password:")
entered_password = sys.stdin.buffer.read1()
correct_password = b"\x9d\x8b\xb7\xc5\xae\xcd\xf5\x97"

print(f"Read {len(entered_password)} bytes.")


entered_password = bytes.fromhex(entered_password.decode("l1"))


if entered_password == correct_password:
    print("Congrats! Here is your flag:")
    print(open("/flag").read().strip())
else:
    print("Incorrect!")
    sys.exit(1)
```

```
hacker@data-dealings~more-hex:/$ echo -n "9d8bb7c5aecdf597" | /challenge/runme 
Enter the password:
Read 16 bytes.
Congrats! Here is your flag:
pwn.college{kR55sS4vVzLFwsmFXfgmCj6Hcdo.QX1UjN0EDL4ITM0EzW}
```

&nbsp;

## level 8

```python title="/challenge/runme"
#!/usr/bin/exec-suid -- /bin/python3 -I

import sys


print("Enter the password:")
entered_password = sys.stdin.buffer.read1()
correct_password = b"83a3c7dddbeeebc2"

print(f"Read {len(entered_password)} bytes.")


correct_password = bytes.fromhex(correct_password.decode("l1"))


if entered_password == correct_password:
    print("Congrats! Here is your flag:")
    print(open("/flag").read().strip())
else:
    print("Incorrect!")
    sys.exit(1)
```

```
hacker@data-dealings~decoding-hex:/$ echo -e -n "\x83\xa3\xc7\xdd\xdb\xee\xeb\xc2" | /challenge/runme
Enter the password:
Read 8 bytes.
Congrats! Here is your flag:
pwn.college{AT4B5MENT3pNgGM4OjIqiXu3M2T.QX2UjN0EDL4ITM0EzW} 
```

```
hacker@data-dealings~decoding-hex:/$ python3 -c 'import sys; sys.stdout.buffer.write(bytes.fromhex("83a3c7dddbeeebc2"))' | /challenge/runme
Enter the password:
Read 8 bytes.
Congrats! Here is your flag:
pwn.college{AT4B5MENT3pNgGM4OjIqiXu3M2T.QX2UjN0EDL4ITM0EzW}
```

&nbsp;

## level 9

```python title="/challenge/runme"
#!/usr/bin/exec-suid -- /bin/python3 -I

import sys


def decode_from_bits(s):
    s = s.decode("latin1")
    assert set(s) <= {"0", "1"}, "non-binary characters found in bitstream!"
    assert len(s) % 8 == 0, "must enter data in complete bytes (each byte is 8 bits)"
    return int.to_bytes(int(s, 2), length=len(s) // 8, byteorder="big")


print("Enter the password:")
entered_password = sys.stdin.buffer.read1()
correct_password = b"1010000010000000111000001100010010010111100011011100111111100101"

print(f"Read {len(entered_password)} bytes.")


correct_password = decode_from_bits(correct_password)


if entered_password == correct_password:
    print("Congrats! Here is your flag:")
    print(open("/flag").read().strip())
else:
    print("Incorrect!")
    sys.exit(1)
```

```python
>>> s = "1010000010000000111000001100010010010111100011011100111111100101"
>>> int.to_bytes(int(s, 2), length=len(s) // 8, byteorder="big")
b'\xa0\x80\xe0\xc4\x97\x8d\xcf\xe5'
```

```
hacker@data-dealings~decoding-practice:/$ printf '\xa0\x80\xe0\xc4\x97\x8d\xcf\xe5' | /challenge/runme
Enter the password:
Read 8 bytes.
Congrats! Here is your flag:
pwn.college{I3JkNU8KLUR7UzAFIiARrACAUm0.QX3UjN0EDL4ITM0EzW}
```
