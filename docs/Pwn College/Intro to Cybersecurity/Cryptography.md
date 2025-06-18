---
custom_edit_url: null
sidebar_position: 3
---

## XOR

```
hacker@cryptography~xor:/$ /challenge/run 
The key: 17
Encrypted secret: 47
Decrypted secret? 
```

```py
In [1]: key = 17
   ...: encrypted_secret = 47
   ...: decrypted_secret = key ^ encrypted_secret
   ...: print(f"Decrypted secret: {decrypted_secret}")
Decrypted secret: 62
```

Now we can provide this as the answer.

```
hacker@cryptography~xor:/$ /challenge/run 
The key: 17
Encrypted secret: 47
Decrypted secret? 62
CORRECT! Your flag:
pwn.college{I0fIIbzFrXKLaqwpVcvpw0ySDFR.ddjM3kDL4ITM0EzW}
```

Let's automate the process so that it works for any input.

```py title="~/auto_script.py" showLineNumbers
#!/usr/bin/env python3

import subprocess
import re

# Run the challenge binary and capture the output
proc = subprocess.Popen(["/challenge/run"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

# Read the key and cipher from output
output = proc.stdout.readline()
key = int(re.search(r'\d+', output).group())

output = proc.stdout.readline()
encrypted_secret = int(re.search(r'\d+', output).group())

# Recover the plain secret using XOR
decrypted_secret = key ^ encrypted_secret

# Send the recovered decrypted_secret as input
proc.stdin.write(f"{decrypted_secret}\n")
proc.stdin.flush()

# Print the remaining output (CORRECT! or INCORRECT! and possibly the flag)
for line in proc.stdout:
    print(line, end="")
```

&nbsp;

## XORing Hex

```
hacker@cryptography~xoring-hex:/$ /challenge/run 
Challenge number 0...
The key: 0x11
Encrypted secret: 0xfd
Decrypted secret? 
```

```py
In [1]: key = 0x11
   ...: encrypted_secret = 0xfd
   ...: decrypted_secret = hex(key ^ encrypted_secret)
   ...: print(f"Decrypted secret: {decrypted_secret}")
Decrypted secret: 0xec
```

Let's enter this.

```
hacker@cryptography~xoring-hex:/$ /challenge/run 
Challenge number 0...
The key: 0x11
Encrypted secret: 0xfd
Decrypted secret? 0xec
You entered: 0xec, decimal 236.
Correct! Moving on.
Challenge number 1...
The key: 0x9a
Encrypted secret: 0xe5
Decrypted secret? 
```

We can see that loops over and asks the same question.
Let's automate the process.

```py title="~/auto_script.py" showLineNumbers
#!/usr/bin/env python3

import subprocess
import re

# Start the challenge process
proc = subprocess.Popen(
    ["/challenge/run"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)

while True:
    line = proc.stdout.readline()
    if not line:
        break
    print(line, end="")

    if line.startswith("The key:"):
        key = int(line.strip().split(":")[1], 16)

        encrypted_line = proc.stdout.readline()
        print(encrypted_line, end="")
        encrypted_secret = int(encrypted_line.strip().split(":")[1], 16)

        decrypted_secret = encrypted_secret ^ key
        proc.stdin.write(f"{decrypted_secret:#04x}\n")
        proc.stdin.flush()

    elif "INCORRECT!" in line or "CORRECT! Your flag:" in line:
        # Print remaining lines (flag or failure)
        for out_line in proc.stdout:
            print(out_line, end="")
        break
```

```
hacker@cryptography~xoring-hex:/$ python ~/script.py
Challenge number 0...
The key: 0xde
Encrypted secret: 0x5d
Decrypted secret? You entered: 0x83, decimal 131.
Correct! Moving on.
Challenge number 1...
The key: 0x2c
Encrypted secret: 0x09
Decrypted secret? You entered: 0x25, decimal 37.
Correct! Moving on.
Challenge number 2...
The key: 0x1f
Encrypted secret: 0x30
Decrypted secret? You entered: 0x2f, decimal 47.
Correct! Moving on.
Challenge number 3...
The key: 0x38
Encrypted secret: 0x0e
Decrypted secret? You entered: 0x36, decimal 54.
Correct! Moving on.
Challenge number 4...
The key: 0x74
Encrypted secret: 0xe6
Decrypted secret? You entered: 0x92, decimal 146.
Correct! Moving on.
Challenge number 5...
The key: 0x08
Encrypted secret: 0xd9
Decrypted secret? You entered: 0xd1, decimal 209.
Correct! Moving on.
Challenge number 6...
The key: 0x2b
Encrypted secret: 0x09
Decrypted secret? You entered: 0x22, decimal 34.
Correct! Moving on.
Challenge number 7...
The key: 0x38
Encrypted secret: 0xa4
Decrypted secret? You entered: 0x9c, decimal 156.
Correct! Moving on.
Challenge number 8...
The key: 0xf1
Encrypted secret: 0x21
Decrypted secret? You entered: 0xd0, decimal 208.
Correct! Moving on.
Challenge number 9...
The key: 0xcf
Encrypted secret: 0x30
Decrypted secret? You entered: 0xff, decimal 255.
Correct! Moving on.
CORRECT! Your flag:
pwn.college{kSOtmx6AacMeAc4SYmd-sZa4sAf.dBzM3kDL4ITM0EzW}
```

&nbsp;

## XORing ASCII

### Source code
```py title="/challenge/run" showLineNumbers
#!/opt/pwn.college/python

import random
import string
import sys

if not sys.stdin.isatty():
    print("You must interact with me directly. No scripting this!")
    sys.exit(1)

for n in range(1, 10):
    print(f"Challenge number {n}...")
    pt_chr, ct_chr = random.sample(
        string.digits + string.ascii_letters + string.punctuation,
        2
    )
    key = ord(pt_chr) ^ ord(ct_chr)

    print(f"- Encrypted Character: {ct_chr}")
    print(f"- XOR Key: {key:#04x}")
    answer = input("- Decrypted Character? ").strip()
    if answer != pt_chr:
        print("Incorrect!")
        sys.exit(1)

    print("Correct! Moving on.")

print("You have mastered XORing ASCII! Your flag:")
print(open("/flag").read())
```

```
hacker@cryptography~xoring-ascii:/$ /challenge/run 
Challenge number 1...
- Encrypted Character: _
- XOR Key: 0x37
- Decrypted Character? 
```

```py
In [1]: key = 0x37
   ...: encrypted_character = ord("_") 
   ...: decrypted_character = chr(key ^ encrypted_character)
   ...: print(f"Decrypted character: {decrypted_character}")
Decrypted character: h
```

```
hacker@cryptography~xoring-ascii:/$ /challenge/run 
Challenge number 1...
- Encrypted Character: _
- XOR Key: 0x37
- Decrypted Character? h
Correct! Moving on.
Challenge number 2...
- Encrypted Character: J
- XOR Key: 0x36
- Decrypted Character? 
```

The challenge tries to prevent automation by requiring that the script be run in a real terminal (TTY) — not as a subprocess with piped input/output (like from `subprocess.Popen()`).

However, we can use `pexpect` which emulates a terminal (PTY), so `isatty()` returns `True`.

```py title="~/auto_script.py" showLineNumbers
import pexpect

p = pexpect.spawn("/challenge/run", encoding="utf-8")

try:
    while True:
        p.expect("Encrypted Character: (.)")
        encrypted_char = p.match.group(1)
        print(f"- Encrypted Char: {encrypted_char}")

        p.expect("XOR Key: (0x[0-9a-fA-F]+)")
        key = int(p.match.group(1), 16)
        print(f"- Key: {key:#04x}")

        plain = chr(ord(encrypted_char) ^ key)

        p.expect("Decrypted Character\\? ")
        p.sendline(plain)

        i = p.expect(["Correct! Moving on.", "You have mastered XORing ASCII! Your flag:", "INCORRECT!"])
        print(p.after)
        if i == 1:
            print(p.readline())  # Print the flag
            break

except pexpect.EOF:
    remaining = p.before.strip()
    if remaining:
        print(remaining)
```

```
hacker@cryptography~xoring-ascii:/$ python ~/script.py 
- Encrypted Char: x
- Key: 0x23
Correct! Moving on.
- Encrypted Char: C
- Key: 0x3e
Correct! Moving on.
- Encrypted Char: k
- Key: 0x47
Correct! Moving on.
- Encrypted Char: G
- Key: 0x2d
Correct! Moving on.
- Encrypted Char: *
- Key: 0x10
Correct! Moving on.
- Encrypted Char: Y
- Key: 0x23
Correct! Moving on.
- Encrypted Char: /
- Key: 0x64
Correct! Moving on.
- Encrypted Char: /
- Key: 0x6d
Correct! Moving on.
- Encrypted Char: p
- Key: 0x44
Correct! Moving on.

You have mastered XORing ASCII! Your flag:
pwn.college{w4z-Se86BfDzuA00U686p_yy3aR.dhjM3kDL4ITM0EzW}
```

&nbsp;

## 
