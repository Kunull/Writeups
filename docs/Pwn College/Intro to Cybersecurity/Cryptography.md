---
custom_edit_url: null
sidebar_position: 3
---

## XOR

### Source code
```py title="/challenge/run"
#!/opt/pwn.college/python

import random
import sys

key = random.randrange(1, 256)
plain_secret = random.randrange(0, 256)
cipher_secret = plain_secret ^ key

print(f"The key: {key}")
print(f"Encrypted secret: {cipher_secret}")
if int(input("Decrypted secret? ")) == plain_secret:
    print("CORRECT! Your flag:")
    print(open("/flag").read())
else:
    print("INCORRECT!")
    sys.exit(1)
```

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

```py title="~/script.py" showLineNumbers
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

### Source code
```py title="/challenge/run" showLineNumbers
#!/opt/pwn.college/python

import random
import sys

for n in range(10):
    print(f"Challenge number {n}...")

    key = random.randrange(1, 256)
    plain_secret = random.randrange(0, 256)
    cipher_secret = plain_secret ^ key

    print(f"The key: {key:#04x}")
    print(f"Encrypted secret: {cipher_secret:#04x}")
    answer = int(input("Decrypted secret? "), 16)
    print(f"You entered: {answer:#04x}, decimal {answer}.")
    if answer != plain_secret:
        print("INCORRECT!")
        sys.exit(1)

    print("Correct! Moving on.")

print("CORRECT! Your flag:")
print(open("/flag").read())
```

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

```py title="~/script.py" showLineNumbers
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

```py title="~/script.py" showLineNumbers
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

## XORing ASCII Strings

### Source code
```py title="/challenge/run" showLineNumbers
#!/opt/pwn.college/python

import random
import string
import sys

from Crypto.Util.strxor import strxor

valid_keys = "!#$%&()"
valid_chars = ''.join(
    c for c in string.ascii_letters
    if all(chr(ord(k)^ord(c)) in string.ascii_letters for k in valid_keys)
)

print(valid_keys, valid_chars)

for n in range(1, 10):
    print(f"Challenge number {n}...")

    key_str = ''.join(random.sample(valid_keys*10, 10))
    pt_str = ''.join(random.sample(valid_chars*10, 10))
    ct_str = strxor(pt_str.encode(), key_str.encode()).decode()

    print(f"- Encrypted String: {ct_str}")
    print(f"- XOR Key String: {key_str}")
    answer = input("- Decrypted String? ").strip()
    if answer != pt_str:
        print("Incorrect!")
        sys.exit(1)

    print("Correct! Moving on.")

print("You have mastered XORing ASCII! Your flag:")
print(open("/flag").read())
```

```
hacker@cryptography~xoring-ascii-strings:/$ /challenge/run 
!#$%&() bgjklmnopqBGJKLMNOPQ
Challenge number 1...
- Encrypted String: iEndTdkaTB
- XOR Key String: $)#(%#&&$)
- Decrypted String? 
```

```py
In [1]: from Crypto.Util.strxor import strxor
   ...: encrypted_string = b"iEndTdkaTB"
   ...: key = b"$)#(%#&&$)"
   ...: decrypted_string = strxor(encrypted_string, key)
   ...: print(f"Decrypted string: {decrypted_string}")
Decrypted string: b'MlMLqGMGpk'
```

```
hacker@cryptography~xoring-ascii-strings:/$ /challenge/run 
!#$%&() bgjklmnopqBGJKLMNOPQ
Challenge number 1...
- Encrypted String: iEndTdkaTB
- XOR Key String: $)#(%#&&$)
- Decrypted String? MlMLqGMGpk
Correct! Moving on.
Challenge number 2...
- Encrypted String: jjPGSLDkfF
- XOR Key String: !$!%##)!))
- Decrypted String? 
```

Let's automate.

```py title="~/script.py" showLineNumbers
#!/usr/bin/env python3

import subprocess
from Crypto.Util.strxor import strxor

# Start the challenge process
proc = subprocess.Popen(
    ["/challenge/run"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    bufsize=1 
)

while True:
    line = proc.stdout.readline()
    if not line:
        break
    print(line, end="")

    if line.startswith("- Encrypted String:"):
        encrypted_str = line.strip().split(": ", 1)[1]

        key_line = proc.stdout.readline()
        print(key_line, end="")
        key_str = key_line.strip().split(": ", 1)[1]

        # Read until the exact string prompt, not a full line
        prompt = ""
        while not prompt.endswith("- Decrypted String? "):
            char = proc.stdout.read(1)
            if not char:
                break
            prompt += char
            print(char, end="")

        # XOR and decode
        decrypted = strxor(
            encrypted_str.encode("latin1"),
            key_str.encode("latin1")
        ).decode("latin1")

        proc.stdin.write(decrypted + "\n")
        proc.stdin.flush()

    elif "Incorrect!" in line or "Your flag:" in line:
        for out_line in proc.stdout:
            print(out_line, end="")
        break
```

```
hacker@cryptography~xoring-ascii-strings:/$ python ~/script.py
!#$%&() bgjklmnopqBGJKLMNOPQ
Challenge number 1...
- Encrypted String: WUNKDbHUHK
- XOR Key String: &%!&#)%%#$
- Decrypted String? Correct! Moving on.
Challenge number 2...
- Encrypted String: GTOLCfubob
- XOR Key String: (%!#)$$%!(
- Decrypted String? Correct! Moving on.
Challenge number 3...
- Encrypted String: OBovGMfWfi
- XOR Key String: !($&%!!&)$
- Decrypted String? Correct! Moving on.
Challenge number 4...
- Encrypted String: JhHMFiCkjM
- XOR Key String: $#$#(#)%(&
- Decrypted String? Correct! Moving on.
Challenge number 5...
- Encrypted String: ICSnhGkySK
- XOR Key String: #!#%#)))#$
- Decrypted String? Correct! Moving on.
Challenge number 6...
- Encrypted String: IDJFcIjdCk
- XOR Key String: $#%!!&!&(&
- Decrypted String? Correct! Moving on.
Challenge number 7...
- Encrypted String: KmlxeHnfMe
- XOR Key String: &#!()&!)#(
- Decrypted String? Correct! Moving on.
Challenge number 8...
- Encrypted String: iBftYGYIfF
- XOR Key String: %%)%(()$((
- Decrypted String? Correct! Moving on.
Challenge number 9...
- Encrypted String: joJfCjYJSi
- XOR Key String: %#!!)%(%#%
- Decrypted String? Correct! Moving on.
You have mastered XORing ASCII! Your flag:
pwn.college{Mu8QkjC0REoDOGVQrHicFcg9hJ7.dljM3kDL4ITM0EzW}
```

&nbsp;

## One-time Pad

```py title="/challenge/run" showLineNumbers
#!/opt/pwn.college/python

from Crypto.Random import get_random_bytes
from Crypto.Util.strxor import strxor

flag = open("/flag", "rb").read()

key = get_random_bytes(len(flag))
ciphertext = strxor(flag, key)

print(f"One-Time Pad Key (hex): {key.hex()}")
print(f"Flag Ciphertext (hex): {ciphertext.hex()}")
```

```
hacker@cryptography~one-time-pad:/$ /challenge/run
One-Time Pad Key (hex): 7d29459b4f15aa95736ac4a5a348a95ed9c7df9e745f2147572e59385df9918e15b73ffc160d0b27ba0b460c821752ff15f26b39e15bb6a9da3d
Flag Ciphertext (hex): 0d5e2bb52c7ac6f9160da1dee63b9d36839fe9d41c0d44773446126c18b0d9e445ce7eba5e646509de593c42f85a16b321bb3f74d11eccfea737
```

This time, we the flag is encrypted using One-time pad.
In order to get the original, we have to get XOR the bits of the plaintext with the bits of the key one by one.

```py title="~/script.py" showLineNumbers
key_hex = "7d29459b4f15aa95736ac4a5a348a95ed9c7df9e745f2147572e59385df9918e15b73ffc160d0b27ba0b460c821752ff15f26b39e15bb6a9da3d"
cipher_hex = "0d5e2bb52c7ac6f9160da1dee63b9d36839fe9d41c0d44773446126c18b0d9e445ce7eba5e646509de593c42f85a16b321bb3f74d11eccfea737"

key = bytes.fromhex(key_hex)
cipher = bytes.fromhex(cipher_hex)

plaintext = bytes([c ^ k for c, k in zip(cipher, key)])

print("Decrypted flag:", plaintext.decode())
```

```
hacker@cryptography~one-time-pad:/$ python ~/script.py
Decrypted flag: pwn.college{Es4hZX6JhRe0chKTEIHjPyAFHin.dRzNzMDL4ITM0EzW}
```

&nbsp;

## One-time Pad tampering

### Source code
```py title="/challenge/dispatcher" showLineNumbers
#!/opt/pwn.college/python

from Crypto.Util.strxor import strxor

key = open("/challenge/.key", "rb").read()
ciphertext = strxor(b"sleep", key[:5])
```

```py title="/challenge/worker" showLineNumbers
#!/opt/pwn.college/python

from Crypto.Util.strxor import strxor

import time
import sys

key = open("/challenge/.key", "rb").read()

while line := sys.stdin.readline():
    if not line.startswith("TASK: "):
        continue
    data = bytes.fromhex(line.split()[1])
    cipher_len = min(len(data), len(key))
    plaintext = strxor(data[:cipher_len], key[:cipher_len])

    print(f"Hex of plaintext: {plaintext.hex()}")
    print(f"Received command: {plaintext}")
    if plaintext == b"sleep":
        print("Sleeping!")
        time.sleep(1)
    elif plaintext == b"flag!":
        print("Victory! Your flag:")
        print(open("/flag").read())
    else:
        print("Unknown command!")
```

The `/challenge/dispatcher` script gives us the cipher task in hex.

```
hacker@cryptography~one-time-pad-tampering:/$ /challenge/dispatcher 
TASK: 6286bb6ab5
```

If we provide this as input to /challenge/worker, it will first convert the hex string into bytes, then XOR it with the key to recover the plaintext, print the hex of the plaintext, and finally execute the resulting command.

```
hacker@cryptography~one-time-pad-tampering:/$ /challenge/worker 
TASK: 6286bb6ab5
Hex of plaintext: 736c656570
Received command: b'sleep'
Sleeping!
```

Let's script the solution.

```PY title="/challenge/script.py showLineNumbers
from Crypto.Util.strxor import strxor

# Known ciphertext
sleep_cipher_hex = "6286bb6ab5"
sleep_cipher = bytes.fromhex(sleep_cipher_hex)

# Known plaintext
known_plaintext_hex = "736c656570"
known_plaintext = bytes.fromhex(known_plaintext_hex)

# Or just use the following:
# known_plaintext = b"sleep"

# XOR to get key fragment
key_fragment = strxor(sleep_cipher, known_plaintext)

# Encrypt "flag!" with recovered key
command = b"flag!"
encrypted = strxor(command, key_fragment[:len(command)])

# Print encrypted hex
print(encrypted.hex())
```

```
hacker@cryptography~one-time-pad-tampering:/$ python ~/script.py
7786bf68e4
```

```
hacker@cryptography~one-time-pad-tampering:/$ /challenge/worker 
TASK: 7786bf68e4
Hex of plaintext: 666c616721
Received command: b'flag!'
Victory! Your flag:
pwn.college{sHPpXIo63DeFuiDt1Qm6aBHZXv_.QXzcTO2EDL4ITM0EzW}
```

&nbsp;

## Many-time Pad

### Source
```py title="/challenge/run" showLineNumbers
#!/opt/pwn.college/python

from Crypto.Random import get_random_bytes
from Crypto.Util.strxor import strxor

flag = open("/flag", "rb").read()

key = get_random_bytes(256)
ciphertext = strxor(flag, key[:len(flag)])

print(f"Flag Ciphertext (hex): {ciphertext.hex()}")

while True:
    plaintext = bytes.fromhex(input("Plaintext (hex): "))
    ciphertext = strxor(plaintext, key[:len(plaintext)])
    print(f"Ciphertext (hex): {ciphertext.hex()}")
```
