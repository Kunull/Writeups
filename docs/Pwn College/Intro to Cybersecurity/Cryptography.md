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

### Source code
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

The `/challenge/dispatcher` script gives us the cipher task in hex. This is the `sleep` task which was XOR'd with a secret key.

```
hacker@cryptography~one-time-pad-tampering:/$ /challenge/dispatcher 
TASK: 6286bb6ab5
```

If we provide this as input to `/challenge/worker`, it will first convert the hex string into bytes, then XOR it with the key to recover the plaintext, print the hex of the plaintext, and finally execute the resulting command.

```
hacker@cryptography~one-time-pad-tampering:/$ /challenge/worker 
TASK: 6286bb6ab5
Hex of plaintext: 736c656570
Received command: b'sleep'
Sleeping!
```

Let's write a script that determines the secret key and then gives us `flag!` as XOR'd with it.

```PY title="~/script.py" showLineNumbers
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

We can now provide this hex string to the `/challenge/worker`, and get the flag.

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

```
hacker@cryptography~many-time-pad:/$ /challenge/run
Flag Ciphertext (hex): a7cd55d0b293a2dd60c1d2ca382f0b3ccf14b9a500cc14a4f11faa2569f598a9da94a803cd064726b504e1f8e5752e46610d6ba2a15865968dac
Plaintext (hex): 
```

The challenge XORs the raw bytes of flag with the raw bytes of key, and then prints out the cipher flag in hex. 
It then asks for plaintext in hex format, which it converts into raw bytes.

We know that XOR is commutative.

```
flag ciphertext = flag plaintext ^ key 

flag plaintext = flag ciphertext ^ key
```

So, if we just give back the `Flag Ciphertext (hex)`, we would get back `Flag Plaintext (hex)`, which we simply have to convert into bytes.

```
hacker@cryptography~many-time-pad:/$ /challenge/run
Flag Ciphertext (hex): a7cd55d0b293a2dd60c1d2ca382f0b3ccf14b9a500cc14a4f11faa2569f598a9da94a803cd064726b504e1f8e5752e46610d6ba2a15865968dac
Plaintext (hex): a7cd55d0b293a2dd60c1d2ca382f0b3ccf14b9a500cc14a4f11faa2569f598a9da94a803cd064726b504e1f8e5752e46610d6ba2a15865968dac
Ciphertext (hex): 70776e2e636f6c6c6567657b4568673834787048625133486451307a6d6853705849763272716a2e64567a4e7a4d444c3449544d30457a577d0a
Plaintext (hex): 
```

```py
In [1]: flag = bytes.fromhex("70776e2e636f6c6c6567657b4568673834787048625133486451307a6d6853705849763272716a2e64567a4e7a4d444c3449544d30457a577d0a").decode()
   ...: print(flag)
pwn.college{Ehg84xpHbQ3HdQ0zmhSpXIv2rqj.dVzNzMDL4ITM0EzW}
```

&nbsp;

## AES

### Source code
```py title="/challenge/run" showLineNumbers
#!/opt/pwn.college/python

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

flag = open("/flag", "rb").read()

key = get_random_bytes(16)
cipher = AES.new(key=key, mode=AES.MODE_ECB)
ciphertext = cipher.encrypt(pad(flag, cipher.block_size))

print(f"AES Key (hex): {key.hex()}")
print(f"Flag Ciphertext (hex): {ciphertext.hex()}")
```

```
hacker@cryptography~aes:/$ /challenge/run 
AES Key (hex): 5ad958b13b3f977f623de7e7a4f57345
Flag Ciphertext (hex): 5792b94f7f852e4f87caaef91abbfdb724c3e6cd6010bffeefa06c33ae48e3975538da1de3e1f269c82eaaccad6456b24aef08329cf3e41b0bfaae5c82eb6ad2
```

We can simply decode the flag cipher using the `Crypto` library.

```py title="~/script.py" showLineNumber
#!/opt/pwn.college/python

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key_hex = "5ad958b13b3f977f623de7e7a4f57345"
key = bytes.fromhex(key_hex)

flag_cipher_hex = "5792b94f7f852e4f87caaef91abbfdb724c3e6cd6010bffeefa06c33ae48e3975538da1de3e1f269c82eaaccad6456b24aef08329cf3e41b0bfaae5c82eb6ad2"
flag_cipher = bytes.fromhex(flag_cipher_hex)

cipher = AES.new(key=key, mode=AES.MODE_ECB)
flag_plain = unpad(cipher.decrypt(flag_cipher), cipher.block_size)

print(flag_plain.decode())
```

```
hacker@cryptography~aes:/$ python ~/script.py
pwn.college{4mDLEMrwZcIDc7LzmbiYfdSlcYV.dZzNzMDL4ITM0EzW}
```

&nbsp;

## AES-ECB-CPA

### Source code
```py title="/challenge/run" showLineNumbers
#!/opt/pwn.college/python

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

flag = open("/flag", "rb").read()

key = get_random_bytes(16)
cipher = AES.new(key=key, mode=AES.MODE_ECB)

while True:
    print("Choose an action?")
    print("1. Encrypt chosen plaintext.")
    print("2. Encrypt part of the flag.")
    if (choice := int(input("Choice? "))) == 1:
        pt = input("Data? ").strip().encode()
    elif choice == 2:
        index = int(input("Index? "))
        length = int(input("Length? "))
        pt = flag[index:index+length]
    else:
        break

    ct = cipher.encrypt(pad(pt, cipher.block_size))
    print(f"Result: {ct.hex()}")
```

We have to build a lookup table of 1 byte encrypted outputs for every possible printable flag character (e.g., `a-zA-Z0-9_{}-`, etc.).

Then, For each flag index `i`:
- Use Option 2 to encrypt 1 byte: `flag[i]`.
- Compare with our table.
- Recover the flag character at that position.

```py title="~/script.py" showLineNumbers
#!/usr/bin/env python3

from pwn import *
import string

context.log_level = 'error'
p = process("/challenge/run")

def send_choice(choice):
    p.sendlineafter("Choice?", str(choice))

def encrypt_custom(pt: bytes):
    send_choice(1)
    p.sendlineafter("Data?", pt.decode())  # safe since we're only using printable
    p.recvuntil("Result: ")
    return bytes.fromhex(p.recvlineS().strip())

def encrypt_flag_byte(index):
    send_choice(2)
    p.sendlineafter("Index?", str(index))
    p.sendlineafter("Length?", "1")
    p.recvuntil("Result: ")
    return bytes.fromhex(p.recvlineS().strip())

# Only safe printable characters
charset = string.printable.strip()

# Build lookup
print("[*] Building lookup table of printable characters...")
lookup = {}
for ch in charset:
    ct = encrypt_custom(ch.encode())
    lookup[ct] = ch

# Add '}' manually (may be missed by .strip())
if '}' not in charset:
    ct = encrypt_custom(b'}')
    lookup[ct] = '}'

# Recover flag
flag = "pwn.college{"
i = len(flag)

while True:
    ct = encrypt_flag_byte(i)
    ch = lookup.get(ct)

    if not ch:
        flag += '?'
        print(f"[!] Unknown character at index {i}")
        break

    flag += ch
    print(f"[+] {flag}")

    if ch == '}':
        break

    i += 1

print(f"\n[*] Final flag: {flag}")
```

```
hacker@cryptography~aes-ecb-cpa:/$ python ~/script.py
[*] Building lookup table of printable characters...
/home/hacker/script.py:9: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.sendlineafter("Choice?", str(choice))
/nix/store/mjsfqdhpiqz69xczkhcycqmzs4x0xgk6-python3-3.12.8-env/lib/python3.12/site-packages/pwnlib/tubes/tube.py:841: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  res = self.recvuntil(delim, timeout=timeout)
/home/hacker/script.py:13: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.sendlineafter("Data?", pt.decode())  # safe since we're only using printable
/home/hacker/script.py:14: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.recvuntil("Result: ")
/home/hacker/script.py:19: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.sendlineafter("Index?", str(index))
/home/hacker/script.py:20: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.sendlineafter("Length?", "1")
/home/hacker/script.py:21: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.recvuntil("Result: ")
[+] pwn.college{0
[+] pwn.college{0G
[+] pwn.college{0GU
[+] pwn.college{0GUW
[+] pwn.college{0GUWK
[+] pwn.college{0GUWKp
[+] pwn.college{0GUWKpO
[+] pwn.college{0GUWKpOu
[+] pwn.college{0GUWKpOuO
[+] pwn.college{0GUWKpOuOD
[+] pwn.college{0GUWKpOuOD7
[+] pwn.college{0GUWKpOuOD7x
[+] pwn.college{0GUWKpOuOD7x0
[+] pwn.college{0GUWKpOuOD7x09
[+] pwn.college{0GUWKpOuOD7x095
[+] pwn.college{0GUWKpOuOD7x095Y
[+] pwn.college{0GUWKpOuOD7x095YQ
[+] pwn.college{0GUWKpOuOD7x095YQk
[+] pwn.college{0GUWKpOuOD7x095YQkH
[+] pwn.college{0GUWKpOuOD7x095YQkHY
[+] pwn.college{0GUWKpOuOD7x095YQkHYH
[+] pwn.college{0GUWKpOuOD7x095YQkHYHN
[+] pwn.college{0GUWKpOuOD7x095YQkHYHNX
[+] pwn.college{0GUWKpOuOD7x095YQkHYHNXF
[+] pwn.college{0GUWKpOuOD7x095YQkHYHNXF1
[+] pwn.college{0GUWKpOuOD7x095YQkHYHNXF10
[+] pwn.college{0GUWKpOuOD7x095YQkHYHNXF105
[+] pwn.college{0GUWKpOuOD7x095YQkHYHNXF105.
[+] pwn.college{0GUWKpOuOD7x095YQkHYHNXF105.d
[+] pwn.college{0GUWKpOuOD7x095YQkHYHNXF105.dF
[+] pwn.college{0GUWKpOuOD7x095YQkHYHNXF105.dFz
[+] pwn.college{0GUWKpOuOD7x095YQkHYHNXF105.dFzM
[+] pwn.college{0GUWKpOuOD7x095YQkHYHNXF105.dFzM3
[+] pwn.college{0GUWKpOuOD7x095YQkHYHNXF105.dFzM3k
[+] pwn.college{0GUWKpOuOD7x095YQkHYHNXF105.dFzM3kD
[+] pwn.college{0GUWKpOuOD7x095YQkHYHNXF105.dFzM3kDL
[+] pwn.college{0GUWKpOuOD7x095YQkHYHNXF105.dFzM3kDL4
[+] pwn.college{0GUWKpOuOD7x095YQkHYHNXF105.dFzM3kDL4I
[+] pwn.college{0GUWKpOuOD7x095YQkHYHNXF105.dFzM3kDL4IT
[+] pwn.college{0GUWKpOuOD7x095YQkHYHNXF105.dFzM3kDL4ITM
[+] pwn.college{0GUWKpOuOD7x095YQkHYHNXF105.dFzM3kDL4ITM0
[+] pwn.college{0GUWKpOuOD7x095YQkHYHNXF105.dFzM3kDL4ITM0E
[+] pwn.college{0GUWKpOuOD7x095YQkHYHNXF105.dFzM3kDL4ITM0Ez
[+] pwn.college{0GUWKpOuOD7x095YQkHYHNXF105.dFzM3kDL4ITM0EzW
[+] pwn.college{0GUWKpOuOD7x095YQkHYHNXF105.dFzM3kDL4ITM0EzW}

[*] Final flag: pwn.college{0GUWKpOuOD7x095YQkHYHNXF105.dFzM3kDL4ITM0EzW}
```

&nbsp;

## AES-ECB-CPA-HTTP

### Source code
```py title="/challenge/run" showLineNumbers
#!/opt/pwn.college/python

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

import tempfile
import sqlite3
import random
import flask
import os

app = flask.Flask(__name__)

class TemporaryDB:
    def __init__(self):
        self.db_file = tempfile.NamedTemporaryFile("x", suffix=".db")

    def execute(self, sql, parameters=()):
        connection = sqlite3.connect(self.db_file.name)
        connection.row_factory = sqlite3.Row
        cursor = connection.cursor()
        result = cursor.execute(sql, parameters)
        connection.commit()
        return result

key = get_random_bytes(16)
cipher = AES.new(key=key, mode=AES.MODE_ECB)

db = TemporaryDB()
# https://www.sqlite.org/lang_createtable.html
db.execute("""CREATE TABLE secrets AS SELECT ? AS flag""", [open("/flag").read()])

@app.route("/", methods=["GET"])                                                                                                             
def challenge_get():
    query = flask.request.args.get("query") or "'A'"

    try:
        sql = f'SELECT {query} FROM secrets'
        print(f"DEBUG: {sql=}")
        pt = db.execute(sql).fetchone()[0]
    except sqlite3.Error as e:
        flask.abort(500, f"Query: {query}\nError: {e}")
    except TypeError:
        # no records found
        pt = "A"

    ct = cipher.encrypt(pad(pt.encode(), cipher.block_size))

    return f"""
        <html><body>Welcome to pwn.secret!
        <form>SELECT <input type=text name=query value='{query}'> FROM secrets<br><input type=submit value=Submit></form>
        <hr>
        <b>Query:</b> <pre>{sql}</pre><br>
        <b>Results:</b><pre>{ct.hex()}</pre>
        </body></html>
    """

app.secret_key = os.urandom(8)
app.config['SERVER_NAME'] = f"challenge.localhost:80"
app.run("challenge.localhost", 80)
```

```py title="~/script" showLineNumbers
#!/usr/bin/env python3

import requests
import string

url = "http://challenge.localhost/"

# Safer charset: avoids single quote, backslash, etc.
charset = string.printable.strip()

print("[*] Building lookup table...")
lookup = {}

for ch in charset:
    try:
        # Avoid breaking the SQL string with unsafe chars
        query_param = f"'{ch}'"
        r = requests.get(url, params={"query": query_param})

        parts = r.text.split("<pre>")
        if len(parts) < 3:
            print(f"[!] Skipping char: {repr(ch)} — malformed response")
            continue

        ct = parts[2].split("</pre>")[0].strip()
        lookup[ct] = ch
    except Exception as e:
        print(f"[!] Error with char {repr(ch)}: {e}")

print(f"[+] Lookup table built with {len(lookup)} entries")

# Step 2: Extract flag
flag = "pwn.college{"
i = len(flag) + 1

while True:
    try:
        r = requests.get(url, params={"query": f"substr(flag,{i},1)"})
        parts = r.text.split("<pre>")
        if len(parts) < 3:
            print(f"[!] Failed to extract flag[{i}] — malformed response")
            break

        ct = parts[2].split("</pre>")[0].strip()
        ch = lookup.get(ct)

        if not ch:
            print(f"[!] Unknown character at position {i}, ciphertext: {ct}")
            break

        flag += ch
        print(f"[+] {flag}")

        if ch == "}":
            break

        i += 1

    except Exception as e:
        print(f"[!] Error on index {i}: {e}")
        break

print(f"\n[*] Final flag: {flag}")
```

```
hacker@cryptography~aes-ecb-cpa-http:/$ python ~/script.py
[*] Building lookup table...
[+] Lookup table built with 87 entries
[+] pwn.college{c
[+] pwn.college{cM
[+] pwn.college{cMH
[+] pwn.college{cMHT
[+] pwn.college{cMHTy
[+] pwn.college{cMHTyv
[+] pwn.college{cMHTyvr
[+] pwn.college{cMHTyvrP
[+] pwn.college{cMHTyvrP_
[+] pwn.college{cMHTyvrP_6
[+] pwn.college{cMHTyvrP_6V
[+] pwn.college{cMHTyvrP_6Vg
[+] pwn.college{cMHTyvrP_6VgT
[+] pwn.college{cMHTyvrP_6VgTc
[+] pwn.college{cMHTyvrP_6VgTc5
[+] pwn.college{cMHTyvrP_6VgTc5N
[+] pwn.college{cMHTyvrP_6VgTc5NU
[+] pwn.college{cMHTyvrP_6VgTc5NUM
[+] pwn.college{cMHTyvrP_6VgTc5NUMc
[+] pwn.college{cMHTyvrP_6VgTc5NUMc3
[+] pwn.college{cMHTyvrP_6VgTc5NUMc3G
[+] pwn.college{cMHTyvrP_6VgTc5NUMc3Gd
[+] pwn.college{cMHTyvrP_6VgTc5NUMc3Gdn
[+] pwn.college{cMHTyvrP_6VgTc5NUMc3Gdns
[+] pwn.college{cMHTyvrP_6VgTc5NUMc3Gdnsj
[+] pwn.college{cMHTyvrP_6VgTc5NUMc3Gdnsj8
[+] pwn.college{cMHTyvrP_6VgTc5NUMc3Gdnsj8x
[+] pwn.college{cMHTyvrP_6VgTc5NUMc3Gdnsj8x.
[+] pwn.college{cMHTyvrP_6VgTc5NUMc3Gdnsj8x.Q
[+] pwn.college{cMHTyvrP_6VgTc5NUMc3Gdnsj8x.QX
[+] pwn.college{cMHTyvrP_6VgTc5NUMc3Gdnsj8x.QX3
[+] pwn.college{cMHTyvrP_6VgTc5NUMc3Gdnsj8x.QX3E
[+] pwn.college{cMHTyvrP_6VgTc5NUMc3Gdnsj8x.QX3Ez
[+] pwn.college{cMHTyvrP_6VgTc5NUMc3Gdnsj8x.QX3EzM
[+] pwn.college{cMHTyvrP_6VgTc5NUMc3Gdnsj8x.QX3EzM2
[+] pwn.college{cMHTyvrP_6VgTc5NUMc3Gdnsj8x.QX3EzM2E
[+] pwn.college{cMHTyvrP_6VgTc5NUMc3Gdnsj8x.QX3EzM2ED
[+] pwn.college{cMHTyvrP_6VgTc5NUMc3Gdnsj8x.QX3EzM2EDL
[+] pwn.college{cMHTyvrP_6VgTc5NUMc3Gdnsj8x.QX3EzM2EDL4
[+] pwn.college{cMHTyvrP_6VgTc5NUMc3Gdnsj8x.QX3EzM2EDL4I
[+] pwn.college{cMHTyvrP_6VgTc5NUMc3Gdnsj8x.QX3EzM2EDL4IT
[+] pwn.college{cMHTyvrP_6VgTc5NUMc3Gdnsj8x.QX3EzM2EDL4ITM
[+] pwn.college{cMHTyvrP_6VgTc5NUMc3Gdnsj8x.QX3EzM2EDL4ITM0
[+] pwn.college{cMHTyvrP_6VgTc5NUMc3Gdnsj8x.QX3EzM2EDL4ITM0E
[+] pwn.college{cMHTyvrP_6VgTc5NUMc3Gdnsj8x.QX3EzM2EDL4ITM0Ez
[+] pwn.college{cMHTyvrP_6VgTc5NUMc3Gdnsj8x.QX3EzM2EDL4ITM0EzW
[+] pwn.college{cMHTyvrP_6VgTc5NUMc3Gdnsj8x.QX3EzM2EDL4ITM0EzW}

[*] Final flag: pwn.college{cMHTyvrP_6VgTc5NUMc3Gdnsj8x.QX3EzM2EDL4ITM0EzW}
```

## AES-ECB-CPA-HTTP (base64) 

### Source code
```py title="/challenge/run" showLineNumbers
#!/opt/pwn.college/python

from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

import tempfile
import sqlite3
import random
import flask
import os

app = flask.Flask(__name__)

class TemporaryDB:
    def __init__(self):
        self.db_file = tempfile.NamedTemporaryFile("x", suffix=".db")

    def execute(self, sql, parameters=()):
        connection = sqlite3.connect(self.db_file.name)
        connection.row_factory = sqlite3.Row
        cursor = connection.cursor()
        result = cursor.execute(sql, parameters)
        connection.commit()
        return result

key = get_random_bytes(16)
cipher = AES.new(key=key, mode=AES.MODE_ECB)

db = TemporaryDB()
# https://www.sqlite.org/lang_createtable.html
db.execute("""CREATE TABLE secrets AS SELECT ? AS flag""", [open("/flag").read()])

@app.route("/", methods=["GET"])                                                                                                             
def challenge_get():
    query = flask.request.args.get("query") or "'A'"

    try:
        sql = f'SELECT {query} FROM secrets'
        print(f"DEBUG: {sql=}")
        pt = db.execute(sql).fetchone()[0]
    except sqlite3.Error as e:
        flask.abort(500, f"Query: {query}\nError: {e}")
    except TypeError:
        # no records found
        pt = "A"

    ct = cipher.encrypt(pad(pt.encode(), cipher.block_size))

    return f"""
        <html><body>Welcome to pwn.secret!
        <form>SELECT <input type=text name=query value='{query}'> FROM secrets<br><input type=submit value=Submit></form>
        <hr>
        <b>Query:</b> <pre>{sql}</pre><br>
        <b>Results:</b><pre>{b64encode(ct).decode()}</pre>
        </body></html>
    """

app.secret_key = os.urandom(8)
app.config['SERVER_NAME'] = f"challenge.localhost:80"
app.run("challenge.localhost", 80)
```

This time the output is given to us after Base64 encoding.
We just need to modify the last level's script slightly.

```py title="~/script.py" showLineNumbers
#!/usr/bin/env python3

import requests
import string
import base64

url = "http://challenge.localhost/"

# Safer charset: avoids single quote, backslash, etc.
safe_charset = string.printable.strip()

print("[*] Building lookup table...")
lookup = {}

for ch in safe_charset:
    try:
        query_param = f"'{ch}'"
        r = requests.get(url, params={"query": query_param})

        parts = r.text.split("<pre>")
        if len(parts) < 3:
            print(f"[!] Skipping char: {repr(ch)} — malformed response")
            continue

        ct_b64 = parts[2].split("</pre>")[0].strip()
        ct = base64.b64decode(ct_b64)
        lookup[ct] = ch
    except Exception as e:
        print(f"[!] Error with char {repr(ch)}: {e}")

print(f"[+] Lookup table built with {len(lookup)} entries")

# Step 2: Extract flag
flag = "pwn.college{"
i = len(flag) + 1

while True:
    try:
        r = requests.get(url, params={"query": f"substr(flag,{i},1)"})
        parts = r.text.split("<pre>")
        if len(parts) < 3:
            print(f"[!] Failed to extract flag[{i}] — malformed response")
            break

        ct_b64 = parts[2].split("</pre>")[0].strip()
        ct = base64.b64decode(ct_b64)
        ch = lookup.get(ct)

        if not ch:
            print(f"[!] Unknown character at position {i}, ciphertext: {ct_b64}")
            break

        flag += ch
        print(f"[+] {flag}")

        if ch == "}":
            break

        i += 1

    except Exception as e:
        print(f"[!] Error on index {i}: {e}")
        break

print(f"\n[*] Final flag: {flag}")
```

```
hacker@cryptography~aes-ecb-cpa-http-base64:/$ python ~/script.py
[*] Building lookup table...
[!] Skipping char: "'" — malformed response
[+] Lookup table built with 93 entries
[+] pwn.college{c
[+] pwn.college{c5
[+] pwn.college{c5U
[+] pwn.college{c5U6
[+] pwn.college{c5U68
[+] pwn.college{c5U68P
[+] pwn.college{c5U68PE
[+] pwn.college{c5U68PEU
[+] pwn.college{c5U68PEUt
[+] pwn.college{c5U68PEUtD
[+] pwn.college{c5U68PEUtD5
[+] pwn.college{c5U68PEUtD57
[+] pwn.college{c5U68PEUtD57I
[+] pwn.college{c5U68PEUtD57I9
[+] pwn.college{c5U68PEUtD57I9r
[+] pwn.college{c5U68PEUtD57I9rE
[+] pwn.college{c5U68PEUtD57I9rEW
[+] pwn.college{c5U68PEUtD57I9rEW5
[+] pwn.college{c5U68PEUtD57I9rEW5l
[+] pwn.college{c5U68PEUtD57I9rEW5ly
[+] pwn.college{c5U68PEUtD57I9rEW5lyj
[+] pwn.college{c5U68PEUtD57I9rEW5lyjw
[+] pwn.college{c5U68PEUtD57I9rEW5lyjwk
[+] pwn.college{c5U68PEUtD57I9rEW5lyjwk9
[+] pwn.college{c5U68PEUtD57I9rEW5lyjwk9B
[+] pwn.college{c5U68PEUtD57I9rEW5lyjwk9B_
[+] pwn.college{c5U68PEUtD57I9rEW5lyjwk9B_8
[+] pwn.college{c5U68PEUtD57I9rEW5lyjwk9B_8.
[+] pwn.college{c5U68PEUtD57I9rEW5lyjwk9B_8.d
[+] pwn.college{c5U68PEUtD57I9rEW5lyjwk9B_8.dJ
[+] pwn.college{c5U68PEUtD57I9rEW5lyjwk9B_8.dJz
[+] pwn.college{c5U68PEUtD57I9rEW5lyjwk9B_8.dJzM
[+] pwn.college{c5U68PEUtD57I9rEW5lyjwk9B_8.dJzM3
[+] pwn.college{c5U68PEUtD57I9rEW5lyjwk9B_8.dJzM3k
[+] pwn.college{c5U68PEUtD57I9rEW5lyjwk9B_8.dJzM3kD
[+] pwn.college{c5U68PEUtD57I9rEW5lyjwk9B_8.dJzM3kDL
[+] pwn.college{c5U68PEUtD57I9rEW5lyjwk9B_8.dJzM3kDL4
[+] pwn.college{c5U68PEUtD57I9rEW5lyjwk9B_8.dJzM3kDL4I
[+] pwn.college{c5U68PEUtD57I9rEW5lyjwk9B_8.dJzM3kDL4IT
[+] pwn.college{c5U68PEUtD57I9rEW5lyjwk9B_8.dJzM3kDL4ITM
[+] pwn.college{c5U68PEUtD57I9rEW5lyjwk9B_8.dJzM3kDL4ITM0
[+] pwn.college{c5U68PEUtD57I9rEW5lyjwk9B_8.dJzM3kDL4ITM0E
[+] pwn.college{c5U68PEUtD57I9rEW5lyjwk9B_8.dJzM3kDL4ITM0Ez
[+] pwn.college{c5U68PEUtD57I9rEW5lyjwk9B_8.dJzM3kDL4ITM0EzW
[+] pwn.college{c5U68PEUtD57I9rEW5lyjwk9B_8.dJzM3kDL4ITM0EzW}

[*] Final flag: pwn.college{c5U68PEUtD57I9rEW5lyjwk9B_8.dJzM3kDL4ITM0EzW}
```

&nbsp;

## AES-ECB-CPA-Suffix

### Source code

```py title="/challenge/run" showLineNumbers
#!/opt/pwn.college/python

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

flag = open("/flag", "rb").read().strip()

key = get_random_bytes(16)
cipher = AES.new(key=key, mode=AES.MODE_ECB)

while True:
    print("Choose an action?")
    print("1. Encrypt chosen plaintext.")
    print("2. Encrypt the tail end of the flag.")
    if (choice := int(input("Choice? "))) == 1:
        pt = input("Data? ").strip().encode()
    elif choice == 2:
        length = int(input("Length? "))
        pt = flag[-length:]
    else:
        break

    ct = cipher.encrypt(pad(pt, cipher.block_size))
    print(f"Result: {ct.hex()}")
```

In this level, we cannot choose the index, only the length from the end of the flag.

That is no problem however, because we can simply fuzz out the last (`n`), (`n-1`,`n`), (`n-2`,`n-1`,`n`) character sets by creating the lookup tables iteratively.

```
Lookup table for flag[-1] (last character):
┌─────┬────────────────────────────────────┐
│  a  ┆  481aca4f6c7b13a7d16c05af68e430ad  │ 
│  b  ┆  43ddaee5346068b3d6b5abd2432444b1  │
....
│  z  ┆  598f9bbf4d450e2391236aa9629ffdf7  │
└─────┴────────────────────────────────────┘

We find out that flag[-1] character is "b".

Lookup table for flag[-2:] (last two characters):
┌──────┬────────────────────────────────────┐
│  ab  ┆  a174e55dff9609ca8497354bc1ccbdcc  │ 
│  bb  ┆  ccdf8d11170a497e8139f8c35643e7e4  │
....
│  zb  ┆  9afbf086b650105c646b5a7cd8642e50  │
└──────┴────────────────────────────────────┘

We then repeat this step for flag[-3:], flag[-4:].....
```

```py title="~/script.py" showLineNumbers
#!/usr/bin/env python3

from pwn import *
import string

context.log_level = 'error'
p = process("/challenge/run")

# You must use printable ASCII characters due to .encode() in challenge
CHARSET = string.printable.strip().encode()

def send_choice(choice):
    p.sendlineafter(b"Choice?", str(choice).encode())

def encrypt_custom(pt: bytes) -> bytes:
    """
    Encrypt arbitrary plaintext using Option 1.
    Must be valid UTF-8 input, because the challenge uses input().encode().
    """
    send_choice(1)
    try:
        plaintext = pt.decode('utf-8')
    except UnicodeDecodeError:
        return b''  # skip non-UTF-8 bytes
    p.sendlineafter(b"Data?", plaintext.encode())
    p.recvuntil(b"Result: ")
    return bytes.fromhex(p.recvlineS().strip())

def encrypt_flag_tail(length: int) -> bytes:
    send_choice(2)
    p.sendlineafter(b"Length?", str(length).encode())
    p.recvuntil(b"Result: ")
    return bytes.fromhex(p.recvlineS().strip())

# Start with last char of flag
recovered = b""
print("[*] Recovering flag from the end...")

max_len = 64  # reasonable max
while len(recovered) < max_len:
    suffix_len = len(recovered) + 1
    target_ct = encrypt_flag_tail(suffix_len)

    found = False
    for ch in CHARSET:
        guess = bytes([ch]) + recovered
        ct = encrypt_custom(guess)
        if ct == target_ct:
            recovered = bytes([ch]) + recovered
            print(f"[+] Flag so far: {recovered.decode(errors='replace')}")
            found = True
            break

    if not found:
        print(f"[!] Could not determine byte at position -{suffix_len}")
        break

    if recovered.startswith(b"pwn.college{"):
        print(f"\n[*] Final flag: {recovered.decode(errors='replace')}")
        break
```

```
hacker@cryptography~aes-ecb-cpa-suffix:/$ python ~/script.py
[*] Recovering flag from the end...
[+] Flag so far: }
[+] Flag so far: W}
[+] Flag so far: zW}
[+] Flag so far: EzW}
[+] Flag so far: 0EzW}
[+] Flag so far: M0EzW}
[+] Flag so far: TM0EzW}
[+] Flag so far: ITM0EzW}
[+] Flag so far: 4ITM0EzW}
[+] Flag so far: L4ITM0EzW}
[+] Flag so far: DL4ITM0EzW}
[+] Flag so far: kDL4ITM0EzW}
[+] Flag so far: 3kDL4ITM0EzW}
[+] Flag so far: M3kDL4ITM0EzW}
[+] Flag so far: zM3kDL4ITM0EzW}
[+] Flag so far: NzM3kDL4ITM0EzW}
[+] Flag so far: dNzM3kDL4ITM0EzW}
[+] Flag so far: .dNzM3kDL4ITM0EzW}
[+] Flag so far: K.dNzM3kDL4ITM0EzW}
[+] Flag so far: YK.dNzM3kDL4ITM0EzW}
[+] Flag so far: tYK.dNzM3kDL4ITM0EzW}
[+] Flag so far: ItYK.dNzM3kDL4ITM0EzW}
[+] Flag so far: vItYK.dNzM3kDL4ITM0EzW}
[+] Flag so far: rvItYK.dNzM3kDL4ITM0EzW}
[+] Flag so far: srvItYK.dNzM3kDL4ITM0EzW}
[+] Flag so far: TsrvItYK.dNzM3kDL4ITM0EzW}
[+] Flag so far: WTsrvItYK.dNzM3kDL4ITM0EzW}
[+] Flag so far: 6WTsrvItYK.dNzM3kDL4ITM0EzW}
[+] Flag so far: F6WTsrvItYK.dNzM3kDL4ITM0EzW}
[+] Flag so far: MF6WTsrvItYK.dNzM3kDL4ITM0EzW}
[+] Flag so far: uMF6WTsrvItYK.dNzM3kDL4ITM0EzW}
[+] Flag so far: 3uMF6WTsrvItYK.dNzM3kDL4ITM0EzW}
[+] Flag so far: M3uMF6WTsrvItYK.dNzM3kDL4ITM0EzW}
[+] Flag so far: cM3uMF6WTsrvItYK.dNzM3kDL4ITM0EzW}
[+] Flag so far: YcM3uMF6WTsrvItYK.dNzM3kDL4ITM0EzW}
[+] Flag so far: kYcM3uMF6WTsrvItYK.dNzM3kDL4ITM0EzW}
[+] Flag so far: OkYcM3uMF6WTsrvItYK.dNzM3kDL4ITM0EzW}
[+] Flag so far: ZOkYcM3uMF6WTsrvItYK.dNzM3kDL4ITM0EzW}
[+] Flag so far: WZOkYcM3uMF6WTsrvItYK.dNzM3kDL4ITM0EzW}
[+] Flag so far: 3WZOkYcM3uMF6WTsrvItYK.dNzM3kDL4ITM0EzW}
[+] Flag so far: 43WZOkYcM3uMF6WTsrvItYK.dNzM3kDL4ITM0EzW}
[+] Flag so far: V43WZOkYcM3uMF6WTsrvItYK.dNzM3kDL4ITM0EzW}
[+] Flag so far: VV43WZOkYcM3uMF6WTsrvItYK.dNzM3kDL4ITM0EzW}
[+] Flag so far: oVV43WZOkYcM3uMF6WTsrvItYK.dNzM3kDL4ITM0EzW}
[+] Flag so far: soVV43WZOkYcM3uMF6WTsrvItYK.dNzM3kDL4ITM0EzW}
[+] Flag so far: {soVV43WZOkYcM3uMF6WTsrvItYK.dNzM3kDL4ITM0EzW}
[+] Flag so far: e{soVV43WZOkYcM3uMF6WTsrvItYK.dNzM3kDL4ITM0EzW}
[+] Flag so far: ge{soVV43WZOkYcM3uMF6WTsrvItYK.dNzM3kDL4ITM0EzW}
[+] Flag so far: ege{soVV43WZOkYcM3uMF6WTsrvItYK.dNzM3kDL4ITM0EzW}
[+] Flag so far: lege{soVV43WZOkYcM3uMF6WTsrvItYK.dNzM3kDL4ITM0EzW}
[+] Flag so far: llege{soVV43WZOkYcM3uMF6WTsrvItYK.dNzM3kDL4ITM0EzW}
[+] Flag so far: ollege{soVV43WZOkYcM3uMF6WTsrvItYK.dNzM3kDL4ITM0EzW}
[+] Flag so far: college{soVV43WZOkYcM3uMF6WTsrvItYK.dNzM3kDL4ITM0EzW}
[+] Flag so far: .college{soVV43WZOkYcM3uMF6WTsrvItYK.dNzM3kDL4ITM0EzW}
[+] Flag so far: n.college{soVV43WZOkYcM3uMF6WTsrvItYK.dNzM3kDL4ITM0EzW}
[+] Flag so far: wn.college{soVV43WZOkYcM3uMF6WTsrvItYK.dNzM3kDL4ITM0EzW}
[+] Flag so far: pwn.college{soVV43WZOkYcM3uMF6WTsrvItYK.dNzM3kDL4ITM0EzW}

[*] Final flag: pwn.college{soVV43WZOkYcM3uMF6WTsrvItYK.dNzM3kDL4ITM0EzW}
```
