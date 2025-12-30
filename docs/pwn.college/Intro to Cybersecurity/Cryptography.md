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

### Source code

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

```py title="~/script.py" showLineNumbers
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

&nbsp;

## AES-ECB-CPA-Prefix

### Source code

```py title="/challenge/run" showLineNumbers
#!/opt/pwn.college/python

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

flag = open("/flag", "rb").read().strip()

key = get_random_bytes(16)
cipher = AES.new(key=key, mode=AES.MODE_ECB)

for n in range(31337):
    print("")
    print("Choose an action?")
    print("1. Encrypt chosen plaintext.")
    print("2. Prepend something to the flag.")
    if (choice := int(input("Choice? "))) == 1:
        pt = input("Data? ").strip().encode()
    elif choice == 2:
        pt = input("Data? ").strip().encode() + flag
    else:
        break

    padded_pt = pad(pt, cipher.block_size) if len(pt)%cipher.block_size else pt
    ct = cipher.encrypt(padded_pt)
    print(f"Result: {ct.hex()}")

    if n == 0:
        print("I'm here to help!")
        print("For the first 10, I will split them into blocks for you!")
        print("After this, you'll have to split them yourself.")
    if n < 10:
        print(f"# of blocks: {len(ct)//16}.")
        for n,i in enumerate(range(0, len(ct)-15, 16), start=1):
            print(f"Block {n}: {ct[i:i+16].hex()}")
```

### Forward decoding

```
hacker@cryptography~aes-ecb-cpa-prefix:/$ /challenge/run 

Choose an action?
1. Encrypt chosen plaintext.
2. Prepend something to the flag.
Choice? 2
Data? AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Result: fb4907570e3c905e3939d7e4d1940408fb4907570e3c905e3939d7e4d1940408fb4907570e3c905e3939d7e4d1940408fb4907570e3c905e3939d7e4d194040857bcc8ab04c42d5dc5a378454174980c2b38812fc0041a65592e97d34c219a4665b7acc96e86f9c3e3a309d7292bb22d8e4ac0109de872c80768789854af6ead8e9fb7c0324b57a107d89f4e62d3d3f6
I'm here to help!
For the first 10, I will split them into blocks for you!
After this, you'll have to split them yourself.
# of blocks: 9.
Block 1: fb4907570e3c905e3939d7e4d1940408
Block 2: fb4907570e3c905e3939d7e4d1940408
Block 3: fb4907570e3c905e3939d7e4d1940408
Block 4: fb4907570e3c905e3939d7e4d1940408
Block 5: 57bcc8ab04c42d5dc5a378454174980c
Block 6: 2b38812fc0041a65592e97d34c219a46
Block 7: 65b7acc96e86f9c3e3a309d7292bb22d
Block 8: 8e4ac0109de872c80768789854af6ead
Block 9: 8e9fb7c0324b57a107d89f4e62d3d3f6

Choose an action?
1. Encrypt chosen plaintext.
2. Prepend something to the flag.
Choice? 2
Data? AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Result: fb4907570e3c905e3939d7e4d1940408fb4907570e3c905e3939d7e4d1940408fb4907570e3c905e3939d7e4d1940408fb4907570e3c905e3939d7e4d1940408fb4907570e3c905e3939d7e4d1940408b0b8d070502b3008e5bb3e25ec35678bc5a8b3fdb9b3151b19b9844b5b9dbb91ab2c0fed38c63b77df08f03eea6e0f22083365c81f90e552a8859b9d526022c7
# of blocks: 9.
Block 1: fb4907570e3c905e3939d7e4d1940408
Block 2: fb4907570e3c905e3939d7e4d1940408
Block 3: fb4907570e3c905e3939d7e4d1940408
Block 4: fb4907570e3c905e3939d7e4d1940408
Block 5: fb4907570e3c905e3939d7e4d1940408
Block 6: b0b8d070502b3008e5bb3e25ec35678b
Block 7: c5a8b3fdb9b3151b19b9844b5b9dbb91
Block 8: ab2c0fed38c63b77df08f03eea6e0f22
Block 9: 083365c81f90e552a8859b9d526022c7
```

It takes 80 bytes of padding for us to get fully controlled blocks. We would use the 5th block to decode the flag.
For our lookup table we would utilize the option of encrypting our chosen plaintext. 

```
## flag[0] (first character)
5th block:
┌────────────────────────────────────┐
│  5d14951d3280c83e9d3fa1af613f3534  │ ==> "AAAAAAAAAAAAAAA" + flag[0]
└────────────────────────────────────┘
Custom block:
┌────────────────────────────────────┐
│  5d14951d3280c83e9d3fa1af613f3534  │ ==> "AAAAAAAAAAAAAAA" + "p"
└────────────────────────────────────┘

We find out that flag[0] character is "p".

## flag[:2] (first two characters):
5th block:
┌────────────────────────────────────┐
│  2d6277ea4428df717ed338299c87cfff  │ ==> "AAAAAAAAAAAAAA" + flag[:2]
└────────────────────────────────────┘
Custom block:
┌────────────────────────────────────┐
│  2d6277ea4428df717ed338299c87cfff  │ ==> "AAAAAAAAAAAAAA" + "pw"
└────────────────────────────────────┘

We then repeat this step for flag[:3], flag[:4].....
```

```py title="~/script.py" showLineNumbers
#!/usr/bin/env python3

from pwn import *
import string

context.log_level = 'error'
p = process("/challenge/run")

CHARSET = string.printable.strip().encode()
BLOCK_SIZE = 16
TARGET_BLOCK_NUM = 5  # zero-indexed = block 4
TOTAL_PAD = TARGET_BLOCK_NUM * BLOCK_SIZE  # 80 bytes = prefix + flag
MAX_FLAG_LEN = 64

def send_choice(choice):
    p.sendline(str(choice).encode())

def encrypt_custom(pt: bytes) -> bytes:
    """
    Encrypt attacker-controlled input (Option 1)
    """
    send_choice(1)
    try:
        s = pt.decode('utf-8')
    except UnicodeDecodeError:
        return b''
    p.sendline(s.encode())
    p.recvuntil(b"Result: ")
    return p.recvline().strip()

def encrypt_prepended_flag(prefix: bytes) -> bytes:
    """
    Encrypt prefix + flag (Option 2)
    """
    send_choice(2)
    p.sendline(prefix.decode('utf-8', errors='ignore').encode())
    p.recvuntil(b"Result: ")
    return p.recvline().strip()

def get_block(ct: bytes, n: int) -> bytes:
    """
    Return the nth 16-byte block (1-indexed).
    """
    start = (n - 1) * BLOCK_SIZE * 2
    end = start + BLOCK_SIZE * 2
    return ct[start:end]

recovered = b""
print("[*] Recovering flag from the start...")

while len(recovered) < MAX_FLAG_LEN:
    pad_len = TOTAL_PAD - (len(recovered) + 1)
    prefix = b"A" * pad_len

    # Get target block with unknown byte at end
    target_ct = encrypt_prepended_flag(prefix)
    target_block = get_block(target_ct, TARGET_BLOCK_NUM)

    # Build lookup table
    lookup = {}
    for ch in CHARSET:
        guess = prefix + recovered + bytes([ch])
        ct = encrypt_custom(guess)
        guess_block = get_block(ct, TARGET_BLOCK_NUM)
        lookup[guess_block] = ch

    if target_block in lookup:
        recovered += bytes([lookup[target_block]])
        print(f"[+] Flag so far: {recovered.decode(errors='replace')}")
        if recovered.endswith(b"}"):
            print(f"\n[*] Final flag: {recovered.decode(errors='replace')}")
            break
    else:
        print("[!] Failed to match block — maybe wrong block index or alignment.")
        break
```

```
hacker@cryptography~aes-ecb-cpa-prefix:/$ python ~/script.py
[*] Recovering flag from the start...
[+] Flag so far: p
[+] Flag so far: pw
[+] Flag so far: pwn
[+] Flag so far: pwn.
[+] Flag so far: pwn.c
[+] Flag so far: pwn.co
[+] Flag so far: pwn.col
[+] Flag so far: pwn.coll
[+] Flag so far: pwn.colle
[+] Flag so far: pwn.colleg
[+] Flag so far: pwn.college
[+] Flag so far: pwn.college{
[+] Flag so far: pwn.college{0
[+] Flag so far: pwn.college{0H
[+] Flag so far: pwn.college{0H2
[+] Flag so far: pwn.college{0H2p
[+] Flag so far: pwn.college{0H2pG
[+] Flag so far: pwn.college{0H2pGi
[+] Flag so far: pwn.college{0H2pGid
[+] Flag so far: pwn.college{0H2pGida
[+] Flag so far: pwn.college{0H2pGida-
[+] Flag so far: pwn.college{0H2pGida-V
[+] Flag so far: pwn.college{0H2pGida-VG
[+] Flag so far: pwn.college{0H2pGida-VGi
[+] Flag so far: pwn.college{0H2pGida-VGiW
[+] Flag so far: pwn.college{0H2pGida-VGiWY
[+] Flag so far: pwn.college{0H2pGida-VGiWY7
[+] Flag so far: pwn.college{0H2pGida-VGiWY7S
[+] Flag so far: pwn.college{0H2pGida-VGiWY7St
[+] Flag so far: pwn.college{0H2pGida-VGiWY7Stl
[+] Flag so far: pwn.college{0H2pGida-VGiWY7StlP
[+] Flag so far: pwn.college{0H2pGida-VGiWY7StlP2
[+] Flag so far: pwn.college{0H2pGida-VGiWY7StlP2j
[+] Flag so far: pwn.college{0H2pGida-VGiWY7StlP2jm
[+] Flag so far: pwn.college{0H2pGida-VGiWY7StlP2jml
[+] Flag so far: pwn.college{0H2pGida-VGiWY7StlP2jmld
[+] Flag so far: pwn.college{0H2pGida-VGiWY7StlP2jmldE
[+] Flag so far: pwn.college{0H2pGida-VGiWY7StlP2jmldEf
[+] Flag so far: pwn.college{0H2pGida-VGiWY7StlP2jmldEfK
[+] Flag so far: pwn.college{0H2pGida-VGiWY7StlP2jmldEfK.
[+] Flag so far: pwn.college{0H2pGida-VGiWY7StlP2jmldEfK.d
[+] Flag so far: pwn.college{0H2pGida-VGiWY7StlP2jmldEfK.dR
[+] Flag so far: pwn.college{0H2pGida-VGiWY7StlP2jmldEfK.dRz
[+] Flag so far: pwn.college{0H2pGida-VGiWY7StlP2jmldEfK.dRzM
[+] Flag so far: pwn.college{0H2pGida-VGiWY7StlP2jmldEfK.dRzM3
[+] Flag so far: pwn.college{0H2pGida-VGiWY7StlP2jmldEfK.dRzM3k
[+] Flag so far: pwn.college{0H2pGida-VGiWY7StlP2jmldEfK.dRzM3kD
[+] Flag so far: pwn.college{0H2pGida-VGiWY7StlP2jmldEfK.dRzM3kDL
[+] Flag so far: pwn.college{0H2pGida-VGiWY7StlP2jmldEfK.dRzM3kDL4
[+] Flag so far: pwn.college{0H2pGida-VGiWY7StlP2jmldEfK.dRzM3kDL4I
[+] Flag so far: pwn.college{0H2pGida-VGiWY7StlP2jmldEfK.dRzM3kDL4IT
[+] Flag so far: pwn.college{0H2pGida-VGiWY7StlP2jmldEfK.dRzM3kDL4ITM
[+] Flag so far: pwn.college{0H2pGida-VGiWY7StlP2jmldEfK.dRzM3kDL4ITM0
[+] Flag so far: pwn.college{0H2pGida-VGiWY7StlP2jmldEfK.dRzM3kDL4ITM0E
[+] Flag so far: pwn.college{0H2pGida-VGiWY7StlP2jmldEfK.dRzM3kDL4ITM0Ez
[+] Flag so far: pwn.college{0H2pGida-VGiWY7StlP2jmldEfK.dRzM3kDL4ITM0EzW
[+] Flag so far: pwn.college{0H2pGida-VGiWY7StlP2jmldEfK.dRzM3kDL4ITM0EzW}

[*] Final flag: pwn.college{0H2pGida-VGiWY7StlP2jmldEfK.dRzM3kDL4ITM0EzW}
```

### Backward decoding

```
hacker@cryptography~aes-ecb-cpa-prefix:/$ /challenge/run 

Choose an action?
1. Encrypt chosen plaintext.
2. Prepend something to the flag.
Choice? 2
Data? AAAAAAA
Result: 0cd3e1bfc0780a4d6c8be3dd9462223ad6b738a499a8eb2c4887d6b86d00ebf96486bcabb33f1c4972a9de2ac4712317815c0ef9526fafc0bba017a4b46acae6
I'm here to help!
For the first 10, I will split them into blocks for you!
After this, you'll have to split them yourself.
# of blocks: 4.
Block 1: 0cd3e1bfc0780a4d6c8be3dd9462223a
Block 2: d6b738a499a8eb2c4887d6b86d00ebf9
Block 3: 6486bcabb33f1c4972a9de2ac4712317
Block 4: 815c0ef9526fafc0bba017a4b46acae6

Choose an action?
1. Encrypt chosen plaintext.
2. Prepend something to the flag.
Choice? 2
Data? AAAAAAAA
Result: cbdccf7fccf0773a651a567f43363db02b5922fac95649c5b4163ac16247463c19907823a495b6a53c64c77e92e511d4b11232a78b47a6aa416eb171b9141a3f37aba17e7d0921f462278dea33b1f097
# of blocks: 5.
Block 1: cbdccf7fccf0773a651a567f43363db0
Block 2: 2b5922fac95649c5b4163ac16247463c
Block 3: 19907823a495b6a53c64c77e92e511d4
Block 4: b11232a78b47a6aa416eb171b9141a3f
Block 5: 37aba17e7d0921f462278dea33b1f097
```

It takes 8 bytes of padding to push the last flag character `}` into a new block (5th). We would use this block to decode the flag.
For our lookup table we would utilize the option of encrypting our chosen plaintext. 

```
## flag[-1] (last character)
5th block:
┌────────────────────────────────────┐
│  a90b328b65de1c2fea2c293771e853c6  │ ==> flag[-1] + b'\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f'
└────────────────────────────────────┘
Custom block:
┌────────────────────────────────────┐
│  a90b328b65de1c2fea2c293771e853c6  │ ==> "}" + b'\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f'
└────────────────────────────────────┘

We find out that flag[-1] character is "}".

## flag[-2:] (last two characters):
5th block:
┌────────────────────────────────────┐
│  3893f3cf94c0dd7e7afd1e45be9687aa  │ ==> flag[-2:] + b'\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f'
└────────────────────────────────────┘
Custom block:
┌────────────────────────────────────┐
│  3893f3cf94c0dd7e7afd1e45be9687aa  │ ==> "W}" + b'\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f'
└────────────────────────────────────┘

We then repeat this step for flag[-3:], flag[-4:].....
```

```py title="~/script.py" showLineNumbers
#!/usr/bin/env python3

from pwn import *
import string

context.log_level = 'error'
p = process("/challenge/run")

CHARSET = string.printable.strip().encode()
BLOCK_SIZE = 16
TARGET_BLOCK_NUM = 5  # zero-indexed = block 4
TOTAL_PAD = 8  # 80 bytes = prefix + flag
MAX_FLAG_LEN = 64

def send_choice(choice):
    p.sendline(str(choice).encode())

def encrypt_custom(pt: bytes) -> bytes:
    """
    Encrypt attacker-controlled input (Option 1)
    """
    send_choice(1)
    try:
        s = pt.decode('utf-8')
    except UnicodeDecodeError:
        return b''
    p.sendline(s.encode())
    p.recvuntil(b"Result: ")
    return p.recvline().strip()

def encrypt_prepended_flag(prefix: bytes) -> bytes:
    """
    Encrypt prefix + flag (Option 2)
    """
    send_choice(2)
    p.sendline(prefix.decode('utf-8', errors='ignore').encode())
    p.recvuntil(b"Result: ")
    return p.recvline().strip()

def get_block(ct: bytes, n: int) -> bytes:
    """
    Return the nth 16-byte block (1-indexed).
    """
    start = (n - 1) * BLOCK_SIZE * 2
    end = start + BLOCK_SIZE * 2
    return ct[start:end]

recovered = b""
print("[*] Recovering flag from the end...")

while len(recovered) < MAX_FLAG_LEN:
    pad_len = TOTAL_PAD + len(recovered)
    prefix = b"A" * pad_len

    # Get target block with unknown byte at end
    target_ct = encrypt_prepended_flag(prefix)
    target_block = get_block(target_ct, TARGET_BLOCK_NUM)

    # Build lookup table
    lookup = {}
    for ch in CHARSET:
        guess = bytes([ch]) + recovered
        ct = encrypt_custom(guess)
        guess_block = get_block(ct, 1)
        lookup[guess_block] = ch

    if target_block in lookup:
        recovered = bytes([lookup[target_block]]) + recovered
        print(f"[+] Flag so far: {recovered.decode(errors='replace')}")
        if recovered.startswith(b"pwn"):
            print(f"\n[*] Final flag: {recovered.decode(errors='replace')}")
            break
    else:
        print("[!] Failed to match block — maybe wrong block index or alignment.")
        break
```

```
hacker@cryptography~aes-ecb-cpa-prefix:/$ python ~/script.py
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
[+] Flag so far: RzM3kDL4ITM0EzW}
[+] Flag so far: dRzM3kDL4ITM0EzW}
[+] Flag so far: .dRzM3kDL4ITM0EzW}
[+] Flag so far: K.dRzM3kDL4ITM0EzW}
[+] Flag so far: fK.dRzM3kDL4ITM0EzW}
[+] Flag so far: EfK.dRzM3kDL4ITM0EzW}
[+] Flag so far: dEfK.dRzM3kDL4ITM0EzW}
[+] Flag so far: ldEfK.dRzM3kDL4ITM0EzW}
[+] Flag so far: mldEfK.dRzM3kDL4ITM0EzW}
[+] Flag so far: jmldEfK.dRzM3kDL4ITM0EzW}
[+] Flag so far: 2jmldEfK.dRzM3kDL4ITM0EzW}
[+] Flag so far: P2jmldEfK.dRzM3kDL4ITM0EzW}
[+] Flag so far: lP2jmldEfK.dRzM3kDL4ITM0EzW}
[+] Flag so far: tlP2jmldEfK.dRzM3kDL4ITM0EzW}
[+] Flag so far: StlP2jmldEfK.dRzM3kDL4ITM0EzW}
[+] Flag so far: 7StlP2jmldEfK.dRzM3kDL4ITM0EzW}
[+] Flag so far: Y7StlP2jmldEfK.dRzM3kDL4ITM0EzW}
[+] Flag so far: WY7StlP2jmldEfK.dRzM3kDL4ITM0EzW}
[+] Flag so far: iWY7StlP2jmldEfK.dRzM3kDL4ITM0EzW}
[+] Flag so far: GiWY7StlP2jmldEfK.dRzM3kDL4ITM0EzW}
[+] Flag so far: VGiWY7StlP2jmldEfK.dRzM3kDL4ITM0EzW}
[+] Flag so far: -VGiWY7StlP2jmldEfK.dRzM3kDL4ITM0EzW}
[+] Flag so far: a-VGiWY7StlP2jmldEfK.dRzM3kDL4ITM0EzW}
[+] Flag so far: da-VGiWY7StlP2jmldEfK.dRzM3kDL4ITM0EzW}
[+] Flag so far: ida-VGiWY7StlP2jmldEfK.dRzM3kDL4ITM0EzW}
[+] Flag so far: Gida-VGiWY7StlP2jmldEfK.dRzM3kDL4ITM0EzW}
[+] Flag so far: pGida-VGiWY7StlP2jmldEfK.dRzM3kDL4ITM0EzW}
[+] Flag so far: 2pGida-VGiWY7StlP2jmldEfK.dRzM3kDL4ITM0EzW}
[+] Flag so far: H2pGida-VGiWY7StlP2jmldEfK.dRzM3kDL4ITM0EzW}
[+] Flag so far: 0H2pGida-VGiWY7StlP2jmldEfK.dRzM3kDL4ITM0EzW}
[+] Flag so far: {0H2pGida-VGiWY7StlP2jmldEfK.dRzM3kDL4ITM0EzW}
[+] Flag so far: e{0H2pGida-VGiWY7StlP2jmldEfK.dRzM3kDL4ITM0EzW}
[+] Flag so far: ge{0H2pGida-VGiWY7StlP2jmldEfK.dRzM3kDL4ITM0EzW}
[+] Flag so far: ege{0H2pGida-VGiWY7StlP2jmldEfK.dRzM3kDL4ITM0EzW}
[+] Flag so far: lege{0H2pGida-VGiWY7StlP2jmldEfK.dRzM3kDL4ITM0EzW}
[+] Flag so far: llege{0H2pGida-VGiWY7StlP2jmldEfK.dRzM3kDL4ITM0EzW}
[+] Flag so far: ollege{0H2pGida-VGiWY7StlP2jmldEfK.dRzM3kDL4ITM0EzW}
[+] Flag so far: college{0H2pGida-VGiWY7StlP2jmldEfK.dRzM3kDL4ITM0EzW}
[+] Flag so far: .college{0H2pGida-VGiWY7StlP2jmldEfK.dRzM3kDL4ITM0EzW}
[+] Flag so far: n.college{0H2pGida-VGiWY7StlP2jmldEfK.dRzM3kDL4ITM0EzW}
[+] Flag so far: wn.college{0H2pGida-VGiWY7StlP2jmldEfK.dRzM3kDL4ITM0EzW}
[+] Flag so far: pwn.college{0H2pGida-VGiWY7StlP2jmldEfK.dRzM3kDL4ITM0EzW}

[*] Final flag: pwn.college{0H2pGida-VGiWY7StlP2jmldEfK.dRzM3kDL4ITM0EzW}
```

&nbsp;

## AES-ECB-CPA-Prefix-2

### Source code

```py title="/challenge/run" showLineNumbers
#!/opt/pwn.college/python

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

flag = open("/flag", "rb").read().strip()

key = get_random_bytes(16)
cipher = AES.new(key=key, mode=AES.MODE_ECB)

for n in range(31337):
    print("")
    print("Choose an action?")
    print("1. Encrypt chosen plaintext.")
    print("2. Prepend something to the flag.")
    if (choice := int(input("Choice? "))) == 1:
        pt = input("Data? ").strip().encode()
    elif choice == 2:
        pt = input("Data? ").strip().encode() + flag
    else:
        break

    padded_pt = pad(pt, cipher.block_size)
    ct = cipher.encrypt(padded_pt)
    print(f"Result: {ct.hex()}")
```

Our [backward decoding](#backward-decoding) script from the last challenge would work here as well, as we only concern ourselves with the 5th block.

```py title="~/script.py" showLineNumbers
#!/usr/bin/env python3

from pwn import *
import string

context.log_level = 'error'
p = process("/challenge/run")

CHARSET = string.printable.strip().encode()
BLOCK_SIZE = 16
TARGET_BLOCK_NUM = 5  # zero-indexed = block 4
TOTAL_PAD = 8  # 80 bytes = prefix + flag
MAX_FLAG_LEN = 64

def send_choice(choice):
    p.sendline(str(choice).encode())

def encrypt_custom(pt: bytes) -> bytes:
    """
    Encrypt attacker-controlled input (Option 1)
    """
    send_choice(1)
    try:
        s = pt.decode('utf-8')
    except UnicodeDecodeError:
        return b''
    p.sendline(s.encode())
    p.recvuntil(b"Result: ")
    return p.recvline().strip()

def encrypt_prepended_flag(prefix: bytes) -> bytes:
    """
    Encrypt prefix + flag (Option 2)
    """
    send_choice(2)
    p.sendline(prefix.decode('utf-8', errors='ignore').encode())
    p.recvuntil(b"Result: ")
    return p.recvline().strip()

def get_block(ct: bytes, n: int) -> bytes:
    """
    Return the nth 16-byte block (1-indexed).
    """
    start = (n - 1) * BLOCK_SIZE * 2
    end = start + BLOCK_SIZE * 2
    return ct[start:end]

recovered = b""
print("[*] Recovering flag from the end...")

while len(recovered) < MAX_FLAG_LEN:
    pad_len = TOTAL_PAD + len(recovered)
    prefix = b"A" * pad_len

    # Get target block with unknown byte at end
    target_ct = encrypt_prepended_flag(prefix)
    target_block = get_block(target_ct, TARGET_BLOCK_NUM)

    # Build lookup table
    lookup = {}
    for ch in CHARSET:
        guess = bytes([ch]) + recovered
        ct = encrypt_custom(guess)
        guess_block = get_block(ct, 1)
        lookup[guess_block] = ch

    if target_block in lookup:
        recovered = bytes([lookup[target_block]]) + recovered
        print(f"[+] Flag so far: {recovered.decode(errors='replace')}")
        if recovered.startswith(b"pwn"):
            print(f"\n[*] Final flag: {recovered.decode(errors='replace')}")
            break
    else:
        print("[!] Failed to match block — maybe wrong block index or alignment.")
        break
```

```
hacker@cryptography~aes-ecb-cpa-prefix-2:/$ python ~/script.py 
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
[+] Flag so far: VzM3kDL4ITM0EzW}
[+] Flag so far: dVzM3kDL4ITM0EzW}
[+] Flag so far: .dVzM3kDL4ITM0EzW}
[+] Flag so far: t.dVzM3kDL4ITM0EzW}
[+] Flag so far: 7t.dVzM3kDL4ITM0EzW}
[+] Flag so far: i7t.dVzM3kDL4ITM0EzW}
[+] Flag so far: 0i7t.dVzM3kDL4ITM0EzW}
[+] Flag so far: j0i7t.dVzM3kDL4ITM0EzW}
[+] Flag so far: Hj0i7t.dVzM3kDL4ITM0EzW}
[+] Flag so far: HHj0i7t.dVzM3kDL4ITM0EzW}
[+] Flag so far: 9HHj0i7t.dVzM3kDL4ITM0EzW}
[+] Flag so far: v9HHj0i7t.dVzM3kDL4ITM0EzW}
[+] Flag so far: 5v9HHj0i7t.dVzM3kDL4ITM0EzW}
[+] Flag so far: 45v9HHj0i7t.dVzM3kDL4ITM0EzW}
[+] Flag so far: S45v9HHj0i7t.dVzM3kDL4ITM0EzW}
[+] Flag so far: mS45v9HHj0i7t.dVzM3kDL4ITM0EzW}
[+] Flag so far: cmS45v9HHj0i7t.dVzM3kDL4ITM0EzW}
[+] Flag so far: acmS45v9HHj0i7t.dVzM3kDL4ITM0EzW}
[+] Flag so far: bacmS45v9HHj0i7t.dVzM3kDL4ITM0EzW}
[+] Flag so far: EbacmS45v9HHj0i7t.dVzM3kDL4ITM0EzW}
[+] Flag so far: aEbacmS45v9HHj0i7t.dVzM3kDL4ITM0EzW}
[+] Flag so far: FaEbacmS45v9HHj0i7t.dVzM3kDL4ITM0EzW}
[+] Flag so far: 7FaEbacmS45v9HHj0i7t.dVzM3kDL4ITM0EzW}
[+] Flag so far: C7FaEbacmS45v9HHj0i7t.dVzM3kDL4ITM0EzW}
[+] Flag so far: YC7FaEbacmS45v9HHj0i7t.dVzM3kDL4ITM0EzW}
[+] Flag so far: gYC7FaEbacmS45v9HHj0i7t.dVzM3kDL4ITM0EzW}
[+] Flag so far: qgYC7FaEbacmS45v9HHj0i7t.dVzM3kDL4ITM0EzW}
[+] Flag so far: HqgYC7FaEbacmS45v9HHj0i7t.dVzM3kDL4ITM0EzW}
[+] Flag so far: iHqgYC7FaEbacmS45v9HHj0i7t.dVzM3kDL4ITM0EzW}
[+] Flag so far: giHqgYC7FaEbacmS45v9HHj0i7t.dVzM3kDL4ITM0EzW}
[+] Flag so far: {giHqgYC7FaEbacmS45v9HHj0i7t.dVzM3kDL4ITM0EzW}
[+] Flag so far: e{giHqgYC7FaEbacmS45v9HHj0i7t.dVzM3kDL4ITM0EzW}
[+] Flag so far: ge{giHqgYC7FaEbacmS45v9HHj0i7t.dVzM3kDL4ITM0EzW}
[+] Flag so far: ege{giHqgYC7FaEbacmS45v9HHj0i7t.dVzM3kDL4ITM0EzW}
[+] Flag so far: lege{giHqgYC7FaEbacmS45v9HHj0i7t.dVzM3kDL4ITM0EzW}
[+] Flag so far: llege{giHqgYC7FaEbacmS45v9HHj0i7t.dVzM3kDL4ITM0EzW}
[+] Flag so far: ollege{giHqgYC7FaEbacmS45v9HHj0i7t.dVzM3kDL4ITM0EzW}
[+] Flag so far: college{giHqgYC7FaEbacmS45v9HHj0i7t.dVzM3kDL4ITM0EzW}
[+] Flag so far: .college{giHqgYC7FaEbacmS45v9HHj0i7t.dVzM3kDL4ITM0EzW}
[+] Flag so far: n.college{giHqgYC7FaEbacmS45v9HHj0i7t.dVzM3kDL4ITM0EzW}
[+] Flag so far: wn.college{giHqgYC7FaEbacmS45v9HHj0i7t.dVzM3kDL4ITM0EzW}
[+] Flag so far: pwn.college{giHqgYC7FaEbacmS45v9HHj0i7t.dVzM3kDL4ITM0EzW}

[*] Final flag: pwn.college{giHqgYC7FaEbacmS45v9HHj0i7t.dVzM3kDL4ITM0EzW}
```

&nbsp;

## AES-ECB-CPA-Prefix-Miniboss

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
    pt = bytes.fromhex(input("Data? ").strip()) + flag
    ct = cipher.encrypt(pad(pt, cipher.block_size))
    print(f"Ciphertext: {ct.hex()}")
```

This time, the challenge expects our input to be in hex format. 

Also, we cannot create a separate lookup table. Therefore, we will have to use the block in the padded flag's output in order to create the lookup table.

```
hacker@cryptography~aes-ecb-cpa-prefix-miniboss:/$ /challenge/run 
Data? 0f
Ciphertext: 00a3c19a94ec6269f8dcb210b3eaedbb3b3186d87e9c81e822b044acf91c877326594fc26f986ba5bb17ceff011bf8c79a914706c64e516c4030c7d3c51e53bf
Data? 0f0f0f0f0f0f0f0f
Ciphertext: c3286195bd04de381b405f7de8bcd3963fdcca82533782293589a91f39d6dc831320a97b43f30a0b35a1ef12063d76a76a17c4c4debafd66bd7ef446bff954fc5014fb3c8d608deab62f32ccf2f6c6a2
```

This shows us that that a padding of 8 bytes pushes the last byte of the flag in the new, 5th block. (7 bytes of padding would also give us a 5th block, however that would be a block entirely filled with [PKCS#7](https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS#5_and_PKCS#7) padding as noted in the last challenge.)

> But wait... What if exactly 16 bytes of plaintext are encrypted (e.g., no padding needed), but the plaintext byte has a value of 0x01? Left to its own devices, PKCS7 would chop off that byte during unpadding, leaving us with a corrupted plaintext. The solution to this is slightly silly: if the last block of the plaintext is exactly 16 bytes, we add a block of all padding (e.g., 16 padding bytes, each with a value of 0x10). PKCS7 removes the whole block during unpadding, and the sanctity of the plaintext is preserved at the expense of a bit more data.

```
Block 1: c3286195bd04de381b405f7de8bcd396 --> b'\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f' + flag[:8]
Block 2: 3fdcca82533782293589a91f39d6dc83
Block 3: 1320a97b43f30a0b35a1ef12063d76a7
Block 4: 6a17c4c4debafd66bd7ef446bff954fc
Block 5: 5014fb3c8d608deab62f32ccf2f6c6a2 --> flag[-1] + b'\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f'
```

In this case, the first block can be used as the reference lookup block. However, we have to push the `flag[:8]` bytes into the next block so that we can standardize the first block, and fully control it's content. In order to do that, we can simply add 16 more bytes of padding.

```
Data? 0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f
Ciphertext: 655242cbfe80f893d6bc8c064acf7c8ff53d8c0a577545e2cad3e1bd50172916eea1729a41246495debbcc9ad79e134151335e55511e0aeff2d19c41c4a911bd53a22dc4391093e9f9395c0cdd966b472e0c5da7f0bd741b7813d831deac420d
```

We can see that the last byte of the flag is now pushed in the 6th block.

```
Block 1: 655242cbfe80f893d6bc8c064acf7c8f --> b'\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f'
Block 2: f53d8c0a577545e2cad3e1bd50172916 --> b'\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f' + flag[:8]
Block 3: eea1729a41246495debbcc9ad79e1341
Block 4: 51335e55511e0aeff2d19c41c4a911bd
Block 5: 53a22dc4391093e9f9395c0cdd966b47
Block 6: 2e0c5da7f0bd741b7813d831deac420d --> flag[-1] + b'\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f'
```

Now, our first block has been standardized and is entirely under our control.

We know that the last char of the flag is "`}`", hence we can use it while creating the padding, such that the 1st block matches the 6th block.

```
Data? 7d0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f
Ciphertext: 88659faf2ea78c203983aa76e5dbda3c7d8795481949358dc0a87b47df93ab65e53be7ee2cc95b12eaec38e97e89e9cd0b651c7e05af13d57cf46b7b3b3c1920dca5561f8e23fe4b077d80e725e433d288659faf2ea78c203983aa76e5dbda3c
```

```
Block 1: 88659faf2ea78c203983aa76e5dbda3c --> "}" + b'\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f'
Block 2: 7d8795481949358dc0a87b47df93ab65 --> b'\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f' + flag[:8]
Block 3: e53be7ee2cc95b12eaec38e97e89e9cd
Block 4: 0b651c7e05af13d57cf46b7b3b3c1920
Block 5: dca5561f8e23fe4b077d80e725e433d2
Block 6: 88659faf2ea78c203983aa76e5dbda3c --> flag[-1] + b'\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f'
```

Finally! We have managed to create a valid lookup table in the 1st block using our padding. Let's create a solution script for this.

```py title="~/script.py" showLineNumbers
#!/usr/bin/env python3
from pwn import *
import string

context.log_level = 'error'
p = process("/challenge/run")

# Printable chars are fine since they get hex-encoded automatically
CHARSET = string.printable.strip().encode()
BLOCK_SIZE = 16
REF_BLOCK_NUM = 1       # Lookup table block
TARGET_BLOCK_NUM = 6    # Flag byte block
TOTAL_PAD = 23          # Static padding
MAX_FLAG_LEN = 64

def encrypt_prefix(prefix: bytes) -> bytes:
    p.sendline(prefix.hex().encode())   # send hex-encoded
    p.recvuntil(b"Ciphertext: ")
    return p.recvline().strip()

def get_block(ct: bytes, n: int) -> bytes:
    start = (n - 1) * BLOCK_SIZE * 2
    end = start + BLOCK_SIZE * 2
    return ct[start:end]

recovered = b""
print("[*] Recovering flag from the end...")

while len(recovered) < MAX_FLAG_LEN:
    pkcs_byte = max(15 - len(recovered), 0)
    padding = bytes([pkcs_byte]) * TOTAL_PAD
    found = False

    for ch in CHARSET:
        guess = bytes([ch]) + recovered + padding
        ct = encrypt_prefix(guess)
        block_1 = get_block(ct, REF_BLOCK_NUM)
        block_6 = get_block(ct, TARGET_BLOCK_NUM)

        if block_1 == block_6:
            recovered = bytes([ch]) + recovered
            print(f"[+] Flag so far: {recovered.decode(errors='replace')}")
            found = True
            break

    if not found:
        print("[!] Failed to match any byte – check block index/alignment.")
        break

    # Stop when full flag structure is detected
    if recovered.startswith(b"pwn") and recovered.endswith(b"}"):
        print(f"\n[*] Final flag: {recovered.decode(errors='replace')}")
        break
```

```
hacker@cryptography~aes-ecb-cpa-prefix-miniboss:/$ python ~/script.py 
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
[+] Flag so far: MDL4ITM0EzW}
[+] Flag so far: zMDL4ITM0EzW}
[+] Flag so far: NzMDL4ITM0EzW}
[+] Flag so far: zNzMDL4ITM0EzW}
[+] Flag so far: dzNzMDL4ITM0EzW}
[+] Flag so far: ddzNzMDL4ITM0EzW}
[+] Flag so far: .ddzNzMDL4ITM0EzW}
[+] Flag so far: c.ddzNzMDL4ITM0EzW}
[+] Flag so far: 7c.ddzNzMDL4ITM0EzW}
[+] Flag so far: y7c.ddzNzMDL4ITM0EzW}
[+] Flag so far: my7c.ddzNzMDL4ITM0EzW}
[+] Flag so far: rmy7c.ddzNzMDL4ITM0EzW}
[+] Flag so far: qrmy7c.ddzNzMDL4ITM0EzW}
[+] Flag so far: eqrmy7c.ddzNzMDL4ITM0EzW}
[+] Flag so far: Feqrmy7c.ddzNzMDL4ITM0EzW}
[+] Flag so far: IFeqrmy7c.ddzNzMDL4ITM0EzW}
[+] Flag so far: -IFeqrmy7c.ddzNzMDL4ITM0EzW}
[+] Flag so far: P-IFeqrmy7c.ddzNzMDL4ITM0EzW}
[+] Flag so far: VP-IFeqrmy7c.ddzNzMDL4ITM0EzW}
[+] Flag so far: LVP-IFeqrmy7c.ddzNzMDL4ITM0EzW}
[+] Flag so far: 2LVP-IFeqrmy7c.ddzNzMDL4ITM0EzW}
[+] Flag so far: m2LVP-IFeqrmy7c.ddzNzMDL4ITM0EzW}
[+] Flag so far: -m2LVP-IFeqrmy7c.ddzNzMDL4ITM0EzW}
[+] Flag so far: 8-m2LVP-IFeqrmy7c.ddzNzMDL4ITM0EzW}
[+] Flag so far: R8-m2LVP-IFeqrmy7c.ddzNzMDL4ITM0EzW}
[+] Flag so far: TR8-m2LVP-IFeqrmy7c.ddzNzMDL4ITM0EzW}
[+] Flag so far: sTR8-m2LVP-IFeqrmy7c.ddzNzMDL4ITM0EzW}
[+] Flag so far: 3sTR8-m2LVP-IFeqrmy7c.ddzNzMDL4ITM0EzW}
[+] Flag so far: t3sTR8-m2LVP-IFeqrmy7c.ddzNzMDL4ITM0EzW}
[+] Flag so far: at3sTR8-m2LVP-IFeqrmy7c.ddzNzMDL4ITM0EzW}
[+] Flag so far: Pat3sTR8-m2LVP-IFeqrmy7c.ddzNzMDL4ITM0EzW}
[+] Flag so far: jPat3sTR8-m2LVP-IFeqrmy7c.ddzNzMDL4ITM0EzW}
[+] Flag so far: pjPat3sTR8-m2LVP-IFeqrmy7c.ddzNzMDL4ITM0EzW}
[+] Flag so far: UpjPat3sTR8-m2LVP-IFeqrmy7c.ddzNzMDL4ITM0EzW}
[+] Flag so far: {UpjPat3sTR8-m2LVP-IFeqrmy7c.ddzNzMDL4ITM0EzW}
[+] Flag so far: e{UpjPat3sTR8-m2LVP-IFeqrmy7c.ddzNzMDL4ITM0EzW}
[+] Flag so far: ge{UpjPat3sTR8-m2LVP-IFeqrmy7c.ddzNzMDL4ITM0EzW}
[+] Flag so far: ege{UpjPat3sTR8-m2LVP-IFeqrmy7c.ddzNzMDL4ITM0EzW}
[+] Flag so far: lege{UpjPat3sTR8-m2LVP-IFeqrmy7c.ddzNzMDL4ITM0EzW}
[+] Flag so far: llege{UpjPat3sTR8-m2LVP-IFeqrmy7c.ddzNzMDL4ITM0EzW}
[+] Flag so far: ollege{UpjPat3sTR8-m2LVP-IFeqrmy7c.ddzNzMDL4ITM0EzW}
[+] Flag so far: college{UpjPat3sTR8-m2LVP-IFeqrmy7c.ddzNzMDL4ITM0EzW}
[+] Flag so far: .college{UpjPat3sTR8-m2LVP-IFeqrmy7c.ddzNzMDL4ITM0EzW}
[+] Flag so far: n.college{UpjPat3sTR8-m2LVP-IFeqrmy7c.ddzNzMDL4ITM0EzW}
[+] Flag so far: wn.college{UpjPat3sTR8-m2LVP-IFeqrmy7c.ddzNzMDL4ITM0EzW}
[+] Flag so far: pwn.college{UpjPat3sTR8-m2LVP-IFeqrmy7c.ddzNzMDL4ITM0EzW}

[*] Final flag: pwn.college{UpjPat3sTR8-m2LVP-IFeqrmy7c.ddzNzMDL4ITM0EzW}
```

&nbsp;

## AES-ECB-CPA-Prefix-Boss

### Source code

```py title="/challenge/run" showLineNumbers
#!/opt/pwn.college/python

from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

import tempfile
import sqlite3
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
db.execute("""CREATE TABLE posts AS SELECT ? AS content""", [open("/flag", "rb").read().strip()])

@app.route("/", methods=["POST"])
def challenge_post():
    content = flask.request.form.get("content").encode('latin1')
    db.execute("INSERT INTO posts VALUES (?)", [content])
    return flask.redirect(flask.request.path)

@app.route("/reset", methods=["POST"])
def challenge_reset():
    db.execute("DELETE FROM posts WHERE ROWID > 1")
    return flask.redirect("/")

@app.route("/", methods=["GET"])
def challenge_get():
    pt = b"|".join(post["content"] for post in db.execute("SELECT content FROM posts ORDER BY ROWID DESC").fetchall())
    ct = cipher.encrypt(pad(pt, cipher.block_size))

    return f"""
        <html><body>Welcome to pwn.secret!
        <form method=post>Post a secret:<input type=text name=content><input type=submit value=Submit></form>
        <form method=post action=reset><input type=submit value="Reset Database"></form>
        <hr>
        <b>Encrypted backup:</b><pre>{b64encode(ct).decode()}</pre>
        </body></html>
    """

app.secret_key = os.urandom(8)
app.config['SERVER_NAME'] = "challenge.localhost:80"
app.run("challenge.localhost", 80)
```

Let's first find the number of byte required to push last byte of flag into new block.

```
hacker@cryptography~aes-ecb-cpa-prefix-boss:/$ for i in $(seq 1 32); do
  curl -s -X POST \
    -F "content=$(printf '\x0f%.0s' $(seq 1 $i))" \
    http://challenge.localhost/ > /dev/null
  echo -n "Len $i: "
  curl -s http://challenge.localhost/ \
    | grep -oP '(?<=<pre>).*?(?=</pre>)' \
    | base64 -d | wc -c
done
Len 1: 128
Len 2: 128
Len 3: 128
Len 4: 144
Len 5: 144
Len 6: 144
Len 7: 160
Len 8: 176
Len 9: 176
Len 10: 192
Len 11: 208
Len 12: 208
Len 13: 224
Len 14: 240
Len 15: 256
Len 16: 272
Len 17: 288
Len 18: 320
Len 19: 336
Len 20: 352
Len 21: 384
Len 22: 400
Len 23: 416
Len 24: 448
Len 25: 480
Len 26: 496
Len 27: 528
Len 28: 560
Len 29: 592
Len 30: 624
Len 31: 656
Len 32: 688
```

As we can see, it takes 5 bytes of padding to push the last byte of the flag into a new block.

Now, we can craft our script.

```py title="~/script.py" showLineNumbers
#!/usr/bin/env python3
import requests
import base64
import string

URL = "http://challenge.localhost"
CHARSET = string.printable.strip().encode()
BLOCK_SIZE = 16
REF_BLOCK_NUM = 1
TARGET_BLOCK_NUM = 6
TOTAL_PAD = 22
MAX_FLAG_LEN = 64

session = requests.Session()

def reset_db():
    session.post(f"{URL}/reset")

def encrypt_prefix(prefix: bytes) -> bytes:
    # Insert attacker-controlled input
    session.post(URL, data={'content': prefix.decode('latin1')})
    # Retrieve ciphertext
    resp = session.get(URL).text
    ct_b64 = resp.split("<pre>")[1].split("</pre>")[0].strip()
    return base64.b64decode(ct_b64).hex()

def get_block(ct: bytes, n: int) -> bytes:
    start = (n - 1) * BLOCK_SIZE * 2
    end = start + BLOCK_SIZE * 2
    return ct[start:end]

recovered = b""
print("[*] Recovering flag from the end...")

while len(recovered) < MAX_FLAG_LEN:
    # PKCS#7 padding byte dynamically decreases
    pkcs_byte = max(15 - len(recovered), 0)
    padding = bytes([pkcs_byte]) * TOTAL_PAD
    found = False

    for ch in CHARSET:
        guess = bytes([ch]) + recovered + padding
        reset_db()  # keep DB small each try
        ct = encrypt_prefix(guess)

        block_ref = get_block(ct, REF_BLOCK_NUM)
        block_target = get_block(ct, TARGET_BLOCK_NUM)

        if block_ref == block_target:
            recovered = bytes([ch]) + recovered
            print(f"[+] Flag so far: {recovered.decode(errors='replace')}")
            found = True
            break

    if not found:
        print("[!] Failed to match any byte – check block index/alignment.")
        break

    if recovered.startswith(b"pwn") and recovered.endswith(b"}"):
        print(f"\n[*] Final flag: {recovered.decode(errors='replace')}")
        break
```

```
hacker@cryptography~aes-ecb-cpa-prefix-boss:/$ python ~/script.py 
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
[+] Flag so far: ZzM3kDL4ITM0EzW}
[+] Flag so far: dZzM3kDL4ITM0EzW}
[+] Flag so far: .dZzM3kDL4ITM0EzW}
[+] Flag so far: C.dZzM3kDL4ITM0EzW}
[+] Flag so far: iC.dZzM3kDL4ITM0EzW}
[+] Flag so far: biC.dZzM3kDL4ITM0EzW}
[+] Flag so far: SbiC.dZzM3kDL4ITM0EzW}
[+] Flag so far: nSbiC.dZzM3kDL4ITM0EzW}
[+] Flag so far: hnSbiC.dZzM3kDL4ITM0EzW}
[+] Flag so far: NhnSbiC.dZzM3kDL4ITM0EzW}
[+] Flag so far: XNhnSbiC.dZzM3kDL4ITM0EzW}
[+] Flag so far: rXNhnSbiC.dZzM3kDL4ITM0EzW}
[+] Flag so far: FrXNhnSbiC.dZzM3kDL4ITM0EzW}
[+] Flag so far: WFrXNhnSbiC.dZzM3kDL4ITM0EzW}
[+] Flag so far: EWFrXNhnSbiC.dZzM3kDL4ITM0EzW}
[+] Flag so far: FEWFrXNhnSbiC.dZzM3kDL4ITM0EzW}
[+] Flag so far: EFEWFrXNhnSbiC.dZzM3kDL4ITM0EzW}
[+] Flag so far: 9EFEWFrXNhnSbiC.dZzM3kDL4ITM0EzW}
[+] Flag so far: 69EFEWFrXNhnSbiC.dZzM3kDL4ITM0EzW}
[+] Flag so far: 269EFEWFrXNhnSbiC.dZzM3kDL4ITM0EzW}
[+] Flag so far: y269EFEWFrXNhnSbiC.dZzM3kDL4ITM0EzW}
[+] Flag so far: ay269EFEWFrXNhnSbiC.dZzM3kDL4ITM0EzW}
[+] Flag so far: Way269EFEWFrXNhnSbiC.dZzM3kDL4ITM0EzW}
[+] Flag so far: DWay269EFEWFrXNhnSbiC.dZzM3kDL4ITM0EzW}
[+] Flag so far: 8DWay269EFEWFrXNhnSbiC.dZzM3kDL4ITM0EzW}
[+] Flag so far: g8DWay269EFEWFrXNhnSbiC.dZzM3kDL4ITM0EzW}
[+] Flag so far: Vg8DWay269EFEWFrXNhnSbiC.dZzM3kDL4ITM0EzW}
[+] Flag so far: KVg8DWay269EFEWFrXNhnSbiC.dZzM3kDL4ITM0EzW}
[+] Flag so far: lKVg8DWay269EFEWFrXNhnSbiC.dZzM3kDL4ITM0EzW}
[+] Flag so far: ElKVg8DWay269EFEWFrXNhnSbiC.dZzM3kDL4ITM0EzW}
[+] Flag so far: {ElKVg8DWay269EFEWFrXNhnSbiC.dZzM3kDL4ITM0EzW}
[+] Flag so far: e{ElKVg8DWay269EFEWFrXNhnSbiC.dZzM3kDL4ITM0EzW}
[+] Flag so far: ge{ElKVg8DWay269EFEWFrXNhnSbiC.dZzM3kDL4ITM0EzW}
[+] Flag so far: ege{ElKVg8DWay269EFEWFrXNhnSbiC.dZzM3kDL4ITM0EzW}
[+] Flag so far: lege{ElKVg8DWay269EFEWFrXNhnSbiC.dZzM3kDL4ITM0EzW}
[+] Flag so far: llege{ElKVg8DWay269EFEWFrXNhnSbiC.dZzM3kDL4ITM0EzW}
[+] Flag so far: ollege{ElKVg8DWay269EFEWFrXNhnSbiC.dZzM3kDL4ITM0EzW}
[+] Flag so far: college{ElKVg8DWay269EFEWFrXNhnSbiC.dZzM3kDL4ITM0EzW}
[+] Flag so far: .college{ElKVg8DWay269EFEWFrXNhnSbiC.dZzM3kDL4ITM0EzW}
[+] Flag so far: n.college{ElKVg8DWay269EFEWFrXNhnSbiC.dZzM3kDL4ITM0EzW}
[+] Flag so far: wn.college{ElKVg8DWay269EFEWFrXNhnSbiC.dZzM3kDL4ITM0EzW}
[+] Flag so far: pwn.college{ElKVg8DWay269EFEWFrXNhnSbiC.dZzM3kDL4ITM0EzW}

[*] Final flag: pwn.college{ElKVg8DWay269EFEWFrXNhnSbiC.dZzM3kDL4ITM0EzW}
```

&nbsp;

## AES-CBC

### Source code

```py title="/challenge/run" showLineNumbers
#!/opt/pwn.college/python

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

flag = open("/flag", "rb").read()

key = get_random_bytes(16)
cipher = AES.new(key=key, mode=AES.MODE_CBC)
ciphertext = cipher.iv + cipher.encrypt(pad(flag, cipher.block_size))

print(f"AES Key (hex): {key.hex()}")
print(f"Flag Ciphertext (hex): {ciphertext.hex()}")
```

```
hacker@cryptography~aes-cbc:/$ /challenge/run 
AES Key (hex): f3f251ecb272915ab2b231bc8252e633
Flag Ciphertext (hex): e8ffadd10cf2fab51748d9976a83d710bcc067dae2d95d627e6882161a26702566368d2427da2da58937cd6aa8850a3bb5acaec25ccf1065c699a3b67f9b89378b0d06afb23e254cd5ed09bf8b1e7b1f
```

In order to decrypt the flag, we have to use the `MODE_CBC` in AES. Also we have to separate the Initialization vector and the cipher text.

`cipher.iv` is always 16 bytes for AES, so we can split there.

```py title="~/script.py" showLineNumbers
#!/opt/pwn.college/python

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key_hex = "f3f251ecb272915ab2b231bc8252e633"
key = bytes.fromhex(key_hex)

flag_cipher_hex = "e8ffadd10cf2fab51748d9976a83d710bcc067dae2d95d627e6882161a26702566368d2427da2da58937cd6aa8850a3bb5acaec25ccf1065c699a3b67f9b89378b0d06afb23e254cd5ed09bf8b1e7b1f"
flag_cipher = bytes.fromhex(flag_cipher_hex)

# Extract IV and ciphertext
iv = flag_cipher[:16]
ciphertext = flag_cipher[16:]

cipher = AES.new(key, AES.MODE_CBC, iv)
flag_plain = unpad(cipher.decrypt(ciphertext), AES.block_size)

print(flag_plain.decode())
```

```
hacker@cryptography~aes-cbc:/$ python ~/script.py 
pwn.college{EclMIdT_XkgnVQ3DjKo6norcpJ6.ddzM3kDL4ITM0EzW}
```

&nbsp;

## AES-CBC Tampering

### Source code

```py title="/challenge/dispatcher" showLineNumbers
#!/opt/pwn.college/python

import os

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

key = open("/challenge/.key", "rb").read()
cipher = AES.new(key=key, mode=AES.MODE_CBC)
ciphertext = cipher.iv + cipher.encrypt(pad(b"sleep", cipher.block_size))

print(f"TASK: {ciphertext.hex()}")
```

```py title="/challenge/worker" showLineNumbers
#!/opt/pwn.college/python

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes

import time
import sys

key = open("/challenge/.key", "rb").read()

while line := sys.stdin.readline():
    if not line.startswith("TASK: "):
        continue
    data = bytes.fromhex(line.split()[1])
    iv, ciphertext = data[:16], data[16:]

    cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
    try:
        plaintext = unpad(cipher.decrypt(ciphertext), cipher.block_size).decode('latin1')
    except ValueError as e:
        print("Error:", e)
        continue

    print(f"Hex of plaintext: {plaintext.encode('latin1').hex()}")
    print(f"Received command: {plaintext}")
    if plaintext == "sleep":
        print("Sleeping!")
        time.sleep(1)
    elif plaintext == "flag!":
        print("Victory! Your flag:")
        print(open("/flag").read())
    else:
        print("Unknown command!")
```

```
hacker@cryptography~aes-cbc-tampering:/$ /challenge/dispatcher 
TASK: a28438ea597316483da08726f8f246546c66dbb5e901ad7ba356de83b0804833
hacker@cryptography~aes-cbc-tampering:/$ /challenge/worker 
TASK: a28438ea597316483da08726f8f246546c66dbb5e901ad7ba356de83b0804833
Hex of plaintext: 736c656570
Received command: sleep
Sleeping!
```

The `/challenge/dispatcher` gives an output `iv + ciphertext` where ciphertext is AES-CBC encryption of `sleep`, which is then decoded by the `/challenge/worker`.

Once we send the cipher text to the `/challenge/worker`, it first splits it.

```
Ciphertext (CT_1): a28438ea597316483da08726f8f246546c66dbb5e901ad7ba356de83b0804833
Initialization Vector (IV_1): a28438ea597316483da08726f8f24654
AES Encoded text (AE): 6c66dbb5e901ad7ba356de83b0804833
```

Next, `CT` is run through the AES function where it is decrypted to give us the AES decoded text (`AD`). This is then XOR'd with the Intialization vector (`IV_1`), to give us the Plaintext (`PT_1`) which is `sleep`.

```
MSG = IV_1 + CT

                      CT
                      ║               
                      ║
              ┌───────╨───────┐
      ( key ) │  AES_Decrypt  │
              └───────╥───────┘
                      ║     
                      ║    
                      ⌄    
                      AD 
                      ║ 
             IV_1 ==> ⊕    
                      ║    
                      ⌄   
                     PT_1 (sleep)
```

We want the plaintext (`PT_1`) to be `flag!`, so that the `/challenge/worker` gives us the flag. Let's call that (`PT_2`).
We can make use of the various XOR properties to achieve this.

```
AD ⊕ IV_1 ==> PT_1

## XOR both sides with same values
AD ⊕ IV_1 ⊕ PT_1 ⊕ PT_2 ==> PT_1 ⊕ PT_1 ⊕ PT_2   

## Identity property
AD ⊕ IV_1 ⊕ PT_1 ⊕ PT_2 ==> 0 ⊕ PT_2

## Self inverse property
AD ⊕ IV_1 ⊕ PT_1 ⊕ PT_2 ==> PT_2

## Commutative property
AD ⊕ [IV_1 ⊕ (PT_1 ⊕ PT_2)] ==> PT_2
```

Looking at the above expressions, we can see that in order to get `PT_2` from `AD`, we have to use a new Initialization vector: `[IV_1 ⊕ (PT_1 ⊕ PT_2)]`.
So, we have to create a new message text (`MSG_2`) as follows:

```
MSG_2 = IV_2 + CT
      = [IV_1 ⊕ (PT_1 ⊕ PT_2)] + CT

                      CT
                      ║               
                      ║
              ┌───────╨───────┐
      ( key ) │  AES_Decrypt  │
              └───────╥───────┘
                      ║     
                      ║    
                      ⌄    
                      AD
                      ║ 
             IV_2 ==> ⊕    
                      ║    
                      ⌄   
                     PT_2 (flag!)
```

```py title="~/script.py" showLineNumbers
#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.strxor import strxor
import binascii

# Original ciphertext (from the task)
msg_1_hex = "a28438ea597316483da08726f8f246546c66dbb5e901ad7ba356de83b0804833"
msg_1 = bytes.fromhex(msg_1_hex)

# Split IV and ciphertext block
iv_1 = msg_1[:16]
print(f"IV_1: {iv_1}")
ct = msg_1[16:]

# Known original plaintext and desired plaintext, auto-padded
pt_1 = pad(b"sleep", AES.block_size)
print(f"PT_1: {pt_1}")
pt_2 = pad(b"flag!", AES.block_size)
print(f"PT_2: {pt_2}")

# Modified IV calculation using full-block XOR
iv_2 = strxor(iv_1, strxor(pt_1, pt_2))

# Construct modified ciphertext
msg_2 = iv_2 + ct
print("TASK:", msg_2.hex())
```

```
hacker@cryptography~aes-cbc-tampering:/$ python ~/script.py
IV_1: b'\xa2\x848\xeaYs\x16H=\xa0\x87&\xf8\xf2FT'
PT_1: b'sleep\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
PT_2: b'flag!\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
TASK: b7843ce8087316483da08726f8f246546c66dbb5e901ad7ba356de83b0804833
```

```
hacker@cryptography~aes-cbc-tampering:/$ /challenge/worker 
TASK: b7843ce8087316483da08726f8f246546c66dbb5e901ad7ba356de83b0804833
Hex of plaintext: 666c616721
Received command: flag!
Victory! Your flag:
pwn.college{E562wrmpXmo5PkCokLzflg4-OxM.dhzM3kDL4ITM0EzW}
```

&nbsp;

## AES-CBC Resizing

### Source code

```py title="/challenge/dispatcher" showLineNumbers
#!/opt/pwn.college/python

import os

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

key = open("/challenge/.key", "rb").read()
cipher = AES.new(key=key, mode=AES.MODE_CBC)
ciphertext = cipher.iv + cipher.encrypt(pad(b"sleep", cipher.block_size))

print(f"TASK: {ciphertext.hex()}")
```

```py title="/challenge/worker" showLineNumbers
#!/opt/pwn.college/python

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes

import time
import sys

key = open("/challenge/.key", "rb").read()

while line := sys.stdin.readline():
    if not line.startswith("TASK: "):
        continue
    data = bytes.fromhex(line.split()[1])
    iv, ciphertext = data[:16], data[16:]

    cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
    try:
        plaintext = unpad(cipher.decrypt(ciphertext), cipher.block_size).decode('latin1')
    except ValueError as e:
        print("Error:", e)
        continue

    print(f"Hex of plaintext: {plaintext.encode('latin1').hex()}")
    print(f"Received command: {plaintext}")
    if plaintext == "sleep":
        print("Sleeping!")
        time.sleep(1)
    elif plaintext == "flag":
        print("Victory! Your flag:")
        print(open("/flag").read())
    else:
        print("Unknown command!")
```

Our last solution should word with very minute changes.

```py title="~/script.py" showLineNumbers
#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.strxor import strxor
import binascii

# Original ciphertext (from the task)
msg_1_hex = "8546be2b905db97d2e8bac51835e5357f264b34be22319d357ff57d0a451e01e"
msg_1 = bytes.fromhex(msg_1_hex)

# Split IV and ciphertext block
iv_1 = msg_1[:16]
print(f"IV_1: {iv_1}")
ct = msg_1[16:]

# Known original plaintext and desired plaintext, auto-padded
pt_1 = pad(b"sleep", AES.block_size)
print(f"PT_1: {pt_1}")
pt_2 = pad(b"flag", AES.block_size)
print(f"PT_2: {pt_2}")

# Modified IV calculation using full-block XOR
iv_2 = strxor(iv_1, strxor(pt_1, pt_2))

# Construct modified ciphertext
msg_2 = iv_2 + ct
print("TASK:", msg_2.hex())
```

```
hacker@cryptography~aes-cbc-resizing:~$ python ~/script.py
IV_1: b'\x85F\xbe+\x90]\xb9}.\x8b\xacQ\x83^SW'
PT_1: b'sleep\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
PT_2: b'flag\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c'
TASK: 9046ba29ec5abe7a298cab5684595450f264b34be22319d357ff57d0a451e01e
```

```
hacker@cryptography~aes-cbc-resizing:~$ /challenge/worker 
TASK: 9046ba29ec5abe7a298cab5684595450f264b34be22319d357ff57d0a451e01e
Hex of plaintext: 666c6167
Received command: flag
Victory! Your flag:
pwn.college{M-SmN7np6M8gKce-S1gTI95eeh0.dlzM3kDL4ITM0EzW}
```

&nbsp;

## AES-CBC-POA-Partial-Block

### Source code
```py title="/challenge/dispatcher" showLineNumbers
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

import sys

key = open("/challenge/.key", "rb").read()
cipher = AES.new(key=key, mode=AES.MODE_CBC)

if len(sys.argv) > 1 and sys.argv[1] == "pw":
    plaintext = open("/challenge/.pw", "rb").read().strip()
else:
    plaintext = b"sleep"

ciphertext = cipher.iv + cipher.encrypt(pad(plaintext, cipher.block_size))
print(f"TASK: {ciphertext.hex()}")
```

```py title="/challenge/worker" showLineNumbers
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes

import time
import sys

key = open("/challenge/.key", "rb").read()
pw = open("/challenge/.pw").read().strip()

print(f"The password is {len(pw)} bytes long!")

while line := sys.stdin.readline():
    if not line.startswith("TASK: "):
        continue
    data = bytes.fromhex(line.split()[1])
    iv, ciphertext = data[:16], data[16:]

    cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
    try:
        plaintext = unpad(cipher.decrypt(ciphertext), cipher.block_size).decode('latin1')
    except ValueError as e:
        print("Error:", e)
        continue

    if plaintext == "sleep":
        print("Sleeping!")
        time.sleep(1)
    elif plaintext == pw:
        print("Correct! Use /challenge/redeem to redeem the password for the flag!")
    else:
        print("Unknown command!")
```

```py title="/challenge/redeem" showLineNumbers
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

if input("Password? ").strip() == open("/challenge/.pw").read().strip():
    print("Victory! Your flag:")
    print(open("/flag").read())
```

In this challenge, the error message printed by the `/challenge/worker` is our Oracle. For full explanation, read [this blog](https://www.nccgroup.com/research-blog/cryptopals-exploiting-cbc-padding-oracles/), I cannot explain it any better.

We will also be using the code that they have provided.

```py title="~/script.py" showLineNumbers
#!/usr/bin/env python3
from pwn import *

# Set logging level to 'error' to keep the console clean 
context.log_level = 'error'

BLOCK_SIZE = 16

def single_block_attack(block, oracle):
    """
    Returns the decryption of the given ciphertext block (the 'Intermediary' state).
    This function handles the byte-by-byte guessing for a single block.
    """
    zeroing_iv = [0] * BLOCK_SIZE

    for pad_val in range(1, BLOCK_SIZE + 1):
        padding_iv = [pad_val ^ b for b in zeroing_iv]

        found = False
        for candidate in range(256):
            padding_iv[-pad_val] = candidate
            
            # The oracle here is a function passed from full_attack
            if oracle(bytes(padding_iv), block):
                if pad_val == 1:
                    padding_iv[-2] ^= 1
                    if not oracle(bytes(padding_iv), block):
                        continue 
                
                zeroing_iv[-pad_val] = candidate ^ pad_val
                found = True
                break
        
        if not found:
            raise Exception(f"Padding oracle failed at byte {pad_val}")
            
    return zeroing_iv

def full_attack(iv, ct, oracle):
    """
    Given the iv, ciphertext, and a padding oracle, finds and returns the plaintext.
    This handles the CBC chaining logic.
    """
    assert len(iv) == BLOCK_SIZE and len(ct) % BLOCK_SIZE == 0

    msg = iv + ct
    blocks = [msg[i:i+BLOCK_SIZE] for i in range(0, len(msg), BLOCK_SIZE)]
    result = b''

    # Loop over blocks, treating the previous block as the IV for the current one
    current_iv = blocks[0]
    for i, block in enumerate(blocks[1:]):
        print(f"[*] Decrypting block {i+1}...")
        
        # Attack the block to get the intermediary state
        dec = single_block_attack(block, oracle)
        
        # XOR with the previous ciphertext block to get the actual plaintext
        pt = bytes(iv_byte ^ dec_byte for iv_byte, dec_byte in zip(current_iv, dec))
        result += pt
        current_iv = block

    return result

# --- Execution Flow ---

# 1. Get the target ciphertext from dispatcher
dispatcher = process(['/challenge/dispatcher', 'pw'])
target_line = dispatcher.recvline().decode().strip()
target_hex = target_line.split("TASK: ")[1]
target_bytes = bytes.fromhex(target_hex)
dispatcher.close()

# 2. Start the persistent worker process
worker = process(['/challenge/worker'])
worker.recvline() # Clear the "The password is X bytes long!" line

# 3. Define the Oracle wrapper
# This allows the attack functions to use the worker without needing to know about pwnlib
def oracle_wrapper(iv, block):
    payload = (iv + block).hex()
    worker.sendline(f"TASK: {payload}")
    response = worker.readline().decode()
    return "Error" not in response

# 4. Perform the full attack
iv = target_bytes[:BLOCK_SIZE]
ct = target_bytes[BLOCK_SIZE:]

print(f"[+] Starting full attack on {len(ct)//BLOCK_SIZE} blocks...")
decrypted_padded = full_attack(iv, ct, oracle_wrapper)

# 5. Strip PKCS#7 padding and print result
padding_len = decrypted_padded[-1]
final_pw = decrypted_padded[:-padding_len].decode('latin1')

print(f"DECRYPTED PASSWORD: {final_pw}")

worker.close()
```

```
hacker@cryptography~aes-cbc-poa-partial-block:~$ python ~/script.py 
[+] Starting full attack on 1 blocks...
[*] Decrypting block 1/1...
/home/hacker/script.py:16: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  worker.sendline(f"TASK: {payload}")
DECRYPTED PASSWORD: W1qtA5kIIpB1af
```

Now, we can provide this password to `/challenge/redeem` and get the flag.

```
hacker@cryptography~aes-cbc-poa-partial-block:~$ /challenge/redeem 
Password? W1qtA5kIIpB1af
Victory! Your flag:
pwn.college{oUCM-bqrAeL_iMoqkNRCOvNf_tK.QX4EzM2EDL4ITM0EzW}
```

&nbsp;

## AES-CBC-POA-Full-Block

### Source code

```py title="/challenge/dispatcher" showLineNumbers
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

import sys

key = open("/challenge/.key", "rb").read()
cipher = AES.new(key=key, mode=AES.MODE_CBC)

if len(sys.argv) > 1 and sys.argv[1] == "pw":
    plaintext = open("/challenge/.pw", "rb").read().strip()
else:
    plaintext = b"sleep"

ciphertext = cipher.iv + cipher.encrypt(pad(plaintext, cipher.block_size))
print(f"TASK: {ciphertext.hex()}")
```

```py title="/challenge/worker" showLineNumbers
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes

import time
import sys

key = open("/challenge/.key", "rb").read()
pw = open("/challenge/.pw").read().strip()

print(f"The password is {len(pw)} bytes long!")

while line := sys.stdin.readline():
    if not line.startswith("TASK: "):
        continue
    data = bytes.fromhex(line.split()[1])
    iv, ciphertext = data[:16], data[16:]

    cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
    try:
        plaintext = unpad(cipher.decrypt(ciphertext), cipher.block_size).decode('latin1')
    except ValueError as e:
        print("Error:", e)
        continue

    if plaintext == "sleep":
        print("Sleeping!")
        time.sleep(1)
    elif plaintext == pw:
        print("Correct! Use /challenge/redeem to redeem the password for the flag!")
    else:
        print("Unknown command!")
```

```py title="/challenge/redeem" showLineNumbers
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

if input("Password? ").strip() == open("/challenge/.pw").read().strip():
    print("Victory! Your flag:")
    print(open("/flag").read())
```

Our solution from the last challenge will work on this as well.

```py title="~/script.py" showLineNumbers
#!/usr/bin/env python3
from pwn import *

# Set logging level to 'error' to keep the console clean 
context.log_level = 'error'

BLOCK_SIZE = 16

def single_block_attack(block, oracle):
    """
    Returns the decryption of the given ciphertext block (the 'Intermediary' state).
    This function handles the byte-by-byte guessing for a single block.
    """
    zeroing_iv = [0] * BLOCK_SIZE

    for pad_val in range(1, BLOCK_SIZE + 1):
        padding_iv = [pad_val ^ b for b in zeroing_iv]

        found = False
        for candidate in range(256):
            padding_iv[-pad_val] = candidate
            
            # The oracle here is a function passed from full_attack
            if oracle(bytes(padding_iv), block):
                if pad_val == 1:
                    padding_iv[-2] ^= 1
                    if not oracle(bytes(padding_iv), block):
                        continue 
                
                zeroing_iv[-pad_val] = candidate ^ pad_val
                found = True
                break
        
        if not found:
            raise Exception(f"Padding oracle failed at byte {pad_val}")
            
    return zeroing_iv

def full_attack(iv, ct, oracle):
    """
    Given the iv, ciphertext, and a padding oracle, finds and returns the plaintext.
    This handles the CBC chaining logic.
    """
    assert len(iv) == BLOCK_SIZE and len(ct) % BLOCK_SIZE == 0

    msg = iv + ct
    blocks = [msg[i:i+BLOCK_SIZE] for i in range(0, len(msg), BLOCK_SIZE)]
    result = b''

    # Loop over blocks, treating the previous block as the IV for the current one
    current_iv = blocks[0]
    for i, block in enumerate(blocks[1:]):
        print(f"[*] Decrypting block {i+1}...")
        
        # Attack the block to get the intermediary state
        dec = single_block_attack(block, oracle)
        
        # XOR with the previous ciphertext block to get the actual plaintext
        pt = bytes(iv_byte ^ dec_byte for iv_byte, dec_byte in zip(current_iv, dec))
        result += pt
        current_iv = block

    return result

# --- Execution Flow ---

# 1. Get the target ciphertext from dispatcher
dispatcher = process(['/challenge/dispatcher', 'pw'])
target_line = dispatcher.recvline().decode().strip()
target_hex = target_line.split("TASK: ")[1]
target_bytes = bytes.fromhex(target_hex)
dispatcher.close()

# 2. Start the persistent worker process
worker = process(['/challenge/worker'])
worker.recvline() # Clear the "The password is X bytes long!" line

# 3. Define the Oracle wrapper
# This allows the attack functions to use the worker without needing to know about pwnlib
def oracle_wrapper(iv, block):
    payload = (iv + block).hex()
    worker.sendline(f"TASK: {payload}")
    response = worker.readline().decode()
    return "Error" not in response

# 4. Perform the full attack
iv = target_bytes[:BLOCK_SIZE]
ct = target_bytes[BLOCK_SIZE:]

print(f"[+] Starting full attack on {len(ct)//BLOCK_SIZE} blocks...")
decrypted_padded = full_attack(iv, ct, oracle_wrapper)

# 5. Strip PKCS#7 padding and print result
padding_len = decrypted_padded[-1]
final_pw = decrypted_padded[:-padding_len].decode('latin1')

print(f"DECRYPTED PASSWORD: {final_pw}")

worker.close()
```

```
hacker@cryptography~aes-cbc-poa-full-block:~$ python ~/script.py 
[+] Starting full attack on 2 blocks...
[*] Decrypting block 1/2...
/home/hacker/script.py:16: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  worker.sendline(f"TASK: {payload}")
[*] Decrypting block 2/2...
DECRYPTED PASSWORD: RKY4LmMia8cQrIi3
```

```
hacker@cryptography~aes-cbc-poa-full-block:~$ /challenge/redeem 
Password? RKY4LmMia8cQrIi3
Victory! Your flag:
pwn.college{kELoPJer4WkimXiR96tK5jYbWrh.QX5EzM2EDL4ITM0EzW}
```

&nbsp;

## AES-CBC-POA-Multi-Block

### Source code

```py title="/challenge/dispatcher" showLineNumbers
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

import sys

key = open("/challenge/.key", "rb").read()
cipher = AES.new(key=key, mode=AES.MODE_CBC)

if len(sys.argv) > 1 and sys.argv[1] == "flag":
    plaintext = open("/flag", "rb").read().strip()
else:
    plaintext = b"sleep"

ciphertext = cipher.iv + cipher.encrypt(pad(plaintext, cipher.block_size))
print(f"TASK: {ciphertext.hex()}")
```

```py title="/challenge/worker" showLineNumbers
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes

import time
import sys

key = open("/challenge/.key", "rb").read()

while line := sys.stdin.readline():
    if not line.startswith("TASK: "):
        continue
    data = bytes.fromhex(line.split()[1])
    iv, ciphertext = data[:16], data[16:]

    cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
    try:
        plaintext = unpad(cipher.decrypt(ciphertext), cipher.block_size).decode('latin1')
    except ValueError as e:
        print("Error:", e)
        continue

    if plaintext == "sleep":
        print("Sleeping!")
        time.sleep(1)
    else:
        print("Unknown command!")
```

This time we have to call `/challenge/dispatcher` with the `flag` argument, and perform the attack on multiple blocks.

```py title="~/script.py" showLineNumbers
#!/usr/bin/env python3
from pwn import *

# Set logging level to 'error' to keep the console clean 
context.log_level = 'error'

BLOCK_SIZE = 16

def single_block_attack(block, oracle):
    """
    Returns the decryption of the given ciphertext block (the 'Intermediary' state).
    This function handles the byte-by-byte guessing for a single block.
    """
    zeroing_iv = [0] * BLOCK_SIZE

    for pad_val in range(1, BLOCK_SIZE + 1):
        padding_iv = [pad_val ^ b for b in zeroing_iv]

        found = False
        for candidate in range(256):
            padding_iv[-pad_val] = candidate
            
            # The oracle here is a function passed from full_attack
            if oracle(bytes(padding_iv), block):
                # Handle the edge case where the actual plaintext byte might naturally 
                # end in 0x01, creating a false positive for the padding oracle.
                if pad_val == 1:
                    padding_iv[-2] ^= 1
                    if not oracle(bytes(padding_iv), block):
                        continue 
                
                zeroing_iv[-pad_val] = candidate ^ pad_val
                found = True
                break
        
        if not found:
            raise Exception(f"Padding oracle failed at byte {pad_val}")
            
    return zeroing_iv

def full_attack(iv, ct, oracle):
    """
    Given the iv, ciphertext, and a padding oracle, finds and returns the plaintext.
    This handles the CBC chaining logic.
    """
    assert len(iv) == BLOCK_SIZE and len(ct) % BLOCK_SIZE == 0

    msg = iv + ct
    blocks = [msg[i:i+BLOCK_SIZE] for i in range(0, len(msg), BLOCK_SIZE)]
    result = b''

    # Loop over blocks, treating the previous block as the IV for the current one
    current_iv = blocks[0]
    for i, block in enumerate(blocks[1:]):
        print(f"[*] Decrypting block {i+1}...")
        
        # Attack the block to get the intermediary state
        dec = single_block_attack(block, oracle)
        
        # XOR with the previous ciphertext block to get the actual plaintext
        pt = bytes(iv_byte ^ dec_byte for iv_byte, dec_byte in zip(current_iv, dec))
        result += pt
        current_iv = block

    return result

# --- Execution Flow ---

# 1. Get Flag
disp = process(['/challenge/dispatcher', 'flag'])
data = bytes.fromhex(disp.recvline().decode().split("TASK: ")[1])
disp.close()

# 2. Start Worker
worker = process(['/challenge/worker'])

# 3. Define the Oracle wrapper
def oracle_wrapper(iv, block):
    payload = (iv + block).hex()
    worker.sendline(f"TASK: {payload}")
    response = worker.readline().decode()
    return "Error" not in response

# 4. Perform the full attack
iv = data[:BLOCK_SIZE]
ct = data[BLOCK_SIZE:]

print(f"[+] Starting full attack on {len(ct)//BLOCK_SIZE} blocks...")
decrypted_padded = full_attack(iv, ct, oracle_wrapper)

# 5. Strip PKCS#7 padding and print result
padding_len = decrypted_padded[-1]
final_output = decrypted_padded[:-padding_len].decode('latin1')

print(f"DECRYPTED FLAG: {final_output}")

worker.close()
```

```
hacker@cryptography~aes-cbc-poa-multi-block:/$ python ~/script.py 
[+] Starting full attack on 4 blocks...
[*] Decrypting block 1...
/home/hacker/script.py:80: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  worker.sendline(f"TASK: {payload}")
[*] Decrypting block 2...
[*] Decrypting block 3...
[*] Decrypting block 4...
DECRYPTED FLAG: pwn.college{s3BeSgy9UkMJLF5j5pgb4aihoE0.dBDN3kDL4ITM0EzW}
```

&nbsp;

## AES-CBC-POA-Encrypt

### Source code

```py title="/challenge/dispatcher" showLineNumbers
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

import os

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

key = open("/challenge/.key", "rb").read()
cipher = AES.new(key=key, mode=AES.MODE_CBC)
ciphertext = cipher.iv + cipher.encrypt(pad(b"sleep", cipher.block_size))

print(f"TASK: {ciphertext.hex()}")
```

```py title="/challenge/worker" showLineNumbers
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes

import time
import sys

key = open("/challenge/.key", "rb").read()

while line := sys.stdin.readline():
    if not line.startswith("TASK: "):
        continue
    data = bytes.fromhex(line.split()[1])
    iv, ciphertext = data[:16], data[16:]

    cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
    try:
        plaintext = unpad(cipher.decrypt(ciphertext), cipher.block_size).decode('latin1')
    except ValueError as e:
        print("Error:", e)
        continue

    if plaintext == "sleep":
        print("Sleeping!")
        time.sleep(1)
    elif plaintext == "please give me the flag, kind worker process!":
        print("Victory! Your flag:")
        print(open("/flag").read())
    else:
        print("Unknown command!")
```

Go through [this](https://shrutipriya.com/blogs/yet-another-guide-to-padding-oracle-attack/) explaination.

```py title="~/script.py" showLineNumbers
#!/usr/bin/env python3
from pwn import *
import os

# Set logging level
context.log_level = 'error'
BLOCK_SIZE = 16

def get_intermediate_block(target_block, oracle):
    """
    Standard Padding Oracle attack to find the Intermediate State (I)
    of a specific ciphertext block.
    """
    intermediate = [0] * BLOCK_SIZE
    
    for pad_val in range(1, BLOCK_SIZE + 1):
        # Prepare an IV that forces the desired padding
        prefix = [0] * (BLOCK_SIZE - pad_val)
        suffix = [intermediate[i] ^ pad_val for i in range(BLOCK_SIZE - pad_val, BLOCK_SIZE)]
        test_iv = prefix + [0] + suffix[1:] if pad_val > 1 else prefix + [0]

        found = False
        for candidate in range(256):
            test_iv[BLOCK_SIZE - pad_val] = candidate
            
            if oracle(bytes(test_iv), target_block):
                # Double check for false positives on first byte
                if pad_val == 1:
                    test_iv[BLOCK_SIZE - 2] ^= 1
                    if not oracle(bytes(test_iv), target_block):
                        continue
                
                intermediate[BLOCK_SIZE - pad_val] = candidate ^ pad_val
                found = True
                break
        
        if not found:
            raise Exception(f"Failed to find intermediate byte at pad {pad_val}")
            
    return bytes(intermediate)

# 1. Start Worker Process
worker = process(['/challenge/worker'])

def oracle_wrapper(iv, block):
    payload = (iv + block).hex()
    worker.sendline(f"TASK: {payload}")
    response = worker.readline().decode()
    return "Error" not in response

# 2. Prepare the target plaintext
target_plaintext = b"please give me the flag, kind worker process!"

# Manual PKCS#7 Padding
pad_len = BLOCK_SIZE - (len(target_plaintext) % BLOCK_SIZE)
padded_pt = target_plaintext + bytes([pad_len] * pad_len)

# Split into blocks
pt_blocks = [padded_pt[i:i+BLOCK_SIZE] for i in range(0, len(padded_pt), BLOCK_SIZE)]

# 3. Encryption Attack (Working Backwards)
# Start with a random final block
current_ciphertext_block = os.urandom(BLOCK_SIZE)
full_payload = current_ciphertext_block

print(f"[*] Starting encryption of {len(pt_blocks)} blocks...")

for pt_block in reversed(pt_blocks):
    print(f"[*] Forging block for: {pt_block}")
    
    # Find the intermediate state of the current block
    intermediate = get_intermediate_block(current_ciphertext_block, oracle_wrapper)
    
    # Calculate the previous block (which acts as the IV for this one)
    # IV = Intermediate ^ Plaintext
    prev_block = bytes(i ^ p for i, p in zip(intermediate, pt_block))
    
    # Prepend to our growing ciphertext
    full_payload = prev_block + full_payload
    current_ciphertext_block = prev_block

# 4. Execute the Forged Ciphertext
print("[+] Forgery complete. Sending payload...")
worker.sendline(f"TASK: {full_payload.hex()}")

# The worker should now output the flag
while True:
    line = worker.readline().decode().strip()
    if line:
        print(line)
    if "Victory" in line or not line:
        # Read the actual flag line
        print(worker.readline().decode().strip())
        break

worker.close()
```

```
hacker@cryptography~aes-cbc-poa-encrypt:/$ python ~/script.py
[*] Starting encryption of 3 blocks...
[*] Forging block for: b'rker process!\x03\x03\x03'
/home/hacker/script.py:47: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  worker.sendline(f"TASK: {payload}")
[*] Forging block for: b'he flag, kind wo'
[*] Forging block for: b'please give me t'
[+] Forgery complete. Sending payload...
/home/hacker/script.py:84: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  worker.sendline(f"TASK: {full_payload.hex()}")
Victory! Your flag:
pwn.college{USmSYRj-VmwCCCdKX1QWNUyadUE.dFDN3kDL4ITM0EzW}
```

&nbsp;

## AES-CBC-POA-Encrypt-2

### Source code

```py title="/challenge/worker" showLineNumbers
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes

import time
import sys

key = open("/challenge/.key", "rb").read()

while line := sys.stdin.readline():
    if not line.startswith("TASK: "):
        continue
    data = bytes.fromhex(line.split()[1])
    iv, ciphertext = data[:16], data[16:]

    cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
    try:
        plaintext = unpad(cipher.decrypt(ciphertext), cipher.block_size).decode('latin1')
    except ValueError as e:
        print("Error:", e)
        continue

    if plaintext == "sleep":
        print("Sleeping!")
        time.sleep(1)
    elif plaintext == "please give me the flag, kind worker process!":
        print("Victory! Your flag:")
        print(open("/flag").read())
    else:
        print("Unknown command!")
```

Since we did not rely on the `/challenge/dispatcher` in the previous challenge, our script will work in this one as well.

```py title="~/script.py" showLineNumbers
#!/usr/bin/env python3
from pwn import *
import os

# Set logging level
context.log_level = 'error'
BLOCK_SIZE = 16

def get_intermediate_block(target_block, oracle):
    """
    Standard Padding Oracle attack to find the Intermediate State (I)
    of a specific ciphertext block.
    """
    intermediate = [0] * BLOCK_SIZE
    
    for pad_val in range(1, BLOCK_SIZE + 1):
        # Prepare an IV that forces the desired padding
        prefix = [0] * (BLOCK_SIZE - pad_val)
        suffix = [intermediate[i] ^ pad_val for i in range(BLOCK_SIZE - pad_val, BLOCK_SIZE)]
        test_iv = prefix + [0] + suffix[1:] if pad_val > 1 else prefix + [0]

        found = False
        for candidate in range(256):
            test_iv[BLOCK_SIZE - pad_val] = candidate
            
            if oracle(bytes(test_iv), target_block):
                # Double check for false positives on first byte
                if pad_val == 1:
                    test_iv[BLOCK_SIZE - 2] ^= 1
                    if not oracle(bytes(test_iv), target_block):
                        continue
                
                intermediate[BLOCK_SIZE - pad_val] = candidate ^ pad_val
                found = True
                break
        
        if not found:
            raise Exception(f"Failed to find intermediate byte at pad {pad_val}")
            
    return bytes(intermediate)

# 1. Start Worker Process
worker = process(['/challenge/worker'])

def oracle_wrapper(iv, block):
    payload = (iv + block).hex()
    worker.sendline(f"TASK: {payload}")
    response = worker.readline().decode()
    return "Error" not in response

# 2. Prepare the target plaintext
target_plaintext = b"please give me the flag, kind worker process!"

# Manual PKCS#7 Padding
pad_len = BLOCK_SIZE - (len(target_plaintext) % BLOCK_SIZE)
padded_pt = target_plaintext + bytes([pad_len] * pad_len)

# Split into blocks
pt_blocks = [padded_pt[i:i+BLOCK_SIZE] for i in range(0, len(padded_pt), BLOCK_SIZE)]

# 3. Encryption Attack (Working Backwards)
# Start with a random final block
current_ciphertext_block = os.urandom(BLOCK_SIZE)
full_payload = current_ciphertext_block

print(f"[*] Starting encryption of {len(pt_blocks)} blocks...")

for pt_block in reversed(pt_blocks):
    print(f"[*] Forging block for: {pt_block}")
    
    # Find the intermediate state of the current block
    intermediate = get_intermediate_block(current_ciphertext_block, oracle_wrapper)
    
    # Calculate the previous block (which acts as the IV for this one)
    # IV = Intermediate ^ Plaintext
    prev_block = bytes(i ^ p for i, p in zip(intermediate, pt_block))
    
    # Prepend to our growing ciphertext
    full_payload = prev_block + full_payload
    current_ciphertext_block = prev_block

# 4. Execute the Forged Ciphertext
print("[+] Forgery complete. Sending payload...")
worker.sendline(f"TASK: {full_payload.hex()}")

# The worker should now output the flag
while True:
    line = worker.readline().decode().strip()
    if line:
        print(line)
    if "Victory" in line or not line:
        # Read the actual flag line
        print(worker.readline().decode().strip())
        break

worker.close()
```

```
hacker@cryptography~aes-cbc-poa-encrypt-2:/$ python ~/script.py 
[*] Starting encryption of 3 blocks...
[*] Forging block for: b'rker process!\x03\x03\x03'
/home/hacker/script.py:47: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  worker.sendline(f"TASK: {payload}")
[*] Forging block for: b'he flag, kind wo'
[*] Forging block for: b'please give me t'
[+] Forgery complete. Sending payload...
/home/hacker/script.py:84: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  worker.sendline(f"TASK: {full_payload.hex()}")
Victory! Your flag:
pwn.college{YwEFkr3zdczPL_Gbszd9TskEWvl.QX0IzN4EDL4ITM0EzW}
```

&nbsp;

## DHKE

### Source code
```py title="/challenge/run" showLineNumbers
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

import sys
from Crypto.Random.random import getrandbits

# 2048-bit MODP Group from RFC3526
p = int.from_bytes(bytes.fromhex(
    "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 "
    "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD "
    "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245 "
    "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED "
    "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D "
    "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F "
    "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D "
    "670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B "
    "E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 "
    "DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510 "
    "15728E5A 8AACAA68 FFFFFFFF FFFFFFFF"
), "big")
g = 2
print(f"p = {p:#x}")
print(f"g = {g:#x}")

a = getrandbits(2048)
A = pow(g, a, p)
print(f"A = {A:#x}")

try:
    B = int(input("B? "), 16)
except ValueError:
    print("Invalid B value (not a hex number)", file=sys.stderr)
    sys.exit(1)
if B <= 2**1024:
    print("Invalid B value (B <= 2**1024)", file=sys.stderr)
    sys.exit(1)

s = pow(B, a, p)
try:
    if int(input("s? "), 16) == s:
        print("Correct! Here is your flag:")
        print(open("/flag").read())
    else:
        print("Incorrect... Should have been:", file=sys.stderr)
        print(f"s = {s:#x}")
except ValueError:
    print("Invalid s value (not a hex number)", file=sys.stderr)
    sys.exit(1)
```

```
hacker@cryptography~dhke:/$ /challenge/run 
p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff
g = 0x2
A = 0x776d7f2cfd9c66791e6920fdc1bf9ab8425c11be28aad6001913bdd47fa49c373b386236b6016b622decf9cf69c50336a52e446b9e1a87b670e11be43b08130f2751b0910147c8b58d5b10d6a03a04481979930a1f0bece51d12669a930805ab9b8cb4f654ada5cef2e1000614d337187f4db2de8025a18d85e4e5f611648f9c69137348d5b293c36f1a1e26055644a78b4c739cb22ec8cba9fe526be7033846f6933e5bd9c023fcbfd15c5216950bf56d72b4a8b0d24e8bf6f3901987e3855e0c12d6858fbcb6ba9fbd55ba4dee60370ed4e4225e7060c6b3f48931226a229c51b3c2ccbca2bfe3704b8fbc00f4d0d687d42afbef6b4d385b6161220683cefd
B? 
```

We just need to calculate the intermediate logarithmic modulus.

```py title="~/script.py" showLineNumbers
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

import sys
from Crypto.Random.random import getrandbits

# 2048-bit MODP Group from RFC3526
p = int.from_bytes(bytes.fromhex(
    "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 "
    "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD "
    "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245 "
    "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED "
    "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D "
    "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F "
    "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D "
    "670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B "
    "E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 "
    "DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510 "
    "15728E5A 8AACAA68 FFFFFFFF FFFFFFFF"
), "big")
g = 2
print(f"p = {p:#x}")
print(f"g = {g:#x}")

b = getrandbits(2048)
B = pow(g, b, p)        # B = (g ** b) % p
print(f"B = {B:#x}")

A = 0x776d7f2cfd9c66791e6920fdc1bf9ab8425c11be28aad6001913bdd47fa49c373b386236b6016b622decf9cf69c50336a52e446b9e1a87b670e11be43b08130f2751b0910147c8b58d5b10d6a03a04481979930a1f0bece51d12669a930805ab9b8cb4f654ada5cef2e1000614d337187f4db2de8025a18d85e4e5f611648f9c69137348d5b293c36f1a1e26055644a78b4c739cb22ec8cba9fe526be7033846f6933e5bd9c023fcbfd15c5216950bf56d72b4a8b0d24e8bf6f3901987e3855e0c12d6858fbcb6ba9fbd55ba4dee60370ed4e4225e7060c6b3f48931226a229c51b3c2ccbca2bfe3704b8fbc00f4d0d687d42afbef6b4d385b6161220683cefd
s = pow(A, b, p)        # s = (A ** b) % p = ((g ** a) ** b) % p = (g ** (a * b)) % p
print(f"s = {s:#x}")
```

```
hacker@cryptography~dhke:/$ python ~/script.py 
p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff
g = 0x2
B = 0x565d71332fda27233a0de2869d6c82f6d6e2567ae4d85ce8bf319124507ae3a3b258804db58731ffbae384aa99b9d56131ce4e911530dbf2c0d7874e80502861f30e8d758f7bf2f1b7b9eca630d02bcc97f05ffe3922a1957e4e42dfe15b71f4a0c494c127565bc6ad07f283e4789f4ba11e4f82f377beecccf18a5321d87870fe777143858dddb35f36c1604218afd256cadaf1e49ad64426a4639b0723338a484a09fcc818f277703d96d253c62561fb160713b9b2edccc91871bf65b65cde6da89c8a210faad210f6a26322d225b34f4c7cc9cdeab664623d9422b4c4ea62ea10d2fee178f6a24284d16777c08c82cf06c277fc657cb6f1037a3974f25a96
s = 0x50b6ae92661f4a424752310aa9e81912ca6a27fe6be5698a6aa0858ce173eb01cb35c9f011940b41aee5d8a9f7739c12572d439ff80fdd7f4cdf79f063f8ac707ad59841b1a979b26eca71343133ae949ea499f704d7f9e71ec899b438b0fc69c29b9e2a9e764f9039950aefd97d3c8fc78150ee4132580508bb4f1283bc9642b5d9ae758e88934665d3b9ddac6f5d22021e09a4bc234ff5982e31eabfdde92186b25ac97e20fba93cb9495dcdf125201c47e69066b53d8341c4e8bbb56fa98c1bc5c866d41c293dfd17c40513f16abdef5b44b8a04aeff6c045591631156495252ec195d3bd850b0770445ac1160c5f14cbed22327103191de4a1a80b8d1118
```

```
hacker@cryptography~dhke:/$ /challenge/run 
p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff
g = 0x2
A = 0x776d7f2cfd9c66791e6920fdc1bf9ab8425c11be28aad6001913bdd47fa49c373b386236b6016b622decf9cf69c50336a52e446b9e1a87b670e11be43b08130f2751b0910147c8b58d5b10d6a03a04481979930a1f0bece51d12669a930805ab9b8cb4f654ada5cef2e1000614d337187f4db2de8025a18d85e4e5f611648f9c69137348d5b293c36f1a1e26055644a78b4c739cb22ec8cba9fe526be7033846f6933e5bd9c023fcbfd15c5216950bf56d72b4a8b0d24e8bf6f3901987e3855e0c12d6858fbcb6ba9fbd55ba4dee60370ed4e4225e7060c6b3f48931226a229c51b3c2ccbca2bfe3704b8fbc00f4d0d687d42afbef6b4d385b6161220683cefd
B? 0x565d71332fda27233a0de2869d6c82f6d6e2567ae4d85ce8bf319124507ae3a3b258804db58731ffbae384aa99b9d56131ce4e911530dbf2c0d7874e80502861f30e8d758f7bf2f1b7b9eca630d02bcc97f05ffe3922a1957e4e42dfe15b71f4a0c494c127565bc6ad07f283e4789f4ba11e4f82f377beecccf18a5321d87870fe777143858dddb35f36c1604218afd256cadaf1e49ad64426a4639b0723338a484a09fcc818f277703d96d253c62561fb160713b9b2edccc91871bf65b65cde6da89c8a210faad210f6a26322d225b34f4c7cc9cdeab664623d9422b4c4ea62ea10d2fee178f6a24284d16777c08c82cf06c277fc657cb6f1037a3974f25a96
s? 0x50b6ae92661f4a424752310aa9e81912ca6a27fe6be5698a6aa0858ce173eb01cb35c9f011940b41aee5d8a9f7739c12572d439ff80fdd7f4cdf79f063f8ac707ad59841b1a979b26eca71343133ae949ea499f704d7f9e71ec899b438b0fc69c29b9e2a9e764f9039950aefd97d3c8fc78150ee4132580508bb4f1283bc9642b5d9ae758e88934665d3b9ddac6f5d22021e09a4bc234ff5982e31eabfdde92186b25ac97e20fba93cb9495dcdf125201c47e69066b53d8341c4e8bbb56fa98c1bc5c866d41c293dfd17c40513f16abdef5b44b8a04aeff6c045591631156495252ec195d3bd850b0770445ac1160c5f14cbed22327103191de4a1a80b8d1118
Correct! Here is your flag:
pwn.college{UxMYt-UysLwgfy3zgOXhtbbrEGg.dhzNzMDL4ITM0EzW}
```

&nbsp;

## DHKE-to-AES

### Source code
```py title="/challenge/run" showLineNumbers
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random.random import getrandbits

flag = open("/flag", "rb").read()
assert len(flag) <= 256

# 2048-bit MODP Group from RFC3526
p = int.from_bytes(bytes.fromhex(
    "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 "
    "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD "
    "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245 "
    "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED "
    "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D "
    "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F "
    "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D "
    "670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B "
    "E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 "
    "DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510 "
    "15728E5A 8AACAA68 FFFFFFFF FFFFFFFF"
), "big")
g = 2
print(f"p = {p:#x}")
print(f"g = {g:#x}")

a = getrandbits(2048)
A = pow(g, a, p)
print(f"A = {A:#x}")

try:
    B = int(input("B? "), 16)
except ValueError:
    print("Invalid B value (not a hex number)", file=sys.stderr)
    sys.exit(1)
if B <= 2**1024:
    print("Invalid B value (B <= 2**1024)", file=sys.stderr)
    sys.exit(1)

s = pow(B, a, p)
key = s.to_bytes(256, "little")[:16]

# friendship ended with DHKE, AES is my new best friend
cipher = AES.new(key=key, mode=AES.MODE_CBC)
flag = open("/flag", "rb").read()
ciphertext = cipher.iv + cipher.encrypt(pad(flag, cipher.block_size))
print(f"Flag Ciphertext (hex): {ciphertext.hex()}")
```

```
hacker@cryptography~dhke-to-aes:/$ /challenge/run 
p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff
g = 0x2
A = 0xcad3b10018745d0936249e79b6a0086d3aefd969b095a78cb07687f38ce570b5a1f34d4208887de02dcb8db3c1d90805cf00d9f01dcaa245eb1309c0682c815b2979a7d799a490b89e86d33262e4caa38ae43f757149f6b06a526532edf5b60e06adabbf11d477af53a2b1571e72c7dcc751f840d33b7d6b8ef6bb24ea92d046c2b1c87c7dbd56e525cb47e3f7ab11b601a2347704d44462a1325a387ff40777d201aeb336afeaaf6ffd910f97a0bd727c0465d4ac4add2243b0fd1d3fcc12b4358f3e5a75e31517e86f9bc1adf9cf342a60b9d2a9f9431776b0c5a97d101e529fe452def9b293fec236e181ccc827787b210164aa64e6f4ac8c71869728faa3
B? 
```

This time the secret (`s`) will be the AES encoded flag.

```python title="~/script.py" showLineNumbers
#!/usr/bin/exec-suid -- /usr/bin/python3 -I
from pwn import *
import re
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

context.log_level = "error"
io = process("/challenge/run")

# Grab everything printed at start
start = io.recvuntil(b"A = ")

# Extract p, g, A using regex on whole buffer
p = int(re.search(r"p\s*=\s*(0x[0-9a-fA-F]+)", start.decode()).group(1), 16)
g = int(re.search(r"g\s*=\s*(0x[0-9a-fA-F]+)", start.decode()).group(1), 16)
A = int(re.search(r"g\s*=\s*(0x[0-9a-fA-F]+)", start.decode()).group(1), 16)

# Exploit: B = p + 1 → shared secret = 1
B = p + 1
io.sendlineafter(b"B?", hex(B).encode())

# Read everything the program prints after sending B
out = io.recvall(timeout=2)

# Extract ciphertext
m = re.search(rb"Flag Ciphertext\s*\(hex\)\s*:\s*([0-9a-fA-F]+)", out)
if not m:
    print("[-] Failed to find ciphertext. Output was:")
    print(out.decode(errors="replace"))
    exit(1)

ct = bytes.fromhex(m.group(1).decode())

# Split IV & ciphertext and decrypt
iv = ct[:16]
ciphertext = ct[16:]
key = (1).to_bytes(256, "little")[:16]

cipher = AES.new(key, AES.MODE_CBC, iv)
flag = unpad(cipher.decrypt(ciphertext), AES.block_size)

print("FLAG:", flag.decode(errors="replace"))
```

```
hacker@cryptography~dhke-to-aes:/$ python ~/script.py 
FLAG: pwn.college{AV5q8typYMd4AQiAMRZiN3zq4l_.dNDN3kDL4ITM0EzW}
```

&nbsp;

## RSA 1

### Source code
```py title="/challenge/run" showLineNumbers
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

from Crypto.PublicKey import RSA

flag = open("/flag", "rb").read()
assert len(flag) <= 256

key = RSA.generate(2048)
print(f"(public)  n = {key.n:#x}")
print(f"(public)  e = {key.e:#x}")
print(f"(private) d = {key.d:#x}")

ciphertext = pow(int.from_bytes(flag, "little"), key.e, key.n).to_bytes(256, "little")
print(f"Flag Ciphertext (hex): {ciphertext.hex()}")
```

```
hacker@cryptography~rsa-1:/$ /challenge/run 
(public)  n = 0x932f4eb6d627ae22947f36fdb81861137003b4c23cc4c2f1e41b70b53a7ea5fd9d08d4cbbdf2b1d98cf63ec67a75d0dab6ba9f5a385462275350aca3a1da1210052e54b4db9b7cddad4def27eb44638ec2cd56e7aad91c703a3ff5f332a7b03806f3a3cd61c96185dc03ba8e5341cd3eef478b8f40bbfee68b574f38fe897cfbfd094a91d0d2acbe789450191c83cb12eb268f05445e583bd3c22334f2552bbdc80eca5debba4945f2db7b207b8c4e1158ef74eec04c670b68166de0410a5713b14b9b23bcfe9595af166b02afa204c075407806e76899fb44e66d3a72570d89a4b6bef23dd6163cf5b3e14ce29429df820c0a4f3ab0b07baaf85063720708d5
(public)  e = 0x10001
(private) d = 0x359b9f71dca26b3c5115dcb3a09fd08bc1dab7b59f6893108362b3346eefbe09976ea602e756440cd6d8c1988cf5e87220e7ec2e7221d9f634d4476cfa00715fc063559ae1f9ca0afb9a4d271efbb3bf459880b4b4778b721ce53af1af5b804587d2a9b09e9338a006b89cf445c2cbbcc66e2a98ac9d4c842ff046fc9d48fa6a482259b8a8234cc498f41bc3c571701d9a4c0f465dc569e7db27790062ec0cbdea5661e901cb9caae04d46807cd21db92957d440210452fa142a927891548ffdf718020b8f86ee371e9bde72b57fa898271449390d5d485b3085d1b85421e0615b694ff42d1e8e36cf2b26ed567999c955edba513875c33eabf6b7871a87a469
Flag Ciphertext (hex): ea1b7ab0d106385263dfe2b21f6e907c076714c1632bde8d26e47d04515e3181b23ab4a87c6b651282047e5e4188fb4a5042a04a6a093f0fcf21889917e81f8e91a1bbbf1643b1777b453177b8df8299850fa3ddb73990bcec4d9ce7990c7b304861483816d5d70c510125b9ac820b39c212051a8a77d7b36b7bfff84eba1b376d2941f1ed5e35c5f44af26b996feeeb03b00c079785aee5097eaaf1b7bf16140e1fa3cb1347571f80388a5f3b759f21e66cc57bdae032dfde026bf554c44fcedd395b3364b5e7887d575ebbfcb4b422976449dd23c300d99cf1533f678d110970eebf5e717991f9925c0af90fab7febfdb0fd4f6ec84296d71dd01bd2fa7908
```

Since we have been provided with the decryption key as well (`d`), we can simply write a script to get the decrypted flag.

```python title="~/script.py" showLineNumbers
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

from Crypto.PublicKey import RSA

ciphertext_hex = "ea1b7ab0d106385263dfe2b21f6e907c076714c1632bde8d26e47d04515e3181b23ab4a87c6b651282047e5e4188fb4a5042a04a6a093f0fcf21889917e81f8e91a1bbbf1643b1777b453177b8df8299850fa3ddb73990bcec4d9ce7990c7b304861483816d5d70c510125b9ac820b39c212051a8a77d7b36b7bfff84eba1b376d2941f1ed5e35c5f44af26b996feeeb03b00c079785aee5097eaaf1b7bf16140e1fa3cb1347571f80388a5f3b759f21e66cc57bdae032dfde026bf554c44fcedd395b3364b5e7887d575ebbfcb4b422976449dd23c300d99cf1533f678d110970eebf5e717991f9925c0af90fab7febfdb0fd4f6ec84296d71dd01bd2fa7908"

n = 0x932f4eb6d627ae22947f36fdb81861137003b4c23cc4c2f1e41b70b53a7ea5fd9d08d4cbbdf2b1d98cf63ec67a75d0dab6ba9f5a385462275350aca3a1da1210052e54b4db9b7cddad4def27eb44638ec2cd56e7aad91c703a3ff5f332a7b03806f3a3cd61c96185dc03ba8e5341cd3eef478b8f40bbfee68b574f38fe897cfbfd094a91d0d2acbe789450191c83cb12eb268f05445e583bd3c22334f2552bbdc80eca5debba4945f2db7b207b8c4e1158ef74eec04c670b68166de0410a5713b14b9b23bcfe9595af166b02afa204c075407806e76899fb44e66d3a72570d89a4b6bef23dd6163cf5b3e14ce29429df820c0a4f3ab0b07baaf85063720708d5
e = 0x10001
d = 0x359b9f71dca26b3c5115dcb3a09fd08bc1dab7b59f6893108362b3346eefbe09976ea602e756440cd6d8c1988cf5e87220e7ec2e7221d9f634d4476cfa00715fc063559ae1f9ca0afb9a4d271efbb3bf459880b4b4778b721ce53af1af5b804587d2a9b09e9338a006b89cf445c2cbbcc66e2a98ac9d4c842ff046fc9d48fa6a482259b8a8234cc498f41bc3c571701d9a4c0f465dc569e7db27790062ec0cbdea5661e901cb9caae04d46807cd21db92957d440210452fa142a927891548ffdf718020b8f86ee371e9bde72b57fa898271449390d5d485b3085d1b85421e0615b694ff42d1e8e36cf2b26ed567999c955edba513875c33eabf6b7871a87a469

# Convert ciphertext to bytes
ciphertext_bytes = bytes.fromhex(ciphertext_hex)

# Convert ciphertext to integer
ciphertext_int = int.from_bytes(ciphertext_bytes, "little")

# Compute modulus byte length
mod_len = (n.bit_length() + 7) // 8

# -------- RSA private decrypt --------
flag_int = pow(ciphertext_int, d, n)
flag_bytes = flag_int.to_bytes(mod_len, "little")

# Strip trailing null bytes and the newline at the end
flag = flag_bytes.rstrip(b"\x00").rstrip(b"\n")

print("Flag:", flag.decode())
```

```
hacker@cryptography~rsa-1:/$ python ~/script.py 
Flag: pwn.college{ISQNrKg1YuSVjLUKzY4tPKJoBXH.dlzNzMDL4ITM0EzW}
```

&nbsp;

## RSA 2

### Source code
```py title="/challenge/run" showLineNumbers
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

from Crypto.PublicKey import RSA

flag = open("/flag", "rb").read()
assert len(flag) <= 256

key = RSA.generate(2048)
print(f"e = {key.e:#x}")
print(f"p = {key.p:#x}")
print(f"q = {key.q:#x}")

ciphertext = pow(int.from_bytes(flag, "little"), key.e, key.n).to_bytes(256, "little")
print(f"Flag Ciphertext (hex): {ciphertext.hex()}")
```

```
hacker@cryptography~rsa-2:/$ /challenge/run 
e = 0x10001
p = 0xbf2d3affdef500aaf039aec8c60d275b8077ec5a3e7016eaa9428fda6d01a45acf8770f1f1488e04130bd4c1a9f858b2f46d8ad6e3160af2ba151131d3764d1755e6edf4857651215236bf070488c5a3b762a6969609920745c291c566294d7bf8ef7d2008055d004f9d7c10d3bd55795e434c1746d4dab0f554fdeb9d768dd7
q = 0xbfe1734af8c0b4d66cda8dce2ccc32106d2d0d14665c51baddc6a0da16f5fba82e7773275ecaa1458fd7a093ca80d6821161a5ca1803e9a3c8af1983ee7b792c0fc6b0e589b64baa6b1532224387f5f3e34e4ec7c2a77e2d4aa6fe2716301b7d29406d8716ab0ebe2aac13afce771600092e14e0b61d6a65bd85376447c771a3
Flag Ciphertext (hex): 87ad16387c48ce5ee9fabb30f125b48c637ac296a04f5e26ce02b46ebd07b30ce51611467983272e299ac75789790f03955984cf0a52f059323977cd703ce8e45239cfe798836f994e7594baf9cdcfed7055357b829fb3dc897abdb44d038bffaad24856ca5f32848021a1b10f3889fd004ffce2310755fc429fd75847e6fedd10280568439e78a07d7c4fc7dd267ed7ad97ba093b504e1e4d32c4493c2eba006c4988118b9293514731f7b2febf12e905e3a1ce78e01c10aa543e06bf102f97d226a879e50d0c14e453f509f9573c9fa8b4c15a90926861b2c92dc6e916cdeacd591a02f097fa43bf9484f522e3df723b99754cb021f7f3f2a91b0730bb4f0d
```

This time, instead of `n` and `d`, we have been provided with `p` and `q`.

```py title="~/script.py" showLineNumbers
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse

ciphertext_hex = "87ad16387c48ce5ee9fabb30f125b48c637ac296a04f5e26ce02b46ebd07b30ce51611467983272e299ac75789790f03955984cf0a52f059323977cd703ce8e45239cfe798836f994e7594baf9cdcfed7055357b829fb3dc897abdb44d038bffaad24856ca5f32848021a1b10f3889fd004ffce2310755fc429fd75847e6fedd10280568439e78a07d7c4fc7dd267ed7ad97ba093b504e1e4d32c4493c2eba006c4988118b9293514731f7b2febf12e905e3a1ce78e01c10aa543e06bf102f97d226a879e50d0c14e453f509f9573c9fa8b4c15a90926861b2c92dc6e916cdeacd591a02f097fa43bf9484f522e3df723b99754cb021f7f3f2a91b0730bb4f0d"

p = 0xbf2d3affdef500aaf039aec8c60d275b8077ec5a3e7016eaa9428fda6d01a45acf8770f1f1488e04130bd4c1a9f858b2f46d8ad6e3160af2ba151131d3764d1755e6edf4857651215236bf070488c5a3b762a6969609920745c291c566294d7bf8ef7d2008055d004f9d7c10d3bd55795e434c1746d4dab0f554fdeb9d768dd7
q = 0xbfe1734af8c0b4d66cda8dce2ccc32106d2d0d14665c51baddc6a0da16f5fba82e7773275ecaa1458fd7a093ca80d6821161a5ca1803e9a3c8af1983ee7b792c0fc6b0e589b64baa6b1532224387f5f3e34e4ec7c2a77e2d4aa6fe2716301b7d29406d8716ab0ebe2aac13afce771600092e14e0b61d6a65bd85376447c771a3
e = 0x10001

# Calculate `n`
n = p * q

# Calculate Euler's totient `phi_n`
phi_n = (p - 1) * (q - 1)

# Calculate `d`
d = inverse(e, phi_n)

# Convert ciphertext to bytes
ciphertext_bytes = bytes.fromhex(ciphertext_hex)

# Convert ciphertext to integer
ciphertext_int = int.from_bytes(ciphertext_bytes, "little")

# Compute modulus byte length
mod_len = (n.bit_length() + 7) // 8

# -------- RSA private decrypt --------
flag_int = pow(ciphertext_int, d, n)
flag_bytes = flag_int.to_bytes(mod_len, "little")

# Strip trailing null bytes and the newline at the end
flag = flag_bytes.rstrip(b"\x00").rstrip(b"\n")

print("Flag:", flag.decode())
```

```
hacker@cryptography~rsa-2:/$ python ~/script.py 
Flag: pwn.college{kvHnhBPZ6yStB5IhjIqNOIEP33t.dBDOzMDL4ITM0EzW}
```

&nbsp;

## RSA 3

### Source code
```py title="/challenge/run" showLineNumbers
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

import sys
import string
import random
import pathlib
import base64
import json
import textwrap

from Crypto.Cipher import AES
from Crypto.Hash.SHA256 import SHA256Hash
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Random.random import getrandbits, randrange
from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad, unpad


flag = open("/flag", "rb").read()
config = (pathlib.Path(__file__).parent / ".config").read_text()
level = int(config)


def show(name, value, *, b64=True):
    print(f"{name}: {value}")


def show_b64(name, value):
    show(f"{name} (b64)", base64.b64encode(value).decode())

def show_hex_block(name, value, byte_block_size=16):
    value_to_show = ""

    for i in range(0, len(value), byte_block_size):
        value_to_show += f"{value[i:i+byte_block_size].hex()}"
        value_to_show += " "
    show(f"{name} (hex)", value_to_show)


def show_hex(name, value):
    show(name, hex(value))


def input_(name):
    try:
        return input(f"{name}: ")
    except (KeyboardInterrupt, EOFError):
        print()
        exit(0)


def input_b64(name):
    data = input_(f"{name} (b64)")
    try:
        return base64.b64decode(data)
    except base64.binascii.Error:
        print(f"Failed to decode base64 input: {data!r}", file=sys.stderr)
        exit(1)


def input_hex(name):
    data = input_(name)
    try:
        return int(data, 16)
    except Exception:
        print(f"Failed to decode hex input: {data!r}", file=sys.stderr)
        exit(1)

# ---- snip ----

def level11():
    """
    In this challenge you will complete an RSA challenge-response.
    You will be provided with both the public key and private key.
    """
    key = RSA.generate(2048)

    show_hex("e", key.e)
    show_hex("d", key.d)
    show_hex("n", key.n)

    challenge = int.from_bytes(get_random_bytes(256), "little") % key.n
    show_hex("challenge", challenge)

    response = input_hex("response")
    if pow(response, key.e, key.n) == challenge:
        show("flag", flag.decode())

# ---- snip ----

def challenge():
    challenge_level = globals()[f"level{level}"]
    description = textwrap.dedent(challenge_level.__doc__)

    print("===== Welcome to Cryptography! =====")
    print("In this series of challenges, you will be working with various cryptographic mechanisms.")
    print(description)
    print()

    challenge_level()


challenge()
```

```
hacker@cryptography~rsa-3:/$ /challenge/run 
===== Welcome to Cryptography! =====
In this series of challenges, you will be working with various cryptographic mechanisms.

In this challenge you will complete an RSA challenge-response.
You will be provided with both the public key and private key.


e: 0x10001
d: 0x2afe6a1e38a39329a17a5c0302b1e20037fab7a0b67c336f88c7dd788d77fe46f176c39fcef64756ae56e11f69bb775ccad87930c92d82a88b37b642b622aa8a2dc511b4ad057f88a27457b008283bca10de79d0546224314e9dc97acdc951fef742ffa32f45f7ad193b1e75420e91c8789d3501e7a8e9ab6d1aa4e6b04632b90cf27df10df1a87279b4c7acbb87f61c3be71b1fd3feeb70dc2fc674542a78c8a5eaea2832d17ec4335aea58dfcc461b7c211a91e075309aeef9b6f9a6a125acbf0cb450fad855db0559caa8e9ae5f7a77a60f17b15d4b335072a7b37f6a40e6c652cea8476d0918491cecbe1a7117bb225019b309be7c824bdfcf8e6c09161
n: 0xcc985f1c3b380f1dc0df9c0508320d924a6888b9d96d68fb8af4bd760dd706bf159825e4d5a83b210b54adceaea2dae6fbdc167a6e291d55649afb10376b4e164fd78ab3c384361846ba84e08ba42c0f674995f307682e29d6ca8a9b3caccb49db4e4627fb6956f9fe84580ab76d721d7d181eea270384f36952cb02b2d657e111a2aae9ef9914cb183a25b7095ffe5acd5241ae48e03f35793d8ef1fe5556854434befe7dc40ec0def10f5e939545dfc1f03391d5b24e7d0d13d0e2b5df387eea7129be352aae0864ad915cba2eb63d1ad2b58ab4e4aabada97182944e3437383fd0070906d825d885734c7854e84874e6cb7b7ff737e4dfaa57c2d2ca46389
challenge: 0x7b60b5b649f6dabdae49c1126d2d49655705ac35686fd06e591b284ac980f8c2be83c25d605394d5ad0e8c88c157ada5f7d33e81a3f1d20f000626eddb8daeccfdda14ddb8455f014cff30568055d665d57bc47a423aaf7deed6bf61caefd816144d94f0250bdbdcd44c9322afaf4fdd99e22d46aefdd7ccd138c7b7cefcbad30c9cf30da0767106d3a5ddd1bfec60ff03f4b18046d00db54629f302fce6c1d79cc2e4b4e2e89e9383f38d7d1284562fefb5c3fd71b6252b69ef9838dddfc19a4036393c4d5c82c4fdaceef561cfe2d84c6da4dee0eda81627bf2b031f9db422d4c38a6cbd9c73e7163d8f10be0085accdd41717a0d897d675ba7a64f1638073
response: 
```

This challenge is very similar to [RSA 1](#rsa-1), but instead of the flag, we have to provide the `response` in bytes.

```py title="~/script.py" showLineNumbers
#!/usr/bin/exec-suid -- /usr/bin/python3 -I
from pwn import *
import re

context.log_level = "error"
io = process("/challenge/run")

# -------- Read header --------
start = io.recvuntil(b"challenge: ")
challenge_line = io.recvline()
data = (start + challenge_line).decode()

# -------- Extract values --------
e_hex  = re.search(r"e:\s*(0x[0-9a-fA-F]+)", data).group(1)
d_hex  = re.search(r"d:\s*(0x[0-9a-fA-F]+)", data).group(1)
n_hex  = re.search(r"n:\s*(0x[0-9a-fA-F]+)", data).group(1)
challenge_hex = re.search(r"challenge:\s*(0x[0-9a-fA-F]+)", data).group(1)

# Convert to integers
d_int = int(d_hex, 16)
n_int = int(n_hex, 16)

# Convert challenge to bytes
challenge_bytes = bytes.fromhex(challenge_hex[2:])

# Convert challenge to integer (BIG ENDIAN RSA)
challenge_int = int.from_bytes(challenge_bytes, "big")

# Compute modulus byte length
mod_len = (n_int.bit_length() + 7) // 8

# -------- RSA private decrypt --------
response_int = pow(challenge_int, d_int, n_int)
response_bytes = response_int.to_bytes(mod_len, "big")

# Strip padding/nulls
response_bytes = response_bytes.lstrip(b"\x00")

# Convert to hex for sending
response_hex = "0x" + response_bytes.hex()

print("Response =", response_hex)

# -------- Send response --------
io.sendline(response_hex.encode())

# Print output of challenge
print(io.recvall().decode(errors="ignore"))
```

```
hacker@cryptography~rsa-3:/$ python ~/script.py 
Response = 0xb3335118063ae19ce8186195159b62cdd36db34bcbbcfafc47c6af4b0366f18699353a89700257fc6ee23ae02b0f9b7fd3485ced1ccb598fd37452fd67b8479dd47f83c67ad019d9b5ff02a67e21815d5f78f89bebe15580e5959847bfdcc3b6dfee4ce6f9ebac24785732b51ef16adb168dcf905edc098300a0377ec1c7a55c5b565cc3d6b6a6983dcb30e3ba5b448c33e5cf32225af1016073865a2027d57b036f685225dde3eb1d81feef9e7a2e68b08468238847f8c0a7bf5b9cece46c75bdfaf1dd5391fea267836db2cb8d771268cf2507ca79abae5f5140c46e9c2a3a06a2141e0a37d4c608195d46da1b90dfe1cf66bffcdd0ca590431667fd0b73a8
response: flag: pwn.college{QkUuIiUWRHVN5wMhVDT_Ee2YTVC.dNDOzMDL4ITM0EzW}
```

&nbsp;

## RSA 4
### Source code
```py title="/challenge/run" showLineNumbers
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

import sys
import string
import random
import pathlib
import base64
import json
import textwrap

from Crypto.Cipher import AES
from Crypto.Hash.SHA256 import SHA256Hash
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Random.random import getrandbits, randrange
from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad, unpad


flag = open("/flag", "rb").read()
config = (pathlib.Path(__file__).parent / ".config").read_text()
level = int(config)


def show(name, value, *, b64=True):
    print(f"{name}: {value}")


def show_b64(name, value):
    show(f"{name} (b64)", base64.b64encode(value).decode())

def show_hex_block(name, value, byte_block_size=16):
    value_to_show = ""

    for i in range(0, len(value), byte_block_size):
        value_to_show += f"{value[i:i+byte_block_size].hex()}"
        value_to_show += " "
    show(f"{name} (hex)", value_to_show)


def show_hex(name, value):
    show(name, hex(value))


def input_(name):
    try:
        return input(f"{name}: ")
    except (KeyboardInterrupt, EOFError):
        print()
        exit(0)


def input_b64(name):
    data = input_(f"{name} (b64)")
    try:
        return base64.b64decode(data)
    except base64.binascii.Error:
        print(f"Failed to decode base64 input: {data!r}", file=sys.stderr)
        exit(1)


def input_hex(name):
    data = input_(name)
    try:
        return int(data, 16)
    except Exception:
        print(f"Failed to decode hex input: {data!r}", file=sys.stderr)
        exit(1)

# ---- snip ----

def level12():
    """
    In this challenge you will complete an RSA challenge-response.
    You will provide the public key.
    """
    e = input_hex("e")
    n = input_hex("n")

    if not (e > 2):
        print("Invalid e value (e > 2)", file=sys.stderr)
        exit(1)

    if not (2**512 < n < 2**1024):
        print("Invalid n value (2**512 < n < 2**1024)", file=sys.stderr)
        exit(1)

    challenge = int.from_bytes(get_random_bytes(64), "little")
    show_hex("challenge", challenge)

    response = input_hex("response")
    if pow(response, e, n) == challenge:
        ciphertext = pow(int.from_bytes(flag, "little"), e, n).to_bytes(256, "little")
        show_b64("secret ciphertext", ciphertext)

# ---- snip ----

def challenge():
    challenge_level = globals()[f"level{level}"]
    description = textwrap.dedent(challenge_level.__doc__)

    print("===== Welcome to Cryptography! =====")
    print("In this series of challenges, you will be working with various cryptographic mechanisms.")
    print(description)
    print()

    challenge_level()


challenge()
```

In this challenge, we simply have to simulate the RSA process.

```py title="~/script.py" showLineNumbers
#!/usr/bin/env python3
from pwn import *
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes

# Start the process
io = process("/challenge/run")

# 1. Generate a valid RSA key 
# The challenge requires 512 < n < 1024 bits. Let's use 1024.
key = RSA.generate(1024)
e = key.e
n = key.n
d = key.d

# 2. Send our custom public key to the server
io.sendlineafter(b"e: ", hex(e).encode())
io.sendlineafter(b"n: ", hex(n).encode())

# 3. Receive the challenge
io.recvuntil(b"challenge: ")
challenge_hex = io.recvline().strip().decode()
challenge_int = int(challenge_hex, 16)

print(f"[*] Received Challenge: {hex(challenge_int)[:20]}...")

# 4. Calculate the response: response = challenge^d mod n
# Since we provided n and e, and we have the private d, this is easy.
response = pow(challenge_int, d, n)

# 5. Send the response
io.sendlineafter(b"response: ", hex(response).encode())

# 6. Get the ciphertext and decrypt it
io.recvuntil(b"secret ciphertext (b64): ")
ciphertext_b64 = io.recvline().strip().decode()
ciphertext_bytes = base64.b64decode(ciphertext_b64)
ciphertext_int = int.from_bytes(ciphertext_bytes, "little")

# Decrypt the flag using our private key
# flag_int = ciphertext^d mod n
flag_int = pow(ciphertext_int, d, n)
flag = flag_int.to_bytes((flag_int.bit_length() + 7) // 8, "little")

print(f"[+] Flag: {flag.decode(errors='ignore')}")
```

```
hacker@cryptography~rsa-4:/$ python ~/script.py 
[+] Starting local process '/challenge/run': pid 4397
[*] Received Challenge: 0x5e0d20a6c2bb5ddcf6...
[+] Flag: pwn.college{syiZe0KzEN6HErnKWC5rvDBrI8_.dRDOzMDL4ITM0EzW}

[*] Stopped process '/challenge/run' (pid 4397)
```

&nbsp;

## RSA Signatures

### Source code

```py title="/challenge/dispatcher" showLineNumbers
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

import sys

from base64 import b64encode, b64decode

n = int(open("/challenge/key-n").read(), 16)
d = int(open("/challenge/key-d").read(), 16)

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} [command-b64]")
    sys.exit(1)

command = b64decode(sys.argv[1].strip("\0"))

if b"flag" in command:
    print(f"Command contains 'flag'")
    sys.exit(1)

signature = pow(int.from_bytes(command, "little"), d, n).to_bytes(256, "little")
print(f"Signed command (b64): {b64encode(signature).decode()}")
```

```py title="/challenge/worker" showLineNumbers
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

import sys

from base64 import b64decode

n = int(open("/challenge/key-n").read(), 16)
e = int(open("/challenge/key-e").read(), 16)

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} [signature-b64]")
    sys.exit(1)

signature = b64decode(sys.argv[1])
c = int.from_bytes(signature, "little")
assert c < n, "Message too big!"
command = pow(c, e, n).to_bytes(256, "little").rstrip(b"\x00")

print(f"Received signed command: {command}")
if command == b"flag":
    print(open("/flag").read())
```

### RSA Homomorphism

As the hint suggests, RSA has a mathematical property where the product of two ciphertexts equals the ciphertext of the product:

$$
(m_{1}^d \pmod n) \times (m_{2}^d \pmod n) \equiv (m_{1} \times m_{2})^d \pmod n
$$

We can exploit this to "blind" our request:

- Pick a random number $X$.
- Ask the `/challenge/dispatcher` to sign a message $M_{\text{blind}} = (\text{flag} \times X^e) \pmod n$.
- The Dispatcher signs it, giving us: $S_{\text{blind}} = ((\text{flag} \times X^e)^d) \pmod n$.
- Because $(X^e)^d \equiv X \pmod n$, the signature we get back is actually $(\text{flag}^d \times X) \pmod n$.
- Divide our result by $X$, and you are left with $\text{flag}^d \pmod n$—the valid signature for "flag"!

```py title="~/script.py" showLineNumbers
#!/usr/bin/env python3
from pwn import *
from base64 import b64encode, b64decode
import random

# 1. Setup and Public Key retrieval
n = int(open("/challenge/key-n").read(), 16)
e = int(open("/challenge/key-e").read(), 16)

target_bytes = b"flag"
target_int = int.from_bytes(target_bytes, "little")

# 2. Pick a random blinding factor 'r'
# It must be coprime to n, but for a large RSA modulus, 
# a random number is almost certainly coprime.
r = random.randint(2, n - 1)

# 3. Blind the target: M' = (M * r^e) % n
# We use pow(r, e, n) for efficiency
blinded_message_int = (target_int * pow(r, e, n)) % n

# 4. Request the signature for the blinded message
print(f"[*] Blinding with r={r}")
msg_bytes = blinded_message_int.to_bytes(256, "little")
msg_b64 = b64encode(msg_bytes).decode()

p = process(["/challenge/dispatcher", msg_b64])
output = p.recvall().decode()
sig_blinded_b64 = re.search(r"Signed command \(b64\): (.*)", output).group(1)
sig_blinded_int = int.from_bytes(b64decode(sig_blinded_b64), "little")

# 5. Unblind the signature: S = (S' * r^-1) % n
# Because S' = (M * r^e)^d = M^d * r
r_inv = pow(r, -1, n)
final_sig_int = (sig_blinded_int * r_inv) % n

# 6. Verify and send to worker
final_sig_bytes = final_sig_int.to_bytes(256, "little")
final_sig_b64 = b64encode(final_sig_bytes).decode()

print("[+] Unblinded signature recovered. Sending to worker...")
p_worker = process(["/challenge/worker", final_sig_b64])
print(p_worker.recvall().decode())
```

```
hacker@cryptography~rsa-signatures:~$ python ~/script.py 
[*] Blinding with r=2733147475355304577740047265346531921686815147276109249642624509373967034379998934018736423171369000766854545304886724868083868894636913166464436112794913758257896876704052233827438956601369460655316971990390337752677345443282467711603151836561877060623666003860298522214103486241076285293218144518746609007326164357352987910876932343355800726074475786723694831177843102568721646569811578465448317192905626832981811189988460845268585585278865014859435287178098732903566403509022919288613275500660202153652018310743653789011017358801181038217431284323674732283818816192407142879000835448221706805381645875276397400831
[+] Starting local process '/challenge/dispatcher': pid 5542
[+] Receiving all data: Done (367B)
[*] Process '/challenge/dispatcher' stopped with exit code 0 (pid 5542)
[+] Unblinded signature recovered. Sending to worker...
[+] Starting local process '/challenge/worker': pid 5545
[+] Receiving all data: Done (92B)
[*] Process '/challenge/worker' stopped with exit code 0 (pid 5545)
Received signed command: b'flag'
pwn.college{4yVnfpEiGvmUvZkiOIREhTUetZL.dRDN3kDL4ITM0EzW}
```

&nbsp;

## SHA 1
### Source code
```py title="/challenge/run" showLineNumbers
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

import hashlib


flag = open("/flag").read()
prefix_length = 6
flag_hash = hashlib.sha256(flag.encode("latin")).hexdigest()
print(f"{flag_hash[:prefix_length]=}")

collision = bytes.fromhex(input("Colliding input? ").strip())
collision_hash = hashlib.sha256(collision).hexdigest()
print(f"{collision_hash[:prefix_length]=}")
if collision_hash[:prefix_length] == flag_hash[:prefix_length]:
    print("Collided!")
    print(flag)
```

```
hacker@cryptography~sha-1:/$ /challenge/run 
flag_hash[:prefix_length]='b43752'
Colliding input?
```

This level only checks the first 6 chars of the hash. This dramatically increases our chances of performing a collision attack.

A collision attack is when the hash (or part of hash in this case) is the same for two different input.

```py title="~/script.py" showLineNumbers
import hashlib
import os

target = input("Enter prefix: ").strip()  # e.g. abcd12

i = 0
while True:
    # random 32-byte input
    data = os.urandom(32)
    h = hashlib.sha256(data).hexdigest()
    if h.startswith(target):
        print("FOUND COLLISION!")
        print("input hex =", data.hex())
        print("hash      =", h)
        break

    i += 1
    if i % 100000 == 0:
        print("Tried", i)
```

```
hacker@cryptography~sha-1:/$ python ~/script.py
Enter prefix: b43752
Tried 100000
Tried 200000
Tried 300000
Tried 400000
Tried 500000
Tried 600000
Tried 700000
Tried 800000
Tried 900000
Tried 1000000
Tried 1100000
Tried 1200000
Tried 1300000
Tried 1400000
Tried 1500000
Tried 1600000
Tried 1700000
Tried 1800000
Tried 1900000
Tried 2000000
Tried 2100000
Tried 2200000
Tried 2300000
Tried 2400000
Tried 2500000
Tried 2600000
Tried 2700000
Tried 2800000
Tried 2900000
Tried 3000000
Tried 3100000
Tried 3200000
Tried 3300000
Tried 3400000
Tried 3500000
Tried 3600000
Tried 3700000
Tried 3800000
Tried 3900000
Tried 4000000
Tried 4100000
Tried 4200000
Tried 4300000
Tried 4400000
Tried 4500000
Tried 4600000
Tried 4700000
Tried 4800000
Tried 4900000
Tried 5000000
Tried 5100000
Tried 5200000
Tried 5300000
Tried 5400000
Tried 5500000
Tried 5600000
Tried 5700000
Tried 5800000
Tried 5900000
Tried 6000000
Tried 6100000
Tried 6200000
Tried 6300000
Tried 6400000
Tried 6500000
Tried 6600000
Tried 6700000
Tried 6800000
FOUND COLLISION!
input hex = fa602c843c28441399946130d430bcd8baf6756101bdd720d68b92e9af9368b9
hash      = b437523be9cac6a6cdf1d538a2409d665b110f02532c91fed2832abe64b1ae56
```

Now let's provide this collision input to the challenge.

```
hacker@cryptography~sha-1:/$ /challenge/run 
flag_hash[:prefix_length]='b43752'
Colliding input? 01590f9b14e6099183876f6473aee815834d1fe5280e036761c9c53280bd1959
collision_hash[:prefix_length]='b43752'
Collided!
pwn.college{8O5fwSrKCJhtDbEZCy50AlywZjA.dFDOzMDL4ITM0EzW}
```

## SHA 2
### Source code
```py title="/challenge/run" showLineNumbers
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

import sys
import string
import random
import pathlib
import base64
import json
import textwrap

from Crypto.Cipher import AES
from Crypto.Hash.SHA256 import SHA256Hash
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Random.random import getrandbits, randrange
from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad, unpad


flag = open("/flag", "rb").read()
config = (pathlib.Path(__file__).parent / ".config").read_text()
level = int(config)


def show(name, value, *, b64=True):
    print(f"{name}: {value}")


def show_b64(name, value):
    show(f"{name} (b64)", base64.b64encode(value).decode())

def show_hex_block(name, value, byte_block_size=16):
    value_to_show = ""

    for i in range(0, len(value), byte_block_size):
        value_to_show += f"{value[i:i+byte_block_size].hex()}"
        value_to_show += " "
    show(f"{name} (hex)", value_to_show)


def show_hex(name, value):
    show(name, hex(value))


def input_(name):
    try:
        return input(f"{name}: ")
    except (KeyboardInterrupt, EOFError):
        print()
        exit(0)


def input_b64(name):
    data = input_(f"{name} (b64)")
    try:
        return base64.b64decode(data)
    except base64.binascii.Error:
        print(f"Failed to decode base64 input: {data!r}", file=sys.stderr)
        exit(1)


def input_hex(name):
    data = input_(name)
    try:
        return int(data, 16)
    except Exception:
        print(f"Failed to decode hex input: {data!r}", file=sys.stderr)
        exit(1)

# ---- snip ----

def level10():
    """
    In this challenge you will hash data with a Secure Hash Algorithm (SHA256).
    You will compute a small proof-of-work.
    Your goal is to find response data, which when appended to the challenge data and hashed, begins with 2 null-bytes.
    """
    difficulty = 2

    challenge = get_random_bytes(32)
    show_b64("challenge", challenge)

    response = input_b64("response")
    if SHA256Hash(challenge + response).digest()[:difficulty] == (b'\0' * difficulty):
        show("flag", flag.decode())

# ---- snip ----

def challenge():
    challenge_level = globals()[f"level{level}"]
    description = textwrap.dedent(challenge_level.__doc__)

    print("===== Welcome to Cryptography! =====")
    print("In this series of challenges, you will be working with various cryptographic mechanisms.")
    print(description)
    print()

    challenge_level()


challenge()
```

```
hacker@cryptography~sha-2:/$ /challenge/run 
===== Welcome to Cryptography! =====
In this series of challenges, you will be working with various cryptographic mechanisms.

In this challenge you will hash data with a Secure Hash Algorithm (SHA256).
You will compute a small proof-of-work.
Your goal is to find response data, which when appended to the challenge data and hashed, begins with 2 null-bytes.


challenge (b64): JN1xtwC4IfZOomGDwbJ65zv/aus2YmOnjfMw0Ez9ZVw=
response (b64):
```

```py title="~/script.py" showLineNumbers
#!/usr/bin/env python3
import base64
import hashlib
import itertools
import string

challenge_b64 = "JN1xtwC4IfZOomGDwbJ65zv/aus2YmOnjfMw0Ez9ZVw="
challenge = base64.b64decode(challenge_b64)

# characters to brute-force — adjust if needed
charset = string.ascii_letters + string.digits

print("[*] Searching...")

for length in range(1, 10):   # search for suffixes of length 1..9
    print(f"[*] Trying length = {length}")
    for suffix in itertools.product(charset, repeat=length):
        suffix_bytes = "".join(suffix).encode()
        h = hashlib.sha256(challenge + suffix_bytes).digest()

        if h.startswith(b"\x00\x00"):
            print("[+] FOUND!")
            print("Suffix:", suffix_bytes)
            print("response (b64):", base64.b64encode(suffix_bytes).decode())
            exit()

print("[-] No solution found (increase length or charset).")
```

```
hacker@cryptography~sha-2:/$ python ~/script.py 
[*] Searching...
[*] Trying length = 1
[*] Trying length = 2
[*] Trying length = 3
[+] FOUND!
Suffix: b'BQ5'
response (b64): QlE1
```

Let us provide this response to the challenge.

```
hacker@cryptography~sha-2:/$ /challenge/run 
===== Welcome to Cryptography! =====
In this series of challenges, you will be working with various cryptographic mechanisms.

In this challenge you will hash data with a Secure Hash Algorithm (SHA256).
You will compute a small proof-of-work.
Your goal is to find response data, which when appended to the challenge data and hashed, begins with 2 null-bytes.


challenge (b64): JN1xtwC4IfZOomGDwbJ65zv/aus2YmOnjfMw0Ez9ZVw=
response (b64): QlE1
flag: pwn.college{8B98dEtBXJhcHSGG3LpIIw7Kioy.dJDOzMDL4ITM0EzW}
```
