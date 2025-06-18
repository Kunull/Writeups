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

# Send the recovered plain_secret as input
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
        cipher_secret = int(encrypted_line.strip().split(":")[1], 16)

        plain_secret = cipher_secret ^ key
        proc.stdin.write(f"{plain_secret:#04x}\n")
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

