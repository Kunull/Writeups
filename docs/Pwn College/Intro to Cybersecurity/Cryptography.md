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

```
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
The key: 0xab
Encrypted secret: 0x07
Decrypted secret? 
```
### Automatic solver

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
