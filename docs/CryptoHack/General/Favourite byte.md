---
custom_edit_url: null
---

```python
from pwn import xor

hex_string = '73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d'
byte_string = bytes.fromhex(hex_string)
flag = ""

for num in range(256):
	result = xor(byte_string, num)
	if b'crypto' in result:
		break
flag = result.decode()
print(flag)
```

```python
ciphertext = bytes.fromhex("73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d")
flag = ""
for num in range(256):
    results = [chr(n^num) for n in ciphertext]
    flag = "".join(results)
    if flag.startswith("crypto"):
        print(flag)
```

```python
from pwn import xor

message = bytes.fromhex("0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104")
partial_key = "myXORkey"
result = xor(message, partial_key)
flag = result.decode()
print(flag)
```
