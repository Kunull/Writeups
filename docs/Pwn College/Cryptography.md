---
custom_edit_url: null
pagination_next: null
pagination_prev: null
---

## level 1

> Decode base64-encoded data
>
> flag (b64): cHduLmNvbGxlZ2V7SUwyV284RkdzQjRvNEg3UkVpMjlYUmkzeXp4LmROek56TURMNElUTTBFeld9Cg==

```python title="cryptography1.py"
import base64

flag_bytes = base64.b64decode("cHduLmNvbGxlZ2V7SUwyV284RkdzQjRvNEg3UkVpMjlYUmkzeXp4LmROek56TURMNElUTTBFeld9Cg==")
flag = flag_bytes.decode()
print(flag)
```

&nbsp;

## level 2

> Decrypt a secret encrypted with a one-time pad, assuming a securely transferred key
>
> key (b64): AlZIZ5VCWgVpU/hf2SO7oUGhUzCfjNuJ61N5oSphJjF6/s1FNDmDVwOnUBNH+nRzDpGJ816Dyy7Z/w==\
> secret ciphertext (b64): ciEmSfYtNmkMNJ0knFCPyRv5ZXr33r65iDsy9W8oblsqh4wDfFDteWf1Kl09tzA/Otjdvm7GsXmk9Q==

```python title="cryptography2.py"
import base64
from Crypto.Util.strxor import strxor

ciphertext = base64.b64decode("2OLWcZzJlxZ+pqS0A59Pn4CxMYdtJUmDnhoR3x/pzo+tzUosLHytSWDcdt71zghRjXv481xlREfT1Q==")
key = base64.b64decode("qJW4X/+m+3obwcHPRux799rpB80Fdyyz/XJai1qghuX9tAtqZBXDZwSODJCPg0wduTKsvmwgPhCu3w==")

flag = strxor(ciphertext, key)
print(flag)
```

&nbsp;

## level 3

> Decrypt a secret encrypted with a one-time pad, where the key is reused for arbitrary data
>
> secret ciphertext (b64): 2Uyt1kQzH+nc13zfIv4SSe8Y/d/5gqQ3ZVMfw4b6i8GszpQY1QQmHEDTlGR+5BT2BdPKp9jdHdNyNg==

This level only provides us with the ciphertext.

In order to get the flag, we need to read the source code of `/challenge/run`.

```python title="level 3 code"
def level3():
    """
    In this challenge you will decrypt a secret encrypted with a one-time pad.
    You can encrypt arbitrary data, with the key being reused each time.
    """
    key = get_random_bytes(256)
    assert len(flag) <= len(key)

    ciphertext = strxor(flag, key[:len(flag)])
    show_b64("secret ciphertext", ciphertext)

    while True:
        plaintext = input_b64("plaintext")
        ciphertext = strxor(plaintext, key[:len(plaintext)])
        show_b64("ciphertext", ciphertext)
```

As we can see, the program randomly generate the key.
However, it uses the same key for encrypting both the flag, as well as our input.

Before we use this to our advantage, we must learn the Assocative property of XOR.

### Associative property of XOR

```
A ^ B => C
C ^ B => A

Plain text ^ Key => Cipher text
Cipher text ^ Key => Plain text 
```

As both the key remains the same throughout the process, we can somply provide the `secret ciphertext` value back to the program.

```
plaintext (b64): L7QFIiCxEIsGAv5o11sbk3ai7HF8Zqpi+Di0+a96ipzHs/pNiNaoEfTS+WHO0pJHD4LqAgSlGQBFlA==
ciphertext (b64): cHduLmNvbGxlZ2V7RWhnODR4cEhiUTNIZFEwem1oU3BYSXYycnFqLmRWek56TURMNElUTTBFeld9Cg==
```

Since we provided the Cipher text as `plaintext`, the `ciphertext` result actually contains our flag which is Base64 encoded.

We can easily decrypt it using the same technique as [level 1](#level-1).

```python title="cryptography3.py"
import base64

flag_bytes = base64.b64decode("cHduLmNvbGxlZ2V7RWhnODR4cEhiUTNIZFEwem1oU3BYSXYycnFqLmRWek56TURMNElUTTBFeld9Cg==")
flag = flag_bytes.decode()
print(flag)
```

&nbsp;

## level 4

> Decrypt a secret encrypted with AES using the ECB mode of operation
>
> key (b64): KI0ywQ7vV1e8QMU51M1oGA==
> secret ciphertext (b64): yGGxVHabCZvSIxBfAvwf5oKQeWuhC3g/N47Y39+QpR2RSM3Aa4eg0DgjJ9Nv89sG0Scf6gNIgoPFhlA3hbJkRw==

```python
import base64
from Crypto.Cipher import AES

key= base64.b64decode("lKkw1ElUb6K4mmurnviL4w==")
ciphertext = base64.b64decode("rLvZ0htETOsVy1sr8LnZFmcj5Z22Vlxx3csUYlNDDxavCUSRUmW71YWNwTQWVqVgrXDwvjSIzorUnlMvSQHVmA==")

cipher=AES.new(key=key, mode=AES.MODE_ECB)

plaintext = cipher.decrypt(ciphertext)
flag = plaintext.decode()
print(flag)
```

&nbsp;

## level 5

> Decrypt a secret encrypted with AES-ECB, where arbitrary data is appended to the secret and the key is reused. This level is quite a step up in difficulty (and future levels currently do not build on this level), so if you are completely stuck feel free to move ahead. Check out this lecture video on how to approach level 5.
>
> secret ciphertext (b64): OAjfv42sgkREqYAbpdeVjz/CKaPU54OhFtXmOcR+uLhHYz4RZ+nKBDyXupEwO8SK0faWGiqm0mEGe/Qa3cztAg==\
> secret ciphertext (hex): 3808dfbf8dac824444a9801ba5d7958f 3fc229a3d4e783a116d5e639c47eb8b8 47633e1167e9ca043c97ba91303bc48a d1f6961a2aa6d261067bf41addcced02 

Let's check out how the program is encrypting the plain text.

```python

```


&nbsp;

## level 9

```python
i = 0
while True:
	hash = SHA256Hash(str(i).encode()).hexdigest()[:4]
	if hash == 'tDc=':
		print(i)
		break
	i += 1 
```

&nbsp;

## level 11

```python
```
