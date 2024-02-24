---
custom_edit_url: null
pagination_next: null
pagination_prev: null
---

## level 1

```python
import base64

base64.b64decode("cHduLmNvbGxlZ2V7SUwyV284RkdzQjRvNEg3UkVpMjlYUmkzeXp4LmROek56TURMNElUTTBFeld9Cg==")
```

## level 2

```python
import base64
from Crypto.Util.strxor import strxor

ciphertext=base64.b64decode("2OLWcZzJlxZ+pqS0A59Pn4CxMYdtJUmDnhoR3x/pzo+tzUosLHytSWDcdt71zghRjXv481xlREfT1Q==")

key=base64.b64decode("qJW4X/+m+3obwcHPRux799rpB80Fdyyz/XJai1qghuX9tAtqZBXDZwSODJCPg0wduTKsvmwgPhCu3w==")

plaintext=strxor(ciphertext, key)
print(plaintext)
```

## level 3

```python
import base64
from Crypto.Util.strxor import strxor

ciphertext=base64.b64decode("mUu7sNhvINsTVBpt8ySk9TfshaB3gGPzc0MboO2UkYxdYuuICZCJASCKXwweHS6tcx6EIEj+Baci6g==")

key=base64.b64decode("qJW4X/+m+3obwcHPRux799rpB80Fdyyz/XJai1qghuX9tAtqZBXDZwSODJCPg0wduTKsvmwgPhCu3w==")

plaintext=strxor(ciphertext, key[:len(ciphertext)])
print(plaintext)
```

## level 4

```python
import base64

key=base64.b64decode("lKkw1ElUb6K4mmurnviL4w==")

ciphertext=base64.b64decode("rLvZ0htETOsVy1sr8LnZFmcj5Z22Vlxx3csUYlNDDxavCUSRUmW71YWNwTQWVqVgrXDwvjSIzorUnlMvSQHVmA==")

cipher=AES.new(key=key, mode=AES.MODE_ECB)

plaintext=cipher.decrypt(ciphertext)
print(plaintext)
```

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

## level 11

```python
```
