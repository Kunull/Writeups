---
custom_edit_url: null
---

> I've encrypted the flag with my secret key, you'll never be able to guess it.

```python
from pwn import xor

enc_flag = '0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104'
partial_flag = 'crypto{'

partial_key = xor(enc_flag[:7], partial_flag)
print(f"{partial_key}")
```
