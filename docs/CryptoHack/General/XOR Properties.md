---
custom_edit_url: null
pagination_next: null
pagination_prev: null
---

> Below is a series of outputs where three random keys have been XOR'd together and with the flag. Use the above properties to undo the encryption in the final line to obtain the flag.  
> KEY1 = a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313  
> KEY2 ^ KEY1 = 37dcb292030faa90d07eec17e3b1c6d8daf94c35d4c9191a5e1e  
> KEY2 ^ KEY3 = c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1  
> FLAG ^ KEY1 ^ KEY3 ^ KEY2 = 04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf

Commutative: A ⊕ B = B ⊕ A  
Associative: A ⊕ (B ⊕ C) = (A ⊕ B) ⊕ C  
Identity: A ⊕ 0 = A  
Self-Inverse: A ⊕ A = 0

- The conversion of hexadecimal to bytes is the same as the Hex level.
- After that we can find the key using the given XOR properties.
```
( FLAG ^ KEY1 ^ KEY3 ^ KEY2 ) ^ ( KEY2 ^ KEY3 ) 
= ( FLAG ^ KEY1 ) ^ [( KEY2 ^ KEY3 ) ^ ( KEY2 ^ KEY3 )]   # Associative property
= ( FLAG ^ KEY1 ) ^ 0                                     # Self-inverse property
= ( FLAG ^ KEY1 )                                         # Identity property
= ( FLAG ^ KEY1 ) ^ KEY1
= FLAG ^ ( KEY1 ^ KEY1 )                                  # Associative property
= FLAG ^ 0                                                # Self-inverse property
= FLAG                                                    # Identity property
```
- So we have XOR `FLAG ^ KEY1 ^ KEY3 ^ KEY2` with `KEY2 ^ KEY3 ` and then the result should be XOR with `KEY1`.
## Solution
```python
from pwn import xor

hex_1 = 'a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313'
hex_21 = '37dcb292030faa90d07eec17e3b1c6d8daf94c35d4c9191a5e1e'
hex_23 = 'c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1'
hex_flag123 = '04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf'

def hex_to_bytes(hex_string):
	byte_string = bytes.fromhex(hex_string)
	return byte_string

bytes_1 = hex_to_bytes(hex_1)
bytes_21 = hex_to_bytes(hex_21)
bytes_23 = hex_to_bytes(hex_23)
bytes_flag123 = hex_to_bytes(hex_flag123)

def xOr(arg1, arg2):
	result = xor(arg1, arg2)
	return result

flag1 = xOr(bytes_flag123, bytes_23)
flag = xOr(flag1, bytes_1).decode()
print(f"{flag}")
```
