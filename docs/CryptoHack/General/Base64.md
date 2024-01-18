---
custom_edit_url: null
pagination_next: null
pagination_prev: null
---


> In Python, after importing the base64 module with `import base64`, you can use the `base64.b64encode()` function. Remember to decode the hex first as the challenge description states.

## Solution
```python
import base64
hex_string = '72bca9b68fc16ac7beeb8f849dca1d8a783e8acf9679bf9269f7bf'
given_bytes = bytes.fromhex(hex_string)
flag = base64.b64encode(given_bytes).decode()
print(f"{flag}")
```
