---
sidebar_position: 2
custom_edit_url: null
---

> Included below is a flag encoded as a hex string. Decode this back into bytes to get the flag.  `63727970746f7b596f755f77696c6c5f62655f776f726b696e675f776974685f6865785f737472696e67735f615f6c6f747d`

## Solution
```python
hex_string = "63727970746f7b596f755f77696c6c5f62655f776f726b696e675f776974685f6865785f737472696e67735f615f6c6f747d"
flag = bytes.fromhex(hex_string).decode()
print(f"{flag}")
```
