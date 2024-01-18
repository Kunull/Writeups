---
custom_edit_url: null
pagination_next: null
pagination_prev: null
---

> Python's PyCryptodome library implements this with the methods `bytes_to_long()` and `long_to_bytes()`. You will first have to install PyCryptodome and import it with `from Crypto.Util.number import *`. For more details check the [FAQ](https://cryptohack.org/faq/#install).

## Solution
```python
from Crypto.Util.number import *
integer = 11515195063862318899931685488813747395775516287289682636499965282714637259206269
flag = long_to_bytes(integer).decode()
print(f"{flag}")
```
