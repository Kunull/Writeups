---
custom_edit_url: null
sidebar_position: 5
---

## File Formats: Magic Numbers (Python)


```python title="/challenge/cimg"
#!/opt/pwn.college/python

import os
import sys
from collections import namedtuple

Pixel = namedtuple("Pixel", ["ascii"])


def main():
    if len(sys.argv) >= 2:
        path = sys.argv[1]
        assert path.endswith(".cimg"), "ERROR: file has incorrect extension"
        file = open(path, "rb")
    else:
        file = sys.stdin.buffer

    header = file.read1(4)
    assert len(header) == 4, "ERROR: Failed to read header!"

    assert header[:4] == b"CMge", "ERROR: Invalid magic number!"

    with open("/flag", "r") as f:
        flag = f.read()
        print(flag)


if __name__ == "__main__":
    try:
        main()
    except AssertionError as e:
        print(e, file=sys.stderr)
        sys.exit(-1)
```

The challenge checks if the input file:
1. Ends with the `.cimg` extension.
2. Has the magic number `CMge`.

Let's create the solution file.
```
hacker@reverse-engineering~file-formats-magic-numbers-python:/$ echo "CMge" > ~/solution.cimg
```
```
hacker@reverse-engineering~file-formats-magic-numbers-python:/$ /challenge/cimg ~/solution.cimg 
pwn.college{gnCrQDFokTc18WCgwd5eHW6GcYc.QX1ATN2EDL4ITM0EzW}
```

&nbsp;

## File Formats: Magic Numbers (C)

