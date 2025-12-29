---
custom_edit_url: null
sidebar_position: 5
---

## File Formats: Magic Numbers (Python)

### Source code
```python title="/challenge/cimg" showLineNumbers
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

The challenge performs the following checks:
- File Extension: Must end with `.cimg`
- Header (4 bytes total):
    - Magic number (4 bytes): Must be `CMge`

```
hacker@reverse-engineering~file-formats-magic-numbers-python:/$ echo "CMge" > ~/solution.cimg
```

```
hacker@reverse-engineering~file-formats-magic-numbers-python:/$ /challenge/cimg ~/solution.cimg 
pwn.college{gnCrQDFokTc18WCgwd5eHW6GcYc.QX1ATN2EDL4ITM0EzW}
```

&nbsp;

## File Formats: Magic Numbers (C)

### Source code
```c title="/challenge/cimg.c" showLineNumbers
#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/signal.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/sendfile.h>
#include <sys/prctl.h>
#include <sys/personality.h>
#include <arpa/inet.h>

void win()
{
    char flag[256];
    int flag_fd;
    int flag_length;

    flag_fd = open("/flag", 0);
    if (flag_fd < 0)
    {
        printf("\n  ERROR: Failed to open the flag -- %s!\n", strerror(errno));
        if (geteuid() != 0)
        {
            printf("  Your effective user id is not 0!\n");
            printf("  You must directly run the suid binary in order to have the correct permissions!\n");
        }
        exit(-1);
    }
    flag_length = read(flag_fd, flag, sizeof(flag));
    if (flag_length <= 0)
    {
        printf("\n  ERROR: Failed to read the flag -- %s!\n", strerror(errno));
        exit(-1);
    }
    write(1, flag, flag_length);
    printf("\n\n");
}

void read_exact(int fd, void *dst, int size, char *msg, int exitcode)
{
    int n = read(fd, dst, size);
    if (n != size)
    {
        fprintf(stderr, msg);
        fprintf(stderr, "\n");
        exit(exitcode);
    }
}

struct cimg_header
{
    char magic_number[4];
} __attribute__((packed));

typedef struct
{
    uint8_t ascii;
} pixel_bw_t;
typedef pixel_bw_t pixel_t;

struct cimg
{
    struct cimg_header header;
};

void __attribute__ ((constructor)) disable_buffering()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 1);
}

int main(int argc, char **argv, char **envp)
{

    struct cimg cimg = { 0 };
    int won = 1;

    if (argc > 1)
    {
        if (strcmp(argv[1]+strlen(argv[1])-5, ".cimg"))
        {
            printf("ERROR: Invalid file extension!");
            exit(-1);
        }
        dup2(open(argv[1], O_RDONLY), 0);
    }

    read_exact(0, &cimg.header, sizeof(cimg.header), "ERROR: Failed to read header!", -1);

    if (cimg.header.magic_number[0] != 'c' || cimg.header.magic_number[1] != 'n' || cimg.header.magic_number[2] != '~' || cimg.header.magic_number[3] != 'R')
    {
        puts("ERROR: Invalid magic number!");
        exit(-1);
    }

    if (won) win();

}
```

The challenge performs the following checks:
- File Extension: Must end with `.cimg`
- Header (4 bytes total):
    - Magic number (4 bytes): Must be `cn~R`

```
hacker@reverse-engineering~file-formats-magic-numbers-c:/$ echo "cn~R" > ~/solution.cimg
```

```
hacker@reverse-engineering~file-formats-magic-numbers-c:/$ /challenge/cimg ~/solution.cimg 
pwn.college{IxtdOuGoBMdBfHrqJNAjzZ96L1h.QX2ATN2EDL4ITM0EzW}
```

&nbsp;

## File Formats: Magic Numbers (x86)

```
hacker@reverse-engineering~file-formats-magic-numbers-x86:/$ file /challenge/cimg 
/challenge/cimg: setuid ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=47edd63950d3f7b9b5c95bf4c93080ff12b75711, for GNU/Linux 3.2.0, not stripped
```

This time the code is a binary executable in little endian format.

Let's decompile it using [Binary Ninja Cloud](https://cloud.binary.ninja/).

After some variable renaming and type editing, we are left with the following: 

### Decompilation

#### `main()`

![image](https://github.com/user-attachments/assets/3461de42-2d8b-4851-bb88-f0d28558c942?raw=1)

The challenge performs the following checks:
- File Extension: Must end with `.cimg`
- Header (4 bytes total):
    - Magic number (4 bytes): Must be `0x474D215B`, which is ASCII `GM![` in little-endian

```
hacker@reverse-engineering~file-formats-magic-numbers-x86:/$ echo "(~m6" > ~/solution.cimg
```

```
hacker@reverse-engineering~file-formats-magic-numbers-x86:/$ /challenge/cimg ~/solution.cimg 
pwn.college{U45kfQ4KNJIp6KwDH0lQRHdpFeL.QXwAzMwEDL4ITM0EzW}
```

&nbsp;

## Reading Endianness (Python)

### Source code
```python title="/challenge/cimg" showLineNumbers
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

    assert int.from_bytes(header[:4], "little") == 0x474D215B, "ERROR: Invalid magic number!"

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

The challenge performs the following checks:
- File Extension: Must end with `.cimg`
- Header (4 bytes total):
    - Magic number (4 bytes): Must be `0x474D215B`, which is `GM![` in big-endian or `[!MG` in little-endian ASCII

```python
>>> big_endian = bytearray.fromhex("474D215B").decode()
>>> print(f"Big endian ASCII: {big_endian}")
Big endian ASCII: GM![

>>> little_endian = bytearray.fromhex("474D215B")[::-1].decode()
>>> print(f"Little endian ASCII: {little_endian}")
Little endian ASCII: [!MG
```

### Endianness

#### Big endian

```
  0x1337   0x1338   0x1339   0x1340   
┌────────┬────────┬────────┬────────┐
│   47   │   4D   │   21   │   5B   │
│  ( G ) │  ( M ) │  ( ! ) │  ( [ ) │ 
└────────┴────────┴────────┴────────┘
```

The LSB is stored in the high memory address (`0x1340`) while the MSB is stored in the low memory address (`0x1337`).

This is the format in which humans write numbers. Network traffic is also sent in big endian format.

#### Little endian

```
  0x1337   0x1338   0x1339   0x1340   
┌────────┬────────┬────────┬────────┐
│   5B   │   21   │   4D   │   47   │
│  ( [ ) │  ( ! ) │  ( M ) │  ( G ) │ 
└────────┴────────┴────────┴────────┘
```

The LSB is stored in the low memory address (`0x1337`) while the MSB is stored in the high memory address (`0x1340`).

This is the format in which machines store data. This is the relevant format for our level.

Therefore, we have to set the first 4 bytes of the solution to `[!MG`.

```
hacker@reverse-engineering~reading-endianness-python:/$ echo "[!MG" > ~/solution.cimg
bash: !MG: event not found
```

This is happening because Bash uses `!` for history expansion. So Bash tries to expand `!MG` as a previous command, but can't find one.
We can easily get around this by using single quotes (`'`).

```
hacker@reverse-engineering~reading-endianness-python:/$ echo '[!MG' > ~/solution.cimg
```

```
hacker@reverse-engineering~reading-endianness-python:/$ /challenge/cimg ~/solution.cimg
pwn.college{UeceXp6n13KASFhim5T8GOhpq63.QX3ATN2EDL4ITM0EzW}
```

&nbsp;

## Reading Endianness (C)

### Source code
```c title="/challenge/cimg.c" showLineNumbers
#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/signal.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/sendfile.h>
#include <sys/prctl.h>
#include <sys/personality.h>
#include <arpa/inet.h>

void win()
{
    char flag[256];
    int flag_fd;
    int flag_length;

    flag_fd = open("/flag", 0);
    if (flag_fd < 0)
    {
        printf("\n  ERROR: Failed to open the flag -- %s!\n", strerror(errno));
        if (geteuid() != 0)
        {
            printf("  Your effective user id is not 0!\n");
            printf("  You must directly run the suid binary in order to have the correct permissions!\n");
        }
        exit(-1);
    }
    flag_length = read(flag_fd, flag, sizeof(flag));
    if (flag_length <= 0)
    {
        printf("\n  ERROR: Failed to read the flag -- %s!\n", strerror(errno));
        exit(-1);
    }
    write(1, flag, flag_length);
    printf("\n\n");
}

void read_exact(int fd, void *dst, int size, char *msg, int exitcode)
{
    int n = read(fd, dst, size);
    if (n != size)
    {
        fprintf(stderr, msg);
        fprintf(stderr, "\n");
        exit(exitcode);
    }
}

struct cimg_header
{
    unsigned int magic_number;
} __attribute__((packed));

typedef struct
{
    uint8_t ascii;
} pixel_bw_t;
typedef pixel_bw_t pixel_t;

struct cimg
{
    struct cimg_header header;
};

void __attribute__ ((constructor)) disable_buffering()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 1);
}

int main(int argc, char **argv, char **envp)
{

    struct cimg cimg = { 0 };
    int won = 1;

    if (argc > 1)
    {
        if (strcmp(argv[1]+strlen(argv[1])-5, ".cimg"))
        {
            printf("ERROR: Invalid file extension!");
            exit(-1);
        }
        dup2(open(argv[1], O_RDONLY), 0);
    }

    read_exact(0, &cimg.header, sizeof(cimg.header), "ERROR: Failed to read header!", -1);

    if (cimg.header.magic_number != 1733109083)
    {
        puts("ERROR: Invalid magic number!");
        exit(-1);
    }

    if (won) win();

}
```

- File Extension: Must end with `.cimg`
- Header (4 bytes total):
    - Magic number (4 bytes): Must be `1733109083`, which is `[%Mg` in little-endian ASCII

```python
>>> print('{0:x}'.format(1733109083))
674d255b
>>> little_endian = bytearray.fromhex("674d255b")[::-1].decode()
>>> print(f"Little endian ASCII: {little_endian}")
Little endian ASCII: [%Mg
```

The same concept of endianness applies here.

```
hacker@reverse-engineering~reading-endianness-c:/$ echo '[%Mg' > ~/solution.cimg
```

```
hacker@reverse-engineering~reading-endianness-c:/$ /challenge/cimg ~/solution.cimg
pwn.college{Iz_N1i6LBqszqfN70WeEVNJzFd9.QX4ATN2EDL4ITM0EzW}
```

&nbsp;

## Reading Endianness (x86)

### Decompilation

#### `main()`

![image](https://github.com/user-attachments/assets/7eaea94a-9f4b-439d-890c-67cc3ccd778b?raw=1)

- File Extension: Must end with `.cimg`
- Header (4 bytes total):
    - Magic number (4 bytes): Must be `0x72254f3c`, which is `<0%r` in little-endian ASCII

```python
>>> little_endian = bytearray.fromhex("72254f3c")[::-1].decode()
>>> print(f"Little endian ASCII: {little_endian}")
Little endian ASCII: <O%r
```

```
hacker@reverse-engineering~reading-endianness-c:/$ echo '<0%r' > ~/solution.cimg
```

```
hacker@reverse-engineering~reading-endianness-x86:/$ /challenge/cimg ~/solution.cimg
pwn.college{Et6nh45-ta1HCaJmdwJf5eDGBdd.QXxAzMwEDL4ITM0EzW}
```

&nbsp;

## Version Information (Python)

### Source code
```python title="/challenge/cimg" showLineNumbers
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

    header = file.read1(8)
    assert len(header) == 8, "ERROR: Failed to read header!"

    assert header[:4] == b"<0%R", "ERROR: Invalid magic number!"

    assert int.from_bytes(header[4:8], "little") == 11, "ERROR: Invalid version!"

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

The challenge performs the following checks:
- File Extension: Must end with `.cimg`
- Header (8 bytes total):
    - Magic number (4 bytes): Must be `b"<0%R"`
    - Version (4 bytes): Must be `11` in little-endian

```python title="~/script.py" showLineNumbers
import struct

# Build the header (8 bytes total)
magic = b"<0%R"                   # 4 bytes
version = struct.pack("<I", 11)   # 4 bytes 

header = magic + version

# Full file content
cimg_data = header

# Write to disk
filename = "/home/hacker/solution.cimg"
with open(filename, "wb") as f:
    f.write(cimg_data)

print(f"Wrote {len(cimg_data)} bytes: {cimg_data} to file: '{filename}'")
```

```
hacker@reverse-engineering~version-information-python:/$ python ~/script.py
Wrote 8 bytes: b'<0%R\x0b\x00\x00\x00' to file: '/home/hacker/solution.cimg'
```

```
hacker@reverse-engineering~version-information-python:/$ /challenge/cimg ~/solution.cimg 
pwn.college{QE3tgVGh7hvrbDbs175V291MQid.QX5ATN2EDL4ITM0EzW}
```

&nbsp;

## Version Information (C)

### Source code
```c title="/challenge/cimg.c" showLineNumbers
#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/signal.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/sendfile.h>
#include <sys/prctl.h>
#include <sys/personality.h>
#include <arpa/inet.h>

void win()
{
    char flag[256];
    int flag_fd;
    int flag_length;

    flag_fd = open("/flag", 0);
    if (flag_fd < 0)
    {
        printf("\n  ERROR: Failed to open the flag -- %s!\n", strerror(errno));
        if (geteuid() != 0)
        {
            printf("  Your effective user id is not 0!\n");
            printf("  You must directly run the suid binary in order to have the correct permissions!\n");
        }
        exit(-1);
    }
    flag_length = read(flag_fd, flag, sizeof(flag));
    if (flag_length <= 0)
    {
        printf("\n  ERROR: Failed to read the flag -- %s!\n", strerror(errno));
        exit(-1);
    }
    write(1, flag, flag_length);
    printf("\n\n");
}

void read_exact(int fd, void *dst, int size, char *msg, int exitcode)
{
    int n = read(fd, dst, size);
    if (n != size)
    {
        fprintf(stderr, msg);
        fprintf(stderr, "\n");
        exit(exitcode);
    }
}

struct cimg_header
{
    char magic_number[4];
    uint16_t version;
} __attribute__((packed));

typedef struct
{
    uint8_t ascii;
} pixel_bw_t;
typedef pixel_bw_t pixel_t;

struct cimg
{
    struct cimg_header header;
};

void __attribute__ ((constructor)) disable_buffering()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 1);
}

int main(int argc, char **argv, char **envp)
{

    struct cimg cimg = { 0 };
    int won = 1;

    if (argc > 1)
    {
        if (strcmp(argv[1]+strlen(argv[1])-5, ".cimg"))
        {
            printf("ERROR: Invalid file extension!");
            exit(-1);
        }
        dup2(open(argv[1], O_RDONLY), 0);
    }

    read_exact(0, &cimg.header, sizeof(cimg.header), "ERROR: Failed to read header!", -1);

    if (cimg.header.magic_number[0] != 'c' || cimg.header.magic_number[1] != 'm' || cimg.header.magic_number[2] != '6' || cimg.header.magic_number[3] != 'e')
    {
        puts("ERROR: Invalid magic number!");
        exit(-1);
    }

    if (cimg.header.version != 135)
    {
        puts("ERROR: Unsupported version!");
        exit(-1);
    }

    if (won) win();

}
```

The challenge performs the following checks:
- File Extension: Must end with `.cimg`
- Header (8 bytes total):
    - Magic number (4 bytes): Must be `b"cm6e"`
    - Version (4 bytes): Must be `135` in little-endian
 
```python title="~/script.py" showLineNumbers
import struct

# Build the header (8 bytes total)
magic = b"cm6e"                   # 4 bytes
version = struct.pack("<I", 135)  # 4 bytes 

header = magic + version

# Full file content
cimg_data = header

# Write to disk
filename = "/home/hacker/solution.cimg"
with open(filename, "wb") as f:
    f.write(cimg_data)

print(f"Wrote {len(cimg_data)} bytes: {cimg_data} to file: '{filename}'")
```

```
hacker@reverse-engineering~version-information-c:/$ python ~/script.py
Wrote 8 bytes: b'cm6e\x87\x00\x00\x00' to file: '/home/hacker/solution.cimg'
```

```
hacker@reverse-engineering~version-information-c:/$ /challenge/cimg ~/solution.cimg
pwn.college{MX7npfEYKHEaMMoN-13n0RYXQiX.QXwETN2EDL4ITM0EzW}
```

&nbsp;

## Version Information (x86)

### Decompilation

#### `main()`

![image](https://github.com/user-attachments/assets/8e03222f-a902-493b-9da2-2bca5c8287de?raw=1)

- File Extension: Must end with `.cimg`
- Header (8 bytes total):
    - Magic number (4 bytes): Must be `0x5b6e6e52`
    - Version (4 bytes): Must be `0xaa` in little-endian

```python title="~/script.py" showLineNumbers
import struct

# Build the header (8 bytes total)
magic = bytes.fromhex("5b6e6e52")  # 4 bytes
version = struct.pack("<I", 0xaa)  # 4 bytes 

header = magic + version

# Full file content
cimg_data = header

# Write to disk
filename = "/home/hacker/solution.cimg"
with open(filename, "wb") as f:
    f.write(cimg_data)

print(f"Wrote {len(cimg_data)} bytes: {cimg_data} to file: '{filename}'")
```

```
hacker@reverse-engineering~version-information-x86:/$ python ~/script.py
Wrote 8 bytes: b'[nnR\xaa\x00\x00\x00' to file: '/home/hacker/solution.cimg'
```

```
hacker@reverse-engineering~version-information-x86:/$ /challenge/cimg ~/solution.cimg
pwn.college{MS8bIZFkAQQ3-xwFV98pplsoCa7.QXyAzMwEDL4ITM0EzW}
```

&nbsp;

## Metadata and Data (Python)

### Source code
```python title="/challenge/cimg" showLineNumbers
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

    header = file.read1(20)
    assert len(header) == 20, "ERROR: Failed to read header!"

    assert header[:4] == b"CmgE", "ERROR: Invalid magic number!"

    assert int.from_bytes(header[4:12], "little") == 1, "ERROR: Invalid version!"

    width = int.from_bytes(header[12:16], "little")
    assert width == 59, "ERROR: Incorrect width!"

    height = int.from_bytes(header[16:20], "little")
    assert height == 21, "ERROR: Incorrect height!"

    data = file.read1(width * height)
    assert len(data) == width * height, "ERROR: Failed to read data!"

    pixels = [Pixel(character) for character in data]

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

The challenge performs the following checks:
- File Extension: Must end with `.cimg`
- Header (20 bytes total):
    - Magic number (4 bytes): Must be `b"CmgE"`
    - Version (8 bytes): Must be `1` in little-endian
    - Width (4 bytes): Must be `59` in little-endian
    - Height (4 bytes): Must be `21` in little-endian
- Pixel Data:
    - The number of non-space ASCII characters must be `59 * 21 = 1239`

```python title="~/script.py" showLineNumbers
import struct

# Build the header (20 bytes total)
magic = b"CmgE"                    # 4 bytes
version = struct.pack("<Q", 1)     # 8 bytes 
width = struct.pack("<L", 59)      # 4 bytes 
height = struct.pack("<L", 21)     # 4 bytes

header = magic + version + width + height

# Build the pixel data (59 * 21 = 1239 bytes)
pixel_data = b"." * (59 * 21)

# Full file content
cimg_data = header + pixel_data

# Write to disk
filename = "/home/hacker/solution.cimg"
with open(filename, "wb") as f:
    f.write(cimg_data)

print(f"Wrote {len(cimg_data)} bytes: {cimg_data} to file: '{filename}'")
```

```
hacker@reverse-engineering~metadata-and-data-python:/$ python ~/script.py
Wrote 1259 bytes: b'CmgE\x01\x00\x00\x00\x00\x00\x00\x00;\x00\x00\x00\x15\x00\x00\x00.......................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................' to file: '/home/hacker/solution.cimg'
```

```
hacker@reverse-engineering~metadata-and-data-python:/$ /challenge/cimg ~/solution.cimg 
pwn.college{gmcsTJSAE9Fvci5d7be0NM7T0Af.QXxETN2EDL4ITM0EzW}
```

&nbsp;

## Metadata and Data (C)

### Source code
```c title="/challenge/cimg.c" showLineNumbers
#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/signal.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/sendfile.h>
#include <sys/prctl.h>
#include <sys/personality.h>
#include <arpa/inet.h>

void win()
{
    char flag[256];
    int flag_fd;
    int flag_length;

    flag_fd = open("/flag", 0);
    if (flag_fd < 0)
    {
        printf("\n  ERROR: Failed to open the flag -- %s!\n", strerror(errno));
        if (geteuid() != 0)
        {
            printf("  Your effective user id is not 0!\n");
            printf("  You must directly run the suid binary in order to have the correct permissions!\n");
        }
        exit(-1);
    }
    flag_length = read(flag_fd, flag, sizeof(flag));
    if (flag_length <= 0)
    {
        printf("\n  ERROR: Failed to read the flag -- %s!\n", strerror(errno));
        exit(-1);
    }
    write(1, flag, flag_length);
    printf("\n\n");
}

void read_exact(int fd, void *dst, int size, char *msg, int exitcode)
{
    int n = read(fd, dst, size);
    if (n != size)
    {
        fprintf(stderr, msg);
        fprintf(stderr, "\n");
        exit(exitcode);
    }
}

struct cimg_header
{
    char magic_number[4];
    uint16_t version;
    uint16_t width;
    uint16_t height;
} __attribute__((packed));

typedef struct
{
    uint8_t ascii;
} pixel_bw_t;
typedef pixel_bw_t pixel_t;

struct cimg
{
    struct cimg_header header;
};

#define CIMG_NUM_PIXELS(cimg) ((cimg)->header.width * (cimg)->header.height)
#define CIMG_DATA_SIZE(cimg) (CIMG_NUM_PIXELS(cimg) * sizeof(pixel_t))

void __attribute__ ((constructor)) disable_buffering()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 1);
}

int main(int argc, char **argv, char **envp)
{

    struct cimg cimg = { 0 };
    int won = 1;

    if (argc > 1)
    {
        if (strcmp(argv[1]+strlen(argv[1])-5, ".cimg"))
        {
            printf("ERROR: Invalid file extension!");
            exit(-1);
        }
        dup2(open(argv[1], O_RDONLY), 0);
    }

    read_exact(0, &cimg.header, sizeof(cimg.header), "ERROR: Failed to read header!", -1);

    if (cimg.header.magic_number[0] != 'C' || cimg.header.magic_number[1] != 'N' || cimg.header.magic_number[2] != 'm' || cimg.header.magic_number[3] != 'G')
    {
        puts("ERROR: Invalid magic number!");
        exit(-1);
    }

    if (cimg.header.version != 1)
    {
        puts("ERROR: Unsupported version!");
        exit(-1);
    }

    if (cimg.header.width != 66)
    {
        puts("ERROR: Incorrect width!");
        exit(-1);
    }

    if (cimg.header.height != 17)
    {
        puts("ERROR: Incorrect height!");
        exit(-1);
    }

    unsigned long data_size = cimg.header.width * cimg.header.height * sizeof(pixel_t);
    pixel_t *data = malloc(data_size);
    if (data == NULL)
    {
        puts("ERROR: Failed to allocate memory for the image data!");
        exit(-1);
    }
    read_exact(0, data, data_size, "ERROR: Failed to read data!", -1);

    if (won) win();

}
```

The challenge performs the following checks:
- File Extension: Must end with `.cimg`
- Header (10 bytes total):
    - Magic number (4 bytes): Must be `b"CNmG"`
    - Version (2 bytes): Must be `1` in little-endian
    - Width (2 bytes): Must be `66` in little-endian
    - Height (2 bytes): Must be `17` in little-endian
- Pixel Data:
    - The number of non-space characters must be `66 * 17 = 1122` 

```python title="~/script.py" showLineNumbers
import struct

# Build the header (10 bytes total)
magic = b"CNmG"                    # 4 bytes
version = struct.pack("<H", 1)     # 2 bytes
width = struct.pack("<H", 66)      # 2 bytes 
height = struct.pack("<H", 17)     # 2 bytes 

header = magic + version + width + height

# Build the pixel data (66 * 17 = 1122 bytes)
pixel_data = b"." * (66 * 17)

# Full file content
cimg_data = header + pixel_data

# Write to disk
filename = "/home/hacker/solution.cimg"
with open(filename, "wb") as f:
    f.write(cimg_data)

print(f"Wrote {len(cimg_data)} bytes: {cimg_data} to file: '{filename}'")
```

```
hacker@reverse-engineering~metadata-and-data-c:/$ python ~/script.py
Wrote 1132 bytes: b'CNmG\x01\x00B\x00\x11\x00..................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................' to file: '/home/hacker/solution.cimg'
```

```
hacker@reverse-engineering~metadata-and-data-c:/$ /challenge/cimg ~/solution.cimg 
pwn.college{UiHnq7dEOB75oBiYdd31IiDPdHG.QXyETN2EDL4ITM0EzW}
```

&nbsp;

## Metadata and Data (x86)

### Decompilation

#### `main()`

![image](https://github.com/user-attachments/assets/d0700b9b-d388-4af9-9d10-791a4cf4922a?raw=1)

The challenge performs the following checks:
- File Extension: Must end with `.cimg`
- Header (14 bytes total):
    - Magic number (4 bytes): Must be `0x284e6e72`
    - Version (2 bytes): Must be `1` in little-endian
    - Width (4 bytes): Must be `0x40` (`64`) in little-endian
    - Height (4 bytes): Must be `0xc` (`12`) in little-endian
- Pixel Data:
    - The number of non-space ASCII characters must be `66 * 17 = 1122` 

```python title="~/script.py" showLineNumbers
import struct

# Build the header (14 bytes total)
magic = bytes.fromhex("284e6e72")  # 4 bytes
version = struct.pack("<H", 1)     # 2 bytes
width = struct.pack("<I", 0x40)    # 4 bytes 
height = struct.pack("<I", 0xc)    # 4 bytes 

header = magic + version + width + height

# Build the pixel data (64 * 12 = 768 bytes)
pixel_data = b"." * (64 * 12)

# Full file content
cimg_data = header + pixel_data

# Write to disk
filename = "/home/hacker/solution.cimg"
with open(filename, "wb") as f:
    f.write(cimg_data)

print(f"Wrote {len(cimg_data)} bytes: {cimg_data} to file: '{filename}'")
```

```
hacker@reverse-engineering~metadata-and-data-x86:/$ python ~/script.py
Wrote 782 bytes: b'(Nnr\x01\x00@\x00\x00\x00\x0c\x00\x00\x00................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................' to file: '/home/hacker/solution.cimg'
```

```
hacker@reverse-engineering~metadata-and-data-x86:/$ /challenge/cimg ~/solution.cimg 
pwn.college{UB4Rk1u_RCBjfYamRdf9nAU0tlF.QXzAzMwEDL4ITM0EzW}
```

&nbsp;

## Input Restrictions (Python)

### Source code
```python title="/challenge/cimg" showLineNumbers
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

    header = file.read1(16)
    assert len(header) == 16, "ERROR: Failed to read header!"

    assert header[:4] == b"cIMG", "ERROR: Invalid magic number!"

    assert int.from_bytes(header[4:12], "little") == 1, "ERROR: Invalid version!"

    width = int.from_bytes(header[12:14], "little")
    assert width == 66, "ERROR: Incorrect width!"

    height = int.from_bytes(header[14:16], "little")
    assert height == 17, "ERROR: Incorrect height!"

    data = file.read1(width * height)
    assert len(data) == width * height, "ERROR: Failed to read data!"

    pixels = [Pixel(character) for character in data]

    invalid_character = next((pixel.ascii for pixel in pixels if not (0x20 <= pixel.ascii <= 0x7E)), None)
    assert invalid_character is None, f"ERROR: Invalid character {invalid_character:#04x} in data!"

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

The challenge performs the following checks:
- File Extension: Must end with `.cimg`
- Header (16 bytes total):
    - Magic number (4 bytes): Must be `b"cIMG"`
    - Version (8 bytes): Must be `1` in little-endian
    - Width (2 bytes): Must be `66` in little-endian
    - Height (2 bytes): Must be `17` in little-endian
- Pixel Data:
    - The number of non-space ASCII characters must be `66 * 17 = 1122` 
    - Non-space ASCII must be in between `0x20` and `0x7E`
 
```python title="~/script.py" showLineNumbers
import struct

# Build the header (16 bytes total)
magic = b"cIMG"                    # 4 bytes
version = struct.pack("<Q", 1)     # 8 bytes
width = struct.pack("<H", 66)      # 2 bytes 
height = struct.pack("<H", 17)     # 2 bytes 

header = magic + version + width + height

# Build the pixel data (66 * 17 = 1122 bytes)
pixel_data = b"." * (66 * 17)

# Full file content
cimg_data = header + pixel_data

# Write to disk
filename = "/home/hacker/solution.cimg"
with open(filename, "wb") as f:
    f.write(cimg_data)

print(f"Wrote {len(cimg_data)} bytes: {cimg_data} to file: '{filename}'")
```

```
hacker@reverse-engineering~input-restrictions-python:/$ python ~/script.py 
Wrote 1138 bytes: b'cIMG\x01\x00\x00\x00\x00\x00\x00\x00B\x00\x11\x00..................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................' to file: '/home/hacker/solution.cimg'
```

```
hacker@reverse-engineering~input-restrictions-python:/$ /challenge/cimg ~/solution.cimg 
pwn.college{89KE9mKkbzytvUe2ab0YCyPzt55.QXzETN2EDL4ITM0EzW}
```

&nbsp;

## Input Restrictions (C)

### Source code
```c title="/challenge/cimg.c" showLineNumbers
#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/signal.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/sendfile.h>
#include <sys/prctl.h>
#include <sys/personality.h>
#include <arpa/inet.h>

void win()
{
    char flag[256];
    int flag_fd;
    int flag_length;

    flag_fd = open("/flag", 0);
    if (flag_fd < 0)
    {
        printf("\n  ERROR: Failed to open the flag -- %s!\n", strerror(errno));
        if (geteuid() != 0)
        {
            printf("  Your effective user id is not 0!\n");
            printf("  You must directly run the suid binary in order to have the correct permissions!\n");
        }
        exit(-1);
    }
    flag_length = read(flag_fd, flag, sizeof(flag));
    if (flag_length <= 0)
    {
        printf("\n  ERROR: Failed to read the flag -- %s!\n", strerror(errno));
        exit(-1);
    }
    write(1, flag, flag_length);
    printf("\n\n");
}

void read_exact(int fd, void *dst, int size, char *msg, int exitcode)
{
    int n = read(fd, dst, size);
    if (n != size)
    {
        fprintf(stderr, msg);
        fprintf(stderr, "\n");
        exit(exitcode);
    }
}

struct cimg_header
{
    char magic_number[4];
    uint32_t version;
    uint8_t width;
    uint8_t height;
} __attribute__((packed));

typedef struct
{
    uint8_t ascii;
} pixel_bw_t;
typedef pixel_bw_t pixel_t;

struct cimg
{
    struct cimg_header header;
};

#define CIMG_NUM_PIXELS(cimg) ((cimg)->header.width * (cimg)->header.height)
#define CIMG_DATA_SIZE(cimg) (CIMG_NUM_PIXELS(cimg) * sizeof(pixel_t))

void __attribute__ ((constructor)) disable_buffering()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 1);
}

int main(int argc, char **argv, char **envp)
{

    struct cimg cimg = { 0 };
    int won = 1;

    if (argc > 1)
    {
        if (strcmp(argv[1]+strlen(argv[1])-5, ".cimg"))
        {
            printf("ERROR: Invalid file extension!");
            exit(-1);
        }
        dup2(open(argv[1], O_RDONLY), 0);
    }

    read_exact(0, &cimg.header, sizeof(cimg.header), "ERROR: Failed to read header!", -1);

    if (cimg.header.magic_number[0] != 'c' || cimg.header.magic_number[1] != 'I' || cimg.header.magic_number[2] != 'M' || cimg.header.magic_number[3] != 'G')
    {
        puts("ERROR: Invalid magic number!");
        exit(-1);
    }

    if (cimg.header.version != 1)
    {
        puts("ERROR: Unsupported version!");
        exit(-1);
    }

    if (cimg.header.width != 80)
    {
        puts("ERROR: Incorrect width!");
        exit(-1);
    }

    if (cimg.header.height != 13)
    {
        puts("ERROR: Incorrect height!");
        exit(-1);
    }

    unsigned long data_size = cimg.header.width * cimg.header.height * sizeof(pixel_t);
    pixel_t *data = malloc(data_size);
    if (data == NULL)
    {
        puts("ERROR: Failed to allocate memory for the image data!");
        exit(-1);
    }
    read_exact(0, data, data_size, "ERROR: Failed to read data!", -1);

    for (int i = 0; i < cimg.header.width * cimg.header.height; i++)
    {
        if (data[i].ascii < 0x20 || data[i].ascii > 0x7e)
        {
            fprintf(stderr, "ERROR: Invalid character 0x%x in the image data!\n", data[i].ascii);
            exit(-1);
        }
    }

    if (won) win();

}
```

The challenge performs the following checks:
- File Extension: Must end with `.cimg`
- Header (10 bytes total):
    - Magic number (4 bytes): Must be `b"cIMG"`
    - Version (4 bytes): Must be `1` in little-endian
    - Width (1 bytes): Must be `80` in little-endian
    - Height (1 bytes): Must be `13` in little-endian
- Pixel Data:
    - The number of non-space ASCII characters must be `80 * 13 = 1040` 
    - Non-space ASCII must be in between `0x20` and `0x7e`
 
```python title="~/script.py" showLineNumbers
import struct

# Build the header (10 bytes total)
magic = b"cIMG"                    # 4 bytes
version = struct.pack("<I", 1)     # 4 bytes
width = struct.pack("<B", 80)      # 1 bytes 
height = struct.pack("<B", 13)     # 1 bytes 

header = magic + version + width + height

# Build the pixel data (80 * 13 = 1040 bytes)
pixel_data = b"." * (80 * 13)

# Full file content
cimg_data = header + pixel_data

# Write to disk
filename = "/home/hacker/solution.cimg"
with open(filename, "wb") as f:
    f.write(cimg_data)

print(f"Wrote {len(cimg_data)} bytes: {cimg_data} to file: '{filename}'")
```

```
hacker@reverse-engineering~input-restrictions-c:/$ python ~/script.py
Wrote 1050 bytes: b'cIMG\x01\x00\x00\x00P\r................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................' to file: '/home/hacker/solution.cimg'
```

```
hacker@reverse-engineering~input-restrictions-c:/$ /challenge/cimg ~/solution.cimg 
pwn.college{MncM_uybJBUtPMNqnf4uUZTvN38.QX0ETN2EDL4ITM0EzW}
```

&nbsp;

## Input Restrictions (x86)

### Decompilation

#### `main()`

![image](https://github.com/user-attachments/assets/58e06064-6ea6-4060-8abf-68b8e7e20e3e?raw=1)

![image](https://github.com/user-attachments/assets/516cbc5a-64ee-42dc-a872-f73e2ae2cb99?raw=1)

The challenge performs the following checks:
- File Extension: Must end with `.cimg`
- Header (10 bytes total):
    - Magic number (4 bytes): Must be `0x63494d47"`
    - Version (4 bytes): Must be `1` in little-endian
    - Width (1 bytes): Must be `0x3b` (`59`) in little-endian
    - Height (1 bytes): Must be `0x15` (`21`) in little-endian
- Pixel Data:
    - The number of non-space ASCII bytes must be `80 * 13 = 1040` 
    - Non-space ASCII must be in between `0x20` and `0x7e`
 
```python title="~/script.py" showLineNumbers
import struct

# Build the header (8 bytes total)
magic = bytes.fromhex("63494d47")  # 4 bytes
version = struct.pack("<H", 1)     # 2 bytes
width = struct.pack("<B", 0x3b)    # 1 bytes 
height = struct.pack("<B", 0x15)   # 1 bytes 

header = magic + version + width + height

# Build the pixel data (59 * 21 = 1239 bytes)
pixel_data = b"." * (59 * 21)

# Full file content
cimg_data = header + pixel_data

# Write to disk
filename = "/home/hacker/solution.cimg"
with open(filename, "wb") as f:
    f.write(cimg_data)

print(f"Wrote {len(cimg_data)} bytes: {cimg_data} to file: '{filename}'")
```

```
hacker@reverse-engineering~input-restrictions-x86:/$ python ~/script.py 
Wrote 1247 bytes: b'cIMG\x01\x00;\x15.......................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................' to file: '/home/hacker/solution.cimg'
```

```
hacker@reverse-engineering~input-restrictions-x86:/$ /challenge/cimg ~/solution.cimg 
pwn.college{Qr3ER4NieY66DXLbO5a4RvjVuTi.QX0AzMwEDL4ITM0EzW}
```

&nbsp;

## Behold the cIMG! (Python)

### Source code
```python title="/challenge/cimg" showLineNumbers
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

    header = file.read1(14)
    assert len(header) == 14, "ERROR: Failed to read header!"

    assert header[:4] == b"cIMG", "ERROR: Invalid magic number!"

    assert int.from_bytes(header[4:8], "little") == 1, "ERROR: Invalid version!"

    width = int.from_bytes(header[8:12], "little")

    height = int.from_bytes(header[12:14], "little")

    data = file.read1(width * height)
    assert len(data) == width * height, "ERROR: Failed to read data!"

    pixels = [Pixel(character) for character in data]

    invalid_character = next((pixel.ascii for pixel in pixels if not (0x20 <= pixel.ascii <= 0x7E)), None)
    assert invalid_character is None, f"ERROR: Invalid character {invalid_character:#04x} in data!"

    framebuffer = "".join(
        bytes(pixel.ascii for pixel in pixels[row_start : row_start + width]).decode() + "\n"
        for row_start in range(0, len(pixels), width)
    )
    print(framebuffer)

    nonspace_count = sum(1 for pixel in pixels if chr(pixel.ascii) != " ")
    if nonspace_count != 275:
        return

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

The challenge performs the following checks:
- File Extension: Must end with `.cimg`
- Header (14 bytes total):
    - Magic number (4 bytes): Must be `b"cIMG"`
    - Version (4 bytes): Must be `1` in little-endian
    - Width (4 bytes): Must be in little-endian
    - Height (2 bytes): Must be in little-endian
- Pixel Data:
    - The number of non-space ASCII characters must be `275`
    - Non-space ASCII must be in between `0x20` and `0x7E`

 
Based on the number of pixels (`275`) we want, we can reverse engineer some values for the height (`25`) and weight (`11`).
 
```python title="~/script.py" showLineNumbers
import struct

# Build the header (8 bytes total)
magic = b"cIMG"                   # 4 bytes
version = struct.pack("<L", 1)    # 4 bytes
width = struct.pack("<L", 25)     # 4 bytes 
height = struct.pack("<H", 11)    # 2 bytes 

header = magic + version + width + height

# Build the pixel data (25 * 11 = 275 bytes)
pixel_data = b"." * (25 * 11)

# Full file content
cimg_data = header + pixel_data

# Write to disk
filename = "/home/hacker/solution.cimg"
with open(filename, "wb") as f:
    f.write(cimg_data)

print(f"Wrote {len(cimg_data)} bytes: {cimg_data} to file: '{filename}'")
```

```
hacker@reverse-engineering~behold-the-cimg-python:/$ python ~/script.py 
Wrote 289 bytes: b'cIMG\x01\x00\x00\x00\x19\x00\x00\x00\x0b\x00...................................................................................................................................................................................................................................................................................' to file: '/home/hacker/solution.cimg'
```

```
hacker@reverse-engineering~behold-the-cimg-python:/$ /challenge/cimg ~/solution.cimg 
.........................
.........................
.........................
.........................
.........................
.........................
.........................
.........................
.........................
.........................
.........................

pwn.college{Q-1xYEjUKjuKBEfHIV5c_J4d_fu.QX1ETN2EDL4ITM0EzW}
```

&nbsp;

## Behold the cIMG! (C)

### Source code
```c title="/challenge/cimg.c" showLineNumbers
#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/signal.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/sendfile.h>
#include <sys/prctl.h>
#include <sys/personality.h>
#include <arpa/inet.h>

void win()
{
    char flag[256];
    int flag_fd;
    int flag_length;

    flag_fd = open("/flag", 0);
    if (flag_fd < 0)
    {
        printf("\n  ERROR: Failed to open the flag -- %s!\n", strerror(errno));
        if (geteuid() != 0)
        {
            printf("  Your effective user id is not 0!\n");
            printf("  You must directly run the suid binary in order to have the correct permissions!\n");
        }
        exit(-1);
    }
    flag_length = read(flag_fd, flag, sizeof(flag));
    if (flag_length <= 0)
    {
        printf("\n  ERROR: Failed to read the flag -- %s!\n", strerror(errno));
        exit(-1);
    }
    write(1, flag, flag_length);
    printf("\n\n");
}

void read_exact(int fd, void *dst, int size, char *msg, int exitcode)
{
    int n = read(fd, dst, size);
    if (n != size)
    {
        fprintf(stderr, msg);
        fprintf(stderr, "\n");
        exit(exitcode);
    }
}

struct cimg_header
{
    char magic_number[4];
    uint8_t version;
    uint64_t width;
    uint16_t height;
} __attribute__((packed));

typedef struct
{
    uint8_t ascii;
} pixel_bw_t;
typedef pixel_bw_t pixel_t;

struct cimg
{
    struct cimg_header header;
};

#define CIMG_NUM_PIXELS(cimg) ((cimg)->header.width * (cimg)->header.height)
#define CIMG_DATA_SIZE(cimg) (CIMG_NUM_PIXELS(cimg) * sizeof(pixel_t))

void display(struct cimg *cimg, pixel_t *data)
{
    int idx = 0;
    for (int y = 0; y < cimg->header.height; y++)
    {
        for (int x = 0; x < cimg->header.width; x++)
        {
            idx = (0+y)*((cimg)->header.width) + ((0+x)%((cimg)->header.width));
            putchar(data[y * cimg->header.width + x].ascii);

        }
        puts("");
    }

}

void __attribute__ ((constructor)) disable_buffering()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 1);
}

int main(int argc, char **argv, char **envp)
{

    struct cimg cimg = { 0 };
    int won = 1;

    if (argc > 1)
    {
        if (strcmp(argv[1]+strlen(argv[1])-5, ".cimg"))
        {
            printf("ERROR: Invalid file extension!");
            exit(-1);
        }
        dup2(open(argv[1], O_RDONLY), 0);
    }

    read_exact(0, &cimg.header, sizeof(cimg.header), "ERROR: Failed to read header!", -1);

    if (cimg.header.magic_number[0] != 'c' || cimg.header.magic_number[1] != 'I' || cimg.header.magic_number[2] != 'M' || cimg.header.magic_number[3] != 'G')
    {
        puts("ERROR: Invalid magic number!");
        exit(-1);
    }

    if (cimg.header.version != 1)
    {
        puts("ERROR: Unsupported version!");
        exit(-1);
    }

    unsigned long data_size = cimg.header.width * cimg.header.height * sizeof(pixel_t);
    pixel_t *data = malloc(data_size);
    if (data == NULL)
    {
        puts("ERROR: Failed to allocate memory for the image data!");
        exit(-1);
    }
    read_exact(0, data, data_size, "ERROR: Failed to read data!", -1);

    for (int i = 0; i < cimg.header.width * cimg.header.height; i++)
    {
        if (data[i].ascii < 0x20 || data[i].ascii > 0x7e)
        {
            fprintf(stderr, "ERROR: Invalid character 0x%x in the image data!\n", data[i].ascii);
            exit(-1);
        }
    }

    display(&cimg, data);

    int num_nonspace = 0;
    for (int i = 0; i < cimg.header.width * cimg.header.height; i++)
    {
        if (data[i].ascii != ' ') num_nonspace++;
    }
    if (num_nonspace != 275) won = 0;

    if (won) win();

}
```

The challenge performs the following checks:
- File Extension: Must end with `.cimg`
- Header (15 bytes total):
    - Magic number (4 bytes): Must be `b"cIMG"`
    - Version (1 bytes): Must be `1` in little-endian
    - Width (8 bytes): Must be in little-endian
    - Height (2 bytes): Must be in little-endian
- Pixel Data:
    - The number of non-space ASCII characters must be `275`
    - Non-space ASCII must be in between `0x20` and `0x7E`

 
Based on the number of pixels (`275`) we want, we can reverse engineer some values for the height (`25`) and weight (`11`).
 
```python title="~/script.py" showLineNumbers
import struct
from pwn import *

# Build the header (15 bytes total)
magic = b"cIMG"                    # 4 bytes
version = struct.pack("<B", 1)     # 1 bytes
width = struct.pack("<Q", 25)      # 8 bytes 
height = struct.pack("<H", 11)     # 2 bytes 

header = magic + version + width + height

# Build the pixel data (25 * 11 = 275 bytes)
pixel_data = b"." * (25 * 11)

# Full file content
cimg_data = header + pixel_data

# Write to disk
filename = "/home/hacker/solution.cimg"
with open(filename, "wb") as f:
    f.write(cimg_data)

print(f"Wrote {len(cimg_data)} bytes: {cimg_data} to file: '{filename}'")
```

```
hacker@reverse-engineering~behold-the-cimg-c:/$ python ~/script.py 
Wrote 290 bytes: b'cIMG\x01\x19\x00\x00\x00\x00\x00\x00\x00\x0b\x00...................................................................................................................................................................................................................................................................................' to file: '/home/hacker/solution.cimg'
```

```
hacker@reverse-engineering~behold-the-cimg-c:/$ /challenge/cimg ~/solution.cimg 
.........................
.........................
.........................
.........................
.........................
.........................
.........................
.........................
.........................
.........................
.........................
pwn.college{Y9UIwcU8PAlWDhlav3ieIczJPrB.QX2ETN2EDL4ITM0EzW}
```

&nbsp;

## Behold the cIMG! (x86)

### Decompilation

#### `main()`

![image](https://github.com/user-attachments/assets/cc0aa45c-21d0-4585-8a1d-4117c9e7ee58?raw=1)

![image](https://github.com/user-attachments/assets/e6be3c7d-46dd-41e2-ac83-6c34d1d4eb43?raw=1)

The challenge performs the following checks:
- File Extension: Must end with `.cimg`
- Header (14 bytes total):
    - Magic number (4 bytes): Must be `0x63494d47"`
    - Version (4 bytes): Must be `1` in little-endian
    - Width (4 bytes): Must be in little-endian
    - Height (2 bytes): Must be in little-endian
- Pixel Data:
    - The number of non-space ASCII characters must be `275`
    - Non-space ASCII must be in between `0x20` and `0x7E`
 

```python title="~/script.py" showLineNumbers
import struct
from pwn import *

# Build the header (14 bytes total)
magic = bytes.fromhex("63494d47")  # 4 bytes
version = struct.pack("<L", 1)     # 4 bytes
width = struct.pack("<L", 25)      # 4 bytes 
height = struct.pack("<H", 11)     # 2 bytes 

header = magic + version + width + height

# Build the pixel data (25 * 11 = 275 bytes)
pixel_data = b"." * (25 * 11)

# Full file content
cimg_data = header + pixel_data

# Write to disk
filename = "/home/hacker/solution.cimg"
with open(filename, "wb") as f:
    f.write(cimg_data)

print(f"Wrote {len(cimg_data)} bytes: {cimg_data} to file: '{filename}'")
```

```
hacker@reverse-engineering~behold-the-cimg-x86:/$ python ~/script.py 
Wrote 289 bytes: b'cIMG\x01\x00\x00\x00\x19\x00\x00\x00\x0b\x00...................................................................................................................................................................................................................................................................................' to file: '/home/hacker/solution.cimg'
```

```
hacker@reverse-engineering~behold-the-cimg-x86:/$ /challenge/cimg ~/solution.cimg 
.........................
.........................
.........................
.........................
.........................
.........................
.........................
.........................
.........................
.........................
.........................
pwn.college{8tyvsR_873aVBQOOVrrdXDT1h4x.QX1AzMwEDL4ITM0EzW}
```

&nbsp;

## A Basic cIMG (Python)

### Source code
```python title="/chalenge/cimg" showLineNumbers
#!/opt/pwn.college/python

import os
import sys
from collections import namedtuple

Pixel = namedtuple("Pixel", ["r", "g", "b", "ascii"])


def main():
    if len(sys.argv) >= 2:
        path = sys.argv[1]
        assert path.endswith(".cimg"), "ERROR: file has incorrect extension"
        file = open(path, "rb")
    else:
        file = sys.stdin.buffer

    header = file.read1(10)
    assert len(header) == 10, "ERROR: Failed to read header!"

    assert header[:4] == b"cIMG", "ERROR: Invalid magic number!"

    assert int.from_bytes(header[4:5], "little") == 2, "ERROR: Invalid version!"

    width = int.from_bytes(header[5:6], "little")
    assert width == 39, "ERROR: Incorrect width!"

    height = int.from_bytes(header[6:10], "little")
    assert height == 21, "ERROR: Incorrect height!"

    data = file.read1(width * height * 4)
    assert len(data) == width * height * 4, "ERROR: Failed to read data!"

    pixels = [Pixel(*data[i : i + 4]) for i in range(0, len(data), 4)]

    invalid_character = next((pixel.ascii for pixel in pixels if not (0x20 <= pixel.ascii <= 0x7E)), None)
    assert invalid_character is None, f"ERROR: Invalid character {invalid_character:#04x} in data!"

    ansii_escape = lambda pixel: f"\x1b[38;2;{pixel.r:03};{pixel.g:03};{pixel.b:03}m{chr(pixel.ascii)}\x1b[0m"
    framebuffer = "".join(
        "".join(ansii_escape(pixel) for pixel in pixels[row_start : row_start + width])
        + ansii_escape(Pixel(0, 0, 0, ord("\n")))
        for row_start in range(0, len(pixels), width)
    )
    print(framebuffer)

    nonspace_count = sum(1 for pixel in pixels if chr(pixel.ascii) != " ")
    if nonspace_count != 819:
        return

    asu_maroon = (0x8C, 0x1D, 0x40)
    if any((pixel.r, pixel.g, pixel.b) != asu_maroon for pixel in pixels):
        return

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

The challenge performs the following checks:
- File Extension: Must end with `.cimg`
- Header (10 bytes total):
    - Magic number (4 bytes): Must be `b"cIMG"`
    - Version (1 bytes): Must be `2` in little-endian
    - Width (1 bytes): Must be `39` in little-endian
    - Height (4 bytes): Must be `21` in little-endian
- Pixel Data:
    - The number of non-space ASCII pixels must be `39 * 21 = 819`, i.e. the number of bytes must be `819 * 4 = 3276`
    - Non-space ASCII must be between `0x20` and `0x7E`
    - Must have the non-space ASCII character in ASU maroon `(0x8C, 0x1D, 0x40)` color when 4 consecutive bytes are chunked

This time the challenge treats 4 bytes as one pixel, and the bytes hold the following values:

```
     R        G        B        ASCII to be printed
┌────────┬────────┬────────┬────────┐
│   140  │   29   │   64   │   .    │
└────────┴────────┴────────┴────────┘
```

```python title="~/script.py" showLineNumbers
import struct
from pwn import *

# Build the header (10 bytes total)
magic = b"cIMG"                    # 4 bytes
version = struct.pack("<B", 2)     # 1 bytes
width = struct.pack("<B", 39)      # 1 bytes 
height = struct.pack("<L", 21)     # 4 bytes 

header = magic + version + width + height

# Build the pixel data (39 * 21 * 4 = 3276 bytes)
pixel = b"\x8C\x1D\x40."   
pixel_data = pixel * (39 * 21)  

# Full file content
cimg_data = header + pixel_data

# Write to disk
filename = "/home/hacker/solution.cimg"
with open(filename, "wb") as f:
    f.write(cimg_data)

print(f"Wrote {len(cimg_data)} bytes: {cimg_data} to file: '{filename}'")
```

```
hacker@reverse-engineering~a-basic-cimg-python:/$ python ~/script.py 
Wrote 3286 bytes: b"cIMG\x02'\x15\x00\x00\x00\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@." to file: '/home/hacker/solution.cimg'
```

```
hacker@reverse-engineering~a-basic-cimg-python:/$ /challenge/cimg ~/solution.cimg 
.......................................
.......................................
.......................................
.......................................
.......................................
.......................................
.......................................
.......................................
.......................................
.......................................
.......................................
.......................................
.......................................
.......................................
.......................................
.......................................
.......................................
.......................................
.......................................
.......................................
.......................................

pwn.college{Q6Dv1cf7dB1UwYRL2Mzcu_E967L.QX3ETN2EDL4ITM0EzW}
```

![image](https://github.com/user-attachments/assets/2252eb4a-5c7f-4e33-a513-32544ddf404d?raw=1)

&nbsp;

## A Basic cIMG (C)

### Source code
```c title="/challenge/cimg.c" showLineNumbers
#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/signal.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/sendfile.h>
#include <sys/prctl.h>
#include <sys/personality.h>
#include <arpa/inet.h>

void win()
{
    char flag[256];
    int flag_fd;
    int flag_length;

    flag_fd = open("/flag", 0);
    if (flag_fd < 0)
    {
        printf("\n  ERROR: Failed to open the flag -- %s!\n", strerror(errno));
        if (geteuid() != 0)
        {
            printf("  Your effective user id is not 0!\n");
            printf("  You must directly run the suid binary in order to have the correct permissions!\n");
        }
        exit(-1);
    }
    flag_length = read(flag_fd, flag, sizeof(flag));
    if (flag_length <= 0)
    {
        printf("\n  ERROR: Failed to read the flag -- %s!\n", strerror(errno));
        exit(-1);
    }
    write(1, flag, flag_length);
    printf("\n\n");
}

void read_exact(int fd, void *dst, int size, char *msg, int exitcode)
{
    int n = read(fd, dst, size);
    if (n != size)
    {
        fprintf(stderr, msg);
        fprintf(stderr, "\n");
        exit(exitcode);
    }
}

struct cimg_header
{
    char magic_number[4];
    uint16_t version;
    uint8_t width;
    uint64_t height;
} __attribute__((packed));

typedef struct
{
    uint8_t ascii;
} pixel_bw_t;
#define COLOR_PIXEL_FMT "\x1b[38;2;%03d;%03d;%03dm%c\x1b[0m"
typedef struct
{
    uint8_t r;
    uint8_t g;
    uint8_t b;
    uint8_t ascii;
} pixel_color_t;
typedef pixel_color_t pixel_t;

struct cimg
{
    struct cimg_header header;
};

#define CIMG_NUM_PIXELS(cimg) ((cimg)->header.width * (cimg)->header.height)
#define CIMG_DATA_SIZE(cimg) (CIMG_NUM_PIXELS(cimg) * sizeof(pixel_t))

void display(struct cimg *cimg, pixel_t *data)
{
    int idx = 0;
    for (int y = 0; y < cimg->header.height; y++)
    {
        for (int x = 0; x < cimg->header.width; x++)
        {
            idx = (0+y)*((cimg)->header.width) + ((0+x)%((cimg)->header.width));
            printf("\x1b[38;2;%03d;%03d;%03dm%c\x1b[0m", data[y * cimg->header.width + x].r, data[y * cimg->header.width + x].g, data[y * cimg->header.width + x].b, data[y * cimg->header.width + x].ascii);

        }
        puts("");
    }

}

void __attribute__ ((constructor)) disable_buffering()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 1);
}

int main(int argc, char **argv, char **envp)
{

    struct cimg cimg = { 0 };
    int won = 1;

    if (argc > 1)
    {
        if (strcmp(argv[1]+strlen(argv[1])-5, ".cimg"))
        {
            printf("ERROR: Invalid file extension!");
            exit(-1);
        }
        dup2(open(argv[1], O_RDONLY), 0);
    }

    read_exact(0, &cimg.header, sizeof(cimg.header), "ERROR: Failed to read header!", -1);

    if (cimg.header.magic_number[0] != 'c' || cimg.header.magic_number[1] != 'I' || cimg.header.magic_number[2] != 'M' || cimg.header.magic_number[3] != 'G')
    {
        puts("ERROR: Invalid magic number!");
        exit(-1);
    }

    if (cimg.header.version != 2)
    {
        puts("ERROR: Unsupported version!");
        exit(-1);
    }

    if (cimg.header.width != 51)
    {
        puts("ERROR: Incorrect width!");
        exit(-1);
    }

    if (cimg.header.height != 24)
    {
        puts("ERROR: Incorrect height!");
        exit(-1);
    }

    unsigned long data_size = cimg.header.width * cimg.header.height * sizeof(pixel_t);
    pixel_t *data = malloc(data_size);
    if (data == NULL)
    {
        puts("ERROR: Failed to allocate memory for the image data!");
        exit(-1);
    }
    read_exact(0, data, data_size, "ERROR: Failed to read data!", -1);

    for (int i = 0; i < cimg.header.width * cimg.header.height; i++)
    {
        if (data[i].ascii < 0x20 || data[i].ascii > 0x7e)
        {
            fprintf(stderr, "ERROR: Invalid character 0x%x in the image data!\n", data[i].ascii);
            exit(-1);
        }
    }

    display(&cimg, data);

    for (int i = 0; i < cimg.header.width * cimg.header.height; i++)
    {
        if (data[i].r != 0x8c || data[i].g != 0x1d || data[i].b != 0x40) won = 0;
    }

    int num_nonspace = 0;
    for (int i = 0; i < cimg.header.width * cimg.header.height; i++)
    {
        if (data[i].ascii != ' ') num_nonspace++;
    }
    if (num_nonspace != 1224) won = 0;

    if (won) win();

}
```

The challenge performs the following checks:
- File Extension: Must end with `.cimg`
- Header (15 bytes total):
    - Magic number (4 bytes): Must be `0x63494d47"`
    - Version (2 bytes): Must be `2` in little-endian
    - Width (1 bytes): Must be `51` in little-endian
    - Height (8 bytes): Must be `24` in little-endian
- Pixel Data:
    - The number of non-space ASCII pixels must be `51 * 24 = 1224`, i.e. the number of bytes must be `1224 * 4 = 4896`
    - Non-space ASCII must be between `0x20` and `0x7E`
    - Must have the non-space ASCII character in ASU maroon `(0x8c, 0x1d, 0x40)` color when 4 consecutive bytes are chunked
 
```python title="~/script.py" showLineNumbers
import struct
from pwn import *

# Build the header (15 bytes total)
magic = b"cIMG"                    # 4 bytes
version = struct.pack("<H", 2)     # 2 bytes
width = struct.pack("<B", 51)      # 1 bytes 
height = struct.pack("<Q", 24)     # 8 bytes 

header = magic + version + width + height

# Build the pixel data (51 * 24 * 4 = 4896 bytes)
pixel = b"\x8C\x1D\x40."   
pixel_data = pixel * (51 * 24)  

# Full file content
cimg_data = header + pixel_data

# Write to disk
filename = "/home/hacker/solution.cimg"
with open(filename, "wb") as f:
    f.write(cimg_data)

print(f"Wrote {len(cimg_data)} bytes: {cimg_data} to file: '{filename}'")
```

```
hacker@reverse-engineering~a-basic-cimg-c:/$ python ~/script.py 
Wrote 4907 bytes: b'cIMG\x023\x00\x18\x00\x00\x00\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.' to file: '/home/hacker/solution.cimg'
```

```
hacker@reverse-engineering~a-basic-cimg-c:/$ /challenge/cimg ~/solution.cimg
...................................................
...................................................
...................................................
...................................................
...................................................
...................................................
...................................................
...................................................
...................................................
...................................................
...................................................
...................................................
...................................................
...................................................
...................................................
...................................................
...................................................
...................................................
...................................................
...................................................
...................................................
...................................................
...................................................
...................................................
pwn.college{4IY_xVT2BdscpfYAibCo97rS48E.QX4ETN2EDL4ITM0EzW}
```

![image](https://github.com/user-attachments/assets/cc4e60e6-03e5-4c85-9095-7ae05ba948d8?raw=1)

&nbsp;

## A Basic cIMG (x86)

### Decompilation

#### `main()`

![image](https://github.com/user-attachments/assets/05c4947a-f48f-4982-aa69-6de50094baa4?raw=1)

![image](https://github.com/user-attachments/assets/062d20f5-50bf-4835-94b7-11a3eaa2ce0a?raw=1)

![image](https://github.com/user-attachments/assets/10c4250a-2b6d-407e-a978-9b2ffe72700a?raw=1)

![image](https://github.com/user-attachments/assets/86fb2186-ca81-419b-8acc-9f568ceb313a?raw=1)

![image](https://github.com/user-attachments/assets/b135b9fb-e0c2-4909-abc1-e3ddda07d7f5?raw=1)

![image](https://github.com/user-attachments/assets/891b2f52-5057-409f-ad44-845d20c65cc2?raw=1)

![image](https://github.com/user-attachments/assets/836db900-117c-4ed9-8741-ad054dead51b?raw=1)

The challenge performs the following checks:
- File Extension: Must end with `.cimg`
- Header (24 bytes total):
    - Magic number (4 bytes): Must be `0x63494d47"`
    - Version (4 bytes): Must be `2` in little-endian
    - Width (8 bytes): Must be `75` in little-endian
    - Height (8 bytes): Must be `22` in little-endian
- Pixel Data:
    - The number of non-space ASCII pixels must be `75 * 22 = 1650`, i.e. the number of bytes must be `1650 * 4 = 6600`
    - Non-space ASCII must be between `0x20` and `0x7E`
    - Must have the non-space ASCII character in ASU maroon `(0x8c, 0x1d, 0x40)` color when 4 consecutive bytes are chunked
 
```python title="~/script.py" showLineNumbers
import struct
from pwn import *

# Build the header (24 bytes total)
magic = b"cIMG"                    # 4 bytes
version = struct.pack("<I", 2)     # 4 bytes
width = struct.pack("<Q", 75)      # 8 bytes 
height = struct.pack("<Q", 22)     # 8 bytes 

header = magic + version + width + height

# Build the pixel data (75 * 22 * 4 = 6600 bytes)
pixel = b"\x8c\x1d\x40."   
pixel_data = pixel * (75 * 22)  

# Full file content
cimg_data = header + pixel_data

# Write to disk
filename = "/home/hacker/solution.cimg"
with open(filename, "wb") as f:
    f.write(cimg_data)

print(f"Wrote {len(cimg_data)} bytes: {cimg_data} to file: '{filename}'")
```

```
hacker@reverse-engineering~a-basic-cimg-x86:/$ python ~/script.py 
Wrote 6624 bytes: b'cIMG\x02\x00\x00\x00K\x00\x00\x00\x00\x00\x00\x00\x16\x00\x00\x00\x00\x00\x00\x00\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.\x8c\x1d@.' to file: '/home/hacker/solution.cimg'
```

```
hacker@reverse-engineering~a-basic-cimg-x86:/$ /challenge/cimg ~/solution.cimg 
...........................................................................
...........................................................................
...........................................................................
...........................................................................
...........................................................................
...........................................................................
...........................................................................
...........................................................................
...........................................................................
...........................................................................
...........................................................................
...........................................................................
...........................................................................
...........................................................................
...........................................................................
...........................................................................
...........................................................................
...........................................................................
...........................................................................
...........................................................................
...........................................................................
...........................................................................
pwn.college{UtFfALQAM2u-0NsYhnUJCQXPUZc.QX2AzMwEDL4ITM0EzW}
```

![image](https://github.com/user-attachments/assets/d20bdde0-c41b-4e8a-bb09-df1cb2363a9d?raw=1)

## Internal State Mini (C)

### Source code
```c title="/challenge/cimg.c" showLineNumbers
#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/signal.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/sendfile.h>
#include <sys/prctl.h>
#include <sys/personality.h>
#include <arpa/inet.h>

void win()
{
    char flag[256];
    int flag_fd;
    int flag_length;

    flag_fd = open("/flag", 0);
    if (flag_fd < 0)
    {
        printf("\n  ERROR: Failed to open the flag -- %s!\n", strerror(errno));
        if (geteuid() != 0)
        {
            printf("  Your effective user id is not 0!\n");
            printf("  You must directly run the suid binary in order to have the correct permissions!\n");
        }
        exit(-1);
    }
    flag_length = read(flag_fd, flag, sizeof(flag));
    if (flag_length <= 0)
    {
        printf("\n  ERROR: Failed to read the flag -- %s!\n", strerror(errno));
        exit(-1);
    }
    write(1, flag, flag_length);
    printf("\n\n");
}

void read_exact(int fd, void *dst, int size, char *msg, int exitcode)
{
    int n = read(fd, dst, size);
    if (n != size)
    {
        fprintf(stderr, msg);
        fprintf(stderr, "\n");
        exit(exitcode);
    }
}

char desired_output[] = "\x1b[38;2;200;040;131mc\x1b[0m\x1b[38;2;001;019;165mI\x1b[0m\x1b[38;2;160;134;059mM\x1b[0m\x1b[38;2;195;046;079mG\x1b[0m\x00";

struct cimg_header
{
    char magic_number[4];
    uint16_t version;
    uint8_t width;
    uint8_t height;
} __attribute__((packed));

typedef struct
{
    uint8_t ascii;
} pixel_bw_t;
#define COLOR_PIXEL_FMT "\x1b[38;2;%03d;%03d;%03dm%c\x1b[0m"
typedef struct
{
    uint8_t r;
    uint8_t g;
    uint8_t b;
    uint8_t ascii;
} pixel_color_t;
typedef pixel_color_t pixel_t;

typedef struct
{
    union
    {
        char data[24];
        struct term_str_st
        {
            char color_set[7];   // \x1b[38;2;
            char r[3];          // 255
            char s1;            // ;
            char g[3];          // 255
            char s2;            // ;
            char b[3];          // 255
            char m;            // m
            char c;             // X
            char color_reset[4];     // \x1b[0m
        } str;
    };
} term_pixel_t;

struct cimg
{
    struct cimg_header header;
    unsigned num_pixels;
    term_pixel_t *framebuffer;
};

#define CIMG_NUM_PIXELS(cimg) ((cimg)->header.width * (cimg)->header.height)
#define CIMG_DATA_SIZE(cimg) (CIMG_NUM_PIXELS(cimg) * sizeof(pixel_t))
#define CIMG_FRAMEBUFFER_PIXELS(cimg) ((cimg)->header.width * (cimg)->header.height)
#define CIMG_FRAMEBUFFER_SIZE(cimg) (CIMG_FRAMEBUFFER_PIXELS(cimg) * sizeof(term_pixel_t))

void display(struct cimg *cimg, pixel_t *data)
{
    int idx = 0;
    for (int y = 0; y < cimg->header.height; y++)
    {
        for (int x = 0; x < cimg->header.width; x++)
        {
            idx = (0+y)*((cimg)->header.width) + ((0+x)%((cimg)->header.width));
            char emit_tmp[24+1];
            snprintf(emit_tmp, sizeof(emit_tmp), "\x1b[38;2;%03d;%03d;%03dm%c\x1b[0m", data[y * cimg->header.width + x].r, data[y * cimg->header.width + x].g, data[y * cimg->header.width + x].b, data[y * cimg->header.width + x].ascii);
            memcpy((cimg)->framebuffer[idx%(cimg)->num_pixels].data, emit_tmp, 24);

        }
    }

    for (int i = 0; i < cimg->header.height; i++)
    {
        write(1, cimg->framebuffer+i*cimg->header.width, sizeof(term_pixel_t)*cimg->header.width);
        write(1, "\x1b[38;2;000;000;000m\n\x1b[0m", 24);
    }
}

struct cimg *initialize_framebuffer(struct cimg *cimg)
{
    cimg->num_pixels = CIMG_FRAMEBUFFER_PIXELS(cimg);
    cimg->framebuffer = malloc(CIMG_FRAMEBUFFER_SIZE(cimg)+1);
    if (cimg->framebuffer == NULL)
    {
        puts("ERROR: Failed to allocate memory for the framebuffer!");
        exit(-1);
    }
    for (int idx = 0; idx < cimg->num_pixels; idx += 1)
    {
        char emit_tmp[24+1];
        snprintf(emit_tmp, sizeof(emit_tmp), "\x1b[38;2;%03d;%03d;%03dm%c\x1b[0m", 255, 255, 255, ' ');
        memcpy(cimg->framebuffer[idx].data, emit_tmp, 24);

    }

    return cimg;
}

void __attribute__ ((constructor)) disable_buffering()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 1);
}

int main(int argc, char **argv, char **envp)
{

    struct cimg cimg = { 0 };
    cimg.framebuffer = NULL;
    int won = 1;

    if (argc > 1)
    {
        if (strcmp(argv[1]+strlen(argv[1])-5, ".cimg"))
        {
            printf("ERROR: Invalid file extension!");
            exit(-1);
        }
        dup2(open(argv[1], O_RDONLY), 0);
    }

    read_exact(0, &cimg.header, sizeof(cimg.header), "ERROR: Failed to read header!", -1);

    if (cimg.header.magic_number[0] != 'c' || cimg.header.magic_number[1] != 'I' || cimg.header.magic_number[2] != 'M' || cimg.header.magic_number[3] != 'G')
    {
        puts("ERROR: Invalid magic number!");
        exit(-1);
    }

    if (cimg.header.version != 2)
    {
        puts("ERROR: Unsupported version!");
        exit(-1);
    }

    initialize_framebuffer(&cimg);

    unsigned long data_size = cimg.header.width * cimg.header.height * sizeof(pixel_t);
    pixel_t *data = malloc(data_size);
    if (data == NULL)
    {
        puts("ERROR: Failed to allocate memory for the image data!");
        exit(-1);
    }
    read_exact(0, data, data_size, "ERROR: Failed to read data!", -1);

    for (int i = 0; i < cimg.header.width * cimg.header.height; i++)
    {
        if (data[i].ascii < 0x20 || data[i].ascii > 0x7e)
        {
            fprintf(stderr, "ERROR: Invalid character 0x%x in the image data!\n", data[i].ascii);
            exit(-1);
        }
    }

    display(&cimg, data);

    if (cimg.num_pixels != sizeof(desired_output)/sizeof(term_pixel_t))
    {
        won = 0;
    }
    for (int i = 0; i < cimg.num_pixels && i < sizeof(desired_output)/sizeof(term_pixel_t); i++)
    {
        if (cimg.framebuffer[i].str.c != ((term_pixel_t*)&desired_output)[i].str.c)
        {
            won = 0;
        }
        if (
            cimg.framebuffer[i].str.c != ' ' &&
            cimg.framebuffer[i].str.c != '\n' &&
            memcmp(cimg.framebuffer[i].data, ((term_pixel_t*)&desired_output)[i].data, sizeof(term_pixel_t))
        )
        {
            won = 0;
        }
    }

    if (won) win();

}
```

The challenge performs the following checks:
- File Extension: Must end with `.cimg`
- Header (8 bytes total):
    - Magic number (4 bytes): Must be "`cIMG`"
    - Version (2 bytes): Must be `2` in little-endian
    - Dimensions (2 bytes total): Must be 4 bytes
        - Width (1 bytes): Must be either `4` (if `height = 1`), `2` (if `height = 2`) or `1` (if `height = 4`) in little-endian
        - Height (1 bytes): Must be either `1` (if `width = 4`), `2` (if `width = 2`) or `4` (if `width = 1`) in little-endian
- Pixel Data:
    - The number of non-space ASCII pixels must be `4 * 1 = 4`, i.e. the number of bytes must be `4 * 4 = 16`
    - When pixel data is loaded into the [ANSI escape code](https://en.wikipedia.org/wiki/ANSI_escape_code#24-bit): `"\x1b[38;2;%03d;%03d;%03dm%c\x1b[0m"` one by one and appended together, it should match the following: `"\x1b[38;2;200;040;131mc\x1b[0m\x1b[38;2;001;019;165mI\x1b[0m\x1b[38;2;160;134;059mM\x1b[0m\x1b[38;2;195;046;079mG\x1b[0m\x00";`

The template that the challenge enforces isn't just a random template, it is the the ANSI SGR.

### [ANSI 24-bit escape code](https://en.wikipedia.org/wiki/ANSI_escape_code#24-bit)

Modern terminals supports Truecolor (24-bit RGB), which allows you to set foreground and background colors using RGB.

| Escape Code Sequence | Description | 
|:---|:---|
| `ESC[38;2;{r};{g};{b}m` | Set foreground color as RGB. |

```
\x1b            --> ESC character
[               --> CSI (Control Sequence Initiator)
38;2;R;G;B      --> ANSI SGR parameter meaning “Set 24-bit foreground color”
m               --> End of SGR
.               --> Character printed in RGB colours
\x1b[0m         --> Reset terminal formatting
```

If we write the first pixel as `b"xc8(\x83c"`, the challenge fills in the pixel RGB bytes using the `%03d` placeholder and fills the ASCII character byte with the `%c` placeholder.

```
## Template:
\x1b[38;2;%03d;%03d;%03dm%c\x1b[0m

## First pixel (c)
%03d -> 200 -> "200"
%03d -> 40  -> "040"
%03d -> 131 -> "131"
%c   -> 'c'

## Final ANSII pixel
\x1b[38;2;200;040;131mc\x1b[0m
```

```python title="~/script.py" showLineNumbers
import struct

# Build the header (8 bytes total)
magic = b"cIMG"                     # 4 bytes
version = struct.pack("<H", 2)      # 2 bytes
width  = struct.pack("<B", 4)       # 1 bytes
height = struct.pack("<B", 1)       # 1 bytes

header = magic + version + width + height

# Build the pixel data (51 * 24 * 4 = 4896 bytes)
pixels = [
    (200, 40, 131, ord('c')),
    (1, 19, 165, ord('I')),
    (160, 134, 59, ord('M')),
    (195, 46, 79, ord('G')),
]

pixel_data = b"".join(struct.pack("BBBB", r, g, b, a) for r, g, b, a in pixels)

# Full file content
cimg_data = header + pixel_data

# Write to disk
filename = "/home/hacker/solution.cimg"
with open(filename, "wb") as f:
    f.write(cimg_data)

print(f"Wrote {len(cimg_data)} bytes: {cimg_data} to: {filename}")
```

```
hacker@reverse-engineering~internal-state-mini-c:/$ python ~/script.py 
Wrote 24 bytes: b'cIMG\x02\x00\x04\x01\xc8(\x83c\x01\x13\xa5I\xa0\x86;M\xc3.OG' to: /home/hacker/solution.cimg
```

```
hacker@reverse-engineering~internal-state-mini-c:/$ /challenge/cimg ~/solution.cimg 
cIMG
pwn.college{sxObMoehMoum3fSzW12W3zqJsBu.QX5ETN2EDL4ITM0EzW}
```

<img alt="image" src="https://github.com/user-attachments/assets/0ee560f3-3499-4ea0-8146-10370099cf5a" />

&nbsp;

## Internal State Mini (x86)

### Decompilation

After decompiling the program within IDA, and some variable renaming and type altering, we get the following pseudo-C code:

<img alt="image" src="https://github.com/user-attachments/assets/7bfe15f4-6483-471a-85c9-8c46a90af07f" />

#### `main()`

```c showLineNumbers
int __fastcall main(int argc, const char **argv, const char **envp)
{
  const char *file_arg; // rbp
  int file; // eax
  const char *error_msg; // rdi
  unsigned int v6; // ebx
  unsigned __int8 *v7; // rax
  unsigned __int8 *v8; // rbp
  __int64 i_1; // rax
  __int64 data_i_ascii; // rcx
  char *desired_ansii_sequence; // r12
  unsigned int v12; // r13d
  __int64 framebuffer_2; // r14
  _BOOL8 won; // rbx
  __int64 i; // rbp
  char str_c; // al
  __int128 cimg_header; // [rsp+0h] [rbp-58h] BYREF
  __int64 framebuffer; // [rsp+10h] [rbp-48h]
  unsigned __int64 v20; // [rsp+18h] [rbp-40h]

  v20 = __readfsqword(0x28u);
  cimg_header = 0LL;
  framebuffer = 0LL;
  if ( argc > 1 )
  {
    file_arg = argv[1];
    if ( strcmp(&file_arg[strlen(file_arg) - 5], ".cimg") )
    {
      __printf_chk(1LL, "ERROR: Invalid file extension!");
      goto EXIT;
    }
    file = open(file_arg, 0);
    dup2(file, 0);
  }
  read_exact(0LL, &cimg_header, 8LL, "ERROR: Failed to read header!", 0xFFFFFFFFLL);
  if ( (_DWORD)cimg_header != 'GMIc' )
  {
    error_msg = "ERROR: Invalid magic number!";
PRINT_ERROR_AND_EXIT:
    puts(error_msg);
    goto EXIT;
  }
  error_msg = "ERROR: Unsupported version!";
  if ( WORD2(cimg_header) != 2 )
    goto PRINT_ERROR_AND_EXIT;
  initialize_framebuffer(&cimg_header);
  v6 = 4 * BYTE7(cimg_header) * BYTE6(cimg_header);
  v7 = (unsigned __int8 *)malloc(4LL * BYTE7(cimg_header) * BYTE6(cimg_header));
  error_msg = "ERROR: Failed to allocate memory for the image data!";
  v8 = v7;
  if ( !v7 )
    goto PRINT_ERROR_AND_EXIT;
  read_exact(0LL, v7, v6, "ERROR: Failed to read data!", 0xFFFFFFFFLL);
  i_1 = 0LL;
  while ( BYTE7(cimg_header) * BYTE6(cimg_header) > (int)i_1 )
  {
    data_i_ascii = v8[4 * i_1++ + 3];           // data[i].ascii
    if ( (unsigned __int8)(data_i_ascii - 32) > 0x5Eu )// if (data[i].ascii < 0x20 || data[i].ascii > 0x7e)
    {
      __fprintf_chk(stderr, 1LL, "ERROR: Invalid character 0x%x in the image data!\n", data_i_ascii);
EXIT:
      exit(-1);
    }
  }
  desired_ansii_sequence = desired_output;
  display(&cimg_header, v8);
  v12 = DWORD2(cimg_header);
  framebuffer_2 = framebuffer;
  won = DWORD2(cimg_header) == 4;
  for ( i = 0LL; (_DWORD)i != 4 && v12 > (unsigned int)i; ++i )
  {
    str_c = *(_BYTE *)(framebuffer_2 + 24 * i + 19);
    if ( str_c != desired_ansii_sequence[19] )
      LODWORD(won) = 0;
    if ( str_c != 32 && str_c != 10 )
    {
      if ( memcmp((const void *)(framebuffer_2 + 24 * i), desired_ansii_sequence, 0x18uLL) )
        LODWORD(won) = 0;
    }
    desired_ansii_sequence += 24;
  }
  if ( won )
    win();
  return 0;
}
```

The `desired_ansii_sequence` is the same as last time.

<img alt="image" src="https://github.com/user-attachments/assets/8ea576df-a367-42b1-acb4-d79a08b514a1" />

Expected ANSI sequence:

```
"\x1b[38;2;200;040;131mc\x1b[0m\x1b[38;2;001;019;165mI\x1b[0m\x1b[38;2;160;134;059mM\x1b[0m\x1b[38;2;195;046;079mG\x1b[0m\x00"
```

The reason that `\x1b` is represented as `.` is that the ASCII ESC character is non-printable, and IDA replaces all non-printable characters with (`.`).

We can see that the challenge performs the exact same checks as the [Internal State Mini (C)](#internal-state-mini-c) version:
- File Extension: Must end with `.cimg`
- Header (8 bytes total):
    - Magic number (4 bytes): Must be "`cIMG`"
    - Version (2 bytes): Must be `2` in little-endian
    - Dimensions (2 bytes total): Must be 4 bytes
        - Width (1 bytes): Must be either `4` (if `height = 1`), `2` (if `height = 2`) or `1` (if `height = 4`) in little-endian
        - Height (1 bytes): Must be either `1` (if `width = 4`), `2` (if `width = 2`) or `4` (if `width = 1`) in little-endian
- Pixel Data:
    - The number of non-space ASCII pixels must be `4 * 1 = 4`, i.e. the number of bytes must be `4 * 4 = 16`
    - When pixel data is loaded into the [ANSI escape code](https://en.wikipedia.org/wiki/ANSI_escape_code#24-bit): `"\x1b[38;2;%03d;%03d;%03dm%c\x1b[0m"` one by one and appended together, it should match the following: `"\x1b[38;2;200;040;131mc\x1b[0m\x1b[38;2;001;019;165mI\x1b[0m\x1b[38;2;160;134;059mM\x1b[0m\x1b[38;2;195;046;079mG\x1b[0m\x00";`

```py title="~/script.py" showLineNumbers
import struct

# Build the header (8 bytes total)
magic = b"cIMG"                     # 4 bytes
version = struct.pack("<H", 2)      # 2 bytes
width  = struct.pack("<B", 4)       # 1 bytes
height = struct.pack("<B", 1)       # 1 bytes

header = magic + version + width + height

# Build the pixel data (51 * 24 * 4 = 4896 bytes)
pixels = [
    (200, 40, 131, ord('c')),
    (1, 19, 165, ord('I')),
    (160, 134, 59, ord('M')),
    (195, 46, 79, ord('G')),
]

pixel_data = b"".join(struct.pack("BBBB", r, g, b, a) for r, g, b, a in pixels)

# Full file content
cimg_data = header + pixel_data

# Write to disk
filename = "/home/hacker/solution.cimg"
with open(filename, "wb") as f:
    f.write(cimg_data)

print(f"Wrote {len(cimg_data)} bytes: {cimg_data} to: {filename}")
```

```
hacker@reverse-engineering~internal-state-mini-x86:~$ python ~/script.py 
Wrote 24 bytes: b'cIMG\x02\x00\x04\x01\xc8(\x83c\x01\x13\xa5I\xa0\x86;M\xc3.OG' to: /home/hacker/solution.cimg
```

```
hacker@reverse-engineering~internal-state-mini-x86:~$ /challenge/cimg ~/solution.cimg 
cIMG
pwn.college{gNl9haWUsUcGB0Nwci7BWxzvy8e.QXwITN2EDL4ITM0EzW}
```

<img alt="image" src="https://github.com/user-attachments/assets/16daf53c-e0ac-4f77-a66d-ed7662be07ef" />

&nbsp;

## Internal State (C)

### Source code

```c title="/challenge/cimg.c" showLineNumbers
#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/signal.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/sendfile.h>
#include <sys/prctl.h>
#include <sys/personality.h>
#include <arpa/inet.h>

void win()
{
    char flag[256];
    int flag_fd;
    int flag_length;

    flag_fd = open("/flag", 0);
    if (flag_fd < 0)
    {
        printf("\n  ERROR: Failed to open the flag -- %s!\n", strerror(errno));
        if (geteuid() != 0)
        {
            printf("  Your effective user id is not 0!\n");
            printf("  You must directly run the suid binary in order to have the correct permissions!\n");
        }
        exit(-1);
    }
    flag_length = read(flag_fd, flag, sizeof(flag));
    if (flag_length <= 0)
    {
        printf("\n  ERROR: Failed to read the flag -- %s!\n", strerror(errno));
        exit(-1);
    }
    write(1, flag, flag_length);
    printf("\n\n");
}

void read_exact(int fd, void *dst, int size, char *msg, int exitcode)
{
    int n = read(fd, dst, size);
    if (n != size)
    {
        fprintf(stderr, msg);
        fprintf(stderr, "\n");
        exit(exitcode);
    }
}

char desired_output[] = "\x1b[38;2;255;255;255m.\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m.\x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;228;010;217m \x1b[0m\x1b[38;2;228;010;217m \x1b[0m\x1b[38;2;228;010;217m_\x1b[0m\x1b[38;2;228;010;217m_\x1b[0m\x1b[38;2;228;010;217m_\x1b[0m\x1b[38;2;228;010;217m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;228;010;217m \x1b[0m\x1b[38;2;228;010;217m/\x1b[0m\x1b[38;2;228;010;217m \x1b[0m\x1b[38;2;228;010;217m_\x1b[0m\x1b[38;2;228;010;217m_\x1b[0m\x1b[38;2;228;010;217m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;137;221;241m \x1b[0m\x1b[38;2;137;221;241m_\x1b[0m\x1b[38;2;137;221;241m_\x1b[0m\x1b[38;2;137;221;241m_\x1b[0m\x1b[38;2;137;221;241m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;228;010;217m|\x1b[0m\x1b[38;2;228;010;217m \x1b[0m\x1b[38;2;228;010;217m(\x1b[0m\x1b[38;2;228;010;217m_\x1b[0m\x1b[38;2;228;010;217m_\x1b[0m\x1b[38;2;228;010;217m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;137;221;241m|\x1b[0m\x1b[38;2;137;221;241m_\x1b[0m\x1b[38;2;137;221;241m \x1b[0m\x1b[38;2;137;221;241m_\x1b[0m\x1b[38;2;137;221;241m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;228;010;217m \x1b[0m\x1b[38;2;228;010;217m\\\x1b[0m\x1b[38;2;228;010;217m_\x1b[0m\x1b[38;2;228;010;217m_\x1b[0m\x1b[38;2;228;010;217m_\x1b[0m\x1b[38;2;228;010;217m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;137;221;241m \x1b[0m\x1b[38;2;137;221;241m|\x1b[0m\x1b[38;2;137;221;241m \x1b[0m\x1b[38;2;137;221;241m|\x1b[0m\x1b[38;2;137;221;241m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;137;221;241m \x1b[0m\x1b[38;2;137;221;241m|\x1b[0m\x1b[38;2;137;221;241m \x1b[0m\x1b[38;2;137;221;241m|\x1b[0m\x1b[38;2;137;221;241m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;137;221;241m|\x1b[0m\x1b[38;2;137;221;241m_\x1b[0m\x1b[38;2;137;221;241m_\x1b[0m\x1b[38;2;137;221;241m_\x1b[0m\x1b[38;2;137;221;241m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;250;025;157m \x1b[0m\x1b[38;2;250;025;157m_\x1b[0m\x1b[38;2;250;025;157m_\x1b[0m\x1b[38;2;250;025;157m \x1b[0m\x1b[38;2;250;025;157m \x1b[0m\x1b[38;2;250;025;157m_\x1b[0m\x1b[38;2;250;025;157m_\x1b[0m\x1b[38;2;250;025;157m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;250;025;157m|\x1b[0m\x1b[38;2;250;025;157m \x1b[0m\x1b[38;2;250;025;157m \x1b[0m\x1b[38;2;250;025;157m\\\x1b[0m\x1b[38;2;250;025;157m/\x1b[0m\x1b[38;2;250;025;157m \x1b[0m\x1b[38;2;250;025;157m \x1b[0m\x1b[38;2;250;025;157m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;131;228;012m \x1b[0m\x1b[38;2;131;228;012m \x1b[0m\x1b[38;2;131;228;012m_\x1b[0m\x1b[38;2;131;228;012m_\x1b[0m\x1b[38;2;131;228;012m_\x1b[0m\x1b[38;2;131;228;012m_\x1b[0m\x1b[38;2;131;228;012m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;250;025;157m|\x1b[0m\x1b[38;2;250;025;157m \x1b[0m\x1b[38;2;250;025;157m|\x1b[0m\x1b[38;2;250;025;157m\\\x1b[0m\x1b[38;2;250;025;157m/\x1b[0m\x1b[38;2;250;025;157m|\x1b[0m\x1b[38;2;250;025;157m \x1b[0m\x1b[38;2;250;025;157m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;131;228;012m \x1b[0m\x1b[38;2;131;228;012m/\x1b[0m\x1b[38;2;131;228;012m \x1b[0m\x1b[38;2;131;228;012m_\x1b[0m\x1b[38;2;131;228;012m_\x1b[0m\x1b[38;2;131;228;012m_\x1b[0m\x1b[38;2;131;228;012m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;250;025;157m|\x1b[0m\x1b[38;2;250;025;157m \x1b[0m\x1b[38;2;250;025;157m|\x1b[0m\x1b[38;2;250;025;157m \x1b[0m\x1b[38;2;250;025;157m \x1b[0m\x1b[38;2;250;025;157m|\x1b[0m\x1b[38;2;250;025;157m \x1b[0m\x1b[38;2;250;025;157m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;131;228;012m|\x1b[0m\x1b[38;2;131;228;012m \x1b[0m\x1b[38;2;131;228;012m|\x1b[0m\x1b[38;2;131;228;012m \x1b[0m\x1b[38;2;131;228;012m \x1b[0m\x1b[38;2;131;228;012m_\x1b[0m\x1b[38;2;131;228;012m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;250;025;157m|\x1b[0m\x1b[38;2;250;025;157m_\x1b[0m\x1b[38;2;250;025;157m|\x1b[0m\x1b[38;2;250;025;157m \x1b[0m\x1b[38;2;250;025;157m \x1b[0m\x1b[38;2;250;025;157m|\x1b[0m\x1b[38;2;250;025;157m_\x1b[0m\x1b[38;2;250;025;157m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;131;228;012m|\x1b[0m\x1b[38;2;131;228;012m \x1b[0m\x1b[38;2;131;228;012m|\x1b[0m\x1b[38;2;131;228;012m_\x1b[0m\x1b[38;2;131;228;012m|\x1b[0m\x1b[38;2;131;228;012m \x1b[0m\x1b[38;2;131;228;012m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;131;228;012m \x1b[0m\x1b[38;2;131;228;012m\\\x1b[0m\x1b[38;2;131;228;012m_\x1b[0m\x1b[38;2;131;228;012m_\x1b[0m\x1b[38;2;131;228;012m_\x1b[0m\x1b[38;2;131;228;012m_\x1b[0m\x1b[38;2;131;228;012m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;255;255;255m'\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m'\x1b[0m\x00";

struct cimg_header
{
    char magic_number[4];
    uint16_t version;
    uint8_t width;
    uint8_t height;
} __attribute__((packed));

typedef struct
{
    uint8_t ascii;
} pixel_bw_t;
#define COLOR_PIXEL_FMT "\x1b[38;2;%03d;%03d;%03dm%c\x1b[0m"
typedef struct
{
    uint8_t r;
    uint8_t g;
    uint8_t b;
    uint8_t ascii;
} pixel_color_t;
typedef pixel_color_t pixel_t;

typedef struct
{
    union
    {
        char data[24];
        struct term_str_st
        {
            char color_set[7];   // \x1b[38;2;
            char r[3];          // 255
            char s1;            // ;
            char g[3];          // 255
            char s2;            // ;
            char b[3];          // 255
            char m;            // m
            char c;             // X
            char color_reset[4];     // \x1b[0m
        } str;
    };
} term_pixel_t;

struct cimg
{
    struct cimg_header header;
    unsigned num_pixels;
    term_pixel_t *framebuffer;
};

#define CIMG_NUM_PIXELS(cimg) ((cimg)->header.width * (cimg)->header.height)
#define CIMG_DATA_SIZE(cimg) (CIMG_NUM_PIXELS(cimg) * sizeof(pixel_t))
#define CIMG_FRAMEBUFFER_PIXELS(cimg) ((cimg)->header.width * (cimg)->header.height)
#define CIMG_FRAMEBUFFER_SIZE(cimg) (CIMG_FRAMEBUFFER_PIXELS(cimg) * sizeof(term_pixel_t))

void display(struct cimg *cimg, pixel_t *data)
{
    int idx = 0;
    for (int y = 0; y < cimg->header.height; y++)
    {
        for (int x = 0; x < cimg->header.width; x++)
        {
            idx = (0+y)*((cimg)->header.width) + ((0+x)%((cimg)->header.width));
            char emit_tmp[24+1];
            snprintf(emit_tmp, sizeof(emit_tmp), "\x1b[38;2;%03d;%03d;%03dm%c\x1b[0m", data[y * cimg->header.width + x].r, data[y * cimg->header.width + x].g, data[y * cimg->header.width + x].b, data[y * cimg->header.width + x].ascii);
            memcpy((cimg)->framebuffer[idx%(cimg)->num_pixels].data, emit_tmp, 24);

        }
    }

    for (int i = 0; i < cimg->header.height; i++)
    {
        write(1, cimg->framebuffer+i*cimg->header.width, sizeof(term_pixel_t)*cimg->header.width);
        write(1, "\x1b[38;2;000;000;000m\n\x1b[0m", 24);
    }
}

struct cimg *initialize_framebuffer(struct cimg *cimg)
{
    cimg->num_pixels = CIMG_FRAMEBUFFER_PIXELS(cimg);
    cimg->framebuffer = malloc(CIMG_FRAMEBUFFER_SIZE(cimg)+1);
    if (cimg->framebuffer == NULL)
    {
        puts("ERROR: Failed to allocate memory for the framebuffer!");
        exit(-1);
    }
    for (int idx = 0; idx < cimg->num_pixels; idx += 1)
    {
        char emit_tmp[24+1];
        snprintf(emit_tmp, sizeof(emit_tmp), "\x1b[38;2;%03d;%03d;%03dm%c\x1b[0m", 255, 255, 255, ' ');
        memcpy(cimg->framebuffer[idx].data, emit_tmp, 24);

    }

    return cimg;
}

void __attribute__ ((constructor)) disable_buffering()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 1);
}

int main(int argc, char **argv, char **envp)
{

    struct cimg cimg = { 0 };
    cimg.framebuffer = NULL;
    int won = 1;

    if (argc > 1)
    {
        if (strcmp(argv[1]+strlen(argv[1])-5, ".cimg"))
        {
            printf("ERROR: Invalid file extension!");
            exit(-1);
        }
        dup2(open(argv[1], O_RDONLY), 0);
    }

    read_exact(0, &cimg.header, sizeof(cimg.header), "ERROR: Failed to read header!", -1);

    if (cimg.header.magic_number[0] != 'c' || cimg.header.magic_number[1] != 'I' || cimg.header.magic_number[2] != 'M' || cimg.header.magic_number[3] != 'G')
    {
        puts("ERROR: Invalid magic number!");
        exit(-1);
    }

    if (cimg.header.version != 2)
    {
        puts("ERROR: Unsupported version!");
        exit(-1);
    }

    initialize_framebuffer(&cimg);

    unsigned long data_size = cimg.header.width * cimg.header.height * sizeof(pixel_t);
    pixel_t *data = malloc(data_size);
    if (data == NULL)
    {
        puts("ERROR: Failed to allocate memory for the image data!");
        exit(-1);
    }
    read_exact(0, data, data_size, "ERROR: Failed to read data!", -1);

    for (int i = 0; i < cimg.header.width * cimg.header.height; i++)
    {
        if (data[i].ascii < 0x20 || data[i].ascii > 0x7e)
        {
            fprintf(stderr, "ERROR: Invalid character 0x%x in the image data!\n", data[i].ascii);
            exit(-1);
        }
    }

    display(&cimg, data);

    if (cimg.num_pixels != sizeof(desired_output)/sizeof(term_pixel_t))
    {
        won = 0;
    }
    for (int i = 0; i < cimg.num_pixels && i < sizeof(desired_output)/sizeof(term_pixel_t); i++)
    {
        if (cimg.framebuffer[i].str.c != ((term_pixel_t*)&desired_output)[i].str.c)
        {
            won = 0;
        }
        if (
            cimg.framebuffer[i].str.c != ' ' &&
            cimg.framebuffer[i].str.c != '\n' &&
            memcmp(cimg.framebuffer[i].data, ((term_pixel_t*)&desired_output)[i].data, sizeof(term_pixel_t))
        )
        {
            won = 0;
        }
    }

    if (won) win();

}
```

In this challenge, the desired ANSI sequence is to big for us to manually craft the pixels. We will have to dynamically craft our ASCII payload based on the expected ANSI sequence.

- File Extension: Must end with `.cimg`
- Header (8 bytes total):
    - Magic number (4 bytes): Must be "`cIMG`"
    - Version (2 bytes): Must be `2` in little-endian
    - Dimensions (2 bytes total): Must be `53` x (`num_pixels` / `53`) bytes
        - Width (1 bytes): Must be `53` (discovered by trial and error) in little-endian
        - Height (1 bytes): Must be `num_pixels` / `width` in little-endian
- Pixel Data:
    - The number of non-space ASCII pixels must be `num_pixels`, i.e. the number of bytes must be `4 * num_pixels`
    - When pixel data is loaded into the ANSI escape code: `"\x1b[38;2;%03d;%03d;%03dm%c\x1b[0m"` one by one and appended together, it should match the given ANSI sequence.

```py title="~/script.py" showLineNumbers
from pwn import *
import struct
import re

# Desired ANSII sequence
binary = context.binary = ELF('/challenge/cimg')
desired_ansii_sequence_bytes = binary.string(binary.sym.desired_output)
desired_ansii_sequence = desired_ansii_sequence_bytes.decode("utf-8")

# This regex looks for the RGB numbers and the character that follows the 'm'
# (\d+) matches the digits for R, G, and B
# m(.) matches the 'm' followed by the single character we want
pattern = r"\x1b\[38;2;(\d+);(\d+);(\d+)m(.)"

# Find all matches in the sequence
matches = re.findall(pattern, desired_ansii_sequence)

# Convert the strings to the format you want: (int, int, int, ord(char))
pixels = [
    (int(r), int(g), int(b), ord(char)) 
    for r, g, b, char in matches
]

pixel_data = b"".join(struct.pack("BBBB", r, g, b, a) for r, g, b, a in pixels)

width_value = 53
height_value = len(pixels) // width_value

# Build the header (8 bytes total)
magic = b"cIMG"                                 # 4 bytes
version = struct.pack("<H", 2)                  # 2 bytes
width  = struct.pack("<B", width_value)         # 1 bytes
height = struct.pack("<B", height_value)        # 1 bytes

header = magic + version + width + height

# Full file content
cimg_data = header + pixel_data

# Write to disk
filename = "/home/hacker/solution.cimg"
with open(filename, "wb") as f:
    f.write(cimg_data)

print(f"Wrote {len(cimg_data)} bytes: {cimg_data} to: {filename}")
```

```
hacker@reverse-engineering~internal-state-c:/$ python ~/script.py 
Wrote 3612 bytes: 

# ---- snip ----

to: /home/hacker/solution.cimg
```

```
hacker@reverse-engineering~internal-state-c:/$ /challenge/cimg ~/solution.cimg 
.---------------------------------------------------.
|                                                   |
|                                                   |
|       ___                                         |
|      / __|        ___                             |
|     | (__        |_ _|                            |
|      \___|        | |                             |
|                   | |                             |
|                  |___|      __  __                |
|                            |  \/  |    ____       |
|                            | |\/| |   / ___|      |
|                            | |  | |  | |  _       |
|                            |_|  |_|  | |_| |      |
|                                       \____|      |
|                                                   |
|                                                   |
'---------------------------------------------------'
pwn.college{MeWc9ChLvjW8FhGUVQm-MFmVW7z.QXxITN2EDL4ITM0EzW}
```

<img alt="image" src="https://github.com/user-attachments/assets/bcce1436-44b9-43d6-a71c-319163aa2fa5" />

## Internal State (x86)

### Disassembly

#### `main()`

<img alt="image" src="https://github.com/user-attachments/assets/e5d67d5f-4187-4c0b-90be-e2f808a35102" />

![image](https://github.com/user-attachments/assets/05c4947a-f48f-4982-aa69-6de50094baa4?raw=1)

```c showLineNumbers
int __fastcall main(int argc, const char **argv, const char **envp)
{
  const char *v3; // rbp
  int v4; // eax
  const char *error_msg; // rdi
  unsigned int v6; // ebx
  unsigned __int8 *v7; // rax
  unsigned __int8 *v8; // rbp
  __int64 i_1; // rax
  __int64 data_i_ascii; // rcx
  char *desired_ansii_sequence; // r12
  unsigned int num_pixels; // r14d
  _BYTE *framebuffer_2; // r13
  _BOOL8 won; // rbx
  unsigned int i; // ebp
  char v16; // al
  __int128 cimg_header; // [rsp+0h] [rbp-58h] BYREF
  void *s1; // [rsp+10h] [rbp-48h]
  unsigned __int64 v20; // [rsp+18h] [rbp-40h]

  v20 = __readfsqword(0x28u);
  cimg_header = 0LL;
  s1 = 0LL;
  if ( argc > 1 )
  {
    v3 = argv[1];
    if ( strcmp(&v3[strlen(v3) - 5], ".cimg") )
    {
      __printf_chk(1LL, "ERROR: Invalid file extension!");
      goto EXIT;
    }
    v4 = open(v3, 0);
    dup2(v4, 0);
  }
  read_exact(0LL, &cimg_header, 8LL, "ERROR: Failed to read header!", 0xFFFFFFFFLL);
  if ( (_DWORD)cimg_header != 1196247395 )
  {
    error_msg = "ERROR: Invalid magic number!";
PRINT_ERROR_AND_EXIT:
    puts(error_msg);
    goto EXIT;
  }
  error_msg = "ERROR: Unsupported version!";
  if ( WORD2(cimg_header) != 2 )
    goto PRINT_ERROR_AND_EXIT;
  initialize_framebuffer(&cimg_header);
  v6 = 4 * BYTE7(cimg_header) * BYTE6(cimg_header);
  v7 = (unsigned __int8 *)malloc(4LL * BYTE7(cimg_header) * BYTE6(cimg_header));
  error_msg = "ERROR: Failed to allocate memory for the image data!";
  v8 = v7;
  if ( !v7 )
    goto PRINT_ERROR_AND_EXIT;
  read_exact(0LL, v7, v6, "ERROR: Failed to read data!", 0xFFFFFFFFLL);
  i_1 = 0LL;
  while ( BYTE7(cimg_header) * BYTE6(cimg_header) > (int)i_1 )
  {
    data_i_ascii = v8[4 * i_1++ + 3];
    if ( (unsigned __int8)(data_i_ascii - 32) > 0x5Eu )
    {
      __fprintf_chk(stderr, 1LL, "ERROR: Invalid character 0x%x in the image data!\n", data_i_ascii);
EXIT:
      exit(-1);
    }
  }
  desired_ansii_sequence = desired_output;
  display(&cimg_header, v8);
  num_pixels = DWORD2(cimg_header);
  framebuffer_2 = s1;
  won = DWORD2(cimg_header) == 1365;
  for ( i = 0; i != 1365 && num_pixels > i; ++i )
  {
    v16 = framebuffer_2[19];
    if ( v16 != desired_ansii_sequence[19] )
      LODWORD(won) = 0;
    if ( v16 != 32 && v16 != 10 )
    {
      if ( memcmp(framebuffer_2, desired_ansii_sequence, 0x18uLL) )
        LODWORD(won) = 0;
    }
    framebuffer_2 += 24;
    desired_ansii_sequence += 24;
  }
  if ( won )
    win();
  return 0;
}
```

The required ANSI sequence:

<img alt="image" src="https://github.com/user-attachments/assets/48a42094-e420-4e53-a880-375ea8f7f5d2" />

### Exploit

```py title="~/script.py" showLineNumbers
from pwn import *
import struct
import re

# Desired ANSII sequence
binary = context.binary = ELF('/challenge/cimg')
desired_ansii_sequence_bytes = binary.string(binary.sym.desired_output)
desired_ansii_sequence = desired_ansii_sequence_bytes.decode("utf-8")

# This regex looks for the RGB numbers and the character that follows the 'm'
# (\d+) matches the digits for R, G, and B
# m(.) matches the 'm' followed by the single character we want
pattern = r"\x1b\[38;2;(\d+);(\d+);(\d+)m(.)"

# Find all matches in the sequence
matches = re.findall(pattern, desired_ansii_sequence)

# Convert the strings to the format you want: (int, int, int, ord(char))
pixels = [
    (int(r), int(g), int(b), ord(char)) 
    for r, g, b, char in matches
]

pixel_data = b"".join(struct.pack("BBBB", r, g, b, a) for r, g, b, a in pixels)

width_value = 65
height_value = len(pixels) // width_value

# Build the header (8 bytes total)
magic = b"cIMG"                                 # 4 bytes
version = struct.pack("<H", 2)                  # 2 bytes
width  = struct.pack("<B", width_value)         # 1 bytes
height = struct.pack("<B", height_value)        # 1 bytes

header = magic + version + width + height

# Full file content
cimg_data = header + pixel_data

# Write to disk
filename = "/home/hacker/solution.cimg"
with open(filename, "wb") as f:
    f.write(cimg_data)

print(f"Wrote {len(cimg_data)} bytes: {cimg_data} to: {filename}")
```

```
hacker@reverse-engineering~internal-state-x86:/$ python ~/script.py 
Wrote 5468 bytes: 

# ---- snip ----

to: /home/hacker/solution.cimg
```

```
hacker@reverse-engineering~internal-state-x86:/$ /challenge/cimg ~/solution.cimg 
.---------------------------------------------------------------.
|                                                               |
|                                                               |
|                                                               |
|                                                               |
|                                                        ____   |
|          ___                           ___            / ___|  |
|         / __|                         |_ _|  __  __  | |  _   |
|        | (__                           | |  |  \/  | | |_| |  |
|         \___|                          | |  | |\/| |  \____|  |
|                                       |___| | |  | |          |
|                                             |_|  |_|          |
|                                                               |
|                                                               |
|                                                               |
|                                                               |
|                                                               |
|                                                               |
|                                                               |
|                                                               |
'---------------------------------------------------------------'
pwn.college{gmLJQK0xAMY1I1Cfskv-zutRCEa.QX3AzMwEDL4ITM0EzW}
```

<img alt="image" src="https://github.com/user-attachments/assets/d6d03ad9-ca4c-4a9f-8eff-ec3cfee52055" />

&nbsp;

## File Formats: Directives (C)

### Source code

```c title="/challenge/cimg.c" showLineNumbers
#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/signal.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/sendfile.h>
#include <sys/prctl.h>
#include <sys/personality.h>
#include <arpa/inet.h>

void win()
{
    char flag[256];
    int flag_fd;
    int flag_length;

    flag_fd = open("/flag", 0);
    if (flag_fd < 0)
    {
        printf("\n  ERROR: Failed to open the flag -- %s!\n", strerror(errno));
        if (geteuid() != 0)
        {
            printf("  Your effective user id is not 0!\n");
            printf("  You must directly run the suid binary in order to have the correct permissions!\n");
        }
        exit(-1);
    }
    flag_length = read(flag_fd, flag, sizeof(flag));
    if (flag_length <= 0)
    {
        printf("\n  ERROR: Failed to read the flag -- %s!\n", strerror(errno));
        exit(-1);
    }
    write(1, flag, flag_length);
    printf("\n\n");
}

void read_exact(int fd, void *dst, int size, char *msg, int exitcode)
{
    int n = read(fd, dst, size);
    if (n != size)
    {
        fprintf(stderr, msg);
        fprintf(stderr, "\n");
        exit(exitcode);
    }
}

char desired_output[] = "\x1b[38;2;255;255;255m.\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m.\x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;125;194;085m \x1b[0m\x1b[38;2;125;194;085m_\x1b[0m\x1b[38;2;125;194;085m_\x1b[0m\x1b[38;2;125;194;085m_\x1b[0m\x1b[38;2;125;194;085m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;054;062;047m \x1b[0m\x1b[38;2;054;062;047m \x1b[0m\x1b[38;2;054;062;047m_\x1b[0m\x1b[38;2;054;062;047m_\x1b[0m\x1b[38;2;054;062;047m_\x1b[0m\x1b[38;2;054;062;047m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;125;194;085m|\x1b[0m\x1b[38;2;125;194;085m_\x1b[0m\x1b[38;2;125;194;085m \x1b[0m\x1b[38;2;125;194;085m_\x1b[0m\x1b[38;2;125;194;085m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;054;062;047m \x1b[0m\x1b[38;2;054;062;047m/\x1b[0m\x1b[38;2;054;062;047m \x1b[0m\x1b[38;2;054;062;047m_\x1b[0m\x1b[38;2;054;062;047m_\x1b[0m\x1b[38;2;054;062;047m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;125;194;085m \x1b[0m\x1b[38;2;125;194;085m|\x1b[0m\x1b[38;2;125;194;085m \x1b[0m\x1b[38;2;125;194;085m|\x1b[0m\x1b[38;2;125;194;085m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;183;227;088m \x1b[0m\x1b[38;2;183;227;088m \x1b[0m\x1b[38;2;183;227;088m_\x1b[0m\x1b[38;2;183;227;088m_\x1b[0m\x1b[38;2;183;227;088m_\x1b[0m\x1b[38;2;183;227;088m_\x1b[0m\x1b[38;2;183;227;088m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;054;062;047m|\x1b[0m\x1b[38;2;054;062;047m \x1b[0m\x1b[38;2;054;062;047m(\x1b[0m\x1b[38;2;054;062;047m_\x1b[0m\x1b[38;2;054;062;047m_\x1b[0m\x1b[38;2;054;062;047m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;125;194;085m \x1b[0m\x1b[38;2;125;194;085m|\x1b[0m\x1b[38;2;125;194;085m \x1b[0m\x1b[38;2;125;194;085m|\x1b[0m\x1b[38;2;125;194;085m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;135;246;022m \x1b[0m\x1b[38;2;135;246;022m_\x1b[0m\x1b[38;2;135;246;022m_\x1b[0m\x1b[38;2;135;246;022m \x1b[0m\x1b[38;2;135;246;022m \x1b[0m\x1b[38;2;135;246;022m_\x1b[0m\x1b[38;2;135;246;022m_\x1b[0m\x1b[38;2;135;246;022m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;183;227;088m \x1b[0m\x1b[38;2;183;227;088m/\x1b[0m\x1b[38;2;183;227;088m \x1b[0m\x1b[38;2;183;227;088m_\x1b[0m\x1b[38;2;183;227;088m_\x1b[0m\x1b[38;2;183;227;088m_\x1b[0m\x1b[38;2;183;227;088m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;054;062;047m \x1b[0m\x1b[38;2;054;062;047m\\\x1b[0m\x1b[38;2;054;062;047m_\x1b[0m\x1b[38;2;054;062;047m_\x1b[0m\x1b[38;2;054;062;047m_\x1b[0m\x1b[38;2;054;062;047m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;125;194;085m|\x1b[0m\x1b[38;2;125;194;085m_\x1b[0m\x1b[38;2;125;194;085m_\x1b[0m\x1b[38;2;125;194;085m_\x1b[0m\x1b[38;2;125;194;085m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;135;246;022m|\x1b[0m\x1b[38;2;135;246;022m \x1b[0m\x1b[38;2;135;246;022m \x1b[0m\x1b[38;2;135;246;022m\\\x1b[0m\x1b[38;2;135;246;022m/\x1b[0m\x1b[38;2;135;246;022m \x1b[0m\x1b[38;2;135;246;022m \x1b[0m\x1b[38;2;135;246;022m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;183;227;088m|\x1b[0m\x1b[38;2;183;227;088m \x1b[0m\x1b[38;2;183;227;088m|\x1b[0m\x1b[38;2;183;227;088m \x1b[0m\x1b[38;2;183;227;088m \x1b[0m\x1b[38;2;183;227;088m_\x1b[0m\x1b[38;2;183;227;088m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;135;246;022m|\x1b[0m\x1b[38;2;135;246;022m \x1b[0m\x1b[38;2;135;246;022m|\x1b[0m\x1b[38;2;135;246;022m\\\x1b[0m\x1b[38;2;135;246;022m/\x1b[0m\x1b[38;2;135;246;022m|\x1b[0m\x1b[38;2;135;246;022m \x1b[0m\x1b[38;2;135;246;022m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;183;227;088m|\x1b[0m\x1b[38;2;183;227;088m \x1b[0m\x1b[38;2;183;227;088m|\x1b[0m\x1b[38;2;183;227;088m_\x1b[0m\x1b[38;2;183;227;088m|\x1b[0m\x1b[38;2;183;227;088m \x1b[0m\x1b[38;2;183;227;088m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;135;246;022m|\x1b[0m\x1b[38;2;135;246;022m \x1b[0m\x1b[38;2;135;246;022m|\x1b[0m\x1b[38;2;135;246;022m \x1b[0m\x1b[38;2;135;246;022m \x1b[0m\x1b[38;2;135;246;022m|\x1b[0m\x1b[38;2;135;246;022m \x1b[0m\x1b[38;2;135;246;022m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;183;227;088m \x1b[0m\x1b[38;2;183;227;088m\\\x1b[0m\x1b[38;2;183;227;088m_\x1b[0m\x1b[38;2;183;227;088m_\x1b[0m\x1b[38;2;183;227;088m_\x1b[0m\x1b[38;2;183;227;088m_\x1b[0m\x1b[38;2;183;227;088m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;135;246;022m|\x1b[0m\x1b[38;2;135;246;022m_\x1b[0m\x1b[38;2;135;246;022m|\x1b[0m\x1b[38;2;135;246;022m \x1b[0m\x1b[38;2;135;246;022m \x1b[0m\x1b[38;2;135;246;022m|\x1b[0m\x1b[38;2;135;246;022m_\x1b[0m\x1b[38;2;135;246;022m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;000;000;000m \x1b[0m\x1b[38;2;255;255;255m|\x1b[0m\x1b[38;2;255;255;255m'\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m-\x1b[0m\x1b[38;2;255;255;255m'\x1b[0m\x00";

struct cimg_header
{
    char magic_number[4];
    uint16_t version;
    uint8_t width;
    uint8_t height;
    uint32_t remaining_directives;
} __attribute__((packed));

typedef struct
{
    uint8_t ascii;
} pixel_bw_t;
#define COLOR_PIXEL_FMT "\x1b[38;2;%03d;%03d;%03dm%c\x1b[0m"
typedef struct
{
    uint8_t r;
    uint8_t g;
    uint8_t b;
    uint8_t ascii;
} pixel_color_t;
typedef pixel_color_t pixel_t;

typedef struct
{
    union
    {
        char data[24];
        struct term_str_st
        {
            char color_set[7];   // \x1b[38;2;
            char r[3];          // 255
            char s1;            // ;
            char g[3];          // 255
            char s2;            // ;
            char b[3];          // 255
            char m;            // m
            char c;             // X
            char color_reset[4];     // \x1b[0m
        } str;
    };
} term_pixel_t;

struct cimg
{
    struct cimg_header header;
    unsigned num_pixels;
    term_pixel_t *framebuffer;
};

#define CIMG_NUM_PIXELS(cimg) ((cimg)->header.width * (cimg)->header.height)
#define CIMG_DATA_SIZE(cimg) (CIMG_NUM_PIXELS(cimg) * sizeof(pixel_t))
#define CIMG_FRAMEBUFFER_PIXELS(cimg) ((cimg)->header.width * (cimg)->header.height)
#define CIMG_FRAMEBUFFER_SIZE(cimg) (CIMG_FRAMEBUFFER_PIXELS(cimg) * sizeof(term_pixel_t))

void handle_17571(struct cimg *cimg)
{
    unsigned long data_size = cimg->header.width * cimg->header.height * sizeof(pixel_t);
    pixel_t *data = malloc(data_size);
    if (data == NULL)
    {
        puts("ERROR: Failed to allocate memory for the image data!");
        exit(-1);
    }
    read_exact(0, data, data_size, "ERROR: Failed to read data!", -1);

    for (int i = 0; i < cimg->header.width * cimg->header.height; i++)
    {
        if (data[i].ascii < 0x20 || data[i].ascii > 0x7e)
        {
            fprintf(stderr, "ERROR: Invalid character 0x%x in the image data!\n", data[i].ascii);
            exit(-1);
        }
    }

    int idx = 0;
    for (int y = 0; y < cimg->header.height; y++)
    {
        for (int x = 0; x < cimg->header.width; x++)
        {
            idx = (0+y)*((cimg)->header.width) + ((0+x)%((cimg)->header.width));
            char emit_tmp[24+1];
            snprintf(emit_tmp, sizeof(emit_tmp), "\x1b[38;2;%03d;%03d;%03dm%c\x1b[0m", data[y * cimg->header.width + x].r, data[y * cimg->header.width + x].g, data[y * cimg->header.width + x].b, data[y * cimg->header.width + x].ascii);
            memcpy((cimg)->framebuffer[idx%(cimg)->num_pixels].data, emit_tmp, 24);

        }
    }

}

void display(struct cimg *cimg, pixel_t *data)
{
    for (int i = 0; i < cimg->header.height; i++)
    {
        write(1, cimg->framebuffer+i*cimg->header.width, sizeof(term_pixel_t)*cimg->header.width);
        write(1, "\x1b[38;2;000;000;000m\n\x1b[0m", 24);
    }
}

struct cimg *initialize_framebuffer(struct cimg *cimg)
{
    cimg->num_pixels = CIMG_FRAMEBUFFER_PIXELS(cimg);
    cimg->framebuffer = malloc(CIMG_FRAMEBUFFER_SIZE(cimg)+1);
    if (cimg->framebuffer == NULL)
    {
        puts("ERROR: Failed to allocate memory for the framebuffer!");
        exit(-1);
    }
    for (int idx = 0; idx < cimg->num_pixels; idx += 1)
    {
        char emit_tmp[24+1];
        snprintf(emit_tmp, sizeof(emit_tmp), "\x1b[38;2;%03d;%03d;%03dm%c\x1b[0m", 255, 255, 255, ' ');
        memcpy(cimg->framebuffer[idx].data, emit_tmp, 24);

    }

    return cimg;
}

void __attribute__ ((constructor)) disable_buffering()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 1);
}

int main(int argc, char **argv, char **envp)
{

    struct cimg cimg = { 0 };
    cimg.framebuffer = NULL;
    int won = 1;

    if (argc > 1)
    {
        if (strcmp(argv[1]+strlen(argv[1])-5, ".cimg"))
        {
            printf("ERROR: Invalid file extension!");
            exit(-1);
        }
        dup2(open(argv[1], O_RDONLY), 0);
    }

    read_exact(0, &cimg.header, sizeof(cimg.header), "ERROR: Failed to read header!", -1);

    if (cimg.header.magic_number[0] != 'c' || cimg.header.magic_number[1] != 'I' || cimg.header.magic_number[2] != 'M' || cimg.header.magic_number[3] != 'G')
    {
        puts("ERROR: Invalid magic number!");
        exit(-1);
    }

    if (cimg.header.version != 3)
    {
        puts("ERROR: Unsupported version!");
        exit(-1);
    }

    initialize_framebuffer(&cimg);

    while (cimg.header.remaining_directives--)
    {
        uint16_t directive_code;
        read_exact(0, &directive_code, sizeof(directive_code), "ERROR: Failed to read &directive_code!", -1);

        switch (directive_code)
        {
        case 17571:
            handle_17571(&cimg);
            break;
        default:
            fprintf(stderr, "ERROR: invalid directive_code %ux\n", directive_code);
            exit(-1);
        }
    }
    display(&cimg, NULL);

    if (cimg.num_pixels != sizeof(desired_output)/sizeof(term_pixel_t))
    {
        won = 0;
    }
    for (int i = 0; i < cimg.num_pixels && i < sizeof(desired_output)/sizeof(term_pixel_t); i++)
    {
        if (cimg.framebuffer[i].str.c != ((term_pixel_t*)&desired_output)[i].str.c)
        {
            won = 0;
        }
        if (
            cimg.framebuffer[i].str.c != ' ' &&
            cimg.framebuffer[i].str.c != '\n' &&
            memcmp(cimg.framebuffer[i].data, ((term_pixel_t*)&desired_output)[i].data, sizeof(term_pixel_t))
        )
        {
            won = 0;
        }
    }

    if (won) win();

}
```

- File Extension: Must end with `.cimg`
- Header (12 bytes total):
    - Magic number (4 bytes): Must be "`cIMG`"
    - Version (2 bytes): Must be `2` in little-endian
    - Dimensions (2 bytes total): Must be `53` x (`num_pixels` / `53`) bytes
        - Width (1 bytes): Must be `53` (discovered by trial and error) in little-endian
        - Height (1 bytes): Must be `num_pixels` / `width` in little-endian
    - Remaining Directives (4 bytes): Must be `1` in little-endian (This tells the `while` loop to process one directive).
- Directive Code (2 bytes):
    - Immediately following the header, we must provide the 2-byte code `17571` (\xa3\x44 in little-endian) to trigger the `handle_17571` function 
- Pixel Data:
    - The number of non-space ASCII pixels must be `num_pixels`, i.e. the number of bytes must be `4 * num_pixels`
    - When pixel data is loaded into the ANSI escape code: `"\x1b[38;2;%03d;%03d;%03dm%c\x1b[0m"` one by one and appended together, it should match the given ANSI sequence.

### Exploit
 
```py title="~/script.py" showLineNumbers
from pwn import *
import struct
import re

# Desired ANSII sequence
binary = context.binary = ELF('/challenge/cimg')
desired_ansii_sequence_bytes = binary.string(binary.sym.desired_output)
desired_ansii_sequence = desired_ansii_sequence_bytes.decode("utf-8")

# This regex looks for the RGB numbers and the character that follows the 'm'
# (\d+) matches the digits for R, G, and B
# m(.) matches the 'm' followed by the single character we want
pattern = r"\x1b\[38;2;(\d+);(\d+);(\d+)m(.)"

# Find all matches in the sequence
matches = re.findall(pattern, desired_ansii_sequence)

# Convert the strings to the format you want: (int, int, int, ord(char))
pixels = [
    (int(r), int(g), int(b), ord(char)) 
    for r, g, b, char in matches
]

pixel_data = b"".join(struct.pack("BBBB", r, g, b, a) for r, g, b, a in pixels)

width_value = 55
height_value = len(pixels) // width_value

# Build the header (12 bytes total)
magic = b"cIMG"                                 # 4 bytes
version = struct.pack("<H", 3)                  # 2 bytes
width  = struct.pack("<B", width_value)         # 1 bytes
height = struct.pack("<B", height_value)        # 1 bytes
directives = struct.pack("<I", 1)               # 4 bytes

header = magic + version + width + height + directives

# Add directive code
directive_code = struct.pack("<H", 17571)       # 2 bytes

# Full file content
cimg_data = header + directive_code + pixel_data

# Write to disk
filename = "/home/hacker/solution.cimg"
with open(filename, "wb") as f:
    f.write(cimg_data)

print(f"Wrote {len(cimg_data)} bytes: {cimg_data} to: {filename}")
```

```
hacker@reverse-engineering~file-formats-directives-c:/$ python ~/script.py 
Wrote 3314 bytes:

# ---- snip ----

to: /home/hacker/solution.cimg
```

```
hacker@reverse-engineering~file-formats-directives-c:/$ /challenge/cimg ~/solution.cimg 
.-----------------------------------------------------.
|                                                     |
|                                                     |
|                            ___                      |
|                  ___      |_ _|                     |
|                 / __|      | |              ____    |
|                | (__       | |    __  __   / ___|   |
|                 \___|     |___|  |  \/  | | |  _    |
|                                  | |\/| | | |_| |   |
|                                  | |  | |  \____|   |
|                                  |_|  |_|           |
|                                                     |
|                                                     |
|                                                     |
'-----------------------------------------------------'
pwn.college{YtYqzGPTd8ZcDWzwyHLOGwSsY0S.QXyITN2EDL4ITM0EzW}

<img alt="image" src="https://github.com/user-attachments/assets/ed25f4e4-8075-4e31-baa3-8e39e29bbd59" />
