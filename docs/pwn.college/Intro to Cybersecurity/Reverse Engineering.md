---
custom_edit_url: null
sidebar_position: 5
slug: /pwn-college/intro-to-cybersecurity/reverse-engineering
---

## File Formats: Magic Numbers (Python)

### Source code
```py title="/challenge/cimg" showLineNumbers
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



### Binary Analysis

<figure>
![image](https://github.com/user-attachments/assets/3461de42-2d8b-4851-bb88-f0d28558c942?raw=1)
</figure>

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
```py title="/challenge/cimg" showLineNumbers
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



### Binary Analysis

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
```py title="/challenge/cimg" showLineNumbers
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

### Exploit

```py title="~/script.py" showLineNumbers
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
 
### Exploit

```py title="~/script.py" showLineNumbers
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



### Binary Analysis

![image](https://github.com/user-attachments/assets/8e03222f-a902-493b-9da2-2bca5c8287de?raw=1)

- File Extension: Must end with `.cimg`
- Header (8 bytes total):
    - Magic number (4 bytes): Must be `0x5b6e6e52`
    - Version (4 bytes): Must be `0xaa` in little-endian

### Exploit

```py title="~/script.py" showLineNumbers
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
```py title="/challenge/cimg" showLineNumbers
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

### Exploit

```py title="~/script.py" showLineNumbers
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

### Exploit

```py title="~/script.py" showLineNumbers
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



### Binary Analysis

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

### Exploit

```py title="~/script.py" showLineNumbers
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
```py title="/challenge/cimg" showLineNumbers
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
 
### Exploit

```py title="~/script.py" showLineNumbers
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
 
### Exploit

```py title="~/script.py" showLineNumbers
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



### Binary Analysis

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
 
### Exploit

```py title="~/script.py" showLineNumbers
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
```py title="/challenge/cimg" showLineNumbers
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
 
### Exploit

```py title="~/script.py" showLineNumbers
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
 
### Exploit

```py title="~/script.py" showLineNumbers
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

### Binary Analysis

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
 

### Exploit

```py title="~/script.py" showLineNumbers
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
```py title="/chalenge/cimg" showLineNumbers
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

### Exploit

```py title="~/script.py" showLineNumbers
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
 
### Exploit

```py title="~/script.py" showLineNumbers
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

### Binary Analysis

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
 
### Exploit

```py title="~/script.py" showLineNumbers
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

&nbsp;

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

### Exploit

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

After decompiling the program within IDA, and some variable renaming and type altering, we get the following pseudo-C code:

<img alt="image" src="https://github.com/user-attachments/assets/7bfe15f4-6483-471a-85c9-8c46a90af07f" />

### Binary Analysis

```c title="/challenge/cimg :: main() :: Pseudocode" showLineNumbers
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

However, we can make the disassembly look much closer to the actual C code, if we just add the structs.

```c title="/challenge/cimg :: Local Types" showLineNumbers
# ---- snip ----

struct cimg_header {
    char magic_number[4];
    uint16_t version;
    uint8_t width;
    uint8_t height;
};

typedef struct {
    uint8_t r;
    uint8_t g;
    uint8_t b;
    uint8_t ascii;
} pixel_t;

struct term_str_st {
    char color_set[7];
    char r[3];
    char s1;
    char g[3];
    char s2;
    char b[3];
    char m;
    char c;
    char color_reset[4];
};

union term_pixel_t {
    char data[24];
    struct term_str_st str;
};

struct cimg {
    struct cimg_header header;
    unsigned int num_pixels;
    char __pad[4];                 // ABI padding (x86-64)
    union term_pixel_t *framebuffer;
};

# ---- snip ----
```

<frame>
    <img alt="image" src="https://github.com/user-attachments/assets/f6a30c2e-a79e-4412-beef-021dedc1627a" />
</frame>

After adding the above given struct, changing the types and names of certain variables, and adding some helpful comments, the decompiled code now looks much better.

```c title="/challenge/cimg :: main() :: Pseudocode" showLineNumbers
int __fastcall main(int argc, const char **argv, const char **envp)
{
  const char *file_arg; // rbp
  int file; // eax
  const char *error_msg; // rdi
  unsigned int data_size; // ebx
  unsigned __int8 *data; // rax
  unsigned __int8 *data_1; // rbp
  __int64 i_1; // rax
  char character; // cl
  char *desired_output; // r12
  unsigned int num_pixels; // r13d
  union term_pixel_t *framebuffer; // r14
  _BOOL8 won; // rbx
  __int64 i; // rbp
  char ascii_char; // al
  struct cimg cimg; // [rsp+0h] [rbp-58h] BYREF
  unsigned __int64 v19; // [rsp+18h] [rbp-40h]

  v19 = __readfsqword(0x28u);
  memset(&cimg, 0, sizeof(cimg));
  if ( argc > 1 )
  {
    file_arg = argv[1];
    if ( strcmp(&file_arg[strlen(file_arg) - 5], ".cimg") )// Check if the file extension is correct (.cimg)
    {
      __printf_chk(1LL, "ERROR: Invalid file extension!");
      goto EXIT;
    }
    file = open(file_arg, 0);
    dup2(file, 0);
  }
  read_exact(0LL, &cimg, 8LL, "ERROR: Failed to read header!", 0xFFFFFFFFLL);
  if ( *(_DWORD *)cimg.header.magic_number != 'GMIc' )// Check if the magic number is (cIMG) in big-endian
  {
    error_msg = "ERROR: Invalid magic number!";
OUTPUT_ERROR_MSG_AND_EXIT:
    puts(error_msg);
    goto EXIT;
  }
  error_msg = "ERROR: Unsupported version!";
  if ( cimg.header.version != 2 )               // Check if the cimg_header.version is correct (2)
    goto OUTPUT_ERROR_MSG_AND_EXIT;
  initialize_framebuffer(&cimg);
  data_size = 4 * cimg.header.height * cimg.header.width;
  data = (unsigned __int8 *)malloc(4LL * cimg.header.height * cimg.header.width);
  error_msg = "ERROR: Failed to allocate memory for the image data!";
  data_1 = data;
  if ( !data )
    goto OUTPUT_ERROR_MSG_AND_EXIT;
  read_exact(0LL, data, data_size, "ERROR: Failed to read data!", 0xFFFFFFFFLL);
  i_1 = 0LL;
  while ( cimg.header.height * cimg.header.width > (int)i_1 )
  {
    *(_QWORD *)&character = data_1[4 * i_1++ + 3];
    // Check if the character falls in the range 0x20 - 0x7e
    if ( (unsigned __int8)(character - 0x20) > 0x5Eu )
    {
      __fprintf_chk(stderr, 1LL, "ERROR: Invalid character 0x%x in the image data!\n", *(_QWORD *)&character);
EXIT:
      exit(-1);
    }
  }
  desired_output = ::desired_output;
  display(&cimg, data_1);
  num_pixels = cimg.num_pixels;
  framebuffer = cimg.framebuffer;
  won = cimg.num_pixels == 4;
  for ( i = 0LL; (_DWORD)i != 4 && num_pixels > (unsigned int)i; ++i )
  {
    ascii_char = framebuffer[i].data[19];
    if ( ascii_char != desired_output[19] )
      LODWORD(won) = 0;
    // Check if the ASCII character is a space or new-line character
    if ( ascii_char != ' ' && ascii_char != '\n' )
    {
      if ( memcmp(&framebuffer[i], desired_output, 0x18uLL) )
        LODWORD(won) = 0;
    }
    desired_output += 24;
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

### Exploit

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

### Binary Analysis

<img alt="image" src="https://github.com/user-attachments/assets/e5d67d5f-4187-4c0b-90be-e2f808a35102" />

```c title="main()" showLineNumbers
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
    - Immediately following the header, we must provide the 2-byte code `17571` (little-endian) to trigger the `handle_17571` function 
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
```

<img alt="image" src="https://github.com/user-attachments/assets/ed25f4e4-8075-4e31-baa3-8e39e29bbd59" />

&nbsp;

## File Formats: Directives (x86)



### Binary Analysis

```c title="main()" showLineNumbers
int __fastcall main(int argc, const char **argv, const char **envp)
{
  const char *file_arg; // rbp
  int file; // eax
  const char *error_msg; // rdi
  char *desired_ansii_sequence; // r12
  unsigned int v8; // r14d
  _BYTE *framebuffer_2; // r13
  _BOOL8 won; // rbx
  unsigned int i; // ebp
  char v12; // al
  unsigned __int16 directive_code; // [rsp+0h] [rbp-5Ah] BYREF
  __int128 cimg_header; // [rsp+2h] [rbp-58h] BYREF
  void *framebuffer; // [rsp+12h] [rbp-48h]
  unsigned __int64 v17; // [rsp+1Ah] [rbp-40h]

  v17 = __readfsqword(0x28u);
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
  read_exact(0LL, &cimg_header, 12LL, "ERROR: Failed to read header!", 0xFFFFFFFFLL);
  if ( (_DWORD)cimg_header != 1196247395 )
  {
    error_msg = "ERROR: Invalid magic number!";
PRINT_ERROR_AND_EXIT:
    puts(error_msg);
    goto EXIT;
  }
  error_msg = "ERROR: Unsupported version!";
  if ( WORD2(cimg_header) != 3 )
    goto PRINT_ERROR_AND_EXIT;
  initialize_framebuffer(&cimg_header);
  while ( DWORD2(cimg_header)-- )
  {
    read_exact(0LL, &directive_code, 2LL, "ERROR: Failed to read &directive_code!", 0xFFFFFFFFLL);
    if ( directive_code != 45381 )
    {
      __fprintf_chk(stderr, 1LL, "ERROR: invalid directive_code %ux\n", directive_code);
EXIT:
      exit(-1);
    }
    handle_45381(&cimg_header);
  }
  desired_ansii_sequence = desired_output;
  display(&cimg_header, 0LL);
  v8 = HIDWORD(cimg_header);
  framebuffer_2 = framebuffer;
  won = HIDWORD(cimg_header) == 800;
  for ( i = 0; i < v8 && i != 800; ++i )
  {
    v12 = framebuffer_2[19];
    if ( v12 != desired_ansii_sequence[19] )
      LODWORD(won) = 0;
    if ( v12 != 32 && v12 != 10 )
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

- File Extension: Must end with `.cimg`
- Header (12 bytes total):
    - Magic number (4 bytes): Must be "`cIMG`"
    - Version (2 bytes): Must be `2` in little-endian
    - Dimensions (2 bytes total): Must be `53` x (`num_pixels` / `53`) bytes
        - Width (1 bytes): Must be `53` (discovered by trial and error) in little-endian
        - Height (1 bytes): Must be `num_pixels` / `width` in little-endian
    - Remaining Directives (4 bytes): Must be `1` in little-endian (This tells the `while` loop to process one directive).
- Directive Code (2 bytes):
    - Immediately following the header, we must provide the 2-byte code `45381` (little-endian) to trigger the `handle_17571` function 
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
directive_code = struct.pack("<H", 45381)       # 2 bytes

# Full file content
cimg_data = header + directive_code + pixel_data

# Write to disk
filename = "/home/hacker/solution.cimg"
with open(filename, "wb") as f:
    f.write(cimg_data)

print(f"Wrote {len(cimg_data)} bytes: {cimg_data} to: {filename}")
```

```
hacker@reverse-engineering~file-formats-directives-x86:/$ python ~/script.py
Wrote 3214 bytes:

# ---- snip ----

to: /home/hacker/solution.cimg
```

```
hacker@reverse-engineering~file-formats-directives-x86:/$ /challenge/cimg ~/solution.cimg 
.--------------------------------------.
|                                      |
|                                      |
|                                      |
|                                      |
|                                      |
|                                      |
|                                      |
|                                      |
|                                      |
|    ___              __  __           |
|   / __|       ___  |  \/  |   ____   |
|  | (__       |_ _| | |\/| |  / ___|  |
|   \___|       | |  | |  | | | |  _   |
|               | |  |_|  |_| | |_| |  |
|              |___|           \____|  |
|                                      |
|                                      |
|                                      |
'--------------------------------------'
pwn.college{syk86MEMK8yI4ABF2f5AcH3BOKX.QX4AzMwEDL4ITM0EzW}
```

<img alt="image" src="https://github.com/user-attachments/assets/635a80e9-9b81-4126-b443-99ed91623c08" />

&nbsp;

## The Patch Directive

### Binary Analysis

```c title="main()" showLineNumbers
int __fastcall main(int argc, const char **argv, const char **envp)
{
  const char *file_arg; // rbp
  int file; // eax
  const char *error_msg; // rdi
  char *desired_ansii_sequence; // r12
  unsigned int num_pixels; // r14d
  _BYTE *framebuffer_2; // r13
  _BOOL8 won; // rbx
  unsigned int i; // ebp
  char v12; // al
  unsigned __int16 directive_code; // [rsp+0h] [rbp-5Ah] BYREF
  __int128 buf; // [rsp+2h] [rbp-58h] BYREF
  void *framebuffer; // [rsp+12h] [rbp-48h]
  unsigned __int64 v17; // [rsp+1Ah] [rbp-40h]

  v17 = __readfsqword(0x28u);
  buf = 0LL;
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
  read_exact(0LL, &buf, 12LL, "ERROR: Failed to read header!", 4294967295LL);
  if ( (_DWORD)buf != 'GMIc' )
  {
    error_msg = "ERROR: Invalid magic number!";
PRINT_ERROR_AND_EXIT:
    puts(error_msg);
    goto EXIT;
  }
  error_msg = "ERROR: Unsupported version!";
  if ( WORD2(buf) != 3 )
    goto PRINT_ERROR_AND_EXIT;
  initialize_framebuffer(&buf);
  while ( DWORD2(buf)-- )
  {
    read_exact(0LL, &directive_code, 2LL, "ERROR: Failed to read &directive_code!", 4294967295LL);
    if ( directive_code == 52965 )
    {
      handle_52965(&buf);
    }
    else
    {
      if ( directive_code != 55369 )
      {
        __fprintf_chk(stderr, 1LL, "ERROR: invalid directive_code %ux\n", directive_code);
EXIT:
        exit(-1);
      }
      handle_55369((__int64)&buf);
    }
  }
  desired_ansii_sequence = desired_output;
  display(&buf, 0LL);
  num_pixels = HIDWORD(buf);
  framebuffer_2 = framebuffer;
  won = HIDWORD(buf) == 901;
  for ( i = 0; num_pixels > i && i != 901; ++i )
  {
    v12 = framebuffer_2[19];
    if ( v12 != desired_ansii_sequence[19] )
      LOBYTE(won) = 0;
    if ( v12 != 32 && v12 != 10 )
    {
      if ( memcmp(framebuffer_2, desired_ansii_sequence, 24uLL) )
        LOBYTE(won) = 0;
    }
    framebuffer_2 += 24;
    desired_ansii_sequence += 24;
  }
  if ( (unsigned __int64)total_data <= 1340 && won )
    win();
  return 0;
}
```

Let's find the required width:

```py title="~/script.py" showLineNumbers
from pwn import *
import struct
import re

# Desired ANSII sequence
binary = context.binary = ELF('/challenge/cimg')
desired_ansii_sequence_bytes = binary.string(binary.sym.desired_output)
desired_ansii_sequence = desired_ansii_sequence_bytes.decode("utf-8")
print(desired_ansii_sequence)
```

```
hacker@reverse-engineering~the-patch-directive:/$ python ~/script.py 
[*] '/challenge/cimg'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    FORTIFY:    Enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
.---------------------------------------------------.|                                                   ||                                                   ||       ___                                         ||      / __|        ___                             ||     | (__        |_ _|                            ||      \___|        | |                             ||                   | |                             ||                  |___|      __  __                ||                            |  \/  |    ____       ||                            | |\/| |   / ___|      ||                            | |  | |  | |  _       ||                            |_|  |_|  | |_| |      ||                                       \____|      ||                                                   ||                                                   |'---------------------------------------------------'
```

```py
In [1]: print(len(".---------------------------------------------------."))
53
```

- File Extension: Must end with `.cimg`
- Header (12 bytes total):
    - Magic number (4 bytes): Must be "`cIMG`"
    - Version (2 bytes): Must be `3` in little-endian
    - Dimensions (2 bytes total): Must be `53` x (`num_pixels` / `53`) bytes
        - Width (1 bytes): Must be `53` in little-endian
        - Height (1 bytes): Must be `num_pixels` / `width` in little-endian
    - Remaining Directives (4 bytes): Value TBD (This tells the `while` loop to process one directive).
- Directive Code (2 bytes):
    - Immediately following the header, we must provide the 2-byte code `55369` and / or `52965` (little-endian) to trigger the `handle_55369` and / or `handle_52965` function 
- Pixel Data:
    - The number of non-space ASCII pixels must be `num_pixels`, i.e. the number of bytes must be `4 * num_pixels`
    - When pixel data is loaded into the ANSI escape code: `"\x1b[38;2;%03d;%03d;%03dm%c\x1b[0m"` one by one and appended together, it should match the given ANSI sequence.
 
Let's look at both the handler functions.

```c title="handle_55369()" showLineNumbers
unsigned __int64 __fastcall handle_55369(__int64 user_cimg)
{
  int width; // ebp
  int height; // edx
  size_t num_bytes; // rbp
  unsigned __int8 *allocated_mem; // rax
  unsigned __int8 *allocated_mem2; // r12
  __int64 i_1; // rax
  __int64 char_byte; // rcx
  int i; // r13d
  int chars_printed_in_one_line; // ebp
  int width_1; // r15d
  unsigned __int8 *ansii_pixel; // rax
  __int64 chars_printed_in_one_line_1; // kr00_8
  __int64 v13; // rdx
  __int128 v15; // [rsp+1Fh] [rbp-59h] BYREF
  __int64 v16; // [rsp+2Fh] [rbp-49h]
  unsigned __int64 v17; // [rsp+38h] [rbp-40h]

  width = *(unsigned __int8 *)(user_cimg + 6);
  height = *(unsigned __int8 *)(user_cimg + 7);
  v17 = __readfsqword(40u);
  num_bytes = 4LL * height * width;             // Calculate number of bytes required for pixels
  allocated_mem = (unsigned __int8 *)malloc(num_bytes);// Allocate memory
  if ( !allocated_mem )
  {
    puts("ERROR: Failed to allocate memory for the image data!");
    goto EXIT;
  }
  allocated_mem2 = allocated_mem;
  read_exact(0LL, allocated_mem, (unsigned int)num_bytes, "ERROR: Failed to read data!", 4294967295LL);
  i_1 = 0LL;
  // Check if char_byte falls between 0x20 and 0x7e (i.e. check if it is a printable ASCII character)
  while ( *(unsigned __int8 *)(user_cimg + 7) * *(unsigned __int8 *)(user_cimg + 6) > (int)i_1 )
  {
    char_byte = allocated_mem2[4 * i_1++ + 3];
    if ( (unsigned __int8)(char_byte - 32) > 0x5Eu )
    {
      __fprintf_chk(stderr, 1LL, "ERROR: Invalid character 0x%x in the image data!\n", char_byte);
EXIT:
      exit(-1);
    }
  }
  for ( i = 0; *(unsigned __int8 *)(user_cimg + 7) > i; ++i )
  {
    chars_printed_in_one_line = 0;
    while ( 1 )
    {
      width_1 = *(unsigned __int8 *)(user_cimg + 6);
      if ( width_1 <= chars_printed_in_one_line )
        break;
      ansii_pixel = &allocated_mem2[4 * i * width_1 + 4 * chars_printed_in_one_line];
      __snprintf_chk(
        &v15,
        25LL,
        1LL,
        25LL,
        "\x1B[38;2;%03d;%03d;%03dm%c\x1B[0m",
        *ansii_pixel,
        ansii_pixel[1],
        ansii_pixel[2],
        ansii_pixel[3]);
      chars_printed_in_one_line_1 = chars_printed_in_one_line++;
      v13 = *(_QWORD *)(user_cimg + 16)
          + 24LL * (((unsigned int)(chars_printed_in_one_line_1 % width_1) + i * width_1) % *(_DWORD *)(user_cimg + 12));
      *(_OWORD *)v13 = v15;
      *(_QWORD *)(v13 + 16) = v16;
    }
  }
  return __readfsqword(40u) ^ v17;
}
```

```c title="handle_52965()" showLineNumbers
unsigned __int64 __fastcall handle_52965(__int64 a1)
{
  unsigned int num_bytes; // ebx
  unsigned __int8 *allocated_mem; // rax
  unsigned __int8 *allocated_mem2; // rbp
  __int64 v4; // rax
  __int64 char_byte; // rcx
  int i; // r13d
  int v7; // r14d
  int v8; // eax
  int v9; // ecx
  unsigned int v10; // ebx
  __int64 v11; // rdx
  unsigned __int8 width; // [rsp+Bh] [rbp-5Dh] BYREF
  unsigned __int8 height; // [rsp+Ch] [rbp-5Ch] BYREF
  unsigned __int8 base_x; // [rsp+Dh] [rbp-5Bh] BYREF
  unsigned __int8 base_y; // [rsp+Eh] [rbp-5Ah] BYREF
  __int128 v17; // [rsp+Fh] [rbp-59h] BYREF
  __int64 v18; // [rsp+1Fh] [rbp-49h]
  unsigned __int64 v19; // [rsp+28h] [rbp-40h]

  v19 = __readfsqword(40u);
  read_exact(0LL, &base_x, 1LL, "ERROR: Failed to read &base_x!", 0xFFFFFFFFLL);
  read_exact(0LL, &base_y, 1LL, "ERROR: Failed to read &base_y!", 0xFFFFFFFFLL);
  read_exact(0LL, &width, 1LL, "ERROR: Failed to read &width!", 0xFFFFFFFFLL);
  read_exact(0LL, &height, 1LL, "ERROR: Failed to read &height!", 0xFFFFFFFFLL);
  num_bytes = 4 * height * width;
  allocated_mem = (unsigned __int8 *)malloc(4LL * height * width);
  if ( !allocated_mem )
  {
    puts("ERROR: Failed to allocate memory for the image data!");
    goto EXIT;
  }
  allocated_mem2 = allocated_mem;
  read_exact(0LL, allocated_mem, num_bytes, "ERROR: Failed to read data!", 0xFFFFFFFFLL);
  v4 = 0LL;
  while ( height * width > (int)v4 )
  {
    char_byte = allocated_mem2[4 * v4++ + 3];
    if ( (unsigned __int8)(char_byte - 32) > 0x5Eu )
    {
      __fprintf_chk(stderr, 1LL, "ERROR: Invalid character 0x%x in the image data!\n", char_byte);
EXIT:
      exit(-1);
    }
  }
  for ( i = 0; height > i; ++i )
  {
    v7 = 0;
    while ( width > v7 )
    {
      v8 = v7 + base_x;
      v9 = v7 + i * width;
      ++v7;
      v10 = v8 % *(unsigned __int8 *)(a1 + 6) + *(unsigned __int8 *)(a1 + 6) * (i + base_y);
      __snprintf_chk(
        &v17,
        25LL,
        1LL,
        25LL,
        "\x1B[38;2;%03d;%03d;%03dm%c\x1B[0m",
        allocated_mem2[4 * v9],
        allocated_mem2[4 * v9 + 1],
        allocated_mem2[4 * v9 + 2],
        allocated_mem2[4 * v9 + 3]);
      v11 = *(_QWORD *)(a1 + 16) + 24LL * (v10 % *(_DWORD *)(a1 + 12));
      *(_OWORD *)v11 = v17;
      *(_QWORD *)(v11 + 16) = v18;
    }
  }
  return __readfsqword(0x28u) ^ v19;
}
```

### Exploit

#### Print without using any blank characters

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

directives_payload = b""
directive_count = 0

# Grouping logic to stay under 1340 bytes
for y in range(height_value):
    x = 0
    while x < width_value:
        idx = y * width_value + x
        _, _, _, char = pixels[idx]
        
        if char == ord(' '):
            x += 1
            continue
            
        run_pixels = []
        start_x = x
        while x < width_value:
            curr_idx = y * width_value + x
            curr_r, curr_g, curr_b, curr_char = pixels[curr_idx]
            if curr_char == ord(' '):
                break
            run_pixels.append(struct.pack("BBBB", curr_r, curr_g, curr_b, curr_char))
            x += 1
        
        directive_count += 1
        directives_payload += struct.pack("<H", 52965)
        directives_payload += struct.pack("<B", start_x)
        directives_payload += struct.pack("<B", y)
        directives_payload += struct.pack("<B", len(run_pixels))
        directives_payload += struct.pack("<B", 1)
        directives_payload += b"".join(run_pixels)

# Build the header (12 bytes total)
magic = b"cIMG"                                     # 4 bytes
version = struct.pack("<H", 3)                      # 2 bytes   
width_byte = struct.pack("<B", width_value)         # 1 bytes
height_byte = struct.pack("<B", height_value)       # 1 bytes
dir_count = struct.pack("<I", directive_count)      # 4 bytes

header = magic + version + width_byte + height_byte + dir_count

# Full file content
cimg_data = header + directives_payload

# Write to disk
with open("/home/hacker/solution.cimg", "wb") as f:
    f.write(cimg_data)

print(f"Total Bytes: {len(cimg_data)}")
print(f"Directives used: {directive_count}")
```

```
hacker@reverse-engineering~the-patch-directive:~$ python ~/script.py 
[*] '/challenge/cimg'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    FORTIFY:    Enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
Total Bytes: 1292
Directives used: 70
```

#### Print each border using a directive

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

directives_payload = b""
directive_count = 0

# --- 1. THE FOUR BORDER DIRECTIVES ---

def add_directive(x, y, w, h, pixel_list):
    global directives_payload, directive_count
    directive_count += 1
    directives_payload += struct.pack("<HBBBB", 52965, x, y, w, h)
    for p in pixel_list:
        directives_payload += struct.pack("BBBB", p[0], p[1], p[2], p[3])

# Top Border (Row 0)
top_pixels = [pixels[i] for i in range(width_value)]
add_directive(0, 0, width_value, 1, top_pixels)

# Bottom Border (Row 16)
bottom_pixels = [pixels[i] for i in range(16 * width_value, 17 * width_value)]
add_directive(0, 16, width_value, 1, bottom_pixels)

# Left Border (Rows 1 to 15, Column 0)
left_pixels = [pixels[y * width_value] for y in range(1, 16)]
add_directive(0, 1, 1, 15, left_pixels)

# Right Border (Rows 1 to 15, Column 52)
right_pixels = [pixels[y * width_value + 52] for y in range(1, 16)]
add_directive(52, 1, 1, 15, right_pixels)

# --- 2. LOGO CONTENT (Interior Only) ---
# We skip x=0, x=52, y=0, and y=16 to avoid redrawing borders
for y in range(1, 16):
    x = 1
    while x < width_value - 1:
        idx = y * width_value + x
        _, _, _, char = pixels[idx]
        
        if char == ord(' '):
            x += 1
            continue
            
        run_pixels = []
        start_x = x
        while x < width_value - 1:
            curr_idx = y * width_value + x
            p = pixels[curr_idx]
            if p[3] == ord(' '):
                break
            run_pixels.append(struct.pack("BBBB", p[0], p[1], p[2], p[3]))
            x += 1
        
        directive_count += 1
        directives_payload += struct.pack("<HBBBB", 52965, start_x, y, len(run_pixels), 1)
        directives_payload += b"".join(run_pixels)

# --- 3. HEADER AND OUTPUT ---
header = struct.pack("<IHBBI", 0x474d4963, 3, width_value, height_value, directive_count)
cimg_data = header + directives_payload

with open("/home/hacker/solution.cimg", "wb") as f:
    f.write(cimg_data)

print(f"Total Bytes: {len(cimg_data)}")
print(f"Directives used: {directive_count}")
```

```
hacker@reverse-engineering~the-patch-directive:~$ python ~/script.py 
[*] '/challenge/cimg'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    FORTIFY:    Enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
Total Bytes: 1124
Directives used: 42
```

#### Print each border and each letter using a directive 

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

directives_payload = b""
directive_count = 0

def add_box(x, y, w, h):
    global directives_payload, directive_count
    directive_count += 1
    directives_payload += struct.pack("<HBBBB", 52965, x, y, w, h)
    for row in range(y, y + h):
        for col in range(x, x + w):
            p = pixels[row * width_value + col]
            directives_payload += struct.pack("BBBB", p[0], p[1], p[2], p[3])

# --- BORDERS (4 Directives) ---
add_box(0, 0, width_value, 1)        # Top
add_box(0, 16, width_value, 1)       # Bottom
add_box(0, 1, 1, 15)                  # Left
add_box(52, 1, 1, 15)                 # Right

# --- CHARACTERS (4 Directives) ---
# Coordinates approximate based on the ASCII art provided
add_box(6, 3, 6, 4)   # "C"
add_box(19, 4, 5, 5)   # "I"
add_box(29, 8, 8, 5)   # "M"
add_box(39, 9, 7, 5)   # "G" 

# --- HEADER ---
header = struct.pack("<IHBBI", 0x474d4963, 3, width_value, height_value, directive_count)

# Full file content
cimg_data = header + directives_payload

# Write to disk
with open("/home/hacker/solution.cimg", "wb") as f:
    f.write(cimg_data)

print(f"Total Bytes: {len(cimg_data)}")
print(f"Directives used: {directive_count}")
```

```
hacker@reverse-engineering~the-patch-directive:/$ python ~/script.py 
[*] '/challenge/cimg'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    FORTIFY:    Enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
Total Bytes: 1100
Directives used: 8
hacker@reverse-engineering~the-patch-directive:/$ /challenge/cimg ~/solution.cimg 
```

```
hacker@reverse-engineering~the-patch-directive:~$ /challenge/cimg ~/solution.cimg 
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
pwn.college{UMeXSUaFZYlR24CqDvgWdMZihWp.QX5AzMwEDL4ITM0EzW}
```

<img alt="image" src="https://github.com/user-attachments/assets/9ce34f70-2ab2-44f2-9f59-536f53dcde50" />

&nbsp;

## Optimizing for Space

### Binary Analysis

```c showLineNumbers
int __fastcall main(int argc, const char **argv, const char **envp)
{
  const char *file_arg; // rbp
  int file; // eax
  const char *error_msg; // rdi
  char *desired_ansii_sequence; // r12
  unsigned int v8; // r14d
  _BYTE *framebuffer_2; // r13
  _BOOL8 won; // rbx
  unsigned int i; // ebp
  char v12; // al
  unsigned __int16 directive_code; // [rsp+0h] [rbp-5Ah] BYREF
  __int128 buf; // [rsp+2h] [rbp-58h] BYREF
  void *framebuffer; // [rsp+12h] [rbp-48h]
  unsigned __int64 v17; // [rsp+1Ah] [rbp-40h]

  v17 = __readfsqword(40u);
  buf = 0LL;
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
  read_exact(0LL, &buf, 12LL, "ERROR: Failed to read header!", 0xFFFFFFFFLL);
  if ( (_DWORD)buf != 'GMIc' )
  {
    error_msg = "ERROR: Invalid magic number!";
PRINT_ERROR_AND_EXIT:
    puts(error_msg);
    goto EXIT;
  }
  error_msg = "ERROR: Unsupported version!";
  if ( WORD2(buf) != 3 )
    goto PRINT_ERROR_AND_EXIT;
  initialize_framebuffer(&buf);
  while ( DWORD2(buf)-- )
  {
    read_exact(0LL, &directive_code, 2LL, "ERROR: Failed to read &directive_code!", 0xFFFFFFFFLL);
    if ( directive_code == 52965 )
    {
      handle_52965(&buf);
    }
    else
    {
      if ( directive_code != 55369 )
      {
        __fprintf_chk(stderr, 1LL, "ERROR: invalid directive_code %ux\n", directive_code);
EXIT:
        exit(-1);
      }
      handle_55369(&buf);
    }
  }
  desired_ansii_sequence = desired_output;
  display(&buf, 0LL);
  v8 = HIDWORD(buf);
  framebuffer_2 = framebuffer;
  won = HIDWORD(buf) == 1824;
  for ( i = 0; v8 > i && i != 1824; ++i )
  {
    v12 = framebuffer_2[19];
    if ( v12 != desired_ansii_sequence[19] )
      LOBYTE(won) = 0;
    if ( v12 != 32 && v12 != 10 )
    {
      if ( memcmp(framebuffer_2, desired_ansii_sequence, 24uLL) )
        LOBYTE(won) = 0;
    }
    framebuffer_2 += 24;
    desired_ansii_sequence += 24;
  }
  if ( (unsigned __int64)total_data <= 1337 && won )
    win();
  return 0;
}
```

In this level, the only difference is the restriction on number of bytes. We can only provide `1337` bytes.

### Exploit

#### Print each border using a directive

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

width_value = 76
height_value = len(pixels) // width_value

directives_payload = b""
directive_count = 0

# --- 1. THE FOUR BORDER DIRECTIVES ---

def add_directive(x, y, w, h, pixel_list):
    global directives_payload, directive_count
    directive_count += 1
    directives_payload += struct.pack("<HBBBB", 52965, x, y, w, h)
    for p in pixel_list:
        directives_payload += struct.pack("BBBB", p[0], p[1], p[2], p[3])

# Top Border (Row 0) - 76 pixels
top_pixels = pixels[0 : width_value]
add_directive(0, 0, width_value, 1, top_pixels)

# Bottom Border (Row 23) - 76 pixels
bottom_pixels = pixels[23 * width_value : 24 * width_value]
add_directive(0, 23, width_value, 1, bottom_pixels)

# Left Border (Rows 1 to 22) - 22 pixels
# Note: w=1, h=22. List must have exactly 22 items.
left_pixels = [pixels[y * width_value] for y in range(1, 23)]
add_directive(0, 1, 1, 22, left_pixels)

# Right Border (Rows 1 to 22, Column 75) - 22 pixels
# Note: x=75, w=1, h=22. List must have exactly 22 items.
right_pixels = [pixels[y * width_value + 75] for y in range(1, 23)]
add_directive(75, 1, 1, 22, right_pixels)

# --- 2. LOGO CONTENT (Interior Only) ---
# We skip x=0, x=52, y=0, and y=16 to avoid redrawing borders
for y in range(1, 23):
    x = 1
    while x < width_value - 1:
        idx = y * width_value + x
        _, _, _, char = pixels[idx]
        
        if char == ord(' '):
            x += 1
            continue
            
        run_pixels = []
        start_x = x
        while x < width_value - 1:
            curr_idx = y * width_value + x
            p = pixels[curr_idx]
            if p[3] == ord(' '):
                break
            run_pixels.append(struct.pack("BBBB", p[0], p[1], p[2], p[3]))
            x += 1
        
        directive_count += 1
        directives_payload += struct.pack("<HBBBB", 52965, start_x, y, len(run_pixels), 1)
        directives_payload += b"".join(run_pixels)

# --- 3. HEADER AND OUTPUT ---
header = struct.pack("<IHBBI", 0x474d4963, 3, width_value, height_value, directive_count)
cimg_data = header + directives_payload

with open("/home/hacker/solution.cimg", "wb") as f:
    f.write(cimg_data)

print(f"Total Bytes: {len(cimg_data)} (Limit: 1337)")
print(f"Directives used: {directive_count}")
```

```
hacker@reverse-engineering~optimizing-for-space:~$ python ~/script.py 
[*] '/challenge/cimg'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    FORTIFY:    Enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
Total Bytes: 1364 (Limit: 1337)
Directives used: 42
```

#### Print each border and each line of the text using a directive

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

width_value = 76
height_value = len(pixels) // width_value

directives_payload = b""
directive_count = 0

def add_box(x, y, w, h):
    global directives_payload, directive_count
    directive_count += 1
    directives_payload += struct.pack("<HBBBB", 52965, x, y, w, h)
    for row in range(y, y + h):
        for col in range(x, x + w):
            p = pixels[row * width_value + col]
            directives_payload += struct.pack("BBBB", p[0], p[1], p[2], p[3])

# --- BORDERS (4 Directives) ---
add_box(0, 0, width_value, 1)        # Top
add_box(0, (height_value-1), width_value, 1)       # Bottom

side_border_height = height_value - 2
add_box(0, 1, 1, side_border_height)                  # Left
add_box((width_value-1), 1, 1, side_border_height)                 # Right

# --- CHARACTERS (4 Directives) ---
# Coordinates approximate based on the ASCII art provided
add_box(31, 9, 20, 1)           #             "___   __  __    ____"
add_box(25, 10, 27, 1)          #       "___  |_ _| |  \/  |  / ___|"
add_box(24, 11, 27, 1)          #      "/ __|  | |  | |\/| | | |  _ "
add_box(23, 12, 29, 1)          #     "| (__   | |  | |  | | | |_| |"
add_box(24, 13, 28, 1)          #      "\___| |___| |_|  |_|  \____|"

# --- HEADER ---
header = struct.pack("<IHBBI", 0x474d4963, 3, width_value, height_value, directive_count)

# Full file content
cimg_data = header + directives_payload

# Write to disk
with open("/home/hacker/solution.cimg", "wb") as f:
    f.write(cimg_data)

print(f"Total Bytes: {len(cimg_data)} (Limit: 1337)")
print(f"Directives used: {directive_count}")
```

```
hacker@reverse-engineering~optimizing-for-space:/$ python ~/script.py 
[*] '/challenge/cimg'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    FORTIFY:    Enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
Total Bytes: 1374
Directives used: 9
```

#### Dynamically decide whether header overhead / blank spaces would take less bytes

```py title="~/script.py" showLineNumbers
from pwn import *
import struct
import re

# 1. Setup and Pixel Extraction
binary = context.binary = ELF('/challenge/cimg')
desired_ansii_sequence_bytes = binary.string(binary.sym.desired_output)
desired_ansii_sequence = desired_ansii_sequence_bytes.decode("utf-8")

# Extract RGB and Character data
pattern = r"\x1b\[38;2;(\d+);(\d+);(\d+)m(.)"
matches = re.findall(pattern, desired_ansii_sequence)
pixels = [(int(r), int(g), int(b), ord(char)) for r, g, b, char in matches]

# Global dimensions for the 1824-pixel challenge
width_value = 76
height_value = 24  # 1824 total pixels / 76 width
directives_payload = b""
directive_count = 0

# 2. Directive Builder
def add_directive(x, y, w, h, pixel_list):
    global directives_payload, directive_count
    # Verification to prevent the "Invalid character 0x1" desync error
    if len(pixel_list) != (w * h):
        return 
        
    directive_count += 1
    # Directive Header (6 bytes)
    directives_payload += struct.pack("<HBBBB", 52965, x, y, w, h)
    # Pixel Payload (4 bytes per pixel)
    for p in pixel_list:
        directives_payload += struct.pack("BBBB", p[0], p[1], p[2], p[3])

# 3. Optimized Border Directives
# Top and Bottom (Full row)
add_directive(0, 0, width_value, 1, pixels[0 : width_value])
add_directive(0, 23, width_value, 1, pixels[23 * width_value : 24 * width_value])

# Left and Right Sides (Height = 22 to avoid corner overlap)
side_height = height_value - 2
left_pixels = [pixels[y * width_value] for y in range(1, 23)]
add_directive(0, 1, 1, side_height, left_pixels)

right_pixels = [pixels[y * width_value + 75] for y in range(1, 23)]
add_directive(75, 1, 1, side_height, right_pixels)

# 4. Optimized Logo Content (Horizontal Strips with Bridging)
for y in range(1, 23):
    x = 1
    while x < 75:
        idx = y * width_value + x
        if pixels[idx][3] == ord(' '):
            x += 1
            continue
            
        start_x = x
        run_data = []
        while x < 75:
            p = pixels[y * width_value + x]
            
            if p[3] == ord(' '):
                # BRIDGE LOGIC: If a single space is followed by more ink, 
                # include it to save 6 bytes of header overhead.
                if x + 1 < 75 and pixels[y * width_value + (x+1)][3] != ord(' '):
                    run_data.append(p)
                    x += 1
                    continue
                else:
                    break # Gap is too large, end directive
            
            run_data.append(p)
            x += 1
        
        # Add the horizontal segment
        add_directive(start_x, y, len(run_data), 1, run_data)

# 5. Global Header and File Output
# Magic: 0x474d4963 ('cIMG'), Version: 3, Width: 76, Height: 24, Count: directive_count
header = struct.pack("<IHBBI", 0x474D4963, 3, width_value, height_value, directive_count)
cimg_data = header + directives_payload

with open("/home/hacker/solution.cimg", "wb") as f:
    f.write(cimg_data)

print(f"Total Bytes: {len(cimg_data)} (Limit: 1337)")
print(f"Directives used: {directive_count}")
```

```
hacker@reverse-engineering~optimizing-for-space:~$ python ~/script.py 
[*] '/challenge/cimg'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    FORTIFY:    Enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
Total Bytes: 1328 (Limit: 1337)
Directives used: 24
```

```
hacker@reverse-engineering~optimizing-for-space:~$ /challenge/cimg ~/solution.cimg 
.--------------------------------------------------------------------------.
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                              ___   __  __    ____                        |
|                        ___  |_ _| |  \/  |  / ___|                       |
|                       / __|  | |  | |\/| | | |  _                        |
|                      | (__   | |  | |  | | | |_| |                       |
|                       \___| |___| |_|  |_|  \____|                       |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
'--------------------------------------------------------------------------'
pwn.college{AIEMVclq8dEJTwR93Pr44xYlNxZ.QXwEzMwEDL4ITM0EzW}
```

<img alt="image" src="https://github.com/user-attachments/assets/80de1371-b7a9-49df-9cf0-e3fc0fce2f4d" />

&nbsp;

## Tweaking Images

```
hacker@reverse-engineering~tweaking-images:/$ ls /challenge/
DESCRIPTION.md  cimg  cimg.c  generate_flag_image
```

This time, there is a `generate_flag_image` script, which generates a flag cIMG for us.

```
hacker@reverse-engineering~tweaking-images:/$ /challenge/generate_flag_image 
hacker@reverse-engineering~tweaking-images:/$ ls /challenge/
DESCRIPTION.md  cimg  cimg.c  flag.cimg  generate_flag_image
```

Since, we already have the `/challenge/flag.cimg` file, let's pass it to the `/challenge/cimg` program.

```
hacker@reverse-engineering~tweaking-images:/$ /challenge/cimg /challenge/flag.cimg 
ERROR: invalid directive_code 2x
```

So, the directive code in the `/challenge/flag.cimg` file is `2` but that is not what is expected. 

### Binary Analysis

We can even verify this. For some reason the free version if IDA does not support the file format, so we will have to use Binary Ninja.

<img alt="image" src="https://github.com/user-attachments/assets/4fae5c03-da33-4748-b005-62b338fddd30" />

We can see that it sets the directive code to `2`.

```c
struct.pack(\"<HBBBBBBBB\", 2, p[0], p[1], 1, 1, 0x8c, 0x1d, 0x40, p[2]) 
```

Let's check what the `/challenge/cimg` program expects.

```c showLineNumbers
int __fastcall main(int argc, const char **argv, const char **envp)
{
  const char *v3; // rbp
  int v4; // eax
  const char *v5; // rdi
  unsigned __int16 v8; // [rsp+0h] [rbp-3Ah] BYREF
  __int128 v9; // [rsp+2h] [rbp-38h] BYREF
  __int64 v10; // [rsp+12h] [rbp-28h]
  unsigned __int64 v11; // [rsp+1Ah] [rbp-20h]

  v11 = __readfsqword(0x28u);
  v9 = 0LL;
  v10 = 0LL;
  if ( argc > 1 )
  {
    v3 = argv[1];
    if ( strcmp(&v3[strlen(v3) - 5], ".cimg") )
    {
      __printf_chk(1LL, "ERROR: Invalid file extension!");
      goto LABEL_8;
    }
    v4 = open(v3, 0);
    dup2(v4, 0);
  }
  read_exact(0LL, &v9, 12LL, "ERROR: Failed to read header!", 0xFFFFFFFFLL);
  if ( (_DWORD)v9 != 1196247395 )
  {
    v5 = "ERROR: Invalid magic number!";
LABEL_7:
    puts(v5);
    goto LABEL_8;
  }
  v5 = "ERROR: Unsupported version!";
  if ( WORD2(v9) != 3 )
    goto LABEL_7;
  initialize_framebuffer(&v9);
  while ( DWORD2(v9)-- )
  {
    read_exact(0LL, &v8, 2LL, "ERROR: Failed to read &directive_code!", 0xFFFFFFFFLL);
    if ( v8 == 13725 )
    {
      handle_13725(&v9);
    }
    else
    {
      if ( v8 != 0x8B48 )
      {
        __fprintf_chk(stderr, 1LL, "ERROR: invalid directive_code %ux\n", v8);
LABEL_8:
        exit(-1);
      }
      handle_35656(&v9);
    }
  }
  display(&v9, 0LL);
  return 0;
}
```

The expected directive is `13725`, which is `b"\x9d\x35"`.

Let's craft an exploit that fixes `/challenge/flag.cimg`.

### Exploit

```py title="~/script.py" showLineNumbers
#!/usr/bin/env python3

# Define the paths
input_file = "/challenge/flag.cimg"
output_file = "/home/hacker/fixed_flag.cimg"

with open(input_file, "rb") as f:
    # Read the entire file into a bytearray so we can modify it
    data = bytearray(f.read())

# --- Step 1: Fix the Canvas Height ---
# The header is 12 bytes. Offset 0x07 is the Height.
# The original generator set this to 1. We change it to 100 (0x64).
data[0x07] = 0x40 

# --- Step 2: Fix the Directive Codes ---
# The binary expects code 13725 (0x359D), which is \x9d\x35 in little-endian.
# The generator wrote code 2, which is \x02\x00 in little-endian.
# We replace all instances of the wrong code with the right one.
# We skip the first 12 bytes to avoid accidentally touching the header.
header = data[:12]
body = data[12:].replace(b"\x02\x00", b"\x9d\x35")

# Combine and save
with open(output_file, "wb") as o:
    o.write(header + body)

print(f"Patched file saved to {output_file}")
```

```
hacker@reverse-engineering~tweaking-images:/$ python ~/script.py 
Patched file saved to /home/hacker/fixed_flag.cimg
```

```
hacker@reverse-engineering~tweaking-images:/$ /challenge/cimg ~/fixed_flag.cimg 
                                                                             
                                           ""#    ""#                        
 mmmm  m     m m mm           mmm    mmm     #      #     mmm    mmmm   mmm  
 #" "# "m m m" #"  #         #"  "  #" "#    #      #    #"  #  #" "#  #"  # 
 #   #  #m#m#  #   #         #      #   #    #      #    #""""  #   #  #"""" 
 ##m#"   # #   #   #    #    "#mm"  "#m#"    "mm    "mm  "#mm"  "#m"#  "#mm" 
 #                                                               m  #        
 "                                                                ""         
                                                                             
   m""  m    m m    m     #  mmmmm                 mmmm   mmmm         mmm   
   #    #    # "m  m"  mmm#  #   "#m     m  mmm   #    # m"  "m  m mm    #   
 mm"    #    #  #  #  #" "#  #mmmm""m m m" #" "#  "mmmm" #    #  #"  "   #   
   #    #    #  "mm"  #   #  #   "m #m#m#  #   #  #   "# #    #  #       #   
   #    "mmmm"   ##   "#m##  #    "  # #   "#m#"  "#mmm"  #mm#"  #     mm#mm 
    ""                                                       #               
                                                                             
                                                                             
 mmmmm m     m mmmmmm        #      m    m  mmmm   mmmm   mmmm  m    m  mmmm 
 #   "# "m m"      #"  mmmm  #mmm   #    # m"  "m "   "# "   "# ##  ## m"  "m
 #mmm#"  "#"      m"  #" "#  #" "#  #mmmm# #  m #   mmm"   mmm" # ## # #    #
 #        #      m"   #   #  #   #  #    # #    #     "#     "# # "" # #    #
 #        #     m"    "#m##  ##m#"  #    #  #mm#  "mmm#" "mmm#" #    #  #mm# 
                          #                                                  
                          "                                                  
                                                                             
 mmmmm           mm   m    m m    m                mmmm  m    m mmmmm  mmmmmm
   #    m mm     ##    #  #  #    # m mm          m"  "m  #  #  #      #     
   #    #"  #   #  #    ##   #mmmm# #"  #         #    #   ##   """"mm #mmmmm
   #    #   #   #mm#   m""m  #    # #   #         #    #  m""m       # #     
 mm#mm  #   #  #    # m"  "m #    # #   #    #     #mm#" m"  "m "mmm#" #mmmmm
                                                      #                      
                                                                             
                                                                             
        m    m        mmmmmm mmmm   m         mm  mmmmm mmmmmmm m    m  mmmm 
 mmmmm  ##  ##m     m #      #   "m #        m"#    #      #    ##  ## m"  "m
    m"  # ## #"m m m" #mmmmm #    # #       #" #    #      #    # ## # #  m #
  m"    # "" # #m#m#  #      #    # #      #mmm#m   #      #    # "" # #    #
 #mmmm  #    #  # #   #mmmmm #mmm"  #mmmmm     #  mm#mm    #    #    #  #mm# 
                                                                             
                                                                             
                                                                             
 mmmmmm       m     m ""m                                                    
 #      mmmmm #  #  #   #                                                    
 #mmmmm    m" " #"# #   "mm                                                  
 #       m"    ## ##"   #                                                    
 #mmmmm #mmmm  #   #    #                                                    
                      ""                                                     
```

```
pwn.college{UVdRwo8Qr1PY7qbH033MOInAXHn.QX5EzMwEDL4ITM0EzW}
```

&nbsp;

## Storage and Retrieval

### Binary Analysis

#### `main()`

```c title="/challenge/storage-and-retrieval :: main()"
int __fastcall main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rcx
  int *v5; // rdi
  bool v6; // of
  int v7; // r8d
  const char *v8; // r12
  int v9; // eax
  const char *v10; // rdi
  char *v12; // r12
  unsigned int v13; // r14d
  _BYTE *v14; // r13
  _BOOL8 v15; // rbp
  unsigned int i; // ebx
  char v17; // al
  unsigned __int16 v19; // [rsp+Eh] [rbp-105Ah] BYREF
  int v20; // [rsp+10h] [rbp-1058h] BYREF
  __int16 v21; // [rsp+14h] [rbp-1054h]
  int v22; // [rsp+18h] [rbp-1050h]
  unsigned int v23; // [rsp+1Ch] [rbp-104Ch]
  void *s1; // [rsp+20h] [rbp-1048h]
  unsigned __int64 v25; // [rsp+1028h] [rbp-40h]

  v3 = 1030LL;
  v25 = __readfsqword(0x28u);
  v5 = &v20;
  v6 = __OFSUB__(argc, 1);
  v7 = argc - 1;
  while ( v3 )
  {
    *v5++ = 0;
    --v3;
  }
  if ( !((v7 < 0) ^ v6 | (v7 == 0)) )
  {
    v8 = argv[1];
    if ( strcmp(&v8[strlen(v8) - 5], ".cimg") )
    {
      __printf_chk(1LL, "ERROR: Invalid file extension!");
      goto LABEL_11;
    }
    v9 = open(v8, 0);
    dup2(v9, 0);
  }
  read_exact(0LL, &v20, 12LL, "ERROR: Failed to read header!", 0xFFFFFFFFLL);
  if ( v20 != 1196247395 )
  {
    v10 = "ERROR: Invalid magic number!";
LABEL_10:
    puts(v10);
    goto LABEL_11;
  }
  v10 = "ERROR: Unsupported version!";
  if ( v21 != 3 )
    goto LABEL_10;
  initialize_framebuffer(&v20);
  while ( v22-- )
  {
    read_exact(0LL, &v19, 2LL, "ERROR: Failed to read &directive_code!", 0xFFFFFFFFLL);
    if ( v19 == 3 )
    {
      handle_3(&v20);
    }
    else if ( v19 > 3u )
    {
      if ( v19 != 4 )
      {
LABEL_24:
        __fprintf_chk(stderr, 1LL, "ERROR: invalid directive_code %ux\n", v19);
LABEL_11:
        exit(-1);
      }
      handle_4(&v20);
    }
    else if ( v19 == 1 )
    {
      handle_1(&v20);
    }
    else
    {
      if ( v19 != 2 )
        goto LABEL_24;
      handle_2(&v20);
    }
  }
  v12 = desired_output;
  display(&v20, 0LL);
  v13 = v23;
  v14 = s1;
  v15 = v23 == 1824;
  for ( i = 0; v13 > i && i != 1824; ++i )
  {
    v17 = v14[19];
    if ( v17 != v12[19] )
      LOBYTE(v15) = 0;
    if ( v17 != 32 && v17 != 10 )
    {
      if ( memcmp(v14, v12, 0x18uLL) )
        LOBYTE(v15) = 0;
    }
    v14 += 24;
    v12 += 24;
  }
  if ( (unsigned __int64)total_data <= 0x190 && v15 )
    win();
  return 0;
}
```

#### `handle_1()`

```c title="/challenge/storage-and-retrieval ::  handle_1()"
unsigned __int64 __fastcall handle_1(__int64 a1)
{
  int v1; // ebp
  int v2; // edx
  size_t v3; // rbp
  unsigned __int8 *v4; // rax
  unsigned __int8 *v5; // r12
  __int64 v6; // rax
  __int64 v7; // rcx
  int i; // r13d
  int v9; // ebp
  int v10; // r15d
  unsigned __int8 *v11; // rax
  __int64 v12; // kr00_8
  __int64 v13; // rdx
  __int128 v15; // [rsp+1Fh] [rbp-59h] BYREF
  __int64 v16; // [rsp+2Fh] [rbp-49h]
  unsigned __int64 v17; // [rsp+38h] [rbp-40h]

  v1 = *(unsigned __int8 *)(a1 + 6);
  v2 = *(unsigned __int8 *)(a1 + 7);
  v17 = __readfsqword(0x28u);
  v3 = 4LL * v2 * v1;
  v4 = (unsigned __int8 *)malloc(v3);
  if ( !v4 )
  {
    puts("ERROR: Failed to allocate memory for the image data!");
    goto LABEL_7;
  }
  v5 = v4;
  read_exact(0LL, v4, (unsigned int)v3, "ERROR: Failed to read data!", 0xFFFFFFFFLL);
  v6 = 0LL;
  while ( *(unsigned __int8 *)(a1 + 7) * *(unsigned __int8 *)(a1 + 6) > (int)v6 )
  {
    v7 = v5[4 * v6++ + 3];
    if ( (unsigned __int8)(v7 - 32) > 0x5Eu )
    {
      __fprintf_chk(stderr, 1LL, "ERROR: Invalid character 0x%x in the image data!\n", v7);
LABEL_7:
      exit(-1);
    }
  }
  for ( i = 0; *(unsigned __int8 *)(a1 + 7) > i; ++i )
  {
    v9 = 0;
    while ( 1 )
    {
      v10 = *(unsigned __int8 *)(a1 + 6);
      if ( v10 <= v9 )
        break;
      v11 = &v5[4 * i * v10 + 4 * v9];
      __snprintf_chk(&v15, 25LL, 1LL, 25LL, "\x1B[38;2;%03d;%03d;%03dm%c\x1B[0m", *v11, v11[1], v11[2], v11[3]);
      v12 = v9++;
      v13 = *(_QWORD *)(a1 + 16) + 24LL * (((unsigned int)(v12 % v10) + i * v10) % *(_DWORD *)(a1 + 12));
      *(_OWORD *)v13 = v15;
      *(_QWORD *)(v13 + 16) = v16;
    }
  }
  return __readfsqword(0x28u) ^ v17;
}
```

#### `handle_2()`

```c showLineNumbers
unsigned __int64 __fastcall handle_2(__int64 a1)
{
  unsigned int v1; // ebx
  unsigned __int8 *v2; // rax
  unsigned __int8 *v3; // rbp
  __int64 v4; // rax
  __int64 v5; // rcx
  int i; // r13d
  int v7; // r14d
  int v8; // eax
  int v9; // ecx
  unsigned int v10; // ebx
  __int64 v11; // rdx
  unsigned __int8 v13; // [rsp+Bh] [rbp-5Dh] BYREF
  unsigned __int8 v14; // [rsp+Ch] [rbp-5Ch] BYREF
  unsigned __int8 v15; // [rsp+Dh] [rbp-5Bh] BYREF
  unsigned __int8 v16; // [rsp+Eh] [rbp-5Ah] BYREF
  __int128 v17; // [rsp+Fh] [rbp-59h] BYREF
  __int64 v18; // [rsp+1Fh] [rbp-49h]
  unsigned __int64 v19; // [rsp+28h] [rbp-40h]

  v19 = __readfsqword(0x28u);
  read_exact(0LL, &v15, 1LL, "ERROR: Failed to read &base_x!", 0xFFFFFFFFLL);
  read_exact(0LL, &v16, 1LL, "ERROR: Failed to read &base_y!", 0xFFFFFFFFLL);
  read_exact(0LL, &v13, 1LL, "ERROR: Failed to read &width!", 0xFFFFFFFFLL);
  read_exact(0LL, &v14, 1LL, "ERROR: Failed to read &height!", 0xFFFFFFFFLL);
  v1 = 4 * v14 * v13;
  v2 = (unsigned __int8 *)malloc(4LL * v14 * v13);
  if ( !v2 )
  {
    puts("ERROR: Failed to allocate memory for the image data!");
    goto LABEL_7;
  }
  v3 = v2;
  read_exact(0LL, v2, v1, "ERROR: Failed to read data!", 0xFFFFFFFFLL);
  v4 = 0LL;
  while ( v14 * v13 > (int)v4 )
  {
    v5 = v3[4 * v4++ + 3];
    if ( (unsigned __int8)(v5 - 32) > 0x5Eu )
    {
      __fprintf_chk(stderr, 1LL, "ERROR: Invalid character 0x%x in the image data!\n", v5);
LABEL_7:
      exit(-1);
    }
  }
  for ( i = 0; v14 > i; ++i )
  {
    v7 = 0;
    while ( v13 > v7 )
    {
      v8 = v7 + v15;
      v9 = v7 + i * v13;
      ++v7;
      v10 = v8 % *(unsigned __int8 *)(a1 + 6) + *(unsigned __int8 *)(a1 + 6) * (i + v16);
      __snprintf_chk(
        &v17,
        25LL,
        1LL,
        25LL,
        "\x1B[38;2;%03d;%03d;%03dm%c\x1B[0m",
        v3[4 * v9],
        v3[4 * v9 + 1],
        v3[4 * v9 + 2],
        v3[4 * v9 + 3]);
      v11 = *(_QWORD *)(a1 + 16) + 24LL * (v10 % *(_DWORD *)(a1 + 12));
      *(_OWORD *)v11 = v17;
      *(_QWORD *)(v11 + 16) = v18;
    }
  }
  return __readfsqword(0x28u) ^ v19;
}
```

#### `handle_3()`

```c showLineNumbers
unsigned __int64 __fastcall handle_3(__int64 a1)
{
  __int64 v2; // rax
  void *v3; // rdi
  int v4; // r12d
  unsigned __int8 *v5; // rax
  unsigned __int8 *v6; // rbx
  __int64 v7; // rax
  __int64 v8; // rcx
  unsigned __int8 v10; // [rsp+5h] [rbp-23h] BYREF
  unsigned __int8 v11; // [rsp+6h] [rbp-22h] BYREF
  unsigned __int8 v12; // [rsp+7h] [rbp-21h] BYREF
  unsigned __int64 v13; // [rsp+8h] [rbp-20h]

  v13 = __readfsqword(0x28u);
  read_exact(0LL, &v10, 1LL, "ERROR: Failed to read &sprite_id!", 0xFFFFFFFFLL);
  read_exact(0LL, &v11, 1LL, "ERROR: Failed to read &width!", 0xFFFFFFFFLL);
  read_exact(0LL, &v12, 1LL, "ERROR: Failed to read &height!", 0xFFFFFFFFLL);
  v2 = a1 + 16LL * v10;
  *(_BYTE *)(v2 + 25) = v11;
  v3 = *(void **)(v2 + 32);
  *(_BYTE *)(v2 + 24) = v12;
  if ( v3 )
    free(v3);
  v4 = v12 * v11;
  v5 = (unsigned __int8 *)malloc(v4);
  v6 = v5;
  if ( !v5 )
  {
    puts("ERROR: Failed to allocate memory for the image data!");
    goto LABEL_9;
  }
  read_exact(0LL, v5, (unsigned int)v4, "ERROR: Failed to read data!", 0xFFFFFFFFLL);
  v7 = 0LL;
  while ( v12 * v11 > (int)v7 )
  {
    v8 = v6[v7++];
    if ( (unsigned __int8)(v8 - 32) > 0x5Eu )
    {
      __fprintf_chk(stderr, 1LL, "ERROR: Invalid character 0x%x in the image data!\n", v8);
LABEL_9:
      exit(-1);
    }
  }
  *(_QWORD *)(16LL * v10 + a1 + 32) = v6;
  return __readfsqword(0x28u) ^ v13;
}
```

#### `handle_4()`

```c showLineNumbers
// positive sp value has been detected, the output may be wrong!
unsigned __int64 __fastcall handle_4(__int64 a1)
{
  _DWORD *v2; // rdi
  __int64 v3; // rcx
  __int64 v4; // rdx
  char v5; // r10
  char v6; // r11
  char v7; // bp
  __int64 v8; // rdx
  int v9; // r12d
  int v10; // r8d
  int v11; // edi
  __int64 v12; // rax
  __int64 v13; // r9
  int v14; // r14d
  int v15; // r15d
  int i; // r13d
  int v17; // ebp
  int v18; // ecx
  int v19; // r12d
  int v20; // eax
  __int64 v21; // rdx
  __int64 v22; // rdx
  _BYTE v24[6]; // [rsp-2Fh] [rbp-4005Fh] BYREF
  _BYTE v25[41]; // [rsp-29h] [rbp-40059h] BYREF
  char v26; // [rsp+0h] [rbp-40030h] BYREF
  __int64 v27; // [rsp+1000h] [rbp-3F030h] BYREF
  __int128 v28; // [rsp+3FFD7h] [rbp-59h] BYREF
  __int64 v29; // [rsp+3FFE7h] [rbp-49h]
  unsigned __int64 v30; // [rsp+3FFF0h] [rbp-40h]

  while ( &v26 != (char *)(&v27 - 0x8000) )
    ;
  v30 = __readfsqword(0x28u);
  read_exact(0LL, v24, 6LL, "ERROR: Failed to read &sprite_render_record!", 0xFFFFFFFFLL);
  v2 = v25;
  v3 = 0x10000LL;
  v4 = v24[0];
  v5 = v24[1];
  while ( v3 )
  {
    *v2++ = 0;
    --v3;
  }
  v6 = v24[2];
  v7 = v24[3];
  v8 = a1 + 16 * v4;
  v9 = *(unsigned __int8 *)(v8 + 24);
  while ( v9 > (int)v3 )
  {
    v10 = *(unsigned __int8 *)(v8 + 25);
    v11 = 0;
    v12 = (unsigned int)(v3 * v10);
    while ( v10 > v11 )
    {
      v13 = *(_QWORD *)(v8 + 32);
      v25[4 * v12] = v5;
      v25[4 * v12 + 1] = v6;
      v25[4 * v12 + 2] = v7;
      if ( !v13 )
      {
        fputs("ERROR: attempted to render uninitialized sprite!\n", stderr);
        exit(-1);
      }
      ++v11;
      v25[4 * v12 + 3] = *(_BYTE *)(v13 + v12);
      ++v12;
    }
    LODWORD(v3) = v3 + 1;
  }
  v14 = v24[5];
  v15 = v24[4];
  for ( i = 0; *(unsigned __int8 *)(16LL * v24[0] + a1 + 24) > i; ++i )
  {
    v17 = 0;
    while ( 1 )
    {
      v18 = *(unsigned __int8 *)(16LL * v24[0] + a1 + 25);
      if ( v18 <= v17 )
        break;
      v19 = *(unsigned __int8 *)(a1 + 6);
      __snprintf_chk(
        &v28,
        25LL,
        1LL,
        25LL,
        "\x1B[38;2;%03d;%03d;%03dm%c\x1B[0m",
        (unsigned __int8)v25[4 * v17 + 4 * i * v18],
        (unsigned __int8)v25[4 * v17 + 1 + 4 * i * v18],
        (unsigned __int8)v25[4 * v17 + 2 + 4 * i * v18],
        (unsigned __int8)v25[4 * v17 + 3 + 4 * i * v18]);
      v20 = v17 + v15;
      ++v17;
      v21 = (unsigned int)(v20 % v19);
      LODWORD(v21) = (unsigned int)(v21 + v14 * v19) % *(_DWORD *)(a1 + 12);
      v22 = *(_QWORD *)(a1 + 16) + 24 * v21;
      *(_OWORD *)v22 = v28;
      *(_QWORD *)(v22 + 16) = v29;
    }
    ++v14;
  }
  return __readfsqword(0x28u) ^ v30;
}
```

### Exploit

```py title="~/script.py" showLineNumbers
from pwn import *
import struct
import re

# Desired ANSII sequence
binary = context.binary = ELF('/challenge/cimg')
desired_ansii_sequence_bytes = binary.string(binary.sym.desired_output)
desired_ansii_sequence = desired_ansii_sequence_bytes.decode("utf-8")
print(desired_ansii_sequence)
```

```
hacker@reverse-engineering~storage-and-retrieval:~$ python ~/script.py
[*] '/challenge/cimg'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    FORTIFY:    Enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
.--------------------------------------------------------------------------.|                                                                          ||                                                                          ||                                                                          ||                                                                          ||                                                                          ||                                                                          ||                                                                          ||                                                                          ||                              ___   __  __    ____                        ||                        ___  |_ _| |  \/  |  / ___|                       ||                       / __|  | |  | |\/| | | |  _                        ||                      | (__   | |  | |  | | | |_| |                       ||                       \___| |___| |_|  |_|  \____|                       ||                                                                          ||                                                                          ||                                                                          ||                                                                          ||                                                                          ||                                                                          ||                                                                          ||                                                                          ||                                                                          |'--------------------------------------------------------------------------'
```

```py
In [1]: print(len(".--------------------------------------------------------------------------."))
76
```

Width is 76.

Final script:

```py title="~/script.py" showLineNumbers 
from pwn import *
import struct
import re

# ------------------------------------------------------------
# Extract desired_output
# ------------------------------------------------------------
binary = ELF('/challenge/cimg')
raw = binary.read(binary.sym.desired_output, 45000)
ansi = raw.split(b'\0')[0].decode()

pattern = r"\x1b\[38;2;(\d+);(\d+);(\d+)m(.)"
pixels = re.findall(pattern, ansi)

W, H = 76, 24
assert len(pixels) == W * H

def px(x, y):
    r, g, b, ch = pixels[y * W + x]
    return int(r), int(g), int(b), ch

directives = []

def add_sprite(sid, w, h, data):
    directives.append(struct.pack("<HBBB", 3, sid, w, h) + data.encode())

def render(sid, r, g, b, x, y):
    directives.append(struct.pack("<HBBBBBB", 4, sid, r, g, b, x, y))

WHITE = px(0, 0)[:3]

sid = 0

# ------------------------------------------------------------
# Borders (minimal, full)
# ------------------------------------------------------------
add_sprite(sid, 37, 1, "-" * 37)
render(sid, *WHITE, 1, 0)
render(sid, *WHITE, 38, 0)
render(sid, *WHITE, 1, 23)
render(sid, *WHITE, 38, 23)
sid += 1

add_sprite(sid, 1, 22, "|" * 22)
render(sid, *WHITE, 0, 1)
render(sid, *WHITE, 75, 1)
sid += 1

add_sprite(sid, 1, 1, ".")
render(sid, *WHITE, 0, 0)
render(sid, *WHITE, 75, 0)
sid += 1

add_sprite(sid, 1, 1, "'")
render(sid, *WHITE, 0, 23)
render(sid, *WHITE, 75, 23)
sid += 1

# ------------------------------------------------------------
# Logo split by COLOR (minimal correct partition)
# ------------------------------------------------------------
lx, ly, lw, lh = 22, 9, 35, 5

by_color = {}
for dy in range(lh):
    for dx in range(lw):
        r, g, b, ch = px(lx + dx, ly + dy)
        if ch != " ":
            by_color.setdefault((r, g, b), []).append((dx, dy, ch))

for (r, g, b), pts in by_color.items():
    xs = [p[0] for p in pts]
    ys = [p[1] for p in pts]

    minx, maxx = min(xs), max(xs)
    miny, maxy = min(ys), max(ys)

    w = maxx - minx + 1
    h = maxy - miny + 1

    grid = [" "] * (w * h)
    for x, y, ch in pts:
        grid[(y - miny) * w + (x - minx)] = ch

    add_sprite(sid, w, h, "".join(grid))
    render(sid, r, g, b, lx + minx, ly + miny)
    sid += 1

# ------------------------------------------------------------
# File assembly
# ------------------------------------------------------------
header = struct.pack(
    "<I H B B H H",
    0x474D4963,
    3,
    W,
    H,
    len(directives),
    0
)

payload = header + b"".join(directives)
print("Final Payload Size:", len(payload))

with open("solution.cimg", "wb") as f:
    f.write(payload)
```

```
hacker@reverse-engineering~storage-and-retrieval:~$ python ~/script.py
[*] '/challenge/cimg'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    FORTIFY:    Enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
Final Payload Size: 349
```

```
hacker@reverse-engineering~storage-and-retrieval:~$ /challenge/cimg ~/solution.cimg 
.--------------------------------------------------------------------------.
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                              ___   __  __    ____                        |
|                        ___  |_ _| |  \/  |  / ___|                       |
|                       / __|  | |  | |\/| | | |  _                        |
|                      | (__   | |  | |  | | | |_| |                       |
|                       \___| |___| |_|  |_|  \____|                       |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
'--------------------------------------------------------------------------'
pwn.college{gP6BoUhTPNZk0ED6EhlqT9CLBMs.QXxEzMwEDL4ITM0EzW}
```

&nbsp;

## Extracting Knowledge

> How well do you grasp the cIMG format? This is a chance to show yourself just how much you've learned!
> This level's /challenge/cimg has no way to give you the flag, but we'll give you a cimg file containing it!

```
hacker@reverse-engineering~extracting-knowledge:~$ ls /challenge/
DESCRIPTION.md  cimg  cimg.c  generate_flag_image
```

### Binary Analysis

```py title="/challenge/generate_flag_image"
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

import subprocess
import struct
import os

sprites = {}
directives = []

for c in open("/flag", "rb").read().strip():
    if c not in sprites:
        sprites[c] = len(directives)

        sprite = subprocess.check_output(
            ["/usr/bin/figlet", "-fascii9"],
            input=bytes([c])
        ).split(b"\n")[:-1]

        directives.append(
            struct.pack(
                "<HBBB",
                3,
                sprites[c],
                len(sprite[0]),
                len(sprite),
            ) + b"".join(sprite)
        )

    directives.append(
        struct.pack(
            "<HBBBBBB",
            4,
            sprites[c],
            0xFF,
            0xFF,
            0xFF,
            0,
            0,
        )
    )

img = (
    b"cIMG"
    + struct.pack("<HBBI", 3, 16, 16, len(directives))
    + b"".join(directives)
)

with open("/challenge/flag.cimg", "wb") as o:
    o.write(img)
```

```c title="/challenge/cimg :: main()" showLineNumbers
int __fastcall main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rcx
  int *v5; // rdi
  bool v6; // of
  int v7; // r8d
  const char *v8; // r12
  int v9; // eax
  const char *v10; // rdi
  unsigned __int16 v13; // [rsp+Eh] [rbp-103Ah] BYREF
  int v14; // [rsp+10h] [rbp-1038h] BYREF
  __int16 v15; // [rsp+14h] [rbp-1034h]
  int v16; // [rsp+18h] [rbp-1030h]
  unsigned __int64 v17; // [rsp+1028h] [rbp-20h]

  v3 = 1030LL;
  v17 = __readfsqword(0x28u);
  v5 = &v14;
  v6 = __OFSUB__(argc, 1);
  v7 = argc - 1;
  while ( v3 )
  {
    *v5++ = 0;
    --v3;
  }
  if ( !((v7 < 0) ^ v6 | (v7 == 0)) )
  {
    v8 = argv[1];
    if ( strcmp(&v8[strlen(v8) - 5], ".cimg") )
    {
      __printf_chk(1LL, "ERROR: Invalid file extension!");
      goto LABEL_11;
    }
    v9 = open(v8, 0);
    dup2(v9, 0);
  }
  read_exact(0LL, &v14, 12LL, "ERROR: Failed to read header!", 0xFFFFFFFFLL);
  if ( v14 != 1196247395 )
  {
    v10 = "ERROR: Invalid magic number!";
LABEL_10:
    puts(v10);
    goto LABEL_11;
  }
  v10 = "ERROR: Unsupported version!";
  if ( v15 != 3 )
    goto LABEL_10;
  initialize_framebuffer(&v14);
  while ( v16-- )
  {
    read_exact(0LL, &v13, 2LL, "ERROR: Failed to read &directive_code!", 0xFFFFFFFFLL);
    if ( v13 == 3 )
    {
      handle_3(&v14);
    }
    else if ( v13 > 3u )
    {
      if ( v13 != 4 )
      {
LABEL_24:
        __fprintf_chk(stderr, 1LL, "ERROR: invalid directive_code %ux\n", v13);
LABEL_11:
        exit(-1);
      }
      handle_4(&v14);
    }
    else if ( v13 == 1 )
    {
      handle_1(&v14);
    }
    else
    {
      if ( v13 != 2 )
        goto LABEL_24;
      handle_2(&v14);
    }
  }
  display(&v14, 0LL);
  return 0;
}
```

```c title="/challenge/cimg :: handle_1()" showLineNumbers
unsigned __int64 __fastcall handle_1(__int64 a1)
{
  int v1; // ebp
  int v2; // edx
  size_t v3; // rbp
  unsigned __int8 *v4; // rax
  unsigned __int8 *v5; // r12
  __int64 v6; // rax
  __int64 v7; // rcx
  int i; // r13d
  int v9; // ebp
  int v10; // r15d
  unsigned __int8 *v11; // rax
  __int64 v12; // kr00_8
  __int64 v13; // rdx
  __int128 v15; // [rsp+1Fh] [rbp-59h] BYREF
  __int64 v16; // [rsp+2Fh] [rbp-49h]
  unsigned __int64 v17; // [rsp+38h] [rbp-40h]

  v1 = *(unsigned __int8 *)(a1 + 6);
  v2 = *(unsigned __int8 *)(a1 + 7);
  v17 = __readfsqword(0x28u);
  v3 = 4LL * v2 * v1;
  v4 = (unsigned __int8 *)malloc(v3);
  if ( !v4 )
  {
    puts("ERROR: Failed to allocate memory for the image data!");
    goto LABEL_7;
  }
  v5 = v4;
  read_exact(0LL, v4, (unsigned int)v3, "ERROR: Failed to read data!", 0xFFFFFFFFLL);
  v6 = 0LL;
  while ( *(unsigned __int8 *)(a1 + 7) * *(unsigned __int8 *)(a1 + 6) > (int)v6 )
  {
    v7 = v5[4 * v6++ + 3];
    if ( (unsigned __int8)(v7 - 32) > 0x5Eu )
    {
      __fprintf_chk(stderr, 1LL, "ERROR: Invalid character 0x%x in the image data!\n", v7);
LABEL_7:
      exit(-1);
    }
  }
  for ( i = 0; *(unsigned __int8 *)(a1 + 7) > i; ++i )
  {
    v9 = 0;
    while ( 1 )
    {
      v10 = *(unsigned __int8 *)(a1 + 6);
      if ( v10 <= v9 )
        break;
      v11 = &v5[4 * i * v10 + 4 * v9];
      __snprintf_chk(&v15, 25LL, 1LL, 25LL, "\x1B[38;2;%03d;%03d;%03dm%c\x1B[0m", *v11, v11[1], v11[2], v11[3]);
      v12 = v9++;
      v13 = *(_QWORD *)(a1 + 16) + 24LL * (((unsigned int)(v12 % v10) + i * v10) % *(_DWORD *)(a1 + 12));
      *(_OWORD *)v13 = v15;
      *(_QWORD *)(v13 + 16) = v16;
    }
  }
  return __readfsqword(0x28u) ^ v17;
}
```

```c title="/challenge/cimg :: handle_2()" showLineNumbers
unsigned __int64 __fastcall handle_2(__int64 a1)
{
  unsigned int v1; // ebx
  unsigned __int8 *v2; // rax
  unsigned __int8 *v3; // rbp
  __int64 v4; // rax
  __int64 v5; // rcx
  int i; // r13d
  int v7; // r14d
  int v8; // eax
  int v9; // ecx
  unsigned int v10; // ebx
  __int64 v11; // rdx
  unsigned __int8 v13; // [rsp+Bh] [rbp-5Dh] BYREF
  unsigned __int8 v14; // [rsp+Ch] [rbp-5Ch] BYREF
  unsigned __int8 v15; // [rsp+Dh] [rbp-5Bh] BYREF
  unsigned __int8 v16; // [rsp+Eh] [rbp-5Ah] BYREF
  __int128 v17; // [rsp+Fh] [rbp-59h] BYREF
  __int64 v18; // [rsp+1Fh] [rbp-49h]
  unsigned __int64 v19; // [rsp+28h] [rbp-40h]

  v19 = __readfsqword(0x28u);
  read_exact(0LL, &v15, 1LL, "ERROR: Failed to read &base_x!", 0xFFFFFFFFLL);
  read_exact(0LL, &v16, 1LL, "ERROR: Failed to read &base_y!", 0xFFFFFFFFLL);
  read_exact(0LL, &v13, 1LL, "ERROR: Failed to read &width!", 0xFFFFFFFFLL);
  read_exact(0LL, &v14, 1LL, "ERROR: Failed to read &height!", 0xFFFFFFFFLL);
  v1 = 4 * v14 * v13;
  v2 = (unsigned __int8 *)malloc(4LL * v14 * v13);
  if ( !v2 )
  {
    puts("ERROR: Failed to allocate memory for the image data!");
    goto LABEL_7;
  }
  v3 = v2;
  read_exact(0LL, v2, v1, "ERROR: Failed to read data!", 0xFFFFFFFFLL);
  v4 = 0LL;
  while ( v14 * v13 > (int)v4 )
  {
    v5 = v3[4 * v4++ + 3];
    if ( (unsigned __int8)(v5 - 32) > 0x5Eu )
    {
      __fprintf_chk(stderr, 1LL, "ERROR: Invalid character 0x%x in the image data!\n", v5);
LABEL_7:
      exit(-1);
    }
  }
  for ( i = 0; v14 > i; ++i )
  {
    v7 = 0;
    while ( v13 > v7 )
    {
      v8 = v7 + v15;
      v9 = v7 + i * v13;
      ++v7;
      v10 = v8 % *(unsigned __int8 *)(a1 + 6) + *(unsigned __int8 *)(a1 + 6) * (i + v16);
      __snprintf_chk(
        &v17,
        25LL,
        1LL,
        25LL,
        "\x1B[38;2;%03d;%03d;%03dm%c\x1B[0m",
        v3[4 * v9],
        v3[4 * v9 + 1],
        v3[4 * v9 + 2],
        v3[4 * v9 + 3]);
      v11 = *(_QWORD *)(a1 + 16) + 24LL * (v10 % *(_DWORD *)(a1 + 12));
      *(_OWORD *)v11 = v17;
      *(_QWORD *)(v11 + 16) = v18;
    }
  }
  return __readfsqword(0x28u) ^ v19;
}
```

```c title="/challenge/cimg :: handle_3()" showLineNumbers
unsigned __int64 __fastcall handle_3(__int64 a1)
{
  __int64 v2; // rax
  void *v3; // rdi
  int v4; // r12d
  unsigned __int8 *v5; // rax
  unsigned __int8 *v6; // rbx
  __int64 v7; // rax
  __int64 v8; // rcx
  unsigned __int8 v10; // [rsp+5h] [rbp-23h] BYREF
  unsigned __int8 v11; // [rsp+6h] [rbp-22h] BYREF
  unsigned __int8 v12; // [rsp+7h] [rbp-21h] BYREF
  unsigned __int64 v13; // [rsp+8h] [rbp-20h]

  v13 = __readfsqword(0x28u);
  read_exact(0LL, &v10, 1LL, "ERROR: Failed to read &sprite_id!", 0xFFFFFFFFLL);
  read_exact(0LL, &v11, 1LL, "ERROR: Failed to read &width!", 0xFFFFFFFFLL);
  read_exact(0LL, &v12, 1LL, "ERROR: Failed to read &height!", 0xFFFFFFFFLL);
  v2 = a1 + 16LL * v10;
  *(_BYTE *)(v2 + 25) = v11;
  v3 = *(void **)(v2 + 32);
  *(_BYTE *)(v2 + 24) = v12;
  if ( v3 )
    free(v3);
  v4 = v12 * v11;
  v5 = (unsigned __int8 *)malloc(v4);
  v6 = v5;
  if ( !v5 )
  {
    puts("ERROR: Failed to allocate memory for the image data!");
    goto LABEL_9;
  }
  read_exact(0LL, v5, (unsigned int)v4, "ERROR: Failed to read data!", 0xFFFFFFFFLL);
  v7 = 0LL;
  while ( v12 * v11 > (int)v7 )
  {
    v8 = v6[v7++];
    if ( (unsigned __int8)(v8 - 32) > 0x5Eu )
    {
      __fprintf_chk(stderr, 1LL, "ERROR: Invalid character 0x%x in the image data!\n", v8);
LABEL_9:
      exit(-1);
    }
  }
  *(_QWORD *)(16LL * v10 + a1 + 32) = v6;
  return __readfsqword(0x28u) ^ v13;
}
```

```c title="/challenge/cimg :: handle_4()" showLineNumbers
// positive sp value has been detected, the output may be wrong!
unsigned __int64 __fastcall handle_4(__int64 a1)
{
  _DWORD *v2; // rdi
  __int64 v3; // rcx
  __int64 v4; // rdx
  char v5; // r10
  char v6; // r11
  char v7; // bp
  __int64 v8; // rdx
  int v9; // r12d
  int v10; // r8d
  int v11; // edi
  __int64 v12; // rax
  __int64 v13; // r9
  int v14; // r14d
  int v15; // r15d
  int i; // r13d
  int v17; // ebp
  int v18; // ecx
  int v19; // r12d
  int v20; // eax
  __int64 v21; // rdx
  __int64 v22; // rdx
  _BYTE v24[6]; // [rsp-2Fh] [rbp-4005Fh] BYREF
  _BYTE v25[41]; // [rsp-29h] [rbp-40059h] BYREF
  char v26; // [rsp+0h] [rbp-40030h] BYREF
  __int64 v27; // [rsp+1000h] [rbp-3F030h] BYREF
  __int128 v28; // [rsp+3FFD7h] [rbp-59h] BYREF
  __int64 v29; // [rsp+3FFE7h] [rbp-49h]
  unsigned __int64 v30; // [rsp+3FFF0h] [rbp-40h]

  while ( &v26 != (char *)(&v27 - 0x8000) )
    ;
  v30 = __readfsqword(0x28u);
  read_exact(0LL, v24, 6LL, "ERROR: Failed to read &sprite_render_record!", 0xFFFFFFFFLL);
  v2 = v25;
  v3 = 0x10000LL;
  v4 = v24[0];
  v5 = v24[1];
  while ( v3 )
  {
    *v2++ = 0;
    --v3;
  }
  v6 = v24[2];
  v7 = v24[3];
  v8 = a1 + 16 * v4;
  v9 = *(unsigned __int8 *)(v8 + 24);
  while ( v9 > (int)v3 )
  {
    v10 = *(unsigned __int8 *)(v8 + 25);
    v11 = 0;
    v12 = (unsigned int)(v3 * v10);
    while ( v10 > v11 )
    {
      v13 = *(_QWORD *)(v8 + 32);
      v25[4 * v12] = v5;
      v25[4 * v12 + 1] = v6;
      v25[4 * v12 + 2] = v7;
      if ( !v13 )
      {
        fputs("ERROR: attempted to render uninitialized sprite!\n", stderr);
        exit(-1);
      }
      ++v11;
      v25[4 * v12 + 3] = *(_BYTE *)(v13 + v12);
      ++v12;
    }
    LODWORD(v3) = v3 + 1;
  }
  v14 = v24[5];
  v15 = v24[4];
  for ( i = 0; *(unsigned __int8 *)(16LL * v24[0] + a1 + 24) > i; ++i )
  {
    v17 = 0;
    while ( 1 )
    {
      v18 = *(unsigned __int8 *)(16LL * v24[0] + a1 + 25);
      if ( v18 <= v17 )
        break;
      v19 = *(unsigned __int8 *)(a1 + 6);
      __snprintf_chk(
        &v28,
        25LL,
        1LL,
        25LL,
        "\x1B[38;2;%03d;%03d;%03dm%c\x1B[0m",
        (unsigned __int8)v25[4 * v17 + 4 * i * v18],
        (unsigned __int8)v25[4 * v17 + 1 + 4 * i * v18],
        (unsigned __int8)v25[4 * v17 + 2 + 4 * i * v18],
        (unsigned __int8)v25[4 * v17 + 3 + 4 * i * v18]);
      v20 = v17 + v15;
      ++v17;
      v21 = (unsigned int)(v20 % v19);
      LODWORD(v21) = (unsigned int)(v21 + v14 * v19) % *(_DWORD *)(a1 + 12);
      v22 = *(_QWORD *)(a1 + 16) + 24 * v21;
      *(_OWORD *)v22 = v28;
      *(_QWORD *)(v22 + 16) = v29;
    }
    ++v14;
  }
  return __readfsqword(0x28u) ^ v30;
}
```

```
hacker@reverse-engineering~extracting-knowledge:~$ /challenge/generate_flag_image 
hacker@reverse-engineering~extracting-knowledge:~$ ls /challenge/
DESCRIPTION.md  cimg  cimg.c  flag.cimg  generate_flag_image
```

### Exploit

```py title="~/script.py" showLineNumbers
import struct
import subprocess

CIMG_PATH = "/challenge/flag.cimg"

# ------------------------------------------------------------
# Precompute figlet ascii9 for all printable ASCII
# ------------------------------------------------------------
figlet_map = {}

for c in range(32, 127):
    art = subprocess.check_output(
        ["/usr/bin/figlet", "-fascii9"],
        input=bytes([c])
    ).rstrip(b"\n")
    figlet_map[art] = chr(c)

# ------------------------------------------------------------
# Read cimg file
# ------------------------------------------------------------
with open(CIMG_PATH, "rb") as f:
    data = f.read()

off = 0

# Header
assert data[off:off+4] == b"cIMG"
off += 4
version, width, height, n_directives = struct.unpack_from("<HBBI", data, off)
off += 8
assert version == 3

sprites = {}        # sprite_id -> ascii art
render_order = []   # sprite_ids in order

# ------------------------------------------------------------
# Parse directives
# ------------------------------------------------------------
while n_directives > 0:
    code = struct.unpack_from("<H", data, off)[0]
    off += 2

    if code == 3:  # handle_3
        sprite_id, w, h = struct.unpack_from("<BBB", data, off)
        off += 3

        size = w * h
        sprite_bytes = data[off:off + size]
        off += size

        rows = [
            sprite_bytes[i*w:(i+1)*w]
            for i in range(h)
        ]
        art = b"\n".join(rows)
        sprites[sprite_id] = art

    elif code == 4:  # handle_4
        sprite_id = data[off]
        off += 1
        off += 5  # r, g, b, x, y
        render_order.append(sprite_id)

    else:
        raise ValueError(f"Unknown directive code: {code}")

    n_directives -= 1

# ------------------------------------------------------------
# Decode sprites → characters
# ------------------------------------------------------------
sprite_to_char = {}
for sid, art in sprites.items():
    if art not in figlet_map:
        raise ValueError(f"Unknown figlet art for sprite {sid}")
    sprite_to_char[sid] = figlet_map[art]

# ------------------------------------------------------------
# Recover flag
# ------------------------------------------------------------
flag = "".join(sprite_to_char[sid] for sid in render_order)
print(flag)
```

```
hacker@reverse-engineering~extracting-knowledge:~$ python ~/script.py
pwn.college{s59MKbl6TiR1gXgYJHsskPU-q9b.QXyEzMwEDL4ITM0EzW}
```

&nbsp;

## Advanced Sprites

> This level explores trade-offs between adding just a bit of complexity to a software feature (in this case, the cIMG sprite functionality) and its resulting functionality improvement (making the cIMG file smaller!). We might be getting close to optimal cIMG sizes here, and /challenge/cimg will be very demanding!

### Binary Analysis

```c title="/challenge/cimg :: main()" showLineNumbers
int __fastcall main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rcx
  int *v5; // rdi
  bool v6; // of
  int v7; // r8d
  const char *v8; // r12
  int v9; // eax
  const char *v10; // rdi
  char *v12; // r12
  unsigned int v13; // r14d
  _BYTE *v14; // r13
  _BOOL8 v15; // rbp
  unsigned int i; // ebx
  char v17; // al
  unsigned __int16 v19; // [rsp+Eh] [rbp-105Ah] BYREF
  int v20; // [rsp+10h] [rbp-1058h] BYREF
  __int16 v21; // [rsp+14h] [rbp-1054h]
  int v22; // [rsp+18h] [rbp-1050h]
  unsigned int v23; // [rsp+1Ch] [rbp-104Ch]
  void *s1; // [rsp+20h] [rbp-1048h]
  unsigned __int64 v25; // [rsp+1028h] [rbp-40h]

  v3 = 1030LL;
  v25 = __readfsqword(0x28u);
  v5 = &v20;
  v6 = __OFSUB__(argc, 1);
  v7 = argc - 1;
  while ( v3 )
  {
    *v5++ = 0;
    --v3;
  }
  if ( !((v7 < 0) ^ v6 | (v7 == 0)) )
  {
    v8 = argv[1];
    if ( strcmp(&v8[strlen(v8) - 5], ".cimg") )
    {
      __printf_chk(1LL, "ERROR: Invalid file extension!");
      goto LABEL_11;
    }
    v9 = open(v8, 0);
    dup2(v9, 0);
  }
  read_exact(0LL, &v20, 12LL, "ERROR: Failed to read header!", 0xFFFFFFFFLL);
  if ( v20 != 1196247395 )
  {
    v10 = "ERROR: Invalid magic number!";
LABEL_10:
    puts(v10);
    goto LABEL_11;
  }
  v10 = "ERROR: Unsupported version!";
  if ( v21 != 4 )
    goto LABEL_10;
  initialize_framebuffer(&v20);
  while ( v22-- )
  {
    read_exact(0LL, &v19, 2LL, "ERROR: Failed to read &directive_code!", 0xFFFFFFFFLL);
    if ( v19 == 3 )
    {
      handle_3(&v20);
    }
    else if ( v19 > 3u )
    {
      if ( v19 != 4 )
      {
LABEL_24:
        __fprintf_chk(stderr, 1LL, "ERROR: invalid directive_code %ux\n", v19);
LABEL_11:
        exit(-1);
      }
      handle_4(&v20);
    }
    else if ( v19 == 1 )
    {
      handle_1(&v20);
    }
    else
    {
      if ( v19 != 2 )
        goto LABEL_24;
      handle_2(&v20);
    }
  }
  v12 = desired_output;
  display(&v20, 0LL);
  v13 = v23;
  v14 = s1;
  v15 = v23 == 1824;
  for ( i = 0; v13 > i && i != 1824; ++i )
  {
    v17 = v14[19];
    if ( v17 != v12[19] )
      LOBYTE(v15) = 0;
    if ( v17 != 32 && v17 != 10 )
    {
      if ( memcmp(v14, v12, 0x18uLL) )
        LOBYTE(v15) = 0;
    }
    v14 += 24;
    v12 += 24;
  }
  if ( (unsigned __int64)total_data <= 0x11D && v15 )
    win();
  return 0;
}
```


```c title="/challenge/cimg :: handle_1()" showLineNumbers
unsigned __int64 __fastcall handle_1(__int64 a1)
{
  int v1; // ebp
  int v2; // edx
  size_t v3; // rbp
  unsigned __int8 *v4; // rax
  unsigned __int8 *v5; // r12
  __int64 v6; // rax
  __int64 v7; // rcx
  int i; // r13d
  int v9; // ebp
  int v10; // r15d
  unsigned __int8 *v11; // rax
  __int64 v12; // kr00_8
  __int64 v13; // rdx
  __int128 v15; // [rsp+1Fh] [rbp-59h] BYREF
  __int64 v16; // [rsp+2Fh] [rbp-49h]
  unsigned __int64 v17; // [rsp+38h] [rbp-40h]

  v1 = *(unsigned __int8 *)(a1 + 6);
  v2 = *(unsigned __int8 *)(a1 + 7);
  v17 = __readfsqword(0x28u);
  v3 = 4LL * v2 * v1;
  v4 = (unsigned __int8 *)malloc(v3);
  if ( !v4 )
  {
    puts("ERROR: Failed to allocate memory for the image data!");
    goto LABEL_7;
  }
  v5 = v4;
  read_exact(0LL, v4, (unsigned int)v3, "ERROR: Failed to read data!", 0xFFFFFFFFLL);
  v6 = 0LL;
  while ( *(unsigned __int8 *)(a1 + 7) * *(unsigned __int8 *)(a1 + 6) > (int)v6 )
  {
    v7 = v5[4 * v6++ + 3];
    if ( (unsigned __int8)(v7 - 32) > 0x5Eu )
    {
      __fprintf_chk(stderr, 1LL, "ERROR: Invalid character 0x%x in the image data!\n", v7);
LABEL_7:
      exit(-1);
    }
  }
  for ( i = 0; *(unsigned __int8 *)(a1 + 7) > i; ++i )
  {
    v9 = 0;
    while ( 1 )
    {
      v10 = *(unsigned __int8 *)(a1 + 6);
      if ( v10 <= v9 )
        break;
      v11 = &v5[4 * i * v10 + 4 * v9];
      __snprintf_chk(&v15, 25LL, 1LL, 25LL, "\x1B[38;2;%03d;%03d;%03dm%c\x1B[0m", *v11, v11[1], v11[2], v11[3]);
      v12 = v9++;
      v13 = *(_QWORD *)(a1 + 16) + 24LL * (((unsigned int)(v12 % v10) + i * v10) % *(_DWORD *)(a1 + 12));
      *(_OWORD *)v13 = v15;
      *(_QWORD *)(v13 + 16) = v16;
    }
  }
  return __readfsqword(0x28u) ^ v17;
}
```


```c title="/challenge/cimg :: handle_2()" showLineNumbers
unsigned __int64 __fastcall handle_2(__int64 a1)
{
  unsigned int v1; // ebx
  unsigned __int8 *v2; // rax
  unsigned __int8 *v3; // rbp
  __int64 v4; // rax
  __int64 v5; // rcx
  int i; // r13d
  int v7; // r14d
  int v8; // eax
  int v9; // ecx
  unsigned int v10; // ebx
  __int64 v11; // rdx
  unsigned __int8 v13; // [rsp+Bh] [rbp-5Dh] BYREF
  unsigned __int8 v14; // [rsp+Ch] [rbp-5Ch] BYREF
  unsigned __int8 v15; // [rsp+Dh] [rbp-5Bh] BYREF
  unsigned __int8 v16; // [rsp+Eh] [rbp-5Ah] BYREF
  __int128 v17; // [rsp+Fh] [rbp-59h] BYREF
  __int64 v18; // [rsp+1Fh] [rbp-49h]
  unsigned __int64 v19; // [rsp+28h] [rbp-40h]

  v19 = __readfsqword(0x28u);
  read_exact(0LL, &v15, 1LL, "ERROR: Failed to read &base_x!", 0xFFFFFFFFLL);
  read_exact(0LL, &v16, 1LL, "ERROR: Failed to read &base_y!", 0xFFFFFFFFLL);
  read_exact(0LL, &v13, 1LL, "ERROR: Failed to read &width!", 0xFFFFFFFFLL);
  read_exact(0LL, &v14, 1LL, "ERROR: Failed to read &height!", 0xFFFFFFFFLL);
  v1 = 4 * v14 * v13;
  v2 = (unsigned __int8 *)malloc(4LL * v14 * v13);
  if ( !v2 )
  {
    puts("ERROR: Failed to allocate memory for the image data!");
    goto LABEL_7;
  }
  v3 = v2;
  read_exact(0LL, v2, v1, "ERROR: Failed to read data!", 0xFFFFFFFFLL);
  v4 = 0LL;
  while ( v14 * v13 > (int)v4 )
  {
    v5 = v3[4 * v4++ + 3];
    if ( (unsigned __int8)(v5 - 32) > 0x5Eu )
    {
      __fprintf_chk(stderr, 1LL, "ERROR: Invalid character 0x%x in the image data!\n", v5);
LABEL_7:
      exit(-1);
    }
  }
  for ( i = 0; v14 > i; ++i )
  {
    v7 = 0;
    while ( v13 > v7 )
    {
      v8 = v7 + v15;
      v9 = v7 + i * v13;
      ++v7;
      v10 = v8 % *(unsigned __int8 *)(a1 + 6) + *(unsigned __int8 *)(a1 + 6) * (i + v16);
      __snprintf_chk(
        &v17,
        25LL,
        1LL,
        25LL,
        "\x1B[38;2;%03d;%03d;%03dm%c\x1B[0m",
        v3[4 * v9],
        v3[4 * v9 + 1],
        v3[4 * v9 + 2],
        v3[4 * v9 + 3]);
      v11 = *(_QWORD *)(a1 + 16) + 24LL * (v10 % *(_DWORD *)(a1 + 12));
      *(_OWORD *)v11 = v17;
      *(_QWORD *)(v11 + 16) = v18;
    }
  }
  return __readfsqword(0x28u) ^ v19;
}
```


```c title="/challenge/cimg :: handle_3()" showLineNumbers
unsigned __int64 __fastcall handle_3(__int64 a1)
{
  __int64 v2; // rax
  void *v3; // rdi
  int v4; // r12d
  unsigned __int8 *v5; // rax
  unsigned __int8 *v6; // rbx
  __int64 v7; // rax
  __int64 v8; // rcx
  unsigned __int8 v10; // [rsp+5h] [rbp-23h] BYREF
  unsigned __int8 v11; // [rsp+6h] [rbp-22h] BYREF
  unsigned __int8 v12; // [rsp+7h] [rbp-21h] BYREF
  unsigned __int64 v13; // [rsp+8h] [rbp-20h]

  v13 = __readfsqword(0x28u);
  read_exact(0LL, &v10, 1LL, "ERROR: Failed to read &sprite_id!", 0xFFFFFFFFLL);
  read_exact(0LL, &v11, 1LL, "ERROR: Failed to read &width!", 0xFFFFFFFFLL);
  read_exact(0LL, &v12, 1LL, "ERROR: Failed to read &height!", 0xFFFFFFFFLL);
  v2 = a1 + 16LL * v10;
  *(_BYTE *)(v2 + 25) = v11;
  v3 = *(void **)(v2 + 32);
  *(_BYTE *)(v2 + 24) = v12;
  if ( v3 )
    free(v3);
  v4 = v12 * v11;
  v5 = (unsigned __int8 *)malloc(v4);
  v6 = v5;
  if ( !v5 )
  {
    puts("ERROR: Failed to allocate memory for the image data!");
    goto LABEL_9;
  }
  read_exact(0LL, v5, (unsigned int)v4, "ERROR: Failed to read data!", 0xFFFFFFFFLL);
  v7 = 0LL;
  while ( v12 * v11 > (int)v7 )
  {
    v8 = v6[v7++];
    if ( (unsigned __int8)(v8 - 32) > 0x5Eu )
    {
      __fprintf_chk(stderr, 1LL, "ERROR: Invalid character 0x%x in the image data!\n", v8);
LABEL_9:
      exit(-1);
    }
  }
  *(_QWORD *)(16LL * v10 + a1 + 32) = v6;
  return __readfsqword(0x28u) ^ v13;
}
```


```c title="/challenge/cimg :: handle_4()" showLineNumbers
// positive sp value has been detected, the output may be wrong!
unsigned __int64 __fastcall handle_4(__int64 a1)
{
  _DWORD *v2; // rdi
  __int64 v3; // rcx
  __int64 v4; // rdx
  char v5; // r10
  char v6; // r11
  char v7; // bp
  __int64 v8; // rdx
  int v9; // r12d
  int v10; // r8d
  int v11; // edi
  __int64 v12; // rax
  __int64 v13; // r9
  int i; // r15d
  int j; // r10d
  int v16; // r11d
  __int64 v17; // rdx
  int v18; // r12d
  int v19; // ebp
  int k; // r13d
  int v21; // eax
  __int64 v22; // rax
  __int64 v23; // rdx
  int v24; // r14d
  __int64 v25; // rdx
  __int64 v26; // rdx
  int v28; // [rsp-40h] [rbp-40070h]
  int v29; // [rsp-3Ch] [rbp-4006Ch]
  _BYTE v30[9]; // [rsp-32h] [rbp-40062h] BYREF
  _BYTE v31[41]; // [rsp-29h] [rbp-40059h] BYREF
  char v32; // [rsp+0h] [rbp-40030h] BYREF
  __int64 v33; // [rsp+1000h] [rbp-3F030h] BYREF
  __int128 v34; // [rsp+3FFD7h] [rbp-59h] BYREF
  __int64 v35; // [rsp+3FFE7h] [rbp-49h]
  unsigned __int64 v36; // [rsp+3FFF0h] [rbp-40h]

  while ( &v32 != (char *)(&v33 - 0x8000) )
    ;
  v36 = __readfsqword(0x28u);
  read_exact(0LL, v30, 9LL, "ERROR: Failed to read &sprite_render_record!", 0xFFFFFFFFLL);
  v2 = v31;
  v3 = 0x10000LL;
  v4 = v30[0];
  v5 = v30[1];
  while ( v3 )
  {
    *v2++ = 0;
    --v3;
  }
  v6 = v30[2];
  v7 = v30[3];
  v8 = a1 + 16 * v4;
  v9 = *(unsigned __int8 *)(v8 + 24);
  while ( v9 > (int)v3 )
  {
    v10 = *(unsigned __int8 *)(v8 + 25);
    v11 = 0;
    v12 = (unsigned int)(v3 * v10);
    while ( v10 > v11 )
    {
      v13 = *(_QWORD *)(v8 + 32);
      v31[4 * v12] = v5;
      v31[4 * v12 + 1] = v6;
      v31[4 * v12 + 2] = v7;
      if ( !v13 )
      {
        fputs("ERROR: attempted to render uninitialized sprite!\n", stderr);
        exit(-1);
      }
      ++v11;
      v31[4 * v12 + 3] = *(_BYTE *)(v13 + v12);
      ++v12;
    }
    LODWORD(v3) = v3 + 1;
  }
  for ( i = 0; v30[7] > i; ++i )
  {
    for ( j = 0; v30[6] > j; ++j )
    {
      v16 = 0;
      v17 = a1 + 16LL * v30[0];
      v18 = (unsigned __int8)(v30[4] + j * *(_BYTE *)(v17 + 25));
      v19 = (unsigned __int8)(v30[5] + i * *(_BYTE *)(v17 + 24));
      while ( *(unsigned __int8 *)(16LL * v30[0] + a1 + 24) > v16 )
      {
        for ( k = 0; ; ++k )
        {
          v21 = *(unsigned __int8 *)(16LL * v30[0] + a1 + 25);
          if ( v21 <= k )
            break;
          v22 = k + v16 * v21;
          v23 = (unsigned __int8)v31[4 * v22 + 3];
          if ( (_BYTE)v23 != v30[8] )
          {
            v29 = v16;
            v24 = *(unsigned __int8 *)(a1 + 6);
            v28 = j;
            __snprintf_chk(
              &v34,
              25LL,
              1LL,
              25LL,
              "\x1B[38;2;%03d;%03d;%03dm%c\x1B[0m",
              (unsigned __int8)v31[4 * v22],
              (unsigned __int8)v31[4 * v22 + 1],
              (unsigned __int8)v31[4 * v22 + 2],
              v23);
            v16 = v29;
            j = v28;
            v25 = (unsigned int)((k + v18) % v24);
            LODWORD(v25) = (unsigned int)(v25 + v19 * v24) % *(_DWORD *)(a1 + 12);
            v26 = *(_QWORD *)(a1 + 16) + 24 * v25;
            *(_OWORD *)v26 = v34;
            *(_QWORD *)(v26 + 16) = v35;
          }
        }
        ++v16;
        ++v19;
      }
    }
  }
  return __readfsqword(0x28u) ^ v36;
}
```

### Exploit

```py title="~/script.py"
from pwn import *
import struct
import re

# Desired ANSII sequence
binary = context.binary = ELF('/challenge/cimg')
desired_ansii_sequence_bytes = binary.string(binary.sym.desired_output)
desired_ansii_sequence = desired_ansii_sequence_bytes.decode("utf-8")
print(desired_ansii_sequence)
```

```
hacker@reverse-engineering~advanced-sprites:~$ python ~/script.py
[*] '/challenge/cimg'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    FORTIFY:    Enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
.--------------------------------------------------------------------------.|                                                                          ||                                                                          ||                                                                          ||                                                                          ||                                                                          ||                                                                          ||                                                                          ||                                                                          ||                              ___   __  __    ____                        ||                        ___  |_ _| |  \/  |  / ___|                       ||                       / __|  | |  | |\/| | | |  _                        ||                      | (__   | |  | |  | | | |_| |                       ||                       \___| |___| |_|  |_|  \____|                       ||                                                                          ||                                                                          ||                                                                          ||                                                                          ||                                                                          ||                                                                          ||                                                                          ||                                                                          ||                                                                          |'--------------------------------------------------------------------------'
```

```py
In [1]: print(len(".--------------------------------------------------------------------------."))
76
```

Width is 76.

#### gdb
```
set pagination off
set confirm off

b read_exact
commands
silent
printf "read_exact(len=%ld)  total_data=%ld\n", $rdx, *(unsigned long *)&total_data
continue
end

run solution.cimg
```

```
hacker@reverse-engineering~advanced-sprites:~$ gdb -q /challenge/cimg -x trace_total_data.gdb
Reading symbols from /challenge/cimg...
(No debugging symbols found in /challenge/cimg)
Breakpoint 1 at 0x4016fb
read_exact(len=12)  total_data=0
read_exact(len=2)  total_data=12
read_exact(len=1)  total_data=14
read_exact(len=1)  total_data=15
read_exact(len=1)  total_data=16
read_exact(len=1)  total_data=17
read_exact(len=2)  total_data=18
read_exact(len=1)  total_data=20
read_exact(len=1)  total_data=21
read_exact(len=1)  total_data=22
read_exact(len=1)  total_data=23
read_exact(len=2)  total_data=24
read_exact(len=1)  total_data=26
read_exact(len=1)  total_data=27
read_exact(len=1)  total_data=28
read_exact(len=1)  total_data=29
read_exact(len=2)  total_data=30
read_exact(len=1)  total_data=32
read_exact(len=1)  total_data=33
read_exact(len=1)  total_data=34
read_exact(len=1)  total_data=35
read_exact(len=2)  total_data=36
read_exact(len=9)  total_data=38
read_exact(len=2)  total_data=47
read_exact(len=9)  total_data=49
read_exact(len=2)  total_data=58
read_exact(len=9)  total_data=60
read_exact(len=2)  total_data=69
read_exact(len=9)  total_data=71
read_exact(len=2)  total_data=80
read_exact(len=9)  total_data=82
read_exact(len=2)  total_data=91
read_exact(len=9)  total_data=93
read_exact(len=2)  total_data=102
read_exact(len=9)  total_data=104
read_exact(len=2)  total_data=113
read_exact(len=9)  total_data=115
read_exact(len=2)  total_data=124
read_exact(len=1)  total_data=126
read_exact(len=1)  total_data=127
read_exact(len=1)  total_data=128
read_exact(len=25)  total_data=129
read_exact(len=2)  total_data=154
read_exact(len=9)  total_data=156
read_exact(len=2)  total_data=165
read_exact(len=1)  total_data=167
read_exact(len=1)  total_data=168
read_exact(len=1)  total_data=169
read_exact(len=40)  total_data=170
read_exact(len=2)  total_data=210
read_exact(len=9)  total_data=212
read_exact(len=2)  total_data=221
read_exact(len=1)  total_data=223
read_exact(len=1)  total_data=224
read_exact(len=1)  total_data=225
read_exact(len=35)  total_data=226
read_exact(len=2)  total_data=261
read_exact(len=9)  total_data=263
read_exact(len=2)  total_data=272
read_exact(len=1)  total_data=274
read_exact(len=1)  total_data=275
read_exact(len=1)  total_data=276
read_exact(len=30)  total_data=277
read_exact(len=2)  total_data=307
read_exact(len=9)  total_data=309
.--------------------------------------------------------------------------.
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                              ___   __  __    ____                        |
|                        ___  |_ _| |  \/  |  / ___|                       |
|                       / __|  | |  | |\/| | | |  _                        |
|                      | (__   | |  | |  | | | |_| |                       |
|                       \___| |___| |_|  |_|  \____|                       |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
'--------------------------------------------------------------------------'
[Inferior 1 (process 60494) exited normally]
(gdb) 
```

```py title="~/script.py" showLineNumbers
from pwn import *
import struct
import re

binary = ELF("/challenge/cimg")
ansi = binary.string(binary.sym.desired_output).decode()

pattern = r"\x1b\[38;2;(\d+);(\d+);(\d+)m(.)"
pixels = re.findall(pattern, ansi)

W, H = 76, 24
assert len(pixels) == W * H

def px(x, y):
    r, g, b, ch = pixels[y * W + x]
    return int(r), int(g), int(b), ch

WHITE = px(0, 0)[:3]

directives = []

def add_sprite(sid, w, h, data):
    directives.append(struct.pack("<HBBB", 3, sid, w, h) + data.encode())

def render(sid, r, g, b, x, y, rx, ry, skip):
    directives.append(
        struct.pack("<HBBBBBBBBB",
            4, sid, r, g, b, x, y, rx, ry, ord(skip))
    )

sid = 0

# ------------------------------------------------------------
# SPRITES
# ------------------------------------------------------------

add_sprite(sid, 1, 1, "-")
dash = sid; sid += 1

add_sprite(sid, 1, 1, "|")
pipe = sid; sid += 1

add_sprite(sid, 1, 1, ".")
dot = sid; sid += 1

add_sprite(sid, 1, 1, "'")
quote = sid; sid += 1

# ------------------------------------------------------------
# BORDERS
# ------------------------------------------------------------

# Horizontal border (top + bottom)
render(dash, *WHITE, 0, H - 1, W, 2, ' ')

# Vertical border (left + right)
render(pipe, *WHITE, W - 1, 0, 2, H, ' ')

# ------------------------------------------------------------
# CORNERS (2 renders only, torus-aware)
# ------------------------------------------------------------

# Top-left + top-right
render(dot, *WHITE, W - 1, 0, 2, 1, ' ')

# Bottom-left + bottom-right
render(quote, *WHITE, W - 1, H - 1, 2, 1, ' ')

# ------------------------------------------------------------
# LOGO
# ------------------------------------------------------------

lx, ly, lw, lh = 22, 9, 35, 5
by_color = {}

for dy in range(lh):
    for dx in range(lw):
        r, g, b, ch = px(lx + dx, ly + dy)
        if ch != " ":
            by_color.setdefault((r, g, b), []).append((dx, dy, ch))

for (r, g, b), pts in by_color.items():
    xs = [p[0] for p in pts]
    ys = [p[1] for p in pts]

    minx, maxx = min(xs), max(xs)
    miny, maxy = min(ys), max(ys)

    w = maxx - minx + 1
    h = maxy - miny + 1

    grid = [" "] * (w * h)
    for x, y, ch in pts:
        grid[(y - miny) * w + (x - minx)] = ch

    add_sprite(sid, w, h, "".join(grid))
    render(sid, r, g, b, lx + minx, ly + miny, 1, 1, ' ')
    sid += 1

# ------------------------------------------------------------
# HEADER
# ------------------------------------------------------------

header = struct.pack(
    "<I H B B I",
    0x474D4963,
    4,
    W,
    H,
    len(directives)
)

payload = header + b"".join(directives)
print("Final Payload Size:", len(payload))

with open("solution.cimg", "wb") as f:
    f.write(payload)
```

```
hacker@reverse-engineering~advanced-sprites:~$ python ~/script.py
[*] '/challenge/cimg'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    FORTIFY:    Enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
Final Payload Size: 268
hacker@reverse-engineering~advanced-sprites:~$ /challenge/cimg ~/solution.cimg
.--------------------------------------------------------------------------.
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                              ___   __  __    ____                        |
|                        ___  |_ _| |  \/  |  / ___|                       |
|                       / __|  | |  | |\/| | | |  _                        |
|                      | (__   | |  | |  | | | |_| |                       |
|                       \___| |___| |_|  |_|  \____|                       |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
'--------------------------------------------------------------------------'
pwn.college{4JNfuh3hnmWTXsBKQetE_NAtGxO.QXzEzMwEDL4ITM0EzW}
```

&nbsp;

## Accessing Resources

> Often times, as feature bloat makes a software project more and more complicated, vulnerabilities slip in due to the interaction of too many moving parts. In the course of reverse engineering the software, reverse engineers will often spot such vulnerabilities.
> This is one such scenario. Find and use the vulnerability in /challenge/cimg to get the flag!

### Binary Analysis

```c title="/challenge/cimg :: main()"
int __fastcall main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rcx
  int *v5; // rdi
  bool v6; // of
  int v7; // r8d
  const char *v8; // r12
  int v9; // eax
  const char *v10; // rdi
  unsigned __int16 v13; // [rsp+Eh] [rbp-103Ah] BYREF
  int v14; // [rsp+10h] [rbp-1038h] BYREF
  __int16 v15; // [rsp+14h] [rbp-1034h]
  int v16; // [rsp+18h] [rbp-1030h]
  unsigned __int64 v17; // [rsp+1028h] [rbp-20h]

  v3 = 1030LL;
  v17 = __readfsqword(0x28u);
  v5 = &v14;
  v6 = __OFSUB__(argc, 1);
  v7 = argc - 1;
  while ( v3 )
  {
    *v5++ = 0;
    --v3;
  }
  if ( !((v7 < 0) ^ v6 | (v7 == 0)) )
  {
    v8 = argv[1];
    if ( strcmp(&v8[strlen(v8) - 5], ".cimg") )
    {
      __printf_chk(1LL, "ERROR: Invalid file extension!");
      goto LABEL_11;
    }
    v9 = open(v8, 0);
    dup2(v9, 0);
  }
  read_exact(0LL, &v14, 12LL, "ERROR: Failed to read header!", 0xFFFFFFFFLL);
  if ( v14 != 1196247395 )
  {
    v10 = "ERROR: Invalid magic number!";
LABEL_10:
    puts(v10);
LABEL_11:
    exit(-1);
  }
  v10 = "ERROR: Unsupported version!";
  if ( v15 != 4 )
    goto LABEL_10;
  initialize_framebuffer(&v14);
  while ( 2 )
  {
    if ( v16-- )
    {
      read_exact(0LL, &v13, 2LL, "ERROR: Failed to read &directive_code!", 0xFFFFFFFFLL);
      switch ( v13 )
      {
        case 1u:
          handle_1(&v14);
          continue;
        case 2u:
          handle_2(&v14);
          continue;
        case 3u:
          handle_3(&v14);
          continue;
        case 4u:
          handle_4(&v14);
          continue;
        case 5u:
          handle_5(&v14);
          continue;
        default:
          __fprintf_chk(stderr, 1LL, "ERROR: invalid directive_code %ux\n", v13);
          goto LABEL_11;
      }
    }
    break;
  }
  display(&v14, 0LL);
  return 0;
}
```

```c title="/challenge/cimg :: handle_1()" showLineNumbers
unsigned __int64 __fastcall handle_1(__int64 a1)
{
  int v1; // ebp
  int v2; // edx
  size_t v3; // rbp
  unsigned __int8 *v4; // rax
  unsigned __int8 *v5; // r12
  __int64 v6; // rax
  __int64 v7; // rcx
  int i; // r13d
  int v9; // ebp
  int v10; // r15d
  unsigned __int8 *v11; // rax
  __int64 v12; // kr00_8
  __int64 v13; // rdx
  __int128 v15; // [rsp+1Fh] [rbp-59h] BYREF
  __int64 v16; // [rsp+2Fh] [rbp-49h]
  unsigned __int64 v17; // [rsp+38h] [rbp-40h]

  v1 = *(unsigned __int8 *)(a1 + 6);
  v2 = *(unsigned __int8 *)(a1 + 7);
  v17 = __readfsqword(0x28u);
  v3 = 4LL * v2 * v1;
  v4 = (unsigned __int8 *)malloc(v3);
  if ( !v4 )
  {
    puts("ERROR: Failed to allocate memory for the image data!");
    goto LABEL_7;
  }
  v5 = v4;
  read_exact(0LL, v4, (unsigned int)v3, "ERROR: Failed to read data!", 0xFFFFFFFFLL);
  v6 = 0LL;
  while ( *(unsigned __int8 *)(a1 + 7) * *(unsigned __int8 *)(a1 + 6) > (int)v6 )
  {
    v7 = v5[4 * v6++ + 3];
    if ( (unsigned __int8)(v7 - 32) > 0x5Eu )
    {
      __fprintf_chk(stderr, 1LL, "ERROR: Invalid character 0x%x in the image data!\n", v7);
LABEL_7:
      exit(-1);
    }
  }
  for ( i = 0; *(unsigned __int8 *)(a1 + 7) > i; ++i )
  {
    v9 = 0;
    while ( 1 )
    {
      v10 = *(unsigned __int8 *)(a1 + 6);
      if ( v10 <= v9 )
        break;
      v11 = &v5[4 * i * v10 + 4 * v9];
      __snprintf_chk(&v15, 25LL, 1LL, 25LL, "\x1B[38;2;%03d;%03d;%03dm%c\x1B[0m", *v11, v11[1], v11[2], v11[3]);
      v12 = v9++;
      v13 = *(_QWORD *)(a1 + 16) + 24LL * (((unsigned int)(v12 % v10) + i * v10) % *(_DWORD *)(a1 + 12));
      *(_OWORD *)v13 = v15;
      *(_QWORD *)(v13 + 16) = v16;
    }
  }
  return __readfsqword(0x28u) ^ v17;
}
```

```c title="/challenge/cimg :: handle_2()" showLineNumbers
unsigned __int64 __fastcall handle_2(__int64 a1)
{
  unsigned int v1; // ebx
  unsigned __int8 *v2; // rax
  unsigned __int8 *v3; // rbp
  __int64 v4; // rax
  __int64 v5; // rcx
  int i; // r13d
  int v7; // r14d
  int v8; // eax
  int v9; // ecx
  unsigned int v10; // ebx
  __int64 v11; // rdx
  unsigned __int8 v13; // [rsp+Bh] [rbp-5Dh] BYREF
  unsigned __int8 v14; // [rsp+Ch] [rbp-5Ch] BYREF
  unsigned __int8 v15; // [rsp+Dh] [rbp-5Bh] BYREF
  unsigned __int8 v16; // [rsp+Eh] [rbp-5Ah] BYREF
  __int128 v17; // [rsp+Fh] [rbp-59h] BYREF
  __int64 v18; // [rsp+1Fh] [rbp-49h]
  unsigned __int64 v19; // [rsp+28h] [rbp-40h]

  v19 = __readfsqword(0x28u);
  read_exact(0LL, &v15, 1LL, "ERROR: Failed to read &base_x!", 0xFFFFFFFFLL);
  read_exact(0LL, &v16, 1LL, "ERROR: Failed to read &base_y!", 0xFFFFFFFFLL);
  read_exact(0LL, &v13, 1LL, "ERROR: Failed to read &width!", 0xFFFFFFFFLL);
  read_exact(0LL, &v14, 1LL, "ERROR: Failed to read &height!", 0xFFFFFFFFLL);
  v1 = 4 * v14 * v13;
  v2 = (unsigned __int8 *)malloc(4LL * v14 * v13);
  if ( !v2 )
  {
    puts("ERROR: Failed to allocate memory for the image data!");
    goto LABEL_7;
  }
  v3 = v2;
  read_exact(0LL, v2, v1, "ERROR: Failed to read data!", 0xFFFFFFFFLL);
  v4 = 0LL;
  while ( v14 * v13 > (int)v4 )
  {
    v5 = v3[4 * v4++ + 3];
    if ( (unsigned __int8)(v5 - 32) > 0x5Eu )
    {
      __fprintf_chk(stderr, 1LL, "ERROR: Invalid character 0x%x in the image data!\n", v5);
LABEL_7:
      exit(-1);
    }
  }
  for ( i = 0; v14 > i; ++i )
  {
    v7 = 0;
    while ( v13 > v7 )
    {
      v8 = v7 + v15;
      v9 = v7 + i * v13;
      ++v7;
      v10 = v8 % *(unsigned __int8 *)(a1 + 6) + *(unsigned __int8 *)(a1 + 6) * (i + v16);
      __snprintf_chk(
        &v17,
        25LL,
        1LL,
        25LL,
        "\x1B[38;2;%03d;%03d;%03dm%c\x1B[0m",
        v3[4 * v9],
        v3[4 * v9 + 1],
        v3[4 * v9 + 2],
        v3[4 * v9 + 3]);
      v11 = *(_QWORD *)(a1 + 16) + 24LL * (v10 % *(_DWORD *)(a1 + 12));
      *(_OWORD *)v11 = v17;
      *(_QWORD *)(v11 + 16) = v18;
    }
  }
  return __readfsqword(0x28u) ^ v19;
}
```

```c title="/challenge/cimg :: handle_3()" showLineNumbers
unsigned __int64 __fastcall handle_3(__int64 a1)
{
  __int64 v2; // rax
  void *v3; // rdi
  int v4; // r12d
  unsigned __int8 *v5; // rax
  unsigned __int8 *v6; // rbx
  __int64 v7; // rax
  __int64 v8; // rcx
  unsigned __int8 v10; // [rsp+5h] [rbp-23h] BYREF
  unsigned __int8 v11; // [rsp+6h] [rbp-22h] BYREF
  unsigned __int8 v12; // [rsp+7h] [rbp-21h] BYREF
  unsigned __int64 v13; // [rsp+8h] [rbp-20h]

  v13 = __readfsqword(0x28u);
  read_exact(0LL, &v10, 1LL, "ERROR: Failed to read &sprite_id!", 0xFFFFFFFFLL);
  read_exact(0LL, &v11, 1LL, "ERROR: Failed to read &width!", 0xFFFFFFFFLL);
  read_exact(0LL, &v12, 1LL, "ERROR: Failed to read &height!", 0xFFFFFFFFLL);
  v2 = a1 + 16LL * v10;
  *(_BYTE *)(v2 + 25) = v11;
  v3 = *(void **)(v2 + 32);
  *(_BYTE *)(v2 + 24) = v12;
  if ( v3 )
    free(v3);
  v4 = v12 * v11;
  v5 = (unsigned __int8 *)malloc(v4);
  v6 = v5;
  if ( !v5 )
  {
    puts("ERROR: Failed to allocate memory for the image data!");
    goto LABEL_9;
  }
  read_exact(0LL, v5, (unsigned int)v4, "ERROR: Failed to read data!", 0xFFFFFFFFLL);
  v7 = 0LL;
  while ( v12 * v11 > (int)v7 )
  {
    v8 = v6[v7++];
    if ( (unsigned __int8)(v8 - 32) > 0x5Eu )
    {
      __fprintf_chk(stderr, 1LL, "ERROR: Invalid character 0x%x in the image data!\n", v8);
LABEL_9:
      exit(-1);
    }
  }
  *(_QWORD *)(16LL * v10 + a1 + 32) = v6;
  return __readfsqword(0x28u) ^ v13;
}
```

```c title="/challenge/cimg :: handle_4()" showLineNumbers
// positive sp value has been detected, the output may be wrong!
unsigned __int64 __fastcall handle_4(__int64 a1)
{
  _DWORD *v2; // rdi
  __int64 v3; // rcx
  __int64 v4; // rdx
  char v5; // r10
  char v6; // r11
  char v7; // bp
  __int64 v8; // rdx
  int v9; // r12d
  int v10; // r8d
  int v11; // edi
  __int64 v12; // rax
  __int64 v13; // r9
  int i; // r15d
  int j; // r10d
  int v16; // r11d
  __int64 v17; // rdx
  int v18; // r12d
  int v19; // ebp
  int k; // r13d
  int v21; // eax
  __int64 v22; // rax
  __int64 v23; // rdx
  int v24; // r14d
  __int64 v25; // rdx
  __int64 v26; // rdx
  int v28; // [rsp-40h] [rbp-40070h]
  int v29; // [rsp-3Ch] [rbp-4006Ch]
  _BYTE v30[9]; // [rsp-32h] [rbp-40062h] BYREF
  _BYTE v31[41]; // [rsp-29h] [rbp-40059h] BYREF
  char v32; // [rsp+0h] [rbp-40030h] BYREF
  __int64 v33; // [rsp+1000h] [rbp-3F030h] BYREF
  __int128 v34; // [rsp+3FFD7h] [rbp-59h] BYREF
  __int64 v35; // [rsp+3FFE7h] [rbp-49h]
  unsigned __int64 v36; // [rsp+3FFF0h] [rbp-40h]

  while ( &v32 != (char *)(&v33 - 0x8000) )
    ;
  v36 = __readfsqword(0x28u);
  read_exact(0LL, v30, 9LL, "ERROR: Failed to read &sprite_render_record!", 0xFFFFFFFFLL);
  v2 = v31;
  v3 = 0x10000LL;
  v4 = v30[0];
  v5 = v30[1];
  while ( v3 )
  {
    *v2++ = 0;
    --v3;
  }
  v6 = v30[2];
  v7 = v30[3];
  v8 = a1 + 16 * v4;
  v9 = *(unsigned __int8 *)(v8 + 24);
  while ( v9 > (int)v3 )
  {
    v10 = *(unsigned __int8 *)(v8 + 25);
    v11 = 0;
    v12 = (unsigned int)(v3 * v10);
    while ( v10 > v11 )
    {
      v13 = *(_QWORD *)(v8 + 32);
      v31[4 * v12] = v5;
      v31[4 * v12 + 1] = v6;
      v31[4 * v12 + 2] = v7;
      if ( !v13 )
      {
        fputs("ERROR: attempted to render uninitialized sprite!\n", stderr);
        exit(-1);
      }
      ++v11;
      v31[4 * v12 + 3] = *(_BYTE *)(v13 + v12);
      ++v12;
    }
    LODWORD(v3) = v3 + 1;
  }
  for ( i = 0; v30[7] > i; ++i )
  {
    for ( j = 0; v30[6] > j; ++j )
    {
      v16 = 0;
      v17 = a1 + 16LL * v30[0];
      v18 = (unsigned __int8)(v30[4] + j * *(_BYTE *)(v17 + 25));
      v19 = (unsigned __int8)(v30[5] + i * *(_BYTE *)(v17 + 24));
      while ( *(unsigned __int8 *)(16LL * v30[0] + a1 + 24) > v16 )
      {
        for ( k = 0; ; ++k )
        {
          v21 = *(unsigned __int8 *)(16LL * v30[0] + a1 + 25);
          if ( v21 <= k )
            break;
          v22 = k + v16 * v21;
          v23 = (unsigned __int8)v31[4 * v22 + 3];
          if ( (_BYTE)v23 != v30[8] )
          {
            v29 = v16;
            v24 = *(unsigned __int8 *)(a1 + 6);
            v28 = j;
            __snprintf_chk(
              &v34,
              25LL,
              1LL,
              25LL,
              "\x1B[38;2;%03d;%03d;%03dm%c\x1B[0m",
              (unsigned __int8)v31[4 * v22],
              (unsigned __int8)v31[4 * v22 + 1],
              (unsigned __int8)v31[4 * v22 + 2],
              v23);
            v16 = v29;
            j = v28;
            v25 = (unsigned int)((k + v18) % v24);
            LODWORD(v25) = (unsigned int)(v25 + v19 * v24) % *(_DWORD *)(a1 + 12);
            v26 = *(_QWORD *)(a1 + 16) + 24 * v25;
            *(_OWORD *)v26 = v34;
            *(_QWORD *)(v26 + 16) = v35;
          }
        }
        ++v16;
        ++v19;
      }
    }
  }
  return __readfsqword(0x28u) ^ v36;
}
```

```c title="/challenge/cimg :: handle_5()" showLineNumbers
unsigned __int64 __fastcall handle_5(__int64 a1)
{
  __int16 v2; // dx
  int v3; // eax
  unsigned int v4; // ebp
  void *v5; // rdi
  int v6; // r13d
  unsigned __int8 *v7; // rax
  unsigned __int8 *v8; // rbx
  __int64 v9; // rax
  __int64 v10; // rcx
  char v12[259]; // [rsp+5h] [rbp-133h] BYREF
  unsigned __int64 v13; // [rsp+108h] [rbp-30h]

  v13 = __readfsqword(0x28u);
  memset(v12, 0, sizeof(v12));
  read_exact(0LL, v12, 258LL, "ERROR: Failed to read &sprite_load_record!", 0xFFFFFFFFLL);
  LOBYTE(v2) = v12[2];
  HIBYTE(v2) = v12[1];
  *(_WORD *)(a1 + 16LL * (unsigned __int8)v12[0] + 24) = v2;
  v3 = open(&v12[3], 0);
  if ( v3 < 0 )
  {
    fputs("ERROR: failed to open sprite file\n", stderr);
    goto LABEL_7;
  }
  v4 = v3;
  v5 = *(void **)(16LL * (unsigned __int8)v12[0] + a1 + 32);
  if ( v5 )
    free(v5);
  v6 = (unsigned __int8)v12[2] * (unsigned __int8)v12[1];
  v7 = (unsigned __int8 *)malloc(v6);
  v8 = v7;
  if ( !v7 )
  {
    puts("ERROR: Failed to allocate memory for the image data!");
    goto LABEL_7;
  }
  read_exact(v4, v7, (unsigned int)v6, "ERROR: Failed to read data!", 0xFFFFFFFFLL);
  v9 = 0LL;
  while ( (unsigned __int8)v12[2] * (unsigned __int8)v12[1] > (int)v9 )
  {
    v10 = v8[v9++];
    if ( (unsigned __int8)(v10 - 32) > 0x5Eu )
    {
      __fprintf_chk(stderr, 1LL, "ERROR: Invalid character 0x%x in the image data!\n", v10);
LABEL_7:
      exit(-1);
    }
  }
  *(_QWORD *)(16LL * (unsigned __int8)v12[0] + a1 + 32) = v8;
  close(v4);
  return __readfsqword(0x28u) ^ v13;
}
```

### Exploit

```py
from pwn import *
import struct

MAGIC   = 0x474D4963  # "cIMG"
VERSION = 4
FB_W, FB_H = 80, 80   # tall framebuffer so nothing clips

SPRITE_ID = 0
FLAG_PATH = b"/flag\x00"

# Read enough bytes to cover full flag
SPRITE_W = 1          # ONE column
SPRITE_H = 59         # read 48 bytes vertically

def directive_5(sprite_id, w, h, path):
    # [sprite_id][height][width]
    rec  = bytes([sprite_id, h, w])
    rec += path.ljust(255, b"\x00")
    return struct.pack("<H", 5) + rec

def directive_4(sprite_id, x, y):
    return struct.pack(
        "<HBBBBBBBBB",
        4,
        sprite_id,
        255, 255, 255,
        x, y,
        1, 1,          # NO repetition
        0
    )

directives = [
    directive_5(SPRITE_ID, SPRITE_W, SPRITE_H, FLAG_PATH),
    directive_4(SPRITE_ID, 0, 0),
]

header = struct.pack(
    "<I H B B I",
    MAGIC,
    VERSION,
    FB_W,
    FB_H,
    len(directives)
)

payload = header + b"".join(directives)

with open("solution.cimg", "wb") as f:
    f.write(payload)

print("[+] Run: /challenge/cimg solution.cimg")
```

```
hacker@reverse-engineering~accessing-resources:~$ /challenge/cimg ~/solution.cimg
pwn.college{cl4-LleAt4eMVhiMpLcaDyn4RBc.QX0EzMwEDL4ITM0EzW}
```

&nbsp;

## Unsafe Animations

### Binary Analysis

```c title="/challenge/cimg :: main()" showLineNumbers
int __fastcall main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rcx
  int *v5; // rdi
  bool v6; // of
  int v7; // r8d
  const char *v8; // r12
  int v9; // eax
  const char *v10; // rdi
  unsigned __int16 v13; // [rsp+Eh] [rbp-103Ah] BYREF
  int v14; // [rsp+10h] [rbp-1038h] BYREF
  __int16 v15; // [rsp+14h] [rbp-1034h]
  int v16; // [rsp+18h] [rbp-1030h]
  unsigned __int64 v17; // [rsp+1028h] [rbp-20h]

  v3 = 1030LL;
  v17 = __readfsqword(0x28u);
  v5 = &v14;
  v6 = __OFSUB__(argc, 1);
  v7 = argc - 1;
  while ( v3 )
  {
    *v5++ = 0;
    --v3;
  }
  if ( !((v7 < 0) ^ v6 | (v7 == 0)) )
  {
    v8 = argv[1];
    if ( strcmp(&v8[strlen(v8) - 5], ".cimg") )
    {
      __printf_chk(1LL, "ERROR: Invalid file extension!");
      goto LABEL_11;
    }
    v9 = open(v8, 0);
    dup2(v9, 0);
  }
  read_exact(0LL, &v14, 12LL, "ERROR: Failed to read header!", 0xFFFFFFFFLL);
  if ( v14 != 1196247395 )
  {
    v10 = "ERROR: Invalid magic number!";
LABEL_10:
    puts(v10);
LABEL_11:
    exit(-1);
  }
  v10 = "ERROR: Unsupported version!";
  if ( v15 != 4 )
    goto LABEL_10;
  initialize_framebuffer(&v14);
  while ( 2 )
  {
    if ( v16-- )
    {
      read_exact(0LL, &v13, 2LL, "ERROR: Failed to read &directive_code!", 0xFFFFFFFFLL);
      switch ( v13 )
      {
        case 1u:
          handle_1(&v14);
          continue;
        case 2u:
          handle_2(&v14);
          continue;
        case 3u:
          handle_3(&v14);
          continue;
        case 4u:
          handle_4(&v14);
          continue;
        case 5u:
          handle_5(&v14);
          continue;
        case 6u:
          handle_6(&v14);
          continue;
        case 7u:
          handle_7(&v14);
          continue;
        default:
          __fprintf_chk(stderr, 1LL, "ERROR: invalid directive_code %ux\n", v13);
          goto LABEL_11;
      }
    }
    break;
  }
  display(&v14, 0LL);
  return 0;
}
```

```c title="/challenge/cimg :: handle_1()" showLineNumbers
unsigned __int64 __fastcall handle_1(__int64 a1)
{
  int v1; // ebp
  int v2; // edx
  size_t v3; // rbp
  unsigned __int8 *v4; // rax
  unsigned __int8 *v5; // r12
  __int64 v6; // rax
  __int64 v7; // rcx
  int i; // r13d
  int v9; // ebp
  int v10; // r15d
  unsigned __int8 *v11; // rax
  __int64 v12; // kr00_8
  __int64 v13; // rdx
  __int128 v15; // [rsp+1Fh] [rbp-59h] BYREF
  __int64 v16; // [rsp+2Fh] [rbp-49h]
  unsigned __int64 v17; // [rsp+38h] [rbp-40h]

  v1 = *(unsigned __int8 *)(a1 + 6);
  v2 = *(unsigned __int8 *)(a1 + 7);
  v17 = __readfsqword(0x28u);
  v3 = 4LL * v2 * v1;
  v4 = (unsigned __int8 *)malloc(v3);
  if ( !v4 )
  {
    puts("ERROR: Failed to allocate memory for the image data!");
    goto LABEL_7;
  }
  v5 = v4;
  read_exact(0LL, v4, (unsigned int)v3, "ERROR: Failed to read data!", 0xFFFFFFFFLL);
  v6 = 0LL;
  while ( *(unsigned __int8 *)(a1 + 7) * *(unsigned __int8 *)(a1 + 6) > (int)v6 )
  {
    v7 = v5[4 * v6++ + 3];
    if ( (unsigned __int8)(v7 - 32) > 0x5Eu )
    {
      __fprintf_chk(stderr, 1LL, "ERROR: Invalid character 0x%x in the image data!\n", v7);
LABEL_7:
      exit(-1);
    }
  }
  for ( i = 0; *(unsigned __int8 *)(a1 + 7) > i; ++i )
  {
    v9 = 0;
    while ( 1 )
    {
      v10 = *(unsigned __int8 *)(a1 + 6);
      if ( v10 <= v9 )
        break;
      v11 = &v5[4 * i * v10 + 4 * v9];
      __snprintf_chk(&v15, 25LL, 1LL, 25LL, "\x1B[38;2;%03d;%03d;%03dm%c\x1B[0m", *v11, v11[1], v11[2], v11[3]);
      v12 = v9++;
      v13 = *(_QWORD *)(a1 + 16) + 24LL * (((unsigned int)(v12 % v10) + i * v10) % *(_DWORD *)(a1 + 12));
      *(_OWORD *)v13 = v15;
      *(_QWORD *)(v13 + 16) = v16;
    }
  }
  return __readfsqword(0x28u) ^ v17;
}
```

```c title="/challenge/cimg :: handle_2()" showLineNumbers
unsigned __int64 __fastcall handle_2(__int64 a1)
{
  unsigned int v1; // ebx
  unsigned __int8 *v2; // rax
  unsigned __int8 *v3; // rbp
  __int64 v4; // rax
  __int64 v5; // rcx
  int i; // r13d
  int v7; // r14d
  int v8; // eax
  int v9; // ecx
  unsigned int v10; // ebx
  __int64 v11; // rdx
  unsigned __int8 v13; // [rsp+Bh] [rbp-5Dh] BYREF
  unsigned __int8 v14; // [rsp+Ch] [rbp-5Ch] BYREF
  unsigned __int8 v15; // [rsp+Dh] [rbp-5Bh] BYREF
  unsigned __int8 v16; // [rsp+Eh] [rbp-5Ah] BYREF
  __int128 v17; // [rsp+Fh] [rbp-59h] BYREF
  __int64 v18; // [rsp+1Fh] [rbp-49h]
  unsigned __int64 v19; // [rsp+28h] [rbp-40h]

  v19 = __readfsqword(0x28u);
  read_exact(0LL, &v15, 1LL, "ERROR: Failed to read &base_x!", 0xFFFFFFFFLL);
  read_exact(0LL, &v16, 1LL, "ERROR: Failed to read &base_y!", 0xFFFFFFFFLL);
  read_exact(0LL, &v13, 1LL, "ERROR: Failed to read &width!", 0xFFFFFFFFLL);
  read_exact(0LL, &v14, 1LL, "ERROR: Failed to read &height!", 0xFFFFFFFFLL);
  v1 = 4 * v14 * v13;
  v2 = (unsigned __int8 *)malloc(4LL * v14 * v13);
  if ( !v2 )
  {
    puts("ERROR: Failed to allocate memory for the image data!");
    goto LABEL_7;
  }
  v3 = v2;
  read_exact(0LL, v2, v1, "ERROR: Failed to read data!", 0xFFFFFFFFLL);
  v4 = 0LL;
  while ( v14 * v13 > (int)v4 )
  {
    v5 = v3[4 * v4++ + 3];
    if ( (unsigned __int8)(v5 - 32) > 0x5Eu )
    {
      __fprintf_chk(stderr, 1LL, "ERROR: Invalid character 0x%x in the image data!\n", v5);
LABEL_7:
      exit(-1);
    }
  }
  for ( i = 0; v14 > i; ++i )
  {
    v7 = 0;
    while ( v13 > v7 )
    {
      v8 = v7 + v15;
      v9 = v7 + i * v13;
      ++v7;
      v10 = v8 % *(unsigned __int8 *)(a1 + 6) + *(unsigned __int8 *)(a1 + 6) * (i + v16);
      __snprintf_chk(
        &v17,
        25LL,
        1LL,
        25LL,
        "\x1B[38;2;%03d;%03d;%03dm%c\x1B[0m",
        v3[4 * v9],
        v3[4 * v9 + 1],
        v3[4 * v9 + 2],
        v3[4 * v9 + 3]);
      v11 = *(_QWORD *)(a1 + 16) + 24LL * (v10 % *(_DWORD *)(a1 + 12));
      *(_OWORD *)v11 = v17;
      *(_QWORD *)(v11 + 16) = v18;
    }
  }
  return __readfsqword(0x28u) ^ v19;
}
```

```c title="/challenge/cimg :: handle_3()" showLineNumbers
unsigned __int64 __fastcall handle_3(__int64 a1)
{
  __int64 v2; // rax
  void *v3; // rdi
  int v4; // r12d
  unsigned __int8 *v5; // rax
  unsigned __int8 *v6; // rbx
  __int64 v7; // rax
  __int64 v8; // rcx
  unsigned __int8 v10; // [rsp+5h] [rbp-23h] BYREF
  unsigned __int8 v11; // [rsp+6h] [rbp-22h] BYREF
  unsigned __int8 v12; // [rsp+7h] [rbp-21h] BYREF
  unsigned __int64 v13; // [rsp+8h] [rbp-20h]

  v13 = __readfsqword(0x28u);
  read_exact(0LL, &v10, 1LL, "ERROR: Failed to read &sprite_id!", 0xFFFFFFFFLL);
  read_exact(0LL, &v11, 1LL, "ERROR: Failed to read &width!", 0xFFFFFFFFLL);
  read_exact(0LL, &v12, 1LL, "ERROR: Failed to read &height!", 0xFFFFFFFFLL);
  v2 = a1 + 16LL * v10;
  *(_BYTE *)(v2 + 25) = v11;
  v3 = *(void **)(v2 + 32);
  *(_BYTE *)(v2 + 24) = v12;
  if ( v3 )
    free(v3);
  v4 = v12 * v11;
  v5 = (unsigned __int8 *)malloc(v4);
  v6 = v5;
  if ( !v5 )
  {
    puts("ERROR: Failed to allocate memory for the image data!");
    goto LABEL_9;
  }
  read_exact(0LL, v5, (unsigned int)v4, "ERROR: Failed to read data!", 0xFFFFFFFFLL);
  v7 = 0LL;
  while ( v12 * v11 > (int)v7 )
  {
    v8 = v6[v7++];
    if ( (unsigned __int8)(v8 - 32) > 0x5Eu )
    {
      __fprintf_chk(stderr, 1LL, "ERROR: Invalid character 0x%x in the image data!\n", v8);
LABEL_9:
      exit(-1);
    }
  }
  *(_QWORD *)(16LL * v10 + a1 + 32) = v6;
  return __readfsqword(0x28u) ^ v13;
}
```

```c title="/challenge/cimg :: handle_4()" showLineNumbers
// positive sp value has been detected, the output may be wrong!
unsigned __int64 __fastcall handle_4(__int64 a1)
{
  _DWORD *v2; // rdi
  __int64 v3; // rcx
  __int64 v4; // rdx
  char v5; // r10
  char v6; // r11
  char v7; // bp
  __int64 v8; // rdx
  int v9; // r12d
  int v10; // r8d
  int v11; // edi
  __int64 v12; // rax
  __int64 v13; // r9
  int i; // r15d
  int j; // r10d
  int v16; // r11d
  __int64 v17; // rdx
  int v18; // r12d
  int v19; // ebp
  int k; // r13d
  int v21; // eax
  __int64 v22; // rax
  __int64 v23; // rdx
  int v24; // r14d
  __int64 v25; // rdx
  __int64 v26; // rdx
  int v28; // [rsp-40h] [rbp-40070h]
  int v29; // [rsp-3Ch] [rbp-4006Ch]
  _BYTE v30[9]; // [rsp-32h] [rbp-40062h] BYREF
  _BYTE v31[41]; // [rsp-29h] [rbp-40059h] BYREF
  char v32; // [rsp+0h] [rbp-40030h] BYREF
  __int64 v33; // [rsp+1000h] [rbp-3F030h] BYREF
  __int128 v34; // [rsp+3FFD7h] [rbp-59h] BYREF
  __int64 v35; // [rsp+3FFE7h] [rbp-49h]
  unsigned __int64 v36; // [rsp+3FFF0h] [rbp-40h]

  while ( &v32 != (char *)(&v33 - 0x8000) )
    ;
  v36 = __readfsqword(0x28u);
  read_exact(0LL, v30, 9LL, "ERROR: Failed to read &sprite_render_record!", 0xFFFFFFFFLL);
  v2 = v31;
  v3 = 0x10000LL;
  v4 = v30[0];
  v5 = v30[1];
  while ( v3 )
  {
    *v2++ = 0;
    --v3;
  }
  v6 = v30[2];
  v7 = v30[3];
  v8 = a1 + 16 * v4;
  v9 = *(unsigned __int8 *)(v8 + 24);
  while ( v9 > (int)v3 )
  {
    v10 = *(unsigned __int8 *)(v8 + 25);
    v11 = 0;
    v12 = (unsigned int)(v3 * v10);
    while ( v10 > v11 )
    {
      v13 = *(_QWORD *)(v8 + 32);
      v31[4 * v12] = v5;
      v31[4 * v12 + 1] = v6;
      v31[4 * v12 + 2] = v7;
      if ( !v13 )
      {
        fputs("ERROR: attempted to render uninitialized sprite!\n", stderr);
        exit(-1);
      }
      ++v11;
      v31[4 * v12 + 3] = *(_BYTE *)(v13 + v12);
      ++v12;
    }
    LODWORD(v3) = v3 + 1;
  }
  for ( i = 0; v30[7] > i; ++i )
  {
    for ( j = 0; v30[6] > j; ++j )
    {
      v16 = 0;
      v17 = a1 + 16LL * v30[0];
      v18 = (unsigned __int8)(v30[4] + j * *(_BYTE *)(v17 + 25));
      v19 = (unsigned __int8)(v30[5] + i * *(_BYTE *)(v17 + 24));
      while ( *(unsigned __int8 *)(16LL * v30[0] + a1 + 24) > v16 )
      {
        for ( k = 0; ; ++k )
        {
          v21 = *(unsigned __int8 *)(16LL * v30[0] + a1 + 25);
          if ( v21 <= k )
            break;
          v22 = k + v16 * v21;
          v23 = (unsigned __int8)v31[4 * v22 + 3];
          if ( (_BYTE)v23 != v30[8] )
          {
            v29 = v16;
            v24 = *(unsigned __int8 *)(a1 + 6);
            v28 = j;
            __snprintf_chk(
              &v34,
              25LL,
              1LL,
              25LL,
              "\x1B[38;2;%03d;%03d;%03dm%c\x1B[0m",
              (unsigned __int8)v31[4 * v22],
              (unsigned __int8)v31[4 * v22 + 1],
              (unsigned __int8)v31[4 * v22 + 2],
              v23);
            v16 = v29;
            j = v28;
            v25 = (unsigned int)((k + v18) % v24);
            LODWORD(v25) = (unsigned int)(v25 + v19 * v24) % *(_DWORD *)(a1 + 12);
            v26 = *(_QWORD *)(a1 + 16) + 24 * v25;
            *(_OWORD *)v26 = v34;
            *(_QWORD *)(v26 + 16) = v35;
          }
        }
        ++v16;
        ++v19;
      }
    }
  }
  return __readfsqword(0x28u) ^ v36;
}
```

```c title="/challenge/cimg :: handle_5()" showLineNumbers
unsigned __int64 __fastcall handle_5(__int64 a1)
{
  __int16 v2; // dx
  int v3; // eax
  FILE *v4; // rsi
  const char *v5; // rdi
  unsigned int v6; // ebp
  void *v7; // rdi
  int v8; // r13d
  const char *v9; // rax
  const char *v10; // rbx
  __int64 v11; // rax
  __int64 v12; // rcx
  char v14[259]; // [rsp+5h] [rbp-133h] BYREF
  unsigned __int64 v15; // [rsp+108h] [rbp-30h]

  v15 = __readfsqword(0x28u);
  memset(v14, 0, sizeof(v14));
  read_exact(0LL, v14, 258LL, "ERROR: Failed to read &sprite_load_record!", 0xFFFFFFFFLL);
  LOBYTE(v2) = v14[2];
  HIBYTE(v2) = v14[1];
  *(_WORD *)(a1 + 16LL * (unsigned __int8)v14[0] + 24) = v2;
  v3 = open(&v14[3], 0);
  v4 = stderr;
  v5 = "ERROR: failed to open sprite file\n";
  if ( v3 < 0 )
    goto LABEL_13;
  v6 = v3;
  v7 = *(void **)(16LL * (unsigned __int8)v14[0] + a1 + 32);
  if ( v7 )
    free(v7);
  v8 = (unsigned __int8)v14[2] * (unsigned __int8)v14[1];
  v9 = (const char *)malloc(v8);
  v10 = v9;
  if ( !v9 )
  {
    puts("ERROR: Failed to allocate memory for the image data!");
    goto LABEL_6;
  }
  read_exact(v6, v9, (unsigned int)v8, "ERROR: Failed to read data!", 0xFFFFFFFFLL);
  v11 = 0LL;
  while ( (unsigned __int8)v14[2] * (unsigned __int8)v14[1] > (int)v11 )
  {
    v12 = (unsigned __int8)v10[v11++];
    if ( (unsigned __int8)(v12 - 32) > 0x5Eu )
    {
      __fprintf_chk(stderr, 1LL, "ERROR: Invalid character 0x%x in the image data!\n", v12);
      goto LABEL_6;
    }
  }
  if ( !strncmp(v10, "pwn.college{", 0xCuLL) )
  {
    v4 = stderr;
    v5 = "ERROR: shenanigans detected!!!!!";
LABEL_13:
    fputs(v5, v4);
LABEL_6:
    exit(-1);
  }
  *(_QWORD *)(16LL * (unsigned __int8)v14[0] + a1 + 32) = v10;
  close(v6);
  return __readfsqword(0x28u) ^ v15;
}
```

```c title="/challenge/cimg :: handle_6()" showLineNumbers
unsigned __int64 __fastcall handle_6(__int64 a1)
{
  __uid_t v1; // eax
  char v3; // [rsp+7h] [rbp-11h] BYREF
  unsigned __int64 v4; // [rsp+8h] [rbp-10h]

  v4 = __readfsqword(0x28u);
  read_exact(0LL, &v3, 1LL, "ERROR: Failed to read &clear!", 0xFFFFFFFFLL);
  v1 = geteuid();
  setuid(v1);
  system("clear");
  display(a1, 0LL);
  return __readfsqword(0x28u) ^ v4;
}
```

```c title="/challenge/cimg :: handle_7()" showLineNumbers
unsigned __int64 handle_7()
{
  unsigned int v1; // [rsp+4h] [rbp-24h] BYREF
  struct timespec requested_time; // [rsp+8h] [rbp-20h] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-10h]

  v3 = __readfsqword(0x28u);
  read_exact(0LL, &v1, 4LL, "ERROR: Failed to read &milliseconds!", 0xFFFFFFFFLL);
  requested_time.tv_sec = v1 / 0x3E8;
  requested_time.tv_nsec = 1000000 * (v1 % 0x3E8);
  nanosleep(&requested_time, 0LL);
  return __readfsqword(0x28u) ^ v3;
}
```

### Exploit

```py
from pwn import *
import struct

# MAGIC = 0x47494D43 (1196247395)
# VERSION = 4
# WIDTH = 100 (Offset 6)
# HEIGHT = 100 (Offset 7)
# NUM_INST = 2 (Offset 8)

# We construct the 12-byte header exactly as main() reads it.
# Offset: 0 1 2 3 | 4 5 | 6 | 7 | 8 9 10 11
# Data  : MAGIC   | VER | W | H | NUM_INST
header = struct.pack("<I H B B I", 
    1196247395, # Magic (4 bytes)
    4,          # Version (2 bytes)
    100,        # Width (1 byte)
    100,        # Height (1 byte)
    2           # Num Instructions (4 bytes)
)

def directive_5(sprite_id, w, h, path):
    # struct v12 layout in handle_5:
    # [0]=id, [1]=h, [2]=w, [3...]=path
    # To bypass strncmp(..., 12), total read (w*h) must be < 12.
    rec = struct.pack("<BBB", sprite_id, h, w)
    rec += path.ljust(255, b"\x00")
    return struct.pack("<H", 5) + rec

def directive_4(sprite_id, x, y):
    # [id, R, G, B, x, y, rep_x, rep_y, transp]
    rec = struct.pack("<BBBBBBBBB", sprite_id, 255, 255, 255, x, y, 1, 1, 0)
    return struct.pack("<H", 4) + rec

# Build payload
# After the 12-byte header, the next read is the 2-byte directive code.
payload = (
    header + 
    directive_5(0, 11, 1, b"/flag") + # Load 11 bytes to bypass check
    directive_4(0, 0, 0)              # Render the bypassed data
)

with open("solution.cimg", "wb") as f:
    f.write(payload)

print("[+] Final Payload generated. No extra padding, correct offsets.")
```
