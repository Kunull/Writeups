---
custom_edit_url: null
sidebar_position: 5
---

## File Formats: Magic Numbers (Python)


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

## File Formats: magic Numbers (x86)

```
hacker@reverse-engineering~file-formats-magic-numbers-x86:/$ file /challenge/cimg 
/challenge/cimg: setuid ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=47edd63950d3f7b9b5c95bf4c93080ff12b75711, for GNU/Linux 3.2.0, not stripped
```

This time the code is a binary executable in little endian format.

Let's decompile it using [Binary Ninja Cloud](https://cloud.binary.ninja/).

### Decompilation

#### `main()`

![image](https://github.com/user-attachments/assets/3521b5de-c1d3-437d-9198-f8d1e3cba764)

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
    - Magic number (4 bytes): Must be `0x474D215B`, which is ASCII `GM![` in little-endian

```python
>>> bytearray.fromhex("474D215B").decode()
'GM!['
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
We can easily get around this by using single quotes (`'`)/

```
hacker@reverse-engineering~reading-endianness-python:/$ echo '[!MG' > ~/solution.cimg
```

```
hacker@reverse-engineering~reading-endianness-python:/$ /challenge/cimg ~/solution.cimg
pwn.college{UeceXp6n13KASFhim5T8GOhpq63.QX3ATN2EDL4ITM0EzW}
```

&nbsp;

## Reading Endianness (C)

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
    - Magic number (4 bytes): Must be `1733109083`, which is ASCII `gM%[` in little-endian

```python
>>> print('{0:x}'.format(1733109083))
674d255b
>>> bytearray.fromhex("674d255b").decode()
'gM%['
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

![image](https://github.com/user-attachments/assets/89b4ee75-a998-4673-b449-5d947415bb00)

- File Extension: Must end with `.cimg`
- Header (4 bytes total):
    - Magic number (4 bytes): Must be `0x72254f3c`, which is ASCII `<0%r` in little-endian

```python
>>> bytearray.fromhex("72254f3c").decode()
'r%O<'
```

The same concept of endianness applies here.

```
hacker@reverse-engineering~reading-endianness-c:/$ echo '<0%r' > ~/solution.cimg
```

```
hacker@reverse-engineering~reading-endianness-x86:/$ /challenge/cimg ~/solution.cimg
pwn.college{Et6nh45-ta1HCaJmdwJf5eDGBdd.QXxAzMwEDL4ITM0EzW}
```

&nbsp;

## Version Information (Python)

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
magic = b"<0%R"                  # 4 bytes
version = struct.pack("<I", 11)  # 4 bytes 

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

```c title="/challenge/cimg.c"
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

![image](https://github.com/user-attachments/assets/38fb9dd4-0572-4468-8c0b-d5639826695e)

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
    - Must be exactly `59 × 21 = 1239` bytes

```python title="~/script.py" showLineNumbers
import struct

# Build the header (20 bytes total)
magic = b"CMgE"                 # 4 bytes
version = struct.pack("<H", 1)  # 8 bytes 
width = struct.pack("<H", 59)   # 4 bytes 
height = struct.pack("<H", 21)  # 4 bytes

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
Wrote 1249 bytes: b'CMgE\x01\x00;\x00\x15\x00.......................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................' to file: '/home/hacker/solution.cimg'
```

```
hacker@reverse-engineering~metadata-and-data-python:/$ /challenge/cimg ~/solution.cimg 
pwn.college{gmcsTJSAE9Fvci5d7be0NM7T0Af.QXxETN2EDL4ITM0EzW}
```

&nbsp;

## Metadata and Data (C)

```c title="/challenge/cimg.c"
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
    - Must be exactly `66 × 17 = 1122` bytes

```python title="~/script.py" showLineNumbers
import struct

# Build the header (10 bytes total)
magic = b"CNmG"                 # 4 bytes
version = struct.pack("<H", 1)  # 2 bytes
width = struct.pack("<H", 66)   # 2 bytes 
height = struct.pack("<H", 17)  # 2 bytes 

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

![image](https://github.com/user-attachments/assets/d2c306ff-3b97-400a-9521-1a81000944f6)

The challenge performs the following checks:
- File Extension: Must end with `.cimg`
- Header (14 bytes total):
    - Magic number (4 bytes): Must be `0x284e6e72`
    - Version (2 bytes): Must be `1` in little-endian
    - Width (4 bytes): Must be `0x40` (`64`) in little-endian
    - Height (4 bytes): Must be `0xc` (`12`) in little-endian
- Pixel Data:
    - Must be exactly `66 × 17 = 1122` bytes

```python title="~/script.py" showLineNumbers
import struct

# Build the header (14 bytes total)
magic = bytes.fromhex("284e6e72")  # 4 bytes
version = struct.pack("<H", 1)     # 2 bytes
width = struct.pack("<I", 0x40)      # 4 bytes 
height = struct.pack("<I", 0xc)     # 4 bytes 

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
