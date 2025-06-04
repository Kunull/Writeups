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
- File ends with the `.cimg` extension.
- File has the magic number `CMge`.

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
- File ends with the `.cimg` extension.
- File has the magic number `cn~R`.

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

### Decompilation

Let's decompile it using [Binary Ninja Cloud](https://cloud.binary.ninja/).

#### `main()`

![image](https://github.com/user-attachments/assets/566b6ae6-e0dc-4e4f-9cac-24950f07a701)

The challenge performs the following checks:
- File ends with the `.cimg` extension.
- File has the magic number `0x287e6d36` which is `(~m6` in ASCII.

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
- File ends with the `.cimg` extension.
- File has the magic number `0x474D215B`, which is `GM![` in ASCII. However, it also checks whether the first four bytes are in little-endian format.

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

This is happening because Bash uses `!` for history expansion. So Bash tries to expand.`!MG` as a previous command, but can't find one.
We can easily get around this by using single quotes (`'`)/

```
hacker@reverse-engineering~reading-endianness-python:/$ echo '[!MG' > ~/solution.cimg
```

```
hacker@reverse-engineering~reading-endianness-python:/$ /challenge/cimg ~/solution.cimg
pwn.college{UeceXp6n13KASFhim5T8GOhpq63.QX3ATN2EDL4ITM0EzW}
```
