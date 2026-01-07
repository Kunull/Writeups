---
custom_edit_url: null
sidebar_position: 2
slug: /pwn-college/program-security/reverse-engineering
---

## Terrible Token (Easy)

Let's provide an input which we can easily spot such as `abcde`.

```
hacker@reverse-engineering~terrible-token-easy:/$ /challenge/terrible-token-easy 
###
### Welcome to /challenge/terrible-token-easy!
###

This license verifier software will allow you to read the flag. However, before you can do so, you must verify that you
are licensed to read flag files! This program consumes a license key over stdin. Each program may perform entirely
different operations on that input! You must figure out (by reverse engineering this program) what that license key is.
Providing the correct license key will net you the flag!

Ready to receive your license key!

abcde
Initial input:

        61 62 63 64 65 

The mangling is done! The resulting bytes will be used for the final comparison.

Final result of mangling input:

        61 62 63 64 65 

Expected result:

        6b 77 6c 70 67 

Checking the received license key!

Wrong! No flag for you!
```

```py title="~/script.py" showLineNumbers
hex_string = "6b776c7067" 
ascii_string = bytes.fromhex(hex_string).decode('ascii')
print(ascii_string)
```

```
hacker@reverse-engineering~terrible-token-easy:/$ python ~/script.py 
kwlpg
```

Since there is no mangling performed we can just input `kwlpg` which is the ASCII representation of the expected input.

```
hacker@reverse-engineering~terrible-token-easy:~$ /challenge/terrible-token-easy 
###
### Welcome to /challenge/terrible-token-easy!
###

This license verifier software will allow you to read the flag. However, before you can do so, you must verify that you
are licensed to read flag files! This program consumes a license key over stdin. Each program may perform entirely
different operations on that input! You must figure out (by reverse engineering this program) what that license key is.
Providing the correct license key will net you the flag!

Ready to receive your license key!

kwlpg
Initial input:

        6b 77 6c 70 67 

The mangling is done! The resulting bytes will be used for the final comparison.

Final result of mangling input:

        6b 77 6c 70 67 

Expected result:

        6b 77 6c 70 67 

Checking the received license key!

You win! Here is your flag:
pwn.college{gIx0gHwBB1snl_xHLkQI8Grmugg.0VM1IDL4ITM0EzW}
```

&nbsp;

## Terrible Token (Hard)

### `main()`

<img alt="image" src="https://github.com/user-attachments/assets/8c39503b-9edc-42e8-8c7e-ca8134217e85" />

```c showLineNumber
void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  int buf; // [rsp+22h] [rbp-Eh] BYREF
  __int16 v4; // [rsp+26h] [rbp-Ah]
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  puts("###");
  printf("### Welcome to %s!\n", *a2);
  puts("###");
  putchar(10);
  puts(
    "This license verifier software will allow you to read the flag. However, before you can do so, you must verify that you");
  puts("are licensed to read flag files! This program consumes a license key over stdin. Each program may perform entirely");
  puts(
    "different operations on that input! You must figure out (by reverse engineering this program) what that license key is.");
  puts("Providing the correct license key will net you the flag!\n");
  buf = 0;
  v4 = 0;
  puts("Ready to receive your license key!\n");
  read(0, &buf, 5uLL);
  puts("Checking the received license key!\n");
  if ( !memcmp(&buf, str_Wlyie, 5uLL) )
  {
    sub_12A9();
    exit(0);
  }
  puts("Wrong! No flag for you!");
  exit(1);
}
```

Let's see what the `str_Wlyie` variable references, even though we can kind of make a guess.

<img alt="image" src="https://github.com/user-attachments/assets/b7843599-5d1a-4ebd-9be2-ccbae95934b7" />

So the expected input is `wlyie`

```
hacker@reverse-engineering~terrible-token-hard:~$ /challenge/terrible-token-hard 
###
### Welcome to /challenge/terrible-token-hard!
###

This license verifier software will allow you to read the flag. However, before you can do so, you must verify that you
are licensed to read flag files! This program consumes a license key over stdin. Each program may perform entirely
different operations on that input! You must figure out (by reverse engineering this program) what that license key is.
Providing the correct license key will net you the flag!

Ready to receive your license key!

wlyie
Checking the received license key!

You win! Here is your flag:
pwn.college{AsZVuAhsFKyRARgq4hJZt4DIGnd.0lM1IDL4ITM0EzW}
```

&nbsp;

## Tangled Ticket (Easy)

```
hacker@reverse-engineering~tangled-ticket-easy:~$ /challenge/tangled-ticket-easy 
###
### Welcome to /challenge/tangled-ticket-easy!
###

This license verifier software will allow you to read the flag. However, before you can do so, you must verify that you
are licensed to read flag files! This program consumes a license key over stdin. Each program may perform entirely
different operations on that input! You must figure out (by reverse engineering this program) what that license key is.
Providing the correct license key will net you the flag!

Ready to receive your license key!

abcde
Initial input:

	61 62 63 64 65 

This challenge is now mangling your input using the `swap` mangler for indexes `0` and `1`.

This mangled your input, resulting in:

	62 61 63 64 65 

The mangling is done! The resulting bytes will be used for the final comparison.

Final result of mangling input:

	62 61 63 64 65 

Expected result:

	66 64 7a 7a 75 

Checking the received license key!

Wrong! No flag for you!
```

The challenge flips the 1st and 2nd byte of user input.

```py title="~/script.py" showLineNumbers
hex_string = "66647a7a75" 
ascii_string = bytes.fromhex(hex_string).decode('ascii')
print(ascii_string)
```

```
hacker@reverse-engineering~tangled-ticket-easy:~$ python ~/script.py 
fdzzu
```

Since the expected result is `fdzzu`, our input should be `dfzzu`.

```
hacker@reverse-engineering~tangled-ticket-easy:~$ /challenge/tangled-ticket-easy 
###
### Welcome to /challenge/tangled-ticket-easy!
###

This license verifier software will allow you to read the flag. However, before you can do so, you must verify that you
are licensed to read flag files! This program consumes a license key over stdin. Each program may perform entirely
different operations on that input! You must figure out (by reverse engineering this program) what that license key is.
Providing the correct license key will net you the flag!

Ready to receive your license key!

dfzzu
Initial input:

        64 66 7a 7a 75 

This challenge is now mangling your input using the `swap` mangler for indexes `0` and `1`.

This mangled your input, resulting in:

        66 64 7a 7a 75 

The mangling is done! The resulting bytes will be used for the final comparison.

Final result of mangling input:

        66 64 7a 7a 75 

Expected result:

        66 64 7a 7a 75 

Checking the received license key!

You win! Here is your flag:
pwn.college{8FlXhX2U1VQwVOC4n7Adfe5OkL4.01M1IDL4ITM0EzW}
```

&nbsp;

## Tangled Ticket (Hard)

### `main()`

<img alt="image" src="https://github.com/user-attachments/assets/6fb73a5f-e3bb-43d5-a4ec-64284f03213f" />

```c showLineNumbers
void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  char v3; // [rsp+20h] [rbp-10h]
  int buf; // [rsp+22h] [rbp-Eh] BYREF
  __int16 v5; // [rsp+26h] [rbp-Ah]
  unsigned __int64 v6; // [rsp+28h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  puts("###");
  printf("### Welcome to %s!\n", *a2);
  puts("###");
  putchar(10);
  puts(
    "This license verifier software will allow you to read the flag. However, before you can do so, you must verify that you");
  puts("are licensed to read flag files! This program consumes a license key over stdin. Each program may perform entirely");
  puts(
    "different operations on that input! You must figure out (by reverse engineering this program) what that license key is.");
  puts("Providing the correct license key will net you the flag!\n");
  buf = 0;
  v5 = 0;
  puts("Ready to receive your license key!\n");
  read(0, &buf, 5uLL);
  v3 = BYTE2(buf);
  BYTE2(buf) = v5;
  LOBYTE(v5) = v3;
  puts("Checking the received license key!\n");
  if ( !memcmp(&buf, str_Mdtkq, 5uLL) )
  {
    sub_12A9();
    exit(0);
  }
  puts("Wrong! No flag for you!");
  exit(1);
}
```

Looking at the comments IDA generated next to the variable declarations:
- `int buf; // [rsp+22h]` (A 4-byte integer)
- `__int16 v5; // [rsp+26h]` (A 2-byte integer)

Because `v5` starts at `rsp+0x26` and `buf` starts at `rsp+0x22`, `v5` sits immediately after `buf` in memory. When the program calls `read(0, &buf, 5)`, the first 4 bytes fill up `buf`, and the 5th byte overflows into the start of `v5`.

| Byte Index | Where it lives | IDA Macro   |
|:-----------|:---------------|:------------|
| Index 0    | buf            |	LOBYTE(buf) |
| Index 1    | buf            |	BYTE1(buf)  |
| Index 2    | buf	      | BYTE2(buf)  |
| Index 3    | buf	      | BYTE3(buf)  |
| Index 4    | v5	      | LOBYTE(v5)  |

As a result, looking at the following snippet:
```c showLineNumbers
  v3 = BYTE2(buf);
  BYTE2(buf) = v5;
  LOBYTE(v5) = v3;
```

We can tell that the 3rb byte is being swapped with the fifth one.

Let's look at what the final expected value is within `str_Mdtkq`.

<img alt="image" src="https://github.com/user-attachments/assets/d44c214b-259e-40cf-bf85-0d1507ec31c8" />

If the final expected result, after the 3rd and 5th byte are swapped, is `mdtkq`, then our input should be `mdqtk`.

```
hacker@reverse-engineering~tangled-ticket-hard:~$ /challenge/tangled-ticket-hard 
###
### Welcome to /challenge/tangled-ticket-hard!
###

This license verifier software will allow you to read the flag. However, before you can do so, you must verify that you
are licensed to read flag files! This program consumes a license key over stdin. Each program may perform entirely
different operations on that input! You must figure out (by reverse engineering this program) what that license key is.
Providing the correct license key will net you the flag!

Ready to receive your license key!

mdqkt
Checking the received license key!

You win! Here is your flag:
pwn.college{k2wFcD8pVItlUNHiR6sqAR9VQhY.0FN1IDL4ITM0EzW}
```

&nbsp;

## Bit Bender

```
hacker@reverse-engineering~bit-bender:~$ /challenge/bit-bender 
###
### Welcome to /challenge/bit-bender!
###

Enter a 16-byte key:
abcdabcdabcdabcd
Incorrect!
```

### `main()`

<img alt="image" src="https://github.com/user-attachments/assets/3a845cd5-a542-4cf8-8293-010eee2b9ea0" />

```c showLineNumbers
int __fastcall main(int argc, const char **argv, const char **envp)
{
  unsigned __int64 i; // [rsp+28h] [rbp-58h]
  size_t len_user_input; // [rsp+38h] [rbp-48h]
  char key[17]; // [rsp+40h] [rbp-40h] BYREF
  char ptr_1; // [rsp+51h] [rbp-2Fh]
  __int16 ptr_2; // [rsp+52h] [rbp-2Eh]
  int ptr_4; // [rsp+54h] [rbp-2Ch]
  __int64 v10; // [rsp+58h] [rbp-28h]
  __int64 s1[4]; // [rsp+60h] [rbp-20h] BYREF

  s1[3] = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  strcpy(key, "ONxfgkBdFXMPPspQ");
  ptr_1 = 0;
  ptr_2 = 0;
  ptr_4 = 0;
  v10 = 0LL;
  s1[0] = 0LL;
  s1[1] = 0LL;
  printf("Enter a %d-byte key:\n", 16LL);
  len_user_input = fread(&key[16], 1uLL, 16uLL, stdin);
  if ( len_user_input == 16 )
  {
    for ( i = 0LL; i < 16; ++i )
      *((_BYTE *)s1 + i) = ((unsigned __int8)(key[i + 16] + 107) >> 5) | (8 * (key[i + 16] + 107));
    if ( !memcmp(s1, key, 16uLL) )
    {
      puts("Correct!");
      win();
    }
    else
    {
      puts("Incorrect!");
    }
    return 0;
  }
  else
  {
    printf("Read %zu bytes, expected %zu.\n", len_user_input, 16uLL);
    return 0;
  }
}
```

The program defines a `key` using `strcpy`.
It then reads 16-byte of user input at the `key[16]` right after the key.

Let's look at the operations it performs on the user input:

- `for ( i = 0LL; i < 16; ++i )`: Repeats the following process for each byte of the user input.
	- `key[i + 16] + 107`: It adds the constant `107` (or `0x6B` in hex) to a byte at offset `i` in the user provided input.
	- `(unsigned __int8)`: It casts the result to an 8-bit unsigned integer. This ensures that if the addition exceeds 255, it wraps around (modulo 256).
	- `(X >> 5)`: This takes the top 3 bits and moves them to the bottom.
	- `(8 * X)`: Is mathematically identical to `(X << 3)` because $2^3 = 8$. This shifts the bits left by 3, moving the bottom 5 bits to the top.
	- The `|` (OR) operator: This combines the results of the shifts, performing a 3-bit Left Rotation.
	- `*((_BYTE *)s1 + i)`: This is simply array indexing. It is equivalent to `s1[i]`. It stores the final scrambled byte into the `i`-th position of the destination buffer `s1`.
- `if ( !memcmp(s1, key, 16uLL) )`: Compares the modified user input to the `key`, which is `ONxfgkBdFXMPPspQ`.

We will need a script to solve this challenge.

```py title="~/script.py" showLineNumbers
from pwn import *

target = "ONxfgkBdFXMPPspQ"
input_key = ""

for char in target:
    # Get the ASCII value
    y = ord(char)
    
    # 1. Reverse the Rotation: Rotate Right by 3 bits
    # (y >> 3) handles the main shift
    # (y << 5) & 0xFF wraps the bits that fell off the right back to the left
    rotated_right = ((y >> 3) | (y << 5)) & 0xFF
    
    # 2. Reverse the Addition: Subtract 107
    original_byte = (rotated_right - 107) % 256
    
    input_key += chr(original_byte)

p = process("/challenge/bit-bender")
p.recvuntil("Enter a 16-byte key:")
p.send(input_key)
p.interactive()
```

```
hacker@reverse-engineering~bit-bender:~$ nano ~/script.py
[+] Starting local process '/challenge/bit-bender': pid 1074
/home/hacker/script.py:23: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.recvuntil("Enter a 16-byte key:")
/home/hacker/script.py:24: BytesWarning: Text is not bytes; assuming ISO-8859-1, no guarantees. See https://docs.pwntools.com/#bytes
  p.send(input_key)
[*] Switching to interactive mode

[*] Process '/challenge/bit-bender' stopped with exit code 0 (pid 1074)
Correct!
You win! Here is your flag:
pwn.college{gxGqHwwzUpOv1V9D4d9lx40t1_U.QX4kDM5EDL4ITM0EzW}


[*] Got EOF while reading in interactive
$  
```

&nbsp;

## Substitution Sorcery

```
hacker@reverse-engineering~substitution-sorcery:~$ /challenge/substitution-sorcery 
###
### Welcome to /challenge/substitution-sorcery!
###

Enter a 16-byte key:
abcdabcdabcdabcd
Incorrect!
```

### `main()`

<img alt="image" src="https://github.com/user-attachments/assets/6966a2cf-60d7-4547-a254-5369bd519f46" />

```c showLineNumbers
int __fastcall main(int argc, const char **argv, const char **envp)
{
  unsigned __int64 i; // [rsp+28h] [rbp-58h]
  size_t len_user_input; // [rsp+38h] [rbp-48h]
  char key[17]; // [rsp+40h] [rbp-40h] BYREF
  char ptr_1; // [rsp+51h] [rbp-2Fh]
  __int16 ptr_2; // [rsp+52h] [rbp-2Eh]
  int ptr_4; // [rsp+54h] [rbp-2Ch]
  __int64 v10; // [rsp+58h] [rbp-28h]
  __int64 modified_user_input[4]; // [rsp+60h] [rbp-20h] BYREF

  modified_user_input[3] = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  strcpy(key, "TAyQPEhmuteINaGd");
  ptr_1 = 0;
  ptr_2 = 0;
  ptr_4 = 0;
  v10 = 0LL;
  modified_user_input[0] = 0LL;
  modified_user_input[1] = 0LL;
  printf("Enter a %d-byte key:\n", 16LL);
  len_user_input = fread(&key[16], 1uLL, 16uLL, stdin);
  if ( len_user_input == 16 )
  {
    for ( i = 0LL; i < 16; ++i )
      *((_BYTE *)modified_user_input + i) = substitution_table[key[i + 16] & 127];
    if ( !memcmp(modified_user_input, key, 16uLL) )
    {
      puts("Correct!");
      win();
    }
    else
    {
      puts("Incorrect!");
    }
    return 0;
  }
  else
  {
    printf("Read %zu bytes, expected %zu.\n", len_user_input, 16uLL);
    return 0;
  }
}
```

The program defines a `key` using `strcpy`.
It then reads 16-byte of user input at the `key[16]` right after the key.

Let's look at the operations it performs on the user input:

- `for ( i = 0LL; i < 16; ++i )`: Repeats the following process for each byte of the user input.
	- `key[i + 16] & 127`: Performs logical AND of the byte of user input and `127`. This will zero out the MSB of the user input's byte, thus constraining the result between 0 and 127.
	- `substitution_table[key[i + 16] & 127]`: References the value from `substitution_table` which is at index of the result of the AND operation.
	- `*((_BYTE *)modified_user_input + i)`: This is simply array indexing. It is equivalent to `s1[i]`. It stores the final scrambled byte into the `i`-th position of the destination buffer `modified_user_input`.
- `if ( !memcmp(modified_user_input, key, 16uLL) )`: Compares the modified user input from `modified_user_input` to the `key`, which is `TAyQPEhmuteINaGd`.

Before crafting the solution, we need to see the values present in the `substitution_table`. For this we can double-click on `substitution_table` and IDA will take us to the memory location.

<img alt="image" src="https://github.com/user-attachments/assets/a8bd4260-ca33-4673-b1af-f104949797b9" />

```py title="~/script.py" showLineNumbers
from pwn import *

# The target string we need to match
target = "TAyQPEhmuteINaGd"

# The data extracted from .rodata (d[128])
d = [
    0x18, 0x75, 0x4D, 0x24, 0x65, 0x26, 0x41, 0x79, 0x20, 0x5A, 0x7A, 0x40, 0x2A, 0x0E, 0x7B, 0x35, 
    0x2D, 0x59, 0x3E, 0x66, 0x1E, 0x29, 0x70, 0x12, 0x3B, 0x0D, 0x61, 0x42, 0x67, 0x6B, 0x49, 0x68, 
    0x08, 0x6A, 0x2B, 0x2C, 0x47, 0x03, 0x5B, 0x2E, 0x7F, 0x78, 0x52, 0x19, 0x62, 0x10, 0x43, 0x00, 
    0x45, 0x5D, 0x72, 0x57, 0x37, 0x48, 0x13, 0x21, 0x1D, 0x07, 0x4A, 0x22, 0x31, 0x4B, 0x01, 0x2F, 
    0x06, 0x27, 0x7E, 0x3D, 0x6F, 0x51, 0x6E, 0x64, 0x1C, 0x55, 0x5E, 0x76, 0x4F, 0x71, 0x63, 0x7C, 
    0x04, 0x14, 0x1B, 0x30, 0x34, 0x44, 0x25, 0x0A, 0x16, 0x1A, 0x5C, 0x15, 0x23, 0x69, 0x11, 0x38, 
    0x36, 0x4E, 0x74, 0x3C, 0x3F, 0x77, 0x50, 0x73, 0x60, 0x1F, 0x05, 0x7D, 0x54, 0x53, 0x5F, 0x0C, 
    0x58, 0x3A, 0x4C, 0x32, 0x02, 0x6D, 0x28, 0x33, 0x09, 0x56, 0x46, 0x17, 0x39, 0x0F, 0x6C, 0x0B
]

input_key = ""
for char in target:
    val = ord(char)
    # Find the index in d that contains the target value
    try:
        index = d.index(val)
        input_key += chr(index)
    except ValueError:
        input_key += "?"

p = process("/challenge/substitution-sorcery")
p.recvuntil("Enter a 16-byte key:")
p.send(input_key)
p.interactive()
```

```
hacker@reverse-engineering~substitution-sorcery:~$ python ~/script.py 
[+] Starting local process '/challenge/substitution-sorcery': pid 493
/home/hacker/script.py:29: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.recvuntil("Enter a 16-byte key:")
/home/hacker/script.py:30: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.send(input_key)
[*] Switching to interactive mode

[*] Process '/challenge/substitution-sorcery' stopped with exit code 0 (pid 493)
Correct!
You win! Here is your flag:
pwn.college{kX14bj3XjycJZjbBpmGW8TA2NdL.QX5kDM5EDL4ITM0EzW}


[*] Got EOF while reading in interactive
$  
```

&nbsp;

## Meager Mangler (Easy)

```
hacker@reverse-engineering~meager-mangler-easy:~$ /challenge/meager-mangler-easy 
###
### Welcome to /challenge/meager-mangler-easy!
###

This license verifier software will allow you to read the flag. However, before you can do so, you must verify that you
are licensed to read flag files! This program consumes a license key over stdin. Each program may perform entirely
different operations on that input! You must figure out (by reverse engineering this program) what that license key is.
Providing the correct license key will net you the flag!

Ready to receive your license key!

abcde
Initial input:

	61 62 63 64 65 0a 00 00 00 00 00 00 00 00 00 

This challenge is now mangling your input using the `reverse` mangler.

This mangled your input, resulting in:

	00 00 00 00 00 00 00 00 00 0a 65 64 63 62 61 

This challenge is now mangling your input using the `sort` mangler.

This mangled your input, resulting in:

	00 00 00 00 00 00 00 00 00 0a 61 62 63 64 65 

This challenge is now mangling your input using the `swap` mangler for indexes `3` and `5`.

This mangled your input, resulting in:

	00 00 00 00 00 00 00 00 00 0a 61 62 63 64 65 

The mangling is done! The resulting bytes will be used for the final comparison.

Final result of mangling input:

	00 00 00 00 00 00 00 00 00 0a 61 62 63 64 65 

Expected result:

	65 67 68 6c 6b 68 6c 6c 6d 6d 6e 6f 71 72 75 

Checking the received license key!

Wrong! No flag for you!
```

We simply have to reverse the order of mangling performed by the challenge program.

```py title="~/script.py" showLineNumbers
from pwn import *

target_key = [
    0x65, 0x67, 0x68, 0x6c, 0x6b, 0x68, 0x6c, 0x6c, 
    0x6d, 0x6d, 0x6e, 0x6f, 0x71, 0x72, 0x75
]

# Swap indexes 3 and 5
target_key[3], target_key[5] = target_key[5], target_key[3]

# Convert to characters
input_chars = [chr(b) for b in target_key]

# Reverse
input_chars.reverse()

input_key = "".join(input_chars)
p = process("/challenge/meager-mangler-easy")
p.recvuntil("Ready to receive your license key!")
p.send(input_key)
p.interactive()
```

```
hacker@reverse-engineering~meager-mangler-easy:~$ python ~/script.py 
[+] Starting local process '/challenge/meager-mangler-easy': pid 518
/home/hacker/script.py:25: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.recvuntil("Ready to receive your license key!")
/home/hacker/script.py:26: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.send(input_key)
[*] Switching to interactive mode


[*] Process '/challenge/meager-mangler-easy' stopped with exit code 0 (pid 518)
Initial input:

	75 72 71 6f 6e 6d 6d 6c 6c 6c 6b 68 68 67 65 

This challenge is now mangling your input using the `reverse` mangler.

This mangled your input, resulting in:

	65 67 68 68 6b 6c 6c 6c 6d 6d 6e 6f 71 72 75 

This challenge is now mangling your input using the `sort` mangler.

This mangled your input, resulting in:

	65 67 68 68 6b 6c 6c 6c 6d 6d 6e 6f 71 72 75 

This challenge is now mangling your input using the `swap` mangler for indexes `3` and `5`.

This mangled your input, resulting in:

	65 67 68 6c 6b 68 6c 6c 6d 6d 6e 6f 71 72 75 

The mangling is done! The resulting bytes will be used for the final comparison.

Final result of mangling input:

	65 67 68 6c 6b 68 6c 6c 6d 6d 6e 6f 71 72 75 

Expected result:

	65 67 68 6c 6b 68 6c 6c 6d 6d 6e 6f 71 72 75 

Checking the received license key!

You win! Here is your flag:
pwn.college{MzR69-0xiE3RHabqpkarx11Mhw4.0VM2IDL4ITM0EzW}


[*] Got EOF while reading in interactive
$  
```

Alternatively, since sorting is performed in the mangling steps, even if we just provide the required bytes, the program will bring it to a baseline (sorted string) and then perform the byte swap.

```py title="~/script.py" showLineNumbers
from pwn import *

target_key = [
    0x65, 0x67, 0x68, 0x6c, 0x6b, 0x68, 0x6c, 0x6c, 
    0x6d, 0x6d, 0x6e, 0x6f, 0x71, 0x72, 0x75
]

# Convert to characters
input_chars = [chr(b) for b in target_key]

input_key = "".join(input_chars)
p = process("/challenge/meager-mangler-easy")
p.recvuntil("Ready to receive your license key!")
p.send(input_key)
p.interactive()
```

```
hacker@reverse-engineering~meager-mangler-easy:~$ python ~/script.py
[+] Starting local process '/challenge/meager-mangler-easy': pid 409
/home/hacker/script.py:14: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.recvuntil("Ready to receive your license key!")
/home/hacker/script.py:15: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.send(input_key)
[*] Switching to interactive mode


[*] Process '/challenge/meager-mangler-easy' stopped with exit code 0 (pid 409)
Initial input:

        65 67 68 6c 6b 68 6c 6c 6d 6d 6e 6f 71 72 75 

This challenge is now mangling your input using the `reverse` mangler.

This mangled your input, resulting in:

        75 72 71 6f 6e 6d 6d 6c 6c 68 6b 6c 68 67 65 

This challenge is now mangling your input using the `sort` mangler.

This mangled your input, resulting in:

        65 67 68 68 6b 6c 6c 6c 6d 6d 6e 6f 71 72 75 

This challenge is now mangling your input using the `swap` mangler for indexes `3` and `5`.

This mangled your input, resulting in:

        65 67 68 6c 6b 68 6c 6c 6d 6d 6e 6f 71 72 75 

The mangling is done! The resulting bytes will be used for the final comparison.

Final result of mangling input:

        65 67 68 6c 6b 68 6c 6c 6d 6d 6e 6f 71 72 75 

Expected result:

        65 67 68 6c 6b 68 6c 6c 6d 6d 6e 6f 71 72 75 

Checking the received license key!

You win! Here is your flag:
pwn.college{MzR69-0xiE3RHabqpkarx11Mhw4.0VM2IDL4ITM0EzW}


[*] Got EOF while reading in interactive
$
```

&nbsp;

## Meager Mangler (Hard)

### `main()`

After a bit of analyzing and adding helpful comments, we get the following:

<img alt="image" src="https://github.com/user-attachments/assets/5909cff7-5316-4723-9865-e0faa88c5faf" />

```c showLineNumbers
void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  int modulo_3; // eax
  char v4; // [rsp+2Ch] [rbp-34h]
  char v5; // [rsp+2Eh] [rbp-32h]
  int i; // [rsp+30h] [rbp-30h]
  int j; // [rsp+34h] [rbp-2Ch]
  int k; // [rsp+38h] [rbp-28h]
  int m; // [rsp+3Ch] [rbp-24h]
  __int64 buf[2]; // [rsp+40h] [rbp-20h] BYREF
  __int16 v11; // [rsp+50h] [rbp-10h]
  char v12; // [rsp+52h] [rbp-Eh]
  unsigned __int64 v13; // [rsp+58h] [rbp-8h]

  v13 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  puts("###");
  printf("### Welcome to %s!\n", *a2);
  puts("###");
  putchar(10);
  puts(
    "This license verifier software will allow you to read the flag. However, before you can do so, you must verify that you");
  puts("are licensed to read flag files! This program consumes a license key over stdin. Each program may perform entirely");
  puts(
    "different operations on that input! You must figure out (by reverse engineering this program) what that license key is.");
  puts("Providing the correct license key will net you the flag!\n");
  buf[0] = 0LL;
  buf[1] = 0LL;
  v11 = 0;
  v12 = 0;
  puts("Ready to receive your license key!\n");
  read(0, buf, 18uLL);
  // Perform different bitwise XOR operation for each byte in a set of 3, and repeat
  for ( i = 0; i <= 17; ++i )
  {
    modulo_3 = i % 3;
    if ( i % 3 == 2 )
    {
      // XOR 3rd byte in a set of 3 with 173
      *((_BYTE *)buf + i) ^= 173u;
    }
    else if ( modulo_3 <= 2 )
    {
      if ( modulo_3 )
      {
        if ( modulo_3 == 1 )
          // XOR 2nd byte in a set of 3 with 146
          *((_BYTE *)buf + i) ^= 146u;
      }
      else
      {
        // XOR 1st byte in a set of 3 with 218
        *((_BYTE *)buf + i) ^= 218u;
      }
    }
  }
  // Reverse the string
  for ( j = 0; j <= 8; ++j )
  {
    v5 = *((_BYTE *)buf + j);                   // Move jth byte to a tmp variable
    *((_BYTE *)buf + j) = *((_BYTE *)buf + 17 - j);// Replace the jth byte with the (17-j)th byte
    *((_BYTE *)buf + 17 - j) = v5;              // Replace the (17-j)th byte with the byte in the tmp variable
  }
  // Perform bubble sort
  for ( k = 0; k <= 16; ++k )
  {
    // For each value of k, execute this loop, pushing the largest byte to the end
    for ( m = 0; m < 17 - k; ++m )
    {
      // Compare if current byte is greater than next byte
      if ( *((_BYTE *)buf + m) > *((_BYTE *)buf + m + 1) )
      {
        v4 = *((_BYTE *)buf + m);               // Move mth byte to a tmp variable
        *((_BYTE *)buf + m) = *((_BYTE *)buf + m + 1);// Replace the mth byte with the (m+1)th byte
        *((_BYTE *)buf + m + 1) = v4;           // Replace the (m+1)th byte with the byte in the tmp variable
      }
    }
  }
  puts("Checking the received license key!\n");
  if ( !memcmp(buf, &key, 18uLL) )
  {
    sub_12A9();
    exit(0);
  }
  puts("Wrong! No flag for you!");
  exit(1);
}
```

Finally, let's look at the data pointed to by `&key`.

<img alt="image" src="https://github.com/user-attachments/assets/ff5b949c-5fa5-4bcc-afe7-287540b55058" />

```py title="~/script.py" showLineNumbers
from pwn import *

target_key = [
    0xA0, 0xAC, 0xB4, 0xB5, 0xB7, 0xB7, 0xC1, 0xC1, 0xC6, 
    0xCB, 0xD9, 0xDC, 0xE3, 0xE5, 0xE7, 0xE8, 0xEB, 0xFB
]

xor_keys = [218, 146, 173]
input_chars = []

# Because the sort happened last, we don't know the original index (i).
# We need to find which character C, when XORed with xor_keys[i % 3], results in one of the values in target_key.
# Since XOR is its own inverse: (input ^ key) = target  => (target ^ key) = input

for i in range(18):
    val = target_key[i] ^ xor_keys[i % 3]
    input_chars.append(chr(val))

input_key = "".join(input_chars)

p = process("/challenge/meager-mangler-hard")
p.recvuntil("Ready to receive your license key!")
p.send(input_key)
p.interactive()
```

```
hacker@reverse-engineering~meager-mangler-hard:~$ python ~/script.py 
[+] Starting local process '/challenge/meager-mangler-hard': pid 418
/home/hacker/script.py:35: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.recvuntil("Ready to receive your license key!")
/home/hacker/script.py:36: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.send(input_key)
[*] Switching to interactive mode


[*] Process '/challenge/meager-mangler-hard' stopped with exit code 0 (pid 418)
Checking the received license key!

You win! Here is your flag:
pwn.college{EU2Oii1r9XBUSKr2e7MWoZf_bvk.0lM2IDL4ITM0EzW}


[*] Got EOF while reading in interactive
$  
```

&nbsp;

## Monstrous Mangler (Easy)

```
hacker@reverse-engineering~monstrous-mangler-easy:~$ /challenge/monstrous-mangler-easy 
###
### Welcome to /challenge/monstrous-mangler-easy!
###

This license verifier software will allow you to read the flag. However, before you can do so, you must verify that you
are licensed to read flag files! This program consumes a license key over stdin. Each program may perform entirely
different operations on that input! You must figure out (by reverse engineering this program) what that license key is.
Providing the correct license key will net you the flag!

Ready to receive your license key!

abcde
Initial input:

	61 62 63 64 65 0a 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 

This challenge is now mangling your input using the `reverse` mangler.

This mangled your input, resulting in:

	00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0a 65 64 63 62 61 

This challenge is now mangling your input using the `swap` mangler for indexes `6` and `31`.

This mangled your input, resulting in:

	00 00 00 00 00 00 0a 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 65 64 63 62 61 

This challenge is now mangling your input using the `reverse` mangler.

This mangled your input, resulting in:

	61 62 63 64 65 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0a 00 00 00 00 00 00 

This challenge is now mangling your input using the `swap` mangler for indexes `3` and `24`.

This mangled your input, resulting in:

	61 62 63 00 65 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 64 00 00 00 00 00 0a 00 00 00 00 00 00 

This challenge is now mangling your input using the `swap` mangler for indexes `8` and `23`.

This mangled your input, resulting in:

	61 62 63 00 65 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 64 00 00 00 00 00 0a 00 00 00 00 00 00 

This challenge is now mangling your input using the `sort` mangler.

This mangled your input, resulting in:

	00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0a 61 62 63 64 65 

This challenge is now mangling your input using the `xor` mangler with key `0x19`

This mangled your input, resulting in:

	19 19 19 19 19 19 19 19 19 19 19 19 19 19 19 19 19 19 19 19 19 19 19 19 19 19 19 19 19 19 19 13 78 7b 7a 7d 7c 

The mangling is done! The resulting bytes will be used for the final comparison.

Final result of mangling input:

	19 19 19 19 19 19 19 19 19 19 19 19 19 19 19 19 19 19 19 19 19 19 19 19 19 19 19 19 19 19 19 13 78 7b 7a 7d 7c 

Expected result:

	78 78 78 78 7a 7c 7f 7f 71 71 73 73 73 75 75 74 74 77 76 76 69 68 6a 6d 6c 6c 6c 6f 6e 6e 6e 6e 61 61 60 60 63 

Checking the received license key!

Wrong! No flag for you!
```

Because the 'sort' happened last in the forward chain, it's impossible to know the exact order BEFORE the sort. 
However, the swaps and reverses prior to the sort just moved the positions around. The license key is likely just the characters resulting from the XOR.
Regardless of how the swaps and reverses mangle our input, the sort will bring it to a baseline (sorted string).

```py title=~"~/script.py" showLineNumbers
from pwn import *

target_key = [
    0x78, 0x78, 0x78, 0x78, 0x7a, 0x7c, 0x7f, 0x7f, 0x71, 0x71, 0x73, 0x73, 0x73, 
    0x75, 0x75, 0x74, 0x74, 0x77, 0x76, 0x76, 0x69, 0x68, 0x6a, 0x6d, 0x6c, 0x6c, 
    0x6c, 0x6f, 0x6e, 0x6e, 0x6e, 0x6e, 0x61, 0x61, 0x60, 0x60, 0x63
]

# XOR with 0x19
target_key = [b ^ 0x19 for b in target_key]

# Convert to string (ignoring null bytes at the end)
input_key = ""
for b in expected_result:
    if b == 0: break # Stop at null terminator
    input_key += chr(b)

# print(f"Calculated License Key: {license_key}")

# Connect and send
p = process("/challenge/monstrous-mangler-easy")
p.recvuntil(b"Ready to receive your license key!")
p.send(input_key)
p.interactive()
```

```
hacker@reverse-engineering~monstrous-mangler-easy:~$ python ~/script.py 
[+] Starting local process '/challenge/monstrous-mangler-easy': pid 184
/home/hacker/script.py:27: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.send(input_key)
[*] Switching to interactive mode


[*] Process '/challenge/monstrous-mangler-easy' stopped with exit code 0 (pid 184)
Initial input:

        61 61 61 61 63 65 66 66 68 68 6a 6a 6a 6c 6c 6d 6d 6e 6f 6f 70 71 73 74 75 75 75 76 77 77 77 77 78 78 79 79 7a 

This challenge is now mangling your input using the `reverse` mangler.

This mangled your input, resulting in:

        7a 79 79 78 78 77 77 77 77 76 75 75 75 74 73 71 70 6f 6f 6e 6d 6d 6c 6c 6a 6a 6a 68 68 66 66 65 63 61 61 61 61 

This challenge is now mangling your input using the `swap` mangler for indexes `6` and `31`.

This mangled your input, resulting in:

        7a 79 79 78 78 77 65 77 77 76 75 75 75 74 73 71 70 6f 6f 6e 6d 6d 6c 6c 6a 6a 6a 68 68 66 66 77 63 61 61 61 61 

This challenge is now mangling your input using the `reverse` mangler.

This mangled your input, resulting in:

        61 61 61 61 63 77 66 66 68 68 6a 6a 6a 6c 6c 6d 6d 6e 6f 6f 70 71 73 74 75 75 75 76 77 77 65 77 78 78 79 79 7a 

This challenge is now mangling your input using the `swap` mangler for indexes `3` and `24`.

This mangled your input, resulting in:

        61 61 61 75 63 77 66 66 68 68 6a 6a 6a 6c 6c 6d 6d 6e 6f 6f 70 71 73 74 61 75 75 76 77 77 65 77 78 78 79 79 7a 

This challenge is now mangling your input using the `swap` mangler for indexes `8` and `23`.

This mangled your input, resulting in:

        61 61 61 75 63 77 66 66 74 68 6a 6a 6a 6c 6c 6d 6d 6e 6f 6f 70 71 73 68 61 75 75 76 77 77 65 77 78 78 79 79 7a 

This challenge is now mangling your input using the `sort` mangler.

This mangled your input, resulting in:

        61 61 61 61 63 65 66 66 68 68 6a 6a 6a 6c 6c 6d 6d 6e 6f 6f 70 71 73 74 75 75 75 76 77 77 77 77 78 78 79 79 7a 

This challenge is now mangling your input using the `xor` mangler with key `0x19`

This mangled your input, resulting in:

        78 78 78 78 7a 7c 7f 7f 71 71 73 73 73 75 75 74 74 77 76 76 69 68 6a 6d 6c 6c 6c 6f 6e 6e 6e 6e 61 61 60 60 63 

The mangling is done! The resulting bytes will be used for the final comparison.

Final result of mangling input:

        78 78 78 78 7a 7c 7f 7f 71 71 73 73 73 75 75 74 74 77 76 76 69 68 6a 6d 6c 6c 6c 6f 6e 6e 6e 6e 61 61 60 60 63 

Expected result:

        78 78 78 78 7a 7c 7f 7f 71 71 73 73 73 75 75 74 74 77 76 76 69 68 6a 6d 6c 6c 6c 6f 6e 6e 6e 6e 61 61 60 60 63 

Checking the received license key!

You win! Here is your flag:
pwn.college{MzyPrzGp16a6O881RwlLr4_rVcZ.0VN2IDL4ITM0EzW}


[*] Got EOF while reading in interactive
$  
```

&nbsp;

## Monstrous Mangler (Hard)

### `main()`

```c showLineNumbers
void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  char v3; // [rsp+20h] [rbp-50h]
  char v4; // [rsp+22h] [rbp-4Eh]
  int i; // [rsp+24h] [rbp-4Ch]
  int j; // [rsp+28h] [rbp-48h]
  int k; // [rsp+2Ch] [rbp-44h]
  int m; // [rsp+30h] [rbp-40h]
  int n; // [rsp+34h] [rbp-3Ch]
  int ii; // [rsp+38h] [rbp-38h]
  int jj; // [rsp+3Ch] [rbp-34h]
  __int64 buf; // [rsp+40h] [rbp-30h] BYREF
  __int64 v13; // [rsp+48h] [rbp-28h]
  __int64 v14; // [rsp+50h] [rbp-20h]
  __int64 v15; // [rsp+58h] [rbp-18h]
  int v16; // [rsp+60h] [rbp-10h]
  __int16 v17; // [rsp+64h] [rbp-Ch]
  char v18; // [rsp+66h] [rbp-Ah]
  unsigned __int64 v19; // [rsp+68h] [rbp-8h]

  v19 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  puts("###");
  printf("### Welcome to %s!\n", *a2);
  puts("###");
  putchar(10);
  puts(
    "This license verifier software will allow you to read the flag. However, before you can do so, you must verify that you");
  puts("are licensed to read flag files! This program consumes a license key over stdin. Each program may perform entirely");
  puts(
    "different operations on that input! You must figure out (by reverse engineering this program) what that license key is.");
  puts("Providing the correct license key will net you the flag!\n");
  buf = 0LL;
  v13 = 0LL;
  v14 = 0LL;
  v15 = 0LL;
  v16 = 0;
  v17 = 0;
  v18 = 0;
  puts("Ready to receive your license key!\n");
  read(0, &buf, 38uLL);
  // Perform different bitwise XOR operation for each byte in a set of 2, and repeat
  for ( i = 0; i <= 37; ++i )
  {
    if ( i % 2 )
    {
      if ( i % 2 == 1 )
        // XOR 2nd byte in a set of 2 with 54
        *((_BYTE *)&buf + i) ^= 54u;
    }
    else
    {
      // XOR 1st byte in a set of 2 with 186
      *((_BYTE *)&buf + i) ^= 186u;
    }
  }
  // Perform different bitwise XOR operation for each byte in a set of 6, and repeat
  for ( j = 0; j <= 37; ++j )
  {
    switch ( j % 6 )
    {
      case 0:
        *((_BYTE *)&buf + j) ^= 239u;           // XOR 1st byte in a set of 6 with 239
        break;
      case 1:
        *((_BYTE *)&buf + j) ^= 17u;            // XOR 2nd byte in a set of 6 with 17
        break;
      case 2:
        *((_BYTE *)&buf + j) ^= 122u;           // XOR 3rd byte in a set of 6 with 122
        break;
      case 3:
        *((_BYTE *)&buf + j) ^= 105u;           // XOR 4th byte in a set of 6 with 105
        break;
      case 4:
        *((_BYTE *)&buf + j) ^= 242u;           // XOR 5th byte in a set of 6 with 242
        break;
      case 5:
        *((_BYTE *)&buf + j) ^= 179u;           // XOR 6th byte in a set of 6 with 179
        break;
      default:
        continue;
    }
  }
  // Perform bubble sort
  for ( k = 0; k <= 36; ++k )
  {
    // For each value of k, execute this loop, pushing the largest byte to the end
    for ( m = 0; m < 37 - k; ++m )
    {
      // Compare if current byte is greater than the next byte
      if ( *((_BYTE *)&buf + m) > *((_BYTE *)&buf + m + 1) )
      {
        v4 = *((_BYTE *)&buf + m);              // Move mth byte to a tmp variable
        *((_BYTE *)&buf + m) = *((_BYTE *)&buf + m + 1);// Replace the mth byte with the (m+1)th byte
        *((_BYTE *)&buf + m + 1) = v4;          // Replace the (m+1)th byte with the byte in the tmp variable
      }
    }
  }
  // Perform a bitwise XOR for every byte with 209
  for ( n = 0; n <= 37; ++n )
    *((_BYTE *)&buf + n) ^= 209u;
  // Perform different bitwise XOR operation for each byte in a set of 7, and repeat
  for ( ii = 0; ii <= 37; ++ii )
  {
    switch ( ii % 7 )
    {
      case 0:
        *((_BYTE *)&buf + ii) ^= 53u;           // XOR 1st byte in a set of 7 with 53
        break;
      case 1:
        *((_BYTE *)&buf + ii) ^= 43u;           // XOR 2nd byte in a set of 7 with 43
        break;
      case 2:
        *((_BYTE *)&buf + ii) ^= 147u;          // XOR 3rd byte in a set of 7 with 147
        break;
      case 3:
        *((_BYTE *)&buf + ii) ^= 166u;          // XOR 4th byte in a set of 7 with 166
        break;
      case 4:
        *((_BYTE *)&buf + ii) ^= 71u;           // XOR 5th byte in a set of 7 with 71
        break;
      case 5:
        *((_BYTE *)&buf + ii) ^= 244u;          // XOR 6th byte in a set of 7 with 244
        break;
      case 6:
        *((_BYTE *)&buf + ii) ^= 155u;          // XOR 7th byte in a set of 7 with 155
        break;
      default:
        continue;
    }
  }
  // Swap the 5th and 10th byte
  v3 = BYTE4(buf);                              // Move the 5th byte of user input into a tmp variable
  BYTE4(buf) = BYTE1(v13);                      // Replace the 5th byte of user input with the 10th byte
  BYTE1(v13) = v3;                              // Replace the 10th byte of user input with the value of the tmp variable
                                                // 
  // Perform different bitwise XOR operation for each byte in a set of 2, and repeat
  for ( jj = 0; jj <= 37; ++jj )
  {
    if ( jj % 2 )
    {
      if ( jj % 2 == 1 )
        *((_BYTE *)&buf + jj) ^= 57u;           // XOR 2nd byte in a set of 2 with 57
    }
    else
    {
      *((_BYTE *)&buf + jj) ^= 34u;             // XOR 1st byte in a set of 2 with 34
    }
  }
  puts("Checking the received license key!\n");
  if ( !memcmp(&buf, &key, 38uLL) )
  {
    sub_12A9();
    exit(0);
  }
  puts("Wrong! No flag for you!");
  exit(1);
}
```

Let's look at the data pointed to by `&key`.

<img alt="image" src="https://github.com/user-attachments/assets/cda7cb67-781f-48b2-a8fd-144d0b5b09dc" />

```py title="~/script.py" showLineNumbers
from pwn import *
from z3 import *

# 1. Extracted key from your image
final_key = [
    0xE3, 0xE6, 0x46, 0x67, 0x50, 0x37, 0x44, 0xF0, 0xE8, 0x84, 0x67, 0x9C, 0x32, 0x48, 0xFB, 0xFE,
    0x5E, 0x70, 0x8A, 0x5C, 0x2D, 0x95, 0x92, 0x31, 0x1A, 0xF2, 0xA1, 0xD4, 0x6E, 0x6A, 0xC9, 0xFC,
    0x54, 0xFE, 0x81, 0x2C, 0x2F, 0x84
]

# 2. MANUALLY REVERSE POST-SORT OPERATIONS
# Reverse Loop jj
for i in range(38):
    if i % 2 == 0: final_key[i] ^= 34
    else: final_key[i] ^= 57

# Reverse Swap (5th and 10th bytes)
final_key[4], final_key[9] = final_key[9], final_key[4]

# Reverse Loop ii
ii_keys = [53, 43, 147, 166, 71, 244, 155]
for i in range(38):
    final_key[i] ^= ii_keys[i % 7]

# Reverse Loop n
final_key = [b ^ 209 for b in final_key]

# This final_key is now the result of the BUBBLE SORT. 
# It is a sorted list of the bytes after the first two XOR loops.
target_sorted = sorted(final_key)

# 3. USE Z3 TO FIND THE ORIGINAL INPUT
solver = Solver()
input_bytes = [BitVec(f'b_{i}', 8) for i in range(38)]

# Apply constraints: Input should be printable ASCII
for b in input_bytes:
    solver.add(b >= 32, b <= 126)

# Duplicate the input to simulate the transformations
transformed = [b for b in input_bytes]

# Loop i: XOR 186, 54
for i in range(38):
    if i % 2 == 0: transformed[i] ^= 186
    else: transformed[i] ^= 54

# Loop j: XOR 239, 17, 122, 105, 242, 179
j_keys = [239, 17, 122, 105, 242, 179]
for j in range(38):
    transformed[j] ^= j_keys[j % 6]

# The CRITICAL step: The set of transformed bytes must match the sorted target bytes.
# We don't know the order, but we know the COUNT of each byte value.
for val in set(target_sorted):
    count_in_target = target_sorted.count(val)
    count_in_transformed = Sum([If(transformed[i] == val, 1, 0) for i in range(38)])
    solver.add(count_in_transformed == count_in_target)

if solver.check() == sat:
    model = solver.model()
    solution = "".join(chr(model[b].as_long()) for b in input_bytes)
    print(f"Found License Key: {solution}")
    
    # Connect and send
    p = process("/challenge/monstrous-mangler-hard")
    p.recvuntil(b"Ready to receive your license key!")
    p.send(solution.encode())
    p.interactive()
else:
    print("Could not find a solution.")
```

```
hacker@reverse-engineering~monstrous-mangler-hard:~$ python ~/script.py 
Found License Key: |h)r},hbitsg~mgb{rpgrmx-km?adtpzfaxeso
[+] Starting local process '/challenge/monstrous-mangler-hard': pid 466
[*] Switching to interactive mode


[*] Process '/challenge/monstrous-mangler-hard' stopped with exit code 0 (pid 466)
Checking the received license key!

You win! Here is your flag:
pwn.college{Im1NoqernmD2ffWSMiYohm-Za8d.0lN2IDL4ITM0EzW}


[*] Got EOF while reading in interactive
$  
```

&nbsp;

## Patched Up (Easy)

```
hacker@reverse-engineering~patched-up-easy:~$ /challenge/patched-up-easy 
###
### Welcome to /challenge/patched-up-easy!
###

This license verifier software will allow you to read the flag. However, before you can do so, you must verify that you
are licensed to read flag files! This program consumes a license key over stdin. Each program may perform entirely
different operations on that input! You must figure out (by reverse engineering this program) what that license key is.
Providing the correct license key will net you the flag!

Unfortunately for you, the license key cannot be reversed. You'll have to crack this program.

Changing byte 1/5.
Offset (hex) to change: 1
New value (hex): 1
The byte has been changed: *0x591db96c0001 = 1.
Changing byte 2/5.
Offset (hex) to change: 2
New value (hex): 2
The byte has been changed: *0x591db96c0002 = 2.
Changing byte 3/5.
Offset (hex) to change: 3
New value (hex): 3
The byte has been changed: *0x591db96c0003 = 3.
Changing byte 4/5.
Offset (hex) to change: 4
New value (hex): 4
The byte has been changed: *0x591db96c0004 = 4.
Changing byte 5/5.
Offset (hex) to change: 5
New value (hex): 5
The byte has been changed: *0x591db96c0005 = 5.
Ready to receive your license key!

abcde
Initial input:

	61 62 63 64 65 0a 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 

This challenge is now mangling your input using the `md5` mangler. This mangler cannot be reversed.

This mangled your input, resulting in:

	b0 b6 a0 a5 a5 3b c4 e5 d8 3f b8 b1 f4 a7 2b 89 00 00 00 00 00 00 00 00 00 00 00 00 00 

The mangling is done! The resulting bytes will be used for the final comparison.

Final result of mangling input:

	b0 b6 a0 a5 a5 3b c4 e5 d8 3f b8 b1 f4 a7 2b 89 00 00 00 00 00 00 00 00 00 00 00 00 00 

Expected result:

	a1 12 36 e3 05 13 fe ee 08 bb 1d d7 98 67 19 37 00 00 00 00 00 00 00 00 00 00 00 00 00 

Checking the received license key!

Wrong! No flag for you!
```

Let's open the program within IDA.

### `main()`

```c showLineNumbers
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  unsigned __int8 new_hex_value; // [rsp+2Dh] [rbp-C3h] BYREF
  unsigned __int16 offset_to_change; // [rsp+2Eh] [rbp-C2h] BYREF
  int i_1; // [rsp+30h] [rbp-C0h]
  int i; // [rsp+34h] [rbp-BCh]
  int j; // [rsp+38h] [rbp-B8h]
  int k; // [rsp+3Ch] [rbp-B4h]
  int m; // [rsp+40h] [rbp-B0h]
  int n; // [rsp+44h] [rbp-ACh]
  unsigned __int64 v12; // [rsp+48h] [rbp-A8h]
  char v13[96]; // [rsp+50h] [rbp-A0h] BYREF
  __int64 v14; // [rsp+B0h] [rbp-40h]
  __int64 v15; // [rsp+B8h] [rbp-38h]
  __int64 buf; // [rsp+C0h] [rbp-30h] BYREF
  __int64 v17; // [rsp+C8h] [rbp-28h]
  __int64 v18; // [rsp+D0h] [rbp-20h]
  int v19; // [rsp+D8h] [rbp-18h]
  __int16 v20; // [rsp+DCh] [rbp-14h]
  unsigned __int64 v21; // [rsp+E8h] [rbp-8h]

  v21 = __readfsqword(40u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  puts(
    "This license verifier software will allow you to read the flag. However, before you can do so, you must verify that you");
  puts("are licensed to read flag files! This program consumes a license key over stdin. Each program may perform entirely");
  puts(
    "different operations on that input! You must figure out (by reverse engineering this program) what that license key is.");
  puts("Providing the correct license key will net you the flag!\n");
  puts("Unfortunately for you, the license key cannot be reversed. You'll have to crack this program.\n");
  i_1 = 0;
  v12 = ((unsigned __int64)bin_padding & 0xFFFFFFFFFFFFF000LL) - 4096;
  do
    v3 = i_1++;
  while ( !mprotect((void *)((v3 << 12) + v12), 4096uLL, 7) );
  for ( i = 0; i <= 4; ++i )
  {
    printf("Changing byte %d/5.\n", (unsigned int)(i + 1));
    printf("Offset (hex) to change: ");
    __isoc99_scanf("%hx", &offset_to_change);
    printf("New value (hex): ");
    __isoc99_scanf("%hhx", &new_hex_value);
    *(_BYTE *)(offset_to_change + v12) = new_hex_value;
    printf("The byte has been changed: *%p = %hhx.\n", (const void *)(v12 + offset_to_change), new_hex_value);
  }
  buf = 0LL;
  v17 = 0LL;
  v18 = 0LL;
  v19 = 0;
  v20 = 0;
  puts("Ready to receive your license key!\n");
  read(0, &buf, 29uLL);
  puts("Initial input:\n");
  putchar(9);
  for ( j = 0; j <= 28; ++j )
    printf("%02x ", *((unsigned __int8 *)&buf + j));
  puts("\n");
  puts("This challenge is now mangling your input using the `md5` mangler. This mangler cannot be reversed.\n");
  MD5_Init();
  MD5_Update(v13, &buf, 29LL);
  MD5_Final();
  memset(&buf, 0, 29uLL);
  buf = v14;
  v17 = v15;
  puts("This mangled your input, resulting in:\n");
  putchar(9);
  for ( k = 0; k <= 28; ++k )
    printf("%02x ", *((unsigned __int8 *)&buf + k));
  puts("\n");
  puts("The mangling is done! The resulting bytes will be used for the final comparison.\n");
  puts("Final result of mangling input:\n");
  putchar(9);
  for ( m = 0; m <= 28; ++m )
    printf("%02x ", *((unsigned __int8 *)&buf + m));
  puts("\n");
  puts("Expected result:\n");
  putchar(9);
  for ( n = 0; n <= 28; ++n )
    printf("%02x ", EXPECTED_RESULT[n]);
  puts("\n");
  puts("Checking the received license key!\n");
  if ( !memcmp(&buf, EXPECTED_RESULT, 29uLL) )
  {
    win();
    exit(0);
  }
  puts("Wrong! No flag for you!");
  exit(1);
}
```

At a high level, the program compares the user input at `&buf` with the `EXPECTED_RESULT`, and based on the result, either jumps to `win()` or exits. 

<img alt="image" src="https://github.com/user-attachments/assets/4b2d46d5-563c-4b2a-9f26-1265508f73e1" />

Let's check how the conditional is performed in Assembly.

```asm showLineNumbers
# ---- snip ----

.text:0000000000002005                 lea     rax, [rbp+buf]
.text:0000000000002009                 mov     edx, 1Dh        ; n
.text:000000000000200E                 lea     rsi, EXPECTED_RESULT ; s2
.text:0000000000002015                 mov     rdi, rax        ; s1
.text:0000000000002018                 call    _memcmp
.text:000000000000201D                 test    eax, eax
.text:000000000000201F                 jnz     short loc_2035
.text:0000000000002021                 mov     eax, 0
.text:0000000000002026                 call    win
.text:000000000000202B                 mov     edi, 0          ; status
.text:0000000000002030                 call    _exit
.text:0000000000002035 ; ---------------------------------------------------------------------------
.text:0000000000002035
.text:0000000000002035 loc_2035:                               ; CODE XREF: main+4A3↑j
.text:0000000000002035                 lea     rdi, aWrongNoFlagFor ; "Wrong! No flag for you!"
.text:000000000000203C                 call    _puts
.text:0000000000002041                 mov     edi, 1          ; status
.text:0000000000002046                 call    _exit

# ---- snip ----
```

The `_memcmp` result would be `rax=0` if the values of the hashed user input at `&buf` and `EXPECTED_RESULT` are the same.
This would cause the `test` instruction to set the Zero Flag (ZF), as it would perform bitwise AND of two 0 values.
As we can see, the program then uses a `jnz` to jump to `_exit` if Zero Flag (ZF) is unset (0).
Else, it jumps to `win()`.

So, all in all, if the hashed value is equal to the expected result, we get the flag. However, what if we replace `jnz` with `jz`?
This would cause the program to give us the flag in cases where the hashed value is not equal to the expected result, and hence allow us to pass any random input.

In order to do this, we would have to pass `0x201f` as offset as that is the location of the `jnz` instruction's byte, and pass `0x74` as the replacement byte as that is the opcode for `jz`.

```
hacker@reverse-engineering~patched-up-easy:~$ /challenge/patched-up-easy 
###
### Welcome to /challenge/patched-up-easy!
###

This license verifier software will allow you to read the flag. However, before you can do so, you must verify that you
are licensed to read flag files! This program consumes a license key over stdin. Each program may perform entirely
different operations on that input! You must figure out (by reverse engineering this program) what that license key is.
Providing the correct license key will net you the flag!

Unfortunately for you, the license key cannot be reversed. You'll have to crack this program.

Changing byte 1/5.
Offset (hex) to change: 0x201f          
New value (hex): 0x74
The byte has been changed: *0x5b826945901f = 74.
Changing byte 2/5.
Offset (hex) to change: 0
New value (hex): 0
The byte has been changed: *0x5b8269457000 = 0.
Changing byte 3/5.
Offset (hex) to change: 0
New value (hex): 0
The byte has been changed: *0x5b8269457000 = 0.
Changing byte 4/5.
Offset (hex) to change: 0
New value (hex): 0
The byte has been changed: *0x5b8269457000 = 0.
Changing byte 5/5.
Offset (hex) to change: 0
New value (hex): 0
The byte has been changed: *0x5b8269457000 = 0.
Ready to receive your license key!

abcde
Initial input:

	61 62 63 64 65 0a 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 

This challenge is now mangling your input using the `md5` mangler. This mangler cannot be reversed.

This mangled your input, resulting in:

	b0 b6 a0 a5 a5 3b c4 e5 d8 3f b8 b1 f4 a7 2b 89 00 00 00 00 00 00 00 00 00 00 00 00 00 

The mangling is done! The resulting bytes will be used for the final comparison.

Final result of mangling input:

	b0 b6 a0 a5 a5 3b c4 e5 d8 3f b8 b1 f4 a7 2b 89 00 00 00 00 00 00 00 00 00 00 00 00 00 

Expected result:

	a1 12 36 e3 05 13 fe ee 08 bb 1d d7 98 67 19 37 00 00 00 00 00 00 00 00 00 00 00 00 00 

Checking the received license key!

You win! Here is your flag:
pwn.college{gjwP8_mb1sObPYLR-g7xKyZUQ82.01N2IDL4ITM0EzW}
```

&nbsp;

## Patched Up (Hard)

```
hacker@reverse-engineering~patched-up-hard:~$ /challenge/patched-up-hard 
###
### Welcome to /challenge/patched-up-hard!
###

This license verifier software will allow you to read the flag. However, before you can do so, you must verify that you
are licensed to read flag files! This program consumes a license key over stdin. Each program may perform entirely
different operations on that input! You must figure out (by reverse engineering this program) what that license key is.
Providing the correct license key will net you the flag!

Unfortunately for you, the license key cannot be reversed. You'll have to crack this program.

Changing byte 1/5.
Offset (hex) to change: 
```

### `main()`

```c showLineNumbers
void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  int v3; // eax
  unsigned __int8 new_hex_value; // [rsp+2Dh] [rbp-B3h] BYREF
  unsigned __int16 offset_to_change; // [rsp+2Eh] [rbp-B2h] BYREF
  int v6; // [rsp+30h] [rbp-B0h]
  int i; // [rsp+34h] [rbp-ACh]
  unsigned __int64 v8; // [rsp+38h] [rbp-A8h]
  char v9[96]; // [rsp+40h] [rbp-A0h] BYREF
  __int64 v10[2]; // [rsp+A0h] [rbp-40h] BYREF
  __int64 buf; // [rsp+B0h] [rbp-30h] BYREF
  __int64 v12; // [rsp+B8h] [rbp-28h]
  __int64 v13; // [rsp+C0h] [rbp-20h]
  int v14; // [rsp+C8h] [rbp-18h]
  char v15; // [rsp+CCh] [rbp-14h]
  unsigned __int64 v16; // [rsp+D8h] [rbp-8h]

  v16 = __readfsqword(40u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  puts("###");
  printf("### Welcome to %s!\n", *a2);
  puts("###");
  putchar(10);
  puts(
    "This license verifier software will allow you to read the flag. However, before you can do so, you must verify that you");
  puts("are licensed to read flag files! This program consumes a license key over stdin. Each program may perform entirely");
  puts(
    "different operations on that input! You must figure out (by reverse engineering this program) what that license key is.");
  puts("Providing the correct license key will net you the flag!\n");
  puts("Unfortunately for you, the license key cannot be reversed. You'll have to crack this program.\n");
  v6 = 0;
  v8 = ((unsigned __int64)sub_1369 & 0xFFFFFFFFFFFFF000LL) - 4096;
  do
    v3 = v6++;
  while ( !mprotect((void *)((v3 << 12) + v8), 4096uLL, 7) );
  for ( i = 0; i <= 4; ++i )
  {
    printf("Changing byte %d/5.\n", (unsigned int)(i + 1));
    printf("Offset (hex) to change: ");
    __isoc99_scanf("%hx", &offset_to_change);
    printf("New value (hex): ");
    __isoc99_scanf("%hhx", &new_hex_value);
    *(_BYTE *)(offset_to_change + v8) = new_hex_value;
    printf("The byte has been changed: *%p = %hhx.\n", (const void *)(v8 + offset_to_change), new_hex_value);
  }
  buf = 0LL;
  v12 = 0LL;
  v13 = 0LL;
  v14 = 0;
  v15 = 0;
  puts("Ready to receive your license key!\n");
  read(0, &buf, 28uLL);
  MD5_Init(v9);
  MD5_Update(v9, &buf, 28LL);
  MD5_Final(v10, v9);
  memset(&buf, 0, 28uLL);
  buf = v10[0];
  v12 = v10[1];
  puts("Checking the received license key!\n");
  if ( !memcmp(&buf, &EXPECTED_RESULT, 28uLL) )
  {
    win();
    exit(0);
  }
  puts("Wrong! No flag for you!");
  exit(1);
}
```

<img alt="image" src="https://github.com/user-attachments/assets/1ed28d08-6885-4efb-b101-6bb5ef574bbe" />

Let's look at the disassembly view.

```asm showLineNumbers
# ---- snip ----

.text:0000000000001E1D                 mov     edx, 1Ch        ; n
.text:0000000000001E22                 lea     rsi, EXPECTED_RESULT ; s2
.text:0000000000001E29                 mov     rdi, rax        ; s1
.text:0000000000001E2C                 call    _memcmp
.text:0000000000001E31                 test    eax, eax
.text:0000000000001E33                 jnz     short loc_1E49
.text:0000000000001E35                 mov     eax, 0
.text:0000000000001E3A                 call    win
.text:0000000000001E3F                 mov     edi, 0          ; status
.text:0000000000001E44                 call    _exit
.text:0000000000001E49 ; ---------------------------------------------------------------------------
.text:0000000000001E49
.text:0000000000001E49 loc_1E49:                               ; CODE XREF: main+2FF↑j
.text:0000000000001E49                 lea     rdi, aWrongNoFlagFor ; "Wrong! No flag for you!"
.text:0000000000001E50                 call    _puts
.text:0000000000001E55                 mov     edi, 1          ; status
.text:0000000000001E5A                 call    _exit

# ---- snip ----
```

The `_memcmp` result would be `rax=0` if the values of the hashed user input at `&buf` and `EXPECTED_RESULT` are the same.
This would cause the `test` instruction to set the Zero Flag (ZF), as it would perform bitwise AND of two 0 values.
As we can see, the program then uses a `jnz` to jump to `_exit` if Zero Flag (ZF) is unset (0).
Else, it jumps to `win()`.

So, all in all, if the hashed value is equal to the expected result, we get the flag. However, what if we replace `jnz` with `jz`?
This would cause the program to give us the flag in cases where the hashed value is not equal to the expected result, and hence allow us to pass any random input.

In order to do this, we would have to pass `0x1e33f` as offset as that is the location of the `jnz` instruction's byte, and pass `0x74` as the replacement byte as that is the opcode for `jz`.

```
hacker@reverse-engineering~patched-up-hard:~$ /challenge/patched-up-hard 
###
### Welcome to /challenge/patched-up-hard!
###

This license verifier software will allow you to read the flag. However, before you can do so, you must verify that you
are licensed to read flag files! This program consumes a license key over stdin. Each program may perform entirely
different operations on that input! You must figure out (by reverse engineering this program) what that license key is.
Providing the correct license key will net you the flag!

Unfortunately for you, the license key cannot be reversed. You'll have to crack this program.

Changing byte 1/5.
Offset (hex) to change: 0x1e33
New value (hex): 0x74
The byte has been changed: *0x59e487a84e33 = 74.
Changing byte 2/5.
Offset (hex) to change: 0
New value (hex): 0
The byte has been changed: *0x59e487a83000 = 0.
Changing byte 3/5.
Offset (hex) to change: 0
New value (hex): 0
The byte has been changed: *0x59e487a83000 = 0.
Changing byte 4/5.
Offset (hex) to change: 0
New value (hex): 0
The byte has been changed: *0x59e487a83000 = 0.
Changing byte 5/5.
Offset (hex) to change: 0
New value (hex): 0
The byte has been changed: *0x59e487a83000 = 0.
Ready to receive your license key!

abcde
Checking the received license key!

You win! Here is your flag:
pwn.college{QCJPI0vo5_A9DwOEd0md34s1a1J.0FO2IDL4ITM0EzW}
```

&nbsp;

## Puzzle Patch (Easy)

```
hacker@reverse-engineering~puzzle-patch-easy:~$ /challenge/puzzle-patch-easy 
###
### Welcome to /challenge/puzzle-patch-easy!
###

This license verifier software will allow you to read the flag. However, before you can do so, you must verify that you
are licensed to read flag files! This program consumes a license key over stdin. Each program may perform entirely
different operations on that input! You must figure out (by reverse engineering this program) what that license key is.
Providing the correct license key will net you the flag!

Unfortunately for you, the license key cannot be reversed. You'll have to crack this program.

Changing byte 1/1.
Offset (hex) to change: 0
New value (hex): 0
The byte has been changed: *0x581676738000 = 0.
Ready to receive your license key!

abcde
Initial input:

	61 62 63 64 65 0a 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 

This challenge is now mangling your input using the `md5` mangler. This mangler cannot be reversed.

This mangled your input, resulting in:

	b0 b6 a0 a5 a5 3b c4 e5 d8 3f b8 b1 f4 a7 2b 89 00 00 00 00 00 00 00 00 00 00 00 00 00 

The mangling is done! The resulting bytes will be used for the final comparison.

Final result of mangling input:

	b0 b6 a0 a5 a5 3b c4 e5 d8 3f b8 b1 f4 a7 2b 89 00 00 00 00 00 00 00 00 00 00 00 00 00 

Expected result:

	9e 0a 1f fc ec 2a e6 08 8a df 27 6a 35 33 a0 d2 00 00 00 00 00 00 00 00 00 00 00 00 00 

Checking the received license key!

Wrong! No flag for you!
```

### `main()`

```c showLineNumbers
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  int i_2; // eax
  unsigned __int8 new_hex_value; // [rsp+2Dh] [rbp-C3h] BYREF
  unsigned __int16 offset_to_change; // [rsp+2Eh] [rbp-C2h] BYREF
  int i_1; // [rsp+30h] [rbp-C0h]
  int i; // [rsp+34h] [rbp-BCh]
  int j; // [rsp+38h] [rbp-B8h]
  int k; // [rsp+3Ch] [rbp-B4h]
  int m; // [rsp+40h] [rbp-B0h]
  int n; // [rsp+44h] [rbp-ACh]
  unsigned __int64 v12; // [rsp+48h] [rbp-A8h]
  char v13[96]; // [rsp+50h] [rbp-A0h] BYREF
  __int64 v14[2]; // [rsp+B0h] [rbp-40h] BYREF
  __int64 buf; // [rsp+C0h] [rbp-30h] BYREF
  __int64 v16; // [rsp+C8h] [rbp-28h]
  __int64 v17; // [rsp+D0h] [rbp-20h]
  int v18; // [rsp+D8h] [rbp-18h]
  __int16 v19; // [rsp+DCh] [rbp-14h]
  unsigned __int64 v20; // [rsp+E8h] [rbp-8h]

  v20 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  puts(
    "This license verifier software will allow you to read the flag. However, before you can do so, you must verify that you");
  puts("are licensed to read flag files! This program consumes a license key over stdin. Each program may perform entirely");
  puts(
    "different operations on that input! You must figure out (by reverse engineering this program) what that license key is.");
  puts("Providing the correct license key will net you the flag!\n");
  puts("Unfortunately for you, the license key cannot be reversed. You'll have to crack this program.\n");
  i_1 = 0;
  v12 = ((unsigned __int64)bin_padding & 0xFFFFFFFFFFFFF000LL) - 4096;
  do
    i_2 = i_1++;
  while ( !mprotect((void *)((i_2 << 12) + v12), 4096uLL, 7) );
  for ( i = 0; i <= 0; ++i )
  {
    printf("Changing byte %d/1.\n", (unsigned int)(i + 1));
    printf("Offset (hex) to change: ");
    __isoc99_scanf("%hx", &offset_to_change);
    printf("New value (hex): ");
    __isoc99_scanf("%hhx", &new_hex_value);
    *(_BYTE *)(offset_to_change + v12) = new_hex_value;
    printf("The byte has been changed: *%p = %hhx.\n", (const void *)(v12 + offset_to_change), new_hex_value);
  }
  buf = 0LL;
  v16 = 0LL;
  v17 = 0LL;
  v18 = 0;
  v19 = 0;
  puts("Ready to receive your license key!\n");
  read(0, &buf, 29uLL);
  puts("Initial input:\n");
  putchar(9);
  for ( j = 0; j <= 28; ++j )
    printf("%02x ", *((unsigned __int8 *)&buf + j));
  puts("\n");
  puts("This challenge is now mangling your input using the `md5` mangler. This mangler cannot be reversed.\n");
  MD5_Init(v13);
  MD5_Update(v13, &buf, 29LL);
  MD5_Final(v14, v13);
  memset(&buf, 0, 29uLL);
  buf = v14[0];
  v16 = v14[1];
  puts("This mangled your input, resulting in:\n");
  putchar(9);
  for ( k = 0; k <= 28; ++k )
    printf("%02x ", *((unsigned __int8 *)&buf + k));
  puts("\n");
  puts("The mangling is done! The resulting bytes will be used for the final comparison.\n");
  puts("Final result of mangling input:\n");
  putchar(9);
  for ( m = 0; m <= 28; ++m )
    printf("%02x ", *((unsigned __int8 *)&buf + m));
  puts("\n");
  puts("Expected result:\n");
  putchar(9);
  for ( n = 0; n <= 28; ++n )
    printf("%02x ", EXPECTED_RESULT[n]);
  puts("\n");
  puts("Checking the received license key!\n");
  if ( !memcmp(&buf, EXPECTED_RESULT, 29uLL) )
  {
    win();
    exit(0);
  }
  puts("Wrong! No flag for you!");
  exit(1);
}
```

<img alt="image" src="https://github.com/user-attachments/assets/f304770d-881d-4437-94bf-f235e1769835" />

Let's look at the disassembly view.

```asm showLineNumbers
# ---- snip ----

.text:00000000000024B4                 lea     rax, [rbp+buf]
.text:00000000000024B8                 mov     edx, 1Dh        ; n
.text:00000000000024BD                 lea     rsi, EXPECTED_RESULT ; s2
.text:00000000000024C4                 mov     rdi, rax        ; s1
.text:00000000000024C7                 call    _memcmp
.text:00000000000024CC                 test    eax, eax
.text:00000000000024CE                 jnz     short loc_24E4
.text:00000000000024D0                 mov     eax, 0
.text:00000000000024D5                 call    win
.text:00000000000024DA                 mov     edi, 0          ; status
.text:00000000000024DF                 call    _exit
.text:00000000000024E4 ; ---------------------------------------------------------------------------
.text:00000000000024E4
.text:00000000000024E4 loc_24E4:                               ; CODE XREF: main+4A3↑j
.text:00000000000024E4                 lea     rdi, aWrongNoFlagFor ; "Wrong! No flag for you!"
.text:00000000000024EB                 call    _puts
.text:00000000000024F0                 mov     edi, 1          ; status
.text:00000000000024F5                 call    _exit

# ---- snip ----
```

The `_memcmp` result would be `rax=0` if the values of the hashed user input at `&buf` and `EXPECTED_RESULT` are the same.
This would cause the `test` instruction to set the Zero Flag (ZF), as it would perform bitwise AND of two 0 values.
As we can see, the program then uses a `jnz` to jump to `_exit` if Zero Flag (ZF) is unset (0).
Else, it jumps to `win()`.

So, all in all, if the hashed value is equal to the expected result, we get the flag. However, what if we replace `jnz` with `jz`?
This would cause the program to give us the flag in cases where the hashed value is not equal to the expected result, and hence allow us to pass any random input.

In order to do this, we would have to pass `0x24ce` as offset as that is the location of the `jnz` instruction's byte, and pass `0x74` as the replacement byte as that is the opcode for `jz`.

```
hacker@reverse-engineering~puzzle-patch-easy:~$ /challenge/puzzle-patch-easy 
###
### Welcome to /challenge/puzzle-patch-easy!
###

This license verifier software will allow you to read the flag. However, before you can do so, you must verify that you
are licensed to read flag files! This program consumes a license key over stdin. Each program may perform entirely
different operations on that input! You must figure out (by reverse engineering this program) what that license key is.
Providing the correct license key will net you the flag!

Unfortunately for you, the license key cannot be reversed. You'll have to crack this program.

Changing byte 1/1.
Offset (hex) to change: 0x24ce
New value (hex): 0x74
The byte has been changed: *0x58e2363274ce = 74.
Ready to receive your license key!

abcde
Initial input:

	61 62 63 64 65 0a 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 

This challenge is now mangling your input using the `md5` mangler. This mangler cannot be reversed.

This mangled your input, resulting in:

	b0 b6 a0 a5 a5 3b c4 e5 d8 3f b8 b1 f4 a7 2b 89 00 00 00 00 00 00 00 00 00 00 00 00 00 

The mangling is done! The resulting bytes will be used for the final comparison.

Final result of mangling input:

	b0 b6 a0 a5 a5 3b c4 e5 d8 3f b8 b1 f4 a7 2b 89 00 00 00 00 00 00 00 00 00 00 00 00 00 

Expected result:

	9e 0a 1f fc ec 2a e6 08 8a df 27 6a 35 33 a0 d2 00 00 00 00 00 00 00 00 00 00 00 00 00 

Checking the received license key!

You win! Here is your flag:
pwn.college{4VOxatygoDt8Leb7vJC36o1hFGM.0VO2IDL4ITM0EzW}
```

&nbsp;

## Puzzle Patch (Hard)

```
hacker@reverse-engineering~puzzle-patch-hard:~$ /challenge/puzzle-patch-hard 
###
### Welcome to /challenge/puzzle-patch-hard!
###

This license verifier software will allow you to read the flag. However, before you can do so, you must verify that you
are licensed to read flag files! This program consumes a license key over stdin. Each program may perform entirely
different operations on that input! You must figure out (by reverse engineering this program) what that license key is.
Providing the correct license key will net you the flag!

Unfortunately for you, the license key cannot be reversed. You'll have to crack this program.

Changing byte 1/1.
Offset (hex) to change: 0
New value (hex): 0
The byte has been changed: *0x62630a8cf000 = 0.
Ready to receive your license key!

abcde
Checking the received license key!

Wrong! No flag for you!
```

### `main()`

```c showLineNumbers
void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  int v3; // eax
  unsigned __int8 new_hex_value; // [rsp+2Dh] [rbp-B3h] BYREF
  unsigned __int16 offset_to_change; // [rsp+2Eh] [rbp-B2h] BYREF
  int v6; // [rsp+30h] [rbp-B0h]
  int i; // [rsp+34h] [rbp-ACh]
  unsigned __int64 v8; // [rsp+38h] [rbp-A8h]
  char v9[96]; // [rsp+40h] [rbp-A0h] BYREF
  __int64 v10[2]; // [rsp+A0h] [rbp-40h] BYREF
  __int64 buf; // [rsp+B0h] [rbp-30h] BYREF
  __int64 v12; // [rsp+B8h] [rbp-28h]
  __int64 v13; // [rsp+C0h] [rbp-20h]
  int v14; // [rsp+C8h] [rbp-18h]
  __int16 v15; // [rsp+CCh] [rbp-14h]
  unsigned __int64 v16; // [rsp+D8h] [rbp-8h]

  v16 = __readfsqword(40u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  puts("###");
  printf("### Welcome to %s!\n", *a2);
  puts("###");
  putchar(10);
  puts(
    "This license verifier software will allow you to read the flag. However, before you can do so, you must verify that you");
  puts("are licensed to read flag files! This program consumes a license key over stdin. Each program may perform entirely");
  puts(
    "different operations on that input! You must figure out (by reverse engineering this program) what that license key is.");
  puts("Providing the correct license key will net you the flag!\n");
  puts("Unfortunately for you, the license key cannot be reversed. You'll have to crack this program.\n");
  v6 = 0;
  v8 = ((unsigned __int64)sub_1369 & 0xFFFFFFFFFFFFF000LL) - 4096;
  do
    v3 = v6++;
  while ( !mprotect((void *)((v3 << 12) + v8), 4096uLL, 7) );
  for ( i = 0; i <= 0; ++i )
  {
    printf("Changing byte %d/1.\n", (unsigned int)(i + 1));
    printf("Offset (hex) to change: ");
    __isoc99_scanf("%hx", &offset_to_change);
    printf("New value (hex): ");
    __isoc99_scanf("%hhx", &new_hex_value);
    *(_BYTE *)(offset_to_change + v8) = new_hex_value;
    printf("The byte has been changed: *%p = %hhx.\n", (const void *)(v8 + offset_to_change), new_hex_value);
  }
  buf = 0LL;
  v12 = 0LL;
  v13 = 0LL;
  v14 = 0;
  v15 = 0;
  puts("Ready to receive your license key!\n");
  read(0, &buf, 29uLL);
  MD5_Init(v9);
  MD5_Update(v9, &buf, 29LL);
  MD5_Final(v10, v9);
  memset(&buf, 0, 29uLL);
  buf = v10[0];
  v12 = v10[1];
  puts("Checking the received license key!\n");
  if ( !memcmp(&buf, &EXPECTED_RESULT, 29uLL) )
  {
    win();
    exit(0);
  }
  puts("Wrong! No flag for you!");
  exit(1);
}
```

<img alt="image" src="https://github.com/user-attachments/assets/7746fbd5-7725-40f4-9739-1efd2be6e9e1" />

Lets look at the disassembly view.

```asm showLineNumbers
# ---- snip ----

.text:00000000000023A7                 lea     rax, [rbp+buf]
.text:00000000000023AB                 mov     edx, 1Dh        ; n
.text:00000000000023B0                 lea     rsi, EXPECTED_RESULT ; s2
.text:00000000000023B7                 mov     rdi, rax        ; s1
.text:00000000000023BA                 call    _memcmp
.text:00000000000023BF                 test    eax, eax
.text:00000000000023C1                 jnz     short loc_23D7
.text:00000000000023C3                 mov     eax, 0
.text:00000000000023C8                 call    win
.text:00000000000023CD                 mov     edi, 0          ; status
.text:00000000000023D2                 call    _exit
.text:00000000000023D7 ; ---------------------------------------------------------------------------
.text:00000000000023D7
.text:00000000000023D7 loc_23D7:                               ; CODE XREF: main+301↑j
.text:00000000000023D7                 lea     rdi, aWrongNoFlagFor ; "Wrong! No flag for you!"
.text:00000000000023DE                 call    _puts
.text:00000000000023E3                 mov     edi, 1          ; status
.text:00000000000023E8                 call    _exit

# ---- snip ----
```

The `_memcmp` result would be `rax=0` if the values of the hashed user input at `&buf` and `EXPECTED_RESULT` are the same.
This would cause the `test` instruction to set the Zero Flag (ZF), as it would perform bitwise AND of two 0 values.
As we can see, the program then uses a `jnz` to jump to `_exit` if Zero Flag (ZF) is unset (0).
Else, it jumps to `win()`.

So, all in all, if the hashed value is equal to the expected result, we get the flag. However, what if we replace `jnz` with `jz`?
This would cause the program to give us the flag in cases where the hashed value is not equal to the expected result, and hence allow us to pass any random input.

In order to do this, we would have to pass `0x23c1` as offset as that is the location of the `jnz` instruction's byte, and pass `0x74` as the replacement byte as that is the opcode for `jz`.

```
hacker@reverse-engineering~puzzle-patch-hard:~$ /challenge/puzzle-patch-hard 
###
### Welcome to /challenge/puzzle-patch-hard!
###

This license verifier software will allow you to read the flag. However, before you can do so, you must verify that you
are licensed to read flag files! This program consumes a license key over stdin. Each program may perform entirely
different operations on that input! You must figure out (by reverse engineering this program) what that license key is.
Providing the correct license key will net you the flag!

Unfortunately for you, the license key cannot be reversed. You'll have to crack this program.

Changing byte 1/1.
Offset (hex) to change: 0x23c1
New value (hex): 0x74
The byte has been changed: *0x5718f69e53c1 = 74.
Ready to receive your license key!

abcde
Checking the received license key!

You win! Here is your flag:
pwn.college{AHCbdZU-g-3bj89LQVaaK31zZr9.0FM3IDL4ITM0EzW}
```

&nbsp;

## Patch Perfect (Easy)

```
hacker@reverse-engineering~patch-perfect-easy:~$ /challenge/patch-perfect-easy 
###
### Welcome to /challenge/patch-perfect-easy!
###

This license verifier software will allow you to read the flag. However, before you can do so, you must verify that you
are licensed to read flag files! This program consumes a license key over stdin. Each program may perform entirely
different operations on that input! You must figure out (by reverse engineering this program) what that license key is.
Providing the correct license key will net you the flag!

Unfortunately for you, the license key cannot be reversed. You'll have to crack this program.

In order to ensure code integrity, the code will be hashed and verified.

The pre-crack code integrity hash is:

	ab 78 d1 43 0b f6 4a ce 16 98 cb 48 3c 80 14 92 c2 00 00 00 00 00 00 00 a7 6b 43 

Changing byte 1/2.
Offset (hex) to change: 0
New value (hex): 0
The byte has been changed: *0x5bbf21142000 = 0.
Changing byte 2/2.
Offset (hex) to change: 1
New value (hex): 1
The byte has been changed: *0x5bbf21142001 = 1.
The post-crack code integrity hash is:

	6b cc d1 0a 15 21 4d a9 ec 00 9c d6 45 db 1c eb a6 6b 43 b6 fe 7f 00 00 5d 4a 14 

The code's integrity has been breached, aborting!
```

### `main()`

```c showLineNumbers
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  unsigned __int8 new_hex_value; // [rsp+2Dh] [rbp-F3h] BYREF
  unsigned __int16 offset_to_change; // [rsp+2Eh] [rbp-F2h] BYREF
  int v6; // [rsp+30h] [rbp-F0h]
  int i; // [rsp+34h] [rbp-ECh]
  int j; // [rsp+38h] [rbp-E8h]
  int k; // [rsp+3Ch] [rbp-E4h]
  int m; // [rsp+40h] [rbp-E0h]
  int n; // [rsp+44h] [rbp-DCh]
  int ii; // [rsp+48h] [rbp-D8h]
  int jj; // [rsp+4Ch] [rbp-D4h]
  int kk; // [rsp+50h] [rbp-D0h]
  int mm; // [rsp+54h] [rbp-CCh]
  unsigned __int64 v16; // [rsp+58h] [rbp-C8h]
  char v17[96]; // [rsp+60h] [rbp-C0h] BYREF
  char pre_crack_hash[16]; // [rsp+C0h] [rbp-60h] BYREF
  char post_crack_hash[16]; // [rsp+D0h] [rbp-50h] BYREF
  __int64 v20[2]; // [rsp+E0h] [rbp-40h] BYREF
  __int64 buf; // [rsp+F0h] [rbp-30h] BYREF
  __int64 v22; // [rsp+F8h] [rbp-28h]
  __int64 v23; // [rsp+100h] [rbp-20h]
  int v24; // [rsp+108h] [rbp-18h]
  unsigned __int64 v25; // [rsp+118h] [rbp-8h]

  v25 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  puts("###");
  printf("### Welcome to %s!\n", *argv);
  puts("###");
  putchar(10);
  puts(
    "This license verifier software will allow you to read the flag. However, before you can do so, you must verify that you");
  puts("are licensed to read flag files! This program consumes a license key over stdin. Each program may perform entirely");
  puts(
    "different operations on that input! You must figure out (by reverse engineering this program) what that license key is.");
  puts("Providing the correct license key will net you the flag!\n");
  puts("Unfortunately for you, the license key cannot be reversed. You'll have to crack this program.\n");
  v6 = 0;
  v16 = ((unsigned __int64)bin_padding & 0xFFFFFFFFFFFFF000LL) - 4096;
  do
    v3 = v6++;
  while ( !mprotect((void *)((v3 << 12) + v16), 4096uLL, 7) );
  puts("In order to ensure code integrity, the code will be hashed and verified.\n");
  MD5_Init(v17);
  for ( i = 0; i < v6 - 1; ++i )
    MD5_Update(v17, (i << 12) + v16, 4096LL);
  MD5_Final(pre_crack_hash, v17);
  puts("The pre-crack code integrity hash is:\n");
  putchar(9);
  for ( j = 0; j <= 26; ++j )
    printf("%02x ", (unsigned __int8)pre_crack_hash[j]);
  puts("\n");
  for ( k = 0; k <= 1; ++k )
  {
    printf("Changing byte %d/2.\n", (unsigned int)(k + 1));
    printf("Offset (hex) to change: ");
    __isoc99_scanf("%hx", &offset_to_change);
    printf("New value (hex): ");
    __isoc99_scanf("%hhx", &new_hex_value);
    *(_BYTE *)(offset_to_change + v16) = new_hex_value;
    printf("The byte has been changed: *%p = %hhx.\n", (const void *)(v16 + offset_to_change), new_hex_value);
  }
  MD5_Init(v17);
  for ( m = 0; m < v6 - 1; ++m )
    MD5_Update(v17, (m << 12) + v16, 4096LL);
  MD5_Final(post_crack_hash, v17);
  puts("The post-crack code integrity hash is:\n");
  putchar(9);
  for ( n = 0; n <= 26; ++n )
    printf("%02x ", (unsigned __int8)post_crack_hash[n]);
  puts("\n");
  if ( !memcmp(pre_crack_hash, post_crack_hash, 16uLL) )
  {
    puts("The code's integrity is secure!\n");
    buf = 0LL;
    v22 = 0LL;
    v23 = 0LL;
    v24 = 0;
    puts("Ready to receive your license key!\n");
    read(0, &buf, 27uLL);
    puts("Initial input:\n");
    putchar(9);
    for ( ii = 0; ii <= 26; ++ii )
      printf("%02x ", *((unsigned __int8 *)&buf + ii));
    puts("\n");
    puts("This challenge is now mangling your input using the `md5` mangler. This mangler cannot be reversed.\n");
    MD5_Init(v17);
    MD5_Update(v17, &buf, 27LL);
    MD5_Final(v20, v17);
    memset(&buf, 0, 27uLL);
    buf = v20[0];
    v22 = v20[1];
    puts("This mangled your input, resulting in:\n");
    putchar(9);
    for ( jj = 0; jj <= 26; ++jj )
      printf("%02x ", *((unsigned __int8 *)&buf + jj));
    puts("\n");
    puts("The mangling is done! The resulting bytes will be used for the final comparison.\n");
    puts("Final result of mangling input:\n");
    putchar(9);
    for ( kk = 0; kk <= 26; ++kk )
      printf("%02x ", *((unsigned __int8 *)&buf + kk));
    puts("\n");
    puts("Expected result:\n");
    putchar(9);
    for ( mm = 0; mm <= 26; ++mm )
      printf("%02x ", EXPECTED_RESULT[mm]);
    puts("\n");
    puts("Checking the received license key!\n");
    if ( !memcmp(&buf, EXPECTED_RESULT, 27uLL) )
    {
      win();
      exit(0);
    }
    puts("Wrong! No flag for you!");
    exit(1);
  }
  puts("The code's integrity has been breached, aborting!\n");
  exit(1);
}
```

<img alt="image" src="https://github.com/user-attachments/assets/e023a824-11a0-4e9d-8c0c-9b0ade082495" />

Let's look at the disassembly view.

```asm showLineNumbers
# ---- snip ----

.text:0000000000002733                 lea     rcx, [rbp+post_crack_hash]
.text:0000000000002737                 lea     rax, [rbp+pre_crack_hash]
.text:000000000000273B                 mov     edx, 10h        ; n
.text:0000000000002740                 mov     rsi, rcx        ; s2
.text:0000000000002743                 mov     rdi, rax        ; s1
.text:0000000000002746                 call    _memcmp
.text:000000000000274B                 test    eax, eax
.text:000000000000274D                 jnz     short loc_27BE
.text:000000000000274F                 lea     rdi, aTheCodeSIntegr ; "The code's integrity is secure!\n"
.text:0000000000002756                 call    _puts
.text:000000000000275B                 mov     [rbp+buf], 0
.text:0000000000002763                 mov     [rbp+var_28], 0
.text:000000000000276B                 mov     [rbp+var_20], 0
.text:0000000000002773                 mov     [rbp+var_18], 0
.text:000000000000277A                 lea     rdi, aReadyToReceive ; "Ready to receive your license key!\n"

# ---- snip ----

.text:00000000000027BE ; ---------------------------------------------------------------------------
.text:00000000000027BE
.text:00000000000027BE loc_27BE:                               ; CODE XREF: main+404↑j
.text:00000000000027BE                 lea     rdi, aTheCodeSIntegr_0 ; "The code's integrity has been breached,"...
.text:00000000000027C5                 call    _puts
.text:00000000000027CA                 mov     edi, 1          ; status
.text:00000000000027CF                 call    _exit

# ---- snip ----

.text:00000000000027BE ; ---------------------------------------------------------------------------
.text:00000000000027BE
.text:00000000000027BE loc_27BE:                               ; CODE XREF: main+404↑j
.text:00000000000027BE                 lea     rdi, aTheCodeSIntegr_0 ; "The code's integrity has been breached,"...
.text:00000000000027C5                 call    _puts
.text:00000000000027CA                 mov     edi, 1          ; status
.text:00000000000027CF                 call    _exit

# ---- snip ----
```

The first `_memcmp` result would be `rax=0` if the values of the hashed user input at `pre_crack_hash` and `post_crack_hash` are the same.
This would cause the `test` instruction to set the Zero Flag (ZF), as it would perform bitwise AND of two 0 values.
As we can see, the program then uses a `jnz` to jump to `_exit` if Zero Flag (ZF) is unset (0). Else, it will continue execution.

The second `_memcmp` result would be `rax=0` if the values of the hashed user input at `&buf` and `EXPECTED_RESULT` are the same.
This would cause the `test` instruction to set the Zero Flag (ZF), as it would perform bitwise AND of two 0 values.
As we can see, the program then uses a `jnz` to jump to `_exit` if Zero Flag (ZF) is unset (0).
Else, it jumps to `win()`.

So, all in all, if the hashed value is equal to the expected result, we get the flag. However, what if we replace `jnz` with `jz`?
This would cause the program to give us the flag in cases where the hashed value is not equal to the expected result, and hence allow us to pass any random input.

In order to do this, we would have to pass `0x274d` and `0x29e0` as offsets as those are the locations of `jnz` instruction's byte, and pass `0x74` as the replacement byte as that is the opcode for `jz`.

```
hacker@reverse-engineering~patch-perfect-easy:~$ /challenge/patch-perfect-easy 
###
### Welcome to /challenge/patch-perfect-easy!
###

This license verifier software will allow you to read the flag. However, before you can do so, you must verify that you
are licensed to read flag files! This program consumes a license key over stdin. Each program may perform entirely
different operations on that input! You must figure out (by reverse engineering this program) what that license key is.
Providing the correct license key will net you the flag!

Unfortunately for you, the license key cannot be reversed. You'll have to crack this program.

In order to ensure code integrity, the code will be hashed and verified.

The pre-crack code integrity hash is:

	88 fd 91 be 1f 1b a4 8b d7 e9 28 80 90 4c 89 5b c2 00 00 00 00 00 00 00 47 ea 25 

Changing byte 1/2.
Offset (hex) to change: 0x274d
New value (hex): 0x74
The byte has been changed: *0x62608a63e74d = 74.
Changing byte 2/2.
Offset (hex) to change: 0x29e0
New value (hex): 0x74
The byte has been changed: *0x62608a63e9e0 = 74.
The post-crack code integrity hash is:

	b1 13 cb ba a0 65 ef cc 37 9f 6e 96 ab 6c 09 a1 46 ea 25 e0 fd 7f 00 00 5d ea 63 

The code's integrity is secure!

Ready to receive your license key!

abcde
Initial input:

	61 62 63 64 65 0a 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 

This challenge is now mangling your input using the `md5` mangler. This mangler cannot be reversed.

This mangled your input, resulting in:

	62 46 13 62 43 92 40 49 35 12 c0 2d 7f 2a ed 59 00 00 00 00 00 00 00 00 00 00 00 

The mangling is done! The resulting bytes will be used for the final comparison.

Final result of mangling input:

	62 46 13 62 43 92 40 49 35 12 c0 2d 7f 2a ed 59 00 00 00 00 00 00 00 00 00 00 00 

Expected result:

	d9 f3 00 bf 3e b5 27 c5 a9 06 d1 24 a7 a8 f7 0a 00 00 00 00 00 00 00 00 00 00 00 

Checking the received license key!

You win! Here is your flag:
pwn.college{w_nws7OSeSnuDeBzA0xOrQ8WMOk.0VM3IDL4ITM0EzW}
```

&nbsp;

## Patch Perfect (Hard)

```
hacker@reverse-engineering~patch-perfect-hard:~$ /challenge/patch-perfect-hard 
###
### Welcome to /challenge/patch-perfect-hard!
###

This license verifier software will allow you to read the flag. However, before you can do so, you must verify that you
are licensed to read flag files! This program consumes a license key over stdin. Each program may perform entirely
different operations on that input! You must figure out (by reverse engineering this program) what that license key is.
Providing the correct license key will net you the flag!

Unfortunately for you, the license key cannot be reversed. You'll have to crack this program.

In order to ensure code integrity, the code will be hashed and verified.

Changing byte 1/2.
Offset (hex) to change: 0
New value (hex): 0
The byte has been changed: *0x5d729bd67000 = 0.
Changing byte 2/2.
Offset (hex) to change: 1
New value (hex): 1
The byte has been changed: *0x5d729bd67001 = 1.
The code's integrity has been breached, aborting!
```

### `main()`

```c showLineNumbers
void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  int v3; // eax
  unsigned __int8 new_hex_value; // [rsp+25h] [rbp-DBh] BYREF
  unsigned __int16 offset_to_change; // [rsp+26h] [rbp-DAh] BYREF
  int v6; // [rsp+28h] [rbp-D8h]
  int i; // [rsp+2Ch] [rbp-D4h]
  int j; // [rsp+30h] [rbp-D0h]
  int k; // [rsp+34h] [rbp-CCh]
  unsigned __int64 v10; // [rsp+38h] [rbp-C8h]
  char v11[96]; // [rsp+40h] [rbp-C0h] BYREF
  char pre_crack_hash[16]; // [rsp+A0h] [rbp-60h] BYREF
  char post_crack_hash[16]; // [rsp+B0h] [rbp-50h] BYREF
  __int64 v14[2]; // [rsp+C0h] [rbp-40h] BYREF
  __int64 buf; // [rsp+D0h] [rbp-30h] BYREF
  __int64 v16; // [rsp+D8h] [rbp-28h]
  __int64 v17; // [rsp+E0h] [rbp-20h]
  int v18; // [rsp+E8h] [rbp-18h]
  __int16 v19; // [rsp+ECh] [rbp-14h]
  unsigned __int64 v20; // [rsp+F8h] [rbp-8h]

  v20 = __readfsqword(40u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  puts("###");
  printf("### Welcome to %s!\n", *a2);
  puts("###");
  putchar(10);
  puts(
    "This license verifier software will allow you to read the flag. However, before you can do so, you must verify that you");
  puts("are licensed to read flag files! This program consumes a license key over stdin. Each program may perform entirely");
  puts(
    "different operations on that input! You must figure out (by reverse engineering this program) what that license key is.");
  puts("Providing the correct license key will net you the flag!\n");
  puts("Unfortunately for you, the license key cannot be reversed. You'll have to crack this program.\n");
  v6 = 0;
  v10 = ((unsigned __int64)sub_1369 & 0xFFFFFFFFFFFFF000LL) - 4096;
  do
    v3 = v6++;
  while ( !mprotect((void *)((v3 << 12) + v10), 4096uLL, 7) );
  puts("In order to ensure code integrity, the code will be hashed and verified.\n");
  MD5_Init(v11);
  for ( i = 0; i < v6 - 1; ++i )
    MD5_Update(v11, (i << 12) + v10, 4096LL);
  MD5_Final(pre_crack_hash, v11);
  for ( j = 0; j <= 1; ++j )
  {
    printf("Changing byte %d/2.\n", (unsigned int)(j + 1));
    printf("Offset (hex) to change: ");
    __isoc99_scanf("%hx", &offset_to_change);
    printf("New value (hex): ");
    __isoc99_scanf("%hhx", &new_hex_value);
    *(_BYTE *)(offset_to_change + v10) = new_hex_value;
    printf("The byte has been changed: *%p = %hhx.\n", (const void *)(v10 + offset_to_change), new_hex_value);
  }
  MD5_Init(v11);
  for ( k = 0; k < v6 - 1; ++k )
    MD5_Update(v11, (k << 12) + v10, 4096LL);
  MD5_Final(post_crack_hash, v11);
  if ( !memcmp(pre_crack_hash, post_crack_hash, 16uLL) )
  {
    puts("The code's integrity is secure!\n");
    buf = 0LL;
    v16 = 0LL;
    v17 = 0LL;
    v18 = 0;
    v19 = 0;
    puts("Ready to receive your license key!\n");
    read(0, &buf, 29uLL);
    MD5_Init(v11);
    MD5_Update(v11, &buf, 29LL);
    MD5_Final(v14, v11);
    memset(&buf, 0, 29uLL);
    buf = v14[0];
    v16 = v14[1];
    puts("Checking the received license key!\n");
    if ( !memcmp(&buf, &EXPECTED_RESULT, 29uLL) )
    {
      win();
      exit(0);
    }
    puts("Wrong! No flag for you!");
    exit(1);
  }
  puts("The code's integrity has been breached, aborting!\n");
  exit(1);
}
```

<img alt="image" src="https://github.com/user-attachments/assets/9360cfbb-30c2-4ec8-a90f-e09bb4ccfd5b" />

Disassembly:

```asm showLineNumbers
# ---- snip ----

.text:000000000000214F                 lea     rcx, [rbp+post_crack_hash]
.text:0000000000002153                 lea     rax, [rbp+pre_crack_hash]
.text:0000000000002157                 mov     edx, 10h        ; n
.text:000000000000215C                 mov     rsi, rcx        ; s2
.text:000000000000215F                 mov     rdi, rax        ; s1
.text:0000000000002162                 call    _memcmp
.text:0000000000002167                 test    eax, eax
.text:0000000000002169                 jnz     loc_2252
.text:000000000000216F                 lea     rdi, aTheCodeSIntegr ; "The code's integrity is secure!\n"

# ---- snip ----

.text:0000000000002234                 lea     rax, [rbp+buf]
.text:0000000000002238                 mov     edx, 1Dh        ; n
.text:000000000000223D                 lea     rsi, EXPECTED_RESULT ; s2
.text:0000000000002244                 mov     rdi, rax        ; s1
.text:0000000000002247                 call    _memcmp
.text:000000000000224C                 test    eax, eax
.text:000000000000224E                 jnz     short loc_227C
.text:0000000000002250                 jmp     short loc_2268
.text:0000000000002252 ; ---------------------------------------------------------------------------
.text:0000000000002252
.text:0000000000002252 loc_2252:                               ; CODE XREF: main+342↑j
.text:0000000000002252                 lea     rdi, aTheCodeSIntegr_0 ; "The code's integrity has been breached,"...
.text:0000000000002259                 call    _puts
.text:000000000000225E                 mov     edi, 1          ; status
.text:0000000000002263                 call    _exit

# ---- snip ----
```

The first `_memcmp` result would be `rax=0` if the values of the hashed user input at `pre_crack_hash` and `post_crack_hash` are the same.
This would cause the `test` instruction to set the Zero Flag (ZF), as it would perform bitwise AND of two 0 values.
As we can see, the program then uses a `jnz` to jump to `_exit` if Zero Flag (ZF) is unset (0). Else, it will continue execution.

The second `_memcmp` result would be `rax=0` if the values of the hashed user input at `&buf` and `EXPECTED_RESULT` are the same.
This would cause the `test` instruction to set the Zero Flag (ZF), as it would perform bitwise AND of two 0 values.
As we can see, the program then uses a `jnz` to jump to `_exit` if Zero Flag (ZF) is unset (0).
Else, it jumps to `win()`.

This time, there is a difference in both the `jnz` instructions: 

```asm title="JNZ Short"
.text:000000000000224E                 jnz     short loc_227C
```
Used when offset is under 128 bytes:
- Opcode: `75` (JNZ short)
- Relative Offset: `XX` (The distance to the jump)
- Total bytes: `75 XX`

```asm title="JNZ Near"
.text:0000000000002169                 jnz     loc_2252
```
Used when offset is over 128 bytes:
- Opcode: `0F 85` (JNZ near)
- Relative Offset: `XX XX XX XX` (4-byte displacement)
- Total bytes: `0F 85 XX XX XX XX`

In order to overwrite JNZ near with JZ near, we have to replace the second byte in the Opcode with `0x84`.

In order to solve this challenge, we would have to pass `0x216a` and `0x224e` as offsets as those are the locations of `jnz` instruction's byte, and pass `0x84` and `0x74` as the replacement byte as that is the opcode for `jz`.

```
hacker@reverse-engineering~patch-perfect-hard:~$ /challenge/patch-perfect-hard 
###
### Welcome to /challenge/patch-perfect-hard!
###

This license verifier software will allow you to read the flag. However, before you can do so, you must verify that you
are licensed to read flag files! This program consumes a license key over stdin. Each program may perform entirely
different operations on that input! You must figure out (by reverse engineering this program) what that license key is.
Providing the correct license key will net you the flag!

Unfortunately for you, the license key cannot be reversed. You'll have to crack this program.

In order to ensure code integrity, the code will be hashed and verified.

Changing byte 1/2.
Offset (hex) to change: 0x216a
New value (hex): 0x84
The byte has been changed: *0x58900aa7916a = 84.
Changing byte 2/2.
Offset (hex) to change: 0x224e
New value (hex): 0x74
The byte has been changed: *0x58900aa7924e = 74.
The code's integrity is secure!

Ready to receive your license key!

abcde
Checking the received license key!

You win! Here is your flag:
pwn.college{YNiwod-O5RXrhyhFGbFC_Xq8Bew.0lM3IDL4ITM0EzW}
```

&nbsp;

## Trust the Yancode (Easy)

```
hacker@reverse-engineering~trust-the-yancode-easy:~$ /challenge/trust-the-yancode-easy 
[+] Welcome to /challenge/trust-the-yancode-easy!
[+] This challenge is an custom emulator. It emulates a completely custom
[+] architecture that we call "Yan85"! You'll have to understand the
[+] emulator to understand the architecture, and you'll have to understand
[+] the architecture to understand the code being emulated, and you will
[+] have to understand that code to get the flag. Good luck!
[+]
[+] This is an introductory Yan85 level, where we trigger Yan85 architecture
[+] operations directly. The parts of Yan85 that are used here is the emulated
[+] registers, memory, and system calls.
[+]
[+] This is a *teaching* challenge, which means that it will output
[+] a trace of the Yan85 code as it processes it. The output is here
[+] for you to understand what the challenge is doing, and you should use
[+] it as a guide to help with your reversing of the code.
[+]
[s] IMM b = 0x6b
[s] IMM c = 0x8
[s] IMM a = 0
[s] SYS 0x8 a
[s] ... read_memory

```

### Yan85 Analysis

#### Instructions

The following is the initial analysis of the Yan85 instructions. It can be updated in the further challenges, or as teh program gives more output.

| Yan85 code   | Description |
| :---------------- | :----------- |
| `IMM <reg> = <val>` | Set the register to the value |
| `IMM <reg1> = <reg2>` | Set first register's value to the value in the second register | 
| `SYS <id> <reg>` | Make a syscall based on the identifer, and store the result in the specified register |
| ... `<action>` | Action defined by the syscall is being performed |

#### `read_memory` "syscall"

It seems like the program sets us a `read_memory` call which is equivalent to a `read` syscall.


| ID     | (arg0) unsigned int fd   | (arg1) char *buf   | (arg2) size_t count   |
| :----- | :----------------------- | :----------------- | :-------------------- |
| `0x8`  | `a`                      | `b`                | `c`                   |

So the program sets up a `read_memory` call and read `0x8` bytes from STDIN to `0x6b`.

Let's provide some input.

```
# ---- snip ----

[s] IMM b = 0x6b
[s] IMM c = 0x8
[s] IMM a = 0
[s] SYS 0x8 a
[s] ... read_memory
abcde
[s] ... return value (in register a): 0x6

# ---- snip ----
```

So it read `5` bytes including the newline character, and stored the return value in `a`.

```
# ---- snip ----

[s] IMM b = 0x8b
[s] IMM c = 0x1
[s] IMM a = 0x79
[s] STM *b = a
[s] ADD b c
[s] IMM a = 0xd4
[s] STM *b = a
[s] ADD b c
[s] IMM a = 0xcb
[s] STM *b = a
[s] ADD b c
[s] IMM a = 0x73
[s] STM *b = a
[s] ADD b c
[s] IMM a = 0x86
[s] STM *b = a
[s] ADD b c
[s] IMM a = 0xb5
[s] STM *b = a
[s] ADD b c
[s] IMM a = 0x5b
[s] STM *b = a
[s] ADD b c
[s] IMM a = 0x86
[s] STM *b = a
[s] ADD b c

# ---- snip ----
```

So the program then sets up at array beginning from `0x8b`, and moves some bytes into it one by one.
The final byte string which is moved into the array is: `\x79\xd4\xcb\x73\x86\xb5\x5b\x86`.

Yan85 Emulator:

| Yan85 code   | Description |
| :---------------- | :----------- |
| `IMM <reg> = <val>` | Set the register to the value |
| `IMM <reg1> = <reg2>` | Set first register's value to the value in the second register | 
| `SYS <id> <reg>` | Make a syscall based on the identifer, and store the result in the specified register |
| ... `<action>` | Action defined by the syscall is being performed |
| `ADD <reg1> <reg2>` | Add the values in register 1 and 2 and store result in register 1 |

```
# ---- snip -----

s] IMM a = 0x1
[s] IMM b = 0
[s] IMM c = 0x1
[s] IMM d = 0x49
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
I[s] ... return value (in register a): 0x1
[s] IMM d = 0x4e
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
N[s] ... return value (in register a): 0x1
[s] IMM d = 0x43
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
C[s] ... return value (in register a): 0x1
[s] IMM d = 0x4f
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
O[s] ... return value (in register a): 0x1
[s] IMM d = 0x52
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
R[s] ... return value (in register a): 0x1
[s] IMM d = 0x52
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
R[s] ... return value (in register a): 0x1
[s] IMM d = 0x45
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
E[s] ... return value (in register a): 0x1
[s] IMM d = 0x43
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
C[s] ... return value (in register a): 0x1
[s] IMM d = 0x54
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
T[s] ... return value (in register a): 0x1
[s] IMM d = 0x21
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
![s] ... return value (in register a): 0x1
[s] IMM a = 0x1
[s] IMM d = 0xa
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write

[s] ... return value (in register a): 0x1

# ---- snip ----
```

The program also writes the bytes `"INCORRECT!"` to STDOUT one by one, using the `write` syscall.

#### `write` "syscall"

| ID     | (arg0) unsigned int fd   | (arg1) const char *buf   | (arg2) size_t count   |
| :----- | :----------------------- | :----------------------- | :-------------------- |
| `0X20` | `a`                      | `b`                      | `c`                   |

Finally it exits.

#### `exit` "syscall"

```
# ---- snip ----

[s] SYS 0x1 a
[s] ... exit
```

| ID     | (arg0) int error_code    | 
| :----- | :----------------------- |
| `0x1`  | `a`                      |

In order to solve this challenge, let's provide the byte string which it initializes.

```
hacker@reverse-engineering~trust-the-yancode-easy:~$ printf "\x79\xd4\xcb\x73\x86\xb5\x5b\x86\x23" | /challenge/trust-the-yancode-easy
[+] Welcome to /challenge/trust-the-yancode-easy!
[+] This challenge is an custom emulator. It emulates a completely custom
[+] architecture that we call "Yan85"! You'll have to understand the
[+] emulator to understand the architecture, and you'll have to understand
[+] the architecture to understand the code being emulated, and you will
[+] have to understand that code to get the flag. Good luck!
[+]
[+] This is an introductory Yan85 level, where we trigger Yan85 architecture
[+] operations directly. The parts of Yan85 that are used here is the emulated
[+] registers, memory, and system calls.
[+]
[+] This is a *teaching* challenge, which means that it will output
[+] a trace of the Yan85 code as it processes it. The output is here
[+] for you to understand what the challenge is doing, and you should use
[+] it as a guide to help with your reversing of the code.
[+]
[s] IMM b = 0x6b
[s] IMM c = 0x8
[s] IMM a = 0
[s] SYS 0x8 a
[s] ... read_memory
[s] ... return value (in register a): 0x8
[s] IMM b = 0x8b
[s] IMM c = 0x1
[s] IMM a = 0x79
[s] STM *b = a
[s] ADD b c
[s] IMM a = 0xd4
[s] STM *b = a
[s] ADD b c
[s] IMM a = 0xcb
[s] STM *b = a
[s] ADD b c
[s] IMM a = 0x73
[s] STM *b = a
[s] ADD b c
[s] IMM a = 0x86
[s] STM *b = a
[s] ADD b c
[s] IMM a = 0xb5
[s] STM *b = a
[s] ADD b c
[s] IMM a = 0x5b
[s] STM *b = a
[s] ADD b c
[s] IMM a = 0x86
[s] STM *b = a
[s] ADD b c
[s] IMM a = 0x1
[s] IMM b = 0
[s] IMM c = 0x1
[s] IMM d = 0x43
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
C[s] ... return value (in register a): 0x1
[s] IMM d = 0x4f
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
O[s] ... return value (in register a): 0x1
[s] IMM d = 0x52
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
R[s] ... return value (in register a): 0x1
[s] IMM d = 0x52
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
R[s] ... return value (in register a): 0x1
[s] IMM d = 0x45
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
E[s] ... return value (in register a): 0x1
[s] IMM d = 0x43
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
C[s] ... return value (in register a): 0x1
[s] IMM d = 0x54
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
T[s] ... return value (in register a): 0x1
[s] IMM d = 0x21
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
![s] ... return value (in register a): 0x1
[s] IMM d = 0x20
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
 [s] ... return value (in register a): 0x1
[s] IMM d = 0x59
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
Y[s] ... return value (in register a): 0x1
[s] IMM d = 0x6f
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
o[s] ... return value (in register a): 0x1
[s] IMM d = 0x75
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
u[s] ... return value (in register a): 0x1
[s] IMM d = 0x72
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
r[s] ... return value (in register a): 0x1
[s] IMM d = 0x20
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
 [s] ... return value (in register a): 0x1
[s] IMM d = 0x66
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
f[s] ... return value (in register a): 0x1
[s] IMM d = 0x6c
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
l[s] ... return value (in register a): 0x1
[s] IMM d = 0x61
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
a[s] ... return value (in register a): 0x1
[s] IMM d = 0x67
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
g[s] ... return value (in register a): 0x1
[s] IMM d = 0x3a
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
:[s] ... return value (in register a): 0x1
[s] IMM d = 0xa
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write

[s] ... return value (in register a): 0x1
[s] IMM d = 0x2f
[s] IMM b = 0
[s] STM *b = d
[s] IMM d = 0x66
[s] IMM b = 0x1
[s] STM *b = d
[s] IMM d = 0x6c
[s] IMM b = 0x2
[s] STM *b = d
[s] IMM d = 0x61
[s] IMM b = 0x3
[s] STM *b = d
[s] IMM d = 0x67
[s] IMM b = 0x4
[s] STM *b = d
[s] IMM d = 0
[s] IMM b = 0x5
[s] STM *b = d
[s] IMM a = 0
[s] IMM b = 0
[s] SYS 0x10 a
[s] ... open
[s] ... return value (in register a): 0x3
[s] IMM c = 0x64
[s] SYS 0x8 c
[s] ... read_memory
[s] ... return value (in register c): 0x39
[s] IMM a = 0x1
[s] SYS 0x20 c
[s] ... write
pwn.college{ks-9GPm_6puqSjEYA-bLxxBHRy3.01M3IDL4ITM0EzW}
[s] ... return value (in register c): 0x39
[s] IMM a = 0
[s] IMM d = 0xa
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
[s] ... return value (in register a): 0xff
[s] SYS 0x1 a
[s] ... exit
```

We get the flag, and also get to see some more functionality from the program. Let's analyze that as well.

This time, the `write` syscall writes a different message `"CORRECT! Your flag:"` to STDOUT.

```
# ---- snip ----

s] IMM a = 0x1
[s] IMM b = 0
[s] IMM c = 0x1
[s] IMM d = 0x43
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
C[s] ... return value (in register a): 0x1
[s] IMM d = 0x4f
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
O[s] ... return value (in register a): 0x1
[s] IMM d = 0x52
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
R[s] ... return value (in register a): 0x1
[s] IMM d = 0x52
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
R[s] ... return value (in register a): 0x1
[s] IMM d = 0x45
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
E[s] ... return value (in register a): 0x1
[s] IMM d = 0x43
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
C[s] ... return value (in register a): 0x1
[s] IMM d = 0x54
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
T[s] ... return value (in register a): 0x1
[s] IMM d = 0x21
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
![s] ... return value (in register a): 0x1
[s] IMM d = 0x20
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
 [s] ... return value (in register a): 0x1
[s] IMM d = 0x59
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
Y[s] ... return value (in register a): 0x1
[s] IMM d = 0x6f
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
o[s] ... return value (in register a): 0x1
[s] IMM d = 0x75
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
u[s] ... return value (in register a): 0x1
[s] IMM d = 0x72
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
r[s] ... return value (in register a): 0x1
[s] IMM d = 0x20
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
 [s] ... return value (in register a): 0x1
[s] IMM d = 0x66
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
f[s] ... return value (in register a): 0x1
[s] IMM d = 0x6c
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
l[s] ... return value (in register a): 0x1
[s] IMM d = 0x61
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
a[s] ... return value (in register a): 0x1
[s] IMM d = 0x67
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
g[s] ... return value (in register a): 0x1
[s] IMM d = 0x3a
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
:[s] ... return value (in register a): 0x1
[s] IMM d = 0xa
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write

[s] ... return value (in register a): 0x1

# ---- snip ----
```

It then crafts the string `/flag\00`.

```
# ---- snip ----

[s] IMM d = 0x2f
[s] IMM b = 0
[s] STM *b = d
[s] IMM d = 0x66
[s] IMM b = 0x1
[s] STM *b = d
[s] IMM d = 0x6c
[s] IMM b = 0x2
[s] STM *b = d
[s] IMM d = 0x61
[s] IMM b = 0x3
[s] STM *b = d
[s] IMM d = 0x67
[s] IMM b = 0x4
[s] STM *b = d
[s] IMM d = 0
[s] IMM b = 0x5
[s] STM *b = d

# ---- snip ----
```

Then makes the `open` syscall, opening the flag file at location `0`

```
# ---- snip ----

[s] IMM a = 0
[s] IMM b = 0
[s] SYS 0x10 a
[s] ... open
[s] ... return value (in register a): 0x3

# ---- snip ----
```

#### `open` "syscall"

| ID     | const char *filename     | (arg1) const char *buf   | (arg2) size_t count   |
| :----- | :----------------------- | :----------------------- | :-------------------- |
| `0x10` | `b`                      | `a`                      | `c`                   |

Next, it reads the contents of the `/flag` file to location `0`.

```
# ---- snip ----

[s] IMM c = 0x64
[s] SYS 0x8 c
[s] ... read_memory
[s] ... return value (in register c): 0x39

# ---- snip ----
```

Then the program, write out the file to STDOUT.

```
# ---- snip ----

[s] IMM a = 0x1
[s] SYS 0x20 c
[s] ... write
pwn.college{ks-9GPm_6puqSjEYA-bLxxBHRy3.01M3IDL4ITM0EzW}
[s] ... return value (in register c): 0x39
[s] IMM a = 0
[s] IMM d = 0xa
[s] STM *b = d
[s] SYS 0x20 a
[s] ... write
[s] ... return value (in register a): 0xff
[s] SYS 0x1 a
[s] ... exit
```

That was it for this challenge.

&nbsp;

## Trust the Yancode (Hard)

