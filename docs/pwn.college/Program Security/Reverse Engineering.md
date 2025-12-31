---
custom_edit_url: null
sidebar_position: 1
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

# The 'Expected result' bytes from our terminal output
expected_hex = [
    0x65, 0x67, 0x68, 0x6c, 0x6b, 0x68, 0x6c, 0x6c, 
    0x6d, 0x6d, 0x6e, 0x6f, 0x71, 0x72, 0x75
]

# Step 1: Undo the Swap (indexes 3 and 5)
# The challenge swapped 3 and 5, so we swap them back to get the 'sorted' state
expected_hex[3], expected_hex[5] = expected_hex[5], expected_hex[3]

# Step 2: Convert to characters
# Since the 'sort' and 'reverse' manglers only move characters around 
# without changing their value, we just need the characters themselves.
input_chars = [chr(b) for b in expected_hex]

# Because 'sort' was used, the actual order of our input doesn't 
# matter as much as the content, BUT to be safe, we reverse the 
# list to account for the 'reverse' mangler.
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

# 1. The 'key' bytes from your IDA screenshot
target_key = [
    0xA0, 0xAC, 0xB4, 0xB5, 0xB7, 0xB7, 0xC1, 0xC1, 0xC6, 
    0xCB, 0xD9, 0xDC, 0xE3, 0xE5, 0xE7, 0xE8, 0xEB, 0xFB
]

# 2. The XOR keys used in the modulo 3 loop
xor_keys = [218, 146, 173]

# Because the sort happened last, we don't know the original index (i).
# We need to find which character C, when XORed with xor_keys[i % 3], 
# results in one of the values in target_key.

input_chars = []

# We will try to map each target byte back to a likely original character.
# Since XOR is its own inverse: (input ^ key) = target  => (target ^ key) = input
for i in range(18):
    # The program expects input[i] ^ xor_keys[i % 3] == target[some_index]
    # But since it's sorted, we can try to "unsort" it by matching keys.
    # For a license key, we'll try to find a combination that looks like text.
    
    # We can reconstruct the original by applying the XOR to the target 
    # and seeing what we get.
    val = target_key[i] ^ xor_keys[i % 3]
    input_chars.append(chr(val))

# print("Potential License Key: " + "".join(input_chars))
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
