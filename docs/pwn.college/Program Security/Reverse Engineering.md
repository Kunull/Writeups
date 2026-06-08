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

<figure style={{ textAlign: 'center' }}>
<img alt="image" src="https://github.com/user-attachments/assets/8c39503b-9edc-42e8-8c7e-ca8134217e85" />
</figure>

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

<figure style={{ textAlign: 'center' }}>
<img alt="image" src="https://github.com/user-attachments/assets/b7843599-5d1a-4ebd-9be2-ccbae95934b7" />
</figure>

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

<figure style={{ textAlign: 'center' }}>
<img alt="image" src="https://github.com/user-attachments/assets/6fb73a5f-e3bb-43d5-a4ec-64284f03213f" />
</figure>

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

<figure style={{ textAlign: 'center' }}>
<img alt="image" src="https://github.com/user-attachments/assets/d44c214b-259e-40cf-bf85-0d1507ec31c8" />
</figure>

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

<figure style={{ textAlign: 'center' }}>
<img alt="image" src="https://github.com/user-attachments/assets/3a845cd5-a542-4cf8-8293-010eee2b9ea0" />
</figure>

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

<figure style={{ textAlign: 'center' }}>
<img alt="image" src="https://github.com/user-attachments/assets/6966a2cf-60d7-4547-a254-5369bd519f46" />
</figure>

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

<figure style={{ textAlign: 'center' }}>
<img alt="image" src="https://github.com/user-attachments/assets/a8bd4260-ca33-4673-b1af-f104949797b9" />
</figure>

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

<figure style={{ textAlign: 'center' }}>
<img alt="image" src="https://github.com/user-attachments/assets/5909cff7-5316-4723-9865-e0faa88c5faf" />
</figure>

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

<figure style={{ textAlign: 'center' }}>
<img alt="image" src="https://github.com/user-attachments/assets/ff5b949c-5fa5-4bcc-afe7-287540b55058" />
</figure>

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

```py title="~/script.py" showLineNumbers
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

<figure style={{ textAlign: 'center' }}>
<img alt="image" src="https://github.com/user-attachments/assets/cda7cb67-781f-48b2-a8fd-144d0b5b09dc" />
</figure>

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

<figure style={{ textAlign: 'center' }}>
<img alt="image" src="https://github.com/user-attachments/assets/4b2d46d5-563c-4b2a-9f26-1265508f73e1" />
</figure>

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
.text:0000000000002035 ; ------------------------------------------------------------------------.text:0000000000002035
.text:0000000000002035 loc_2035:                               ; CODE XREF: main+4A3↑j
.text:0000000000002035                 lea     rdi, aWrongNoFlagFor ; "Wrong! No flag for you!"
.text:000000000000203C                 call    _puts
.text:0000000000002041                 mov     edi, 1          ; status
.text:0000000000002046                 call    _exit

# ---- snip ----
---
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

<figure style={{ textAlign: 'center' }}>
<img alt="image" src="https://github.com/user-attachments/assets/1ed28d08-6885-4efb-b101-6bb5ef574bbe" />
</figure>

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
.text:0000000000001E49 ; ------------------------------------------------------------------------.text:0000000000001E49
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

<figure style={{ textAlign: 'center' }}>
<img alt="image" src="https://github.com/user-attachments/assets/f304770d-881d-4437-94bf-f235e1769835" />
</figure>

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
.text:00000000000024E4 ; ------------------------------------------------------------------------.text:00000000000024E4
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

<figure style={{ textAlign: 'center' }}>
<img alt="image" src="https://github.com/user-attachments/assets/7746fbd5-7725-40f4-9739-1efd2be6e9e1" />
</figure>

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
.text:00000000000023D7 ; ------------------------------------------------------------------------.text:00000000000023D7
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

<figure style={{ textAlign: 'center' }}>
<img alt="image" src="https://github.com/user-attachments/assets/e023a824-11a0-4e9d-8c0c-9b0ade082495" />
</figure>

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

.text:00000000000027BE ; ------------------------------------------------------------------------.text:00000000000027BE
.text:00000000000027BE loc_27BE:                               ; CODE XREF: main+404↑j
.text:00000000000027BE                 lea     rdi, aTheCodeSIntegr_0 ; "The code's integrity has been breached,"...
.text:00000000000027C5                 call    _puts
.text:00000000000027CA                 mov     edi, 1          ; status
.text:00000000000027CF                 call    _exit

# ---- snip ----

.text:00000000000027BE ; ------------------------------------------------------------------------.text:00000000000027BE
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

<figure style={{ textAlign: 'center' }}>
<img alt="image" src="https://github.com/user-attachments/assets/9360cfbb-30c2-4ec8-a90f-e09bb4ccfd5b" />
</figure>

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
.text:0000000000002252 ; ------------------------------------------------------------------------.text:0000000000002252
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

This challenge introduces a custom CPU emulator called **Yan85** — a fictional architecture with its own registers, memory model, and syscall interface. The goal is to reverse-engineer what the emulated program does, figure out what input it expects, and provide it to trigger the "CORRECT" path that prints the flag.

The challenge helpfully traces every instruction as it executes, making this an exercise in reading and understanding an unfamiliar ISA from its runtime behavior.

### Registers

The emulator uses at least four named registers: `a`, `b`, `c`, and `d`.

### Instruction Set

From observing the trace, we can identify the following instructions:

| Instruction | Behavior |
|---|---|
| `IMM <reg> = <val>` | Load an immediate value into a register |
| `IMM <reg1> = <reg2>` | Copy one register's value into another |
| `STM *<reg1> = <reg2>` | Store the value of `reg2` into the memory address pointed to by `reg1` |
| `ADD <reg1> <reg2>` | Add `reg2` into `reg1` (in-place) |
| `SYS <id> <reg>` | Invoke a syscall, return value stored in `<reg>` |

### Syscall Table

| ID | Name | arg0 | arg1 | arg2 |
|---|---|---|---|---|
| `0x01` | `exit` | `a` (exit code) | | |
| `0x08` | `read` | `a` (fd) | `b` (buf addr) | `c` (count) |
| `0x10` | `open` | `b` (filename addr) | `a` (flags) | |
| `0x20` | `write` | `a` (fd) | `b` (buf addr) | `c` (count) |

### Tracing the Program

#### Step 1: Read Input

```
IMM b = 0x6b    ; buf = 0x6b
IMM c = 0x8     ; count = 8
IMM a = 0       ; fd = 0 (stdin)
SYS 0x8 a       ; read(stdin, 0x6b, 8)
```

The program reads **8 bytes** from stdin into memory address `0x6b`. The return value (bytes read) is stored in `a`.

#### Step 2: Build a Reference Array

Starting at address `0x8b`, the program writes 8 bytes into memory one at a time:

```
IMM b = 0x8b
IMM c = 0x1
; write 0x79 → [0x8b]
; write 0xd4 → [0x8c]
; write 0xcb → [0x8d]
; write 0x73 → [0x8e]
; write 0x86 → [0x8f]
; write 0xb5 → [0x90]
; write 0x5b → [0x91]
; write 0x86 → [0x92]
```

This hardcodes the expected answer at `0x8b`:

```
\x79\xd4\xcb\x73\x86\xb5\x5b\x86
```

At this point, the program presumably compares our input (at `0x6b`) against this reference (at `0x8b`). If they don't match, it prints `INCORRECT!\n` and exits. If they match, it continues.

#### Step 3: Print the Flag

On a correct match, the program:

1. Prints `CORRECT! Your flag:\n` via repeated single-byte `write` syscalls
2. Constructs the string `/flag\x00` in memory starting at address `0`
3. Calls `open("/flag", 0)`, returns fd `3`
4. Reads up to `0x64` (100) bytes from the flag file into the buffer at `0`
5. Writes the entire flag to stdout
6. Calls `exit`

### Solution

The required input is exactly the 8-byte reference sequence the program hardcodes:

```
hacker@reverse-engineering~trust-the-yancode-easy:~$ printf "\x79\xd4\xcb\x73\x86\xb5\x5b\x86" | /challenge/trust-the-yancode-easy | grep "pwn.college"
pwn.college{ks-9GPm_6puqSjEYA-bLxxBHRy3.01M3IDL4ITM0EzW}
```

&nbsp;

## Trust the Yancode (Hard)

```
hacker@reverse-engineering~trust-the-yancode-hard:~$ /challenge/trust-the-yancode-hard
[+] Welcome to /challenge/trust-the-yancode-hard!
[+] This challenge is an custom emulator. It emulates a completely custom
[+] architecture that we call "Yan85"! You'll have to understand the
[+] emulator to understand the architecture, and you'll have to understand
[+] the architecture to understand the code being emulated, and you will
[+] have to understand that code to get the flag. Good luck!
[+]
[+] This is an introductory Yan85 level, where we trigger Yan85 architecture
[+] operations directly. The parts of Yan85 that are used here is the emulated
[+] registers, memory, and system calls.
```

Unlike the easy version, there is no execution trace — the Yan85 operations are inlined as direct C function calls in the binary. Let's open it in a decompiler.

### Decompilation

```c title="/challenge/trust-the-yancode-hard :: main() :: Pseudocode" showLineNumbers
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  char v4[256]; // [rsp+10h] [rbp-110h] BYREF
  int v5; // [rsp+110h] [rbp-10h]
  __int16 v6; // [rsp+114h] [rbp-Ch]
  char v7; // [rsp+116h] [rbp-Ah]
  _BYTE v8[9]; // [rsp+117h] [rbp-9h] BYREF
  *(_QWORD *)&v8[1] = __readfsqword(0x28u);
  printf("[+] Welcome to %s!\n", *a2);
  puts("[+] This challenge is an custom emulator. It emulates a completely custom");
  puts("[+] architecture that we call \"Yan85\"! You'll have to understand the");
  puts("[+] emulator to understand the architecture, and you'll have to understand");
  puts("[+] the architecture to understand the code being emulated, and you will");
  puts("[+] have to understand that code to get the flag. Good luck!");
  puts("[+]");
  puts("[+] This is an introductory Yan85 level, where we trigger Yan85 architecture");
  puts("[+] operations directly. The parts of Yan85 that are used here is the emulated");
  puts("[+] registers, memory, and system calls.");
  setvbuf(stdout, 0LL, 2, 1uLL);
  memset(v4, 0, sizeof(v4));
  v5 = 0;
  v6 = 0;
  v7 = 0;
  sub_1A97(v4, 0LL, v8);  // run the emulator with a 256-byte memory array
  return 0LL;
}
```

```c title="/challenge/trust-the-yancode-hard :: sub_1A97() :: Pseudocode" showLineNumbers
__int64 __fastcall sub_1A97(__int64 a1)
{
  _BOOL4 v2; // [rsp+1Ch] [rbp-4h]

  // sub_1533 matches the easy trace's IMM instruction — sets a register to an
  // immediate value. sub_1896 matches SYS. Here: IMM b=86 (buf), IMM c=4
  // (count), IMM a=0 (stdin), SYS 0x8 a → read(stdin, mem[86], 4).
  sub_1533(a1, 8LL, 86LL);
  sub_1533(a1, 32LL, 4LL);
  sub_1533(a1, 16LL, 0LL);
  sub_1896(a1, 8LL, 16LL);

  // sub_1687 matches STM — stores a register value into the address held by
  // another register. sub_1568 matches ADD. This block builds the 4-byte
  // reference array at mem[118]: IMM b=118, IMM c=1 (step), then for each
  // byte: IMM a=<val>, STM *b=a, ADD b c to advance the pointer.
  sub_1533(a1, 8LL, 118LL);
  sub_1533(a1, 32LL, 1LL);
  sub_1533(a1, 16LL, 124LL);   // 0x7c
  sub_1687(a1, 8LL, 16LL);
  sub_1568(a1, 8LL, 32LL);
  sub_1533(a1, 16LL, 227LL);   // 0xe3
  sub_1687(a1, 8LL, 16LL);
  sub_1568(a1, 8LL, 32LL);
  sub_1533(a1, 16LL, 138LL);   // 0x8a
  sub_1687(a1, 8LL, 16LL);
  sub_1568(a1, 8LL, 32LL);
  sub_1533(a1, 16LL, 120LL);   // 0x78
  sub_1687(a1, 8LL, 16LL);
  sub_1568(a1, 8LL, 32LL);

  // Direct memcmp between the reference at mem[118] and our input at mem[86].
  // No transformation — the correct input is exactly those four bytes.
  v2 = memcmp((const void *)(a1 + 118), (const void *)(a1 + 86), 4uLL) == 0;

  sub_1533(a1, 16LL, 1LL);
  sub_1533(a1, 8LL, 0LL);
  sub_1533(a1, 32LL, 1LL);
  if ( v2 )
  {
    // CORRECT path: repeated IMM d=<ascii>, STM *b=d, SYS 0x2 a (write)
    // sequences spell out "CORRECT! Your flag:\n" one byte at a time.
    sub_1533(a1, 64LL, 67LL);   // 'C'
    sub_1687(a1, 8LL, 64LL);
    sub_1896(a1, 2LL, 16LL);
    sub_1533(a1, 64LL, 79LL);   // 'O'
    sub_1687(a1, 8LL, 64LL);
    sub_1896(a1, 2LL, 16LL);
    sub_1533(a1, 64LL, 82LL);   // 'R'
    sub_1687(a1, 8LL, 64LL);
    sub_1896(a1, 2LL, 16LL);
    sub_1533(a1, 64LL, 82LL);   // 'R'
    sub_1687(a1, 8LL, 64LL);
    sub_1896(a1, 2LL, 16LL);
    sub_1533(a1, 64LL, 69LL);   // 'E'
    sub_1687(a1, 8LL, 64LL);
    sub_1896(a1, 2LL, 16LL);
    sub_1533(a1, 64LL, 67LL);   // 'C'
    sub_1687(a1, 8LL, 64LL);
    sub_1896(a1, 2LL, 16LL);
    sub_1533(a1, 64LL, 84LL);   // 'T'
    sub_1687(a1, 8LL, 64LL);
    sub_1896(a1, 2LL, 16LL);
    sub_1533(a1, 64LL, 33LL);   // '!'
    sub_1687(a1, 8LL, 64LL);
    sub_1896(a1, 2LL, 16LL);
    sub_1533(a1, 64LL, 32LL);   // ' '
    sub_1687(a1, 8LL, 64LL);
    sub_1896(a1, 2LL, 16LL);
    sub_1533(a1, 64LL, 89LL);   // 'Y'
    sub_1687(a1, 8LL, 64LL);
    sub_1896(a1, 2LL, 16LL);
    sub_1533(a1, 64LL, 111LL);  // 'o'
    sub_1687(a1, 8LL, 64LL);
    sub_1896(a1, 2LL, 16LL);
    sub_1533(a1, 64LL, 117LL);  // 'u'
    sub_1687(a1, 8LL, 64LL);
    sub_1896(a1, 2LL, 16LL);
    sub_1533(a1, 64LL, 114LL);  // 'r'
    sub_1687(a1, 8LL, 64LL);
    sub_1896(a1, 2LL, 16LL);
    sub_1533(a1, 64LL, 32LL);   // ' '
    sub_1687(a1, 8LL, 64LL);
    sub_1896(a1, 2LL, 16LL);
    sub_1533(a1, 64LL, 102LL);  // 'f'
    sub_1687(a1, 8LL, 64LL);
    sub_1896(a1, 2LL, 16LL);
    sub_1533(a1, 64LL, 108LL);  // 'l'
    sub_1687(a1, 8LL, 64LL);
    sub_1896(a1, 2LL, 16LL);
    sub_1533(a1, 64LL, 97LL);   // 'a'
    sub_1687(a1, 8LL, 64LL);
    sub_1896(a1, 2LL, 16LL);
    sub_1533(a1, 64LL, 103LL);  // 'g'
    sub_1687(a1, 8LL, 64LL);
    sub_1896(a1, 2LL, 16LL);
    sub_1533(a1, 64LL, 58LL);   // ':'
    sub_1687(a1, 8LL, 64LL);
    sub_1896(a1, 2LL, 16LL);
    sub_1533(a1, 64LL, 10LL);   // '\n'
    sub_1687(a1, 8LL, 64LL);
    sub_1896(a1, 2LL, 16LL);

    // Build "/flag\0" at mem[0] by writing each character with IMM b=<offset>,
    // STM *b=d. Then SYS 0x10 (open), SYS 0x8 (read), SYS 0x20 (write) to
    // read and print the flag file.
    sub_1533(a1, 64LL, 47LL);   // '/'
    sub_1533(a1, 8LL, 0LL);
    sub_1687(a1, 8LL, 64LL);
    sub_1533(a1, 64LL, 102LL);  // 'f'
    sub_1533(a1, 8LL, 1LL);
    sub_1687(a1, 8LL, 64LL);
    sub_1533(a1, 64LL, 108LL);  // 'l'
    sub_1533(a1, 8LL, 2LL);
    sub_1687(a1, 8LL, 64LL);
    sub_1533(a1, 64LL, 97LL);   // 'a'
    sub_1533(a1, 8LL, 3LL);
    sub_1687(a1, 8LL, 64LL);
    sub_1533(a1, 64LL, 103LL);  // 'g'
    sub_1533(a1, 8LL, 4LL);
    sub_1687(a1, 8LL, 64LL);
    sub_1533(a1, 64LL, 0LL);    // '\0'
    sub_1533(a1, 8LL, 5LL);
    sub_1687(a1, 8LL, 64LL);
    sub_1533(a1, 16LL, 0LL);
    sub_1533(a1, 8LL, 0LL);
    sub_1896(a1, 1LL, 16LL);    // open("/flag", 0)
    sub_1533(a1, 32LL, 100LL);
    sub_1896(a1, 8LL, 32LL);    // read(fd, mem[0], 100)
    sub_1533(a1, 16LL, 1LL);
    sub_1896(a1, 2LL, 32LL);    // write(stdout, mem[0], bytes_read)
    sub_1533(a1, 16LL, 0LL);
  }
  else
  {
    // INCORRECT path: same IMM/STM/SYS write pattern, printing "INCORRECT!\n"
    // one character at a time before falling through to exit.
    sub_1533(a1, 64LL, 73LL);   // 'I'
    sub_1687(a1, 8LL, 64LL);
    sub_1896(a1, 2LL, 16LL);
    sub_1533(a1, 64LL, 78LL);   // 'N'
    sub_1687(a1, 8LL, 64LL);
    sub_1896(a1, 2LL, 16LL);
    sub_1533(a1, 64LL, 67LL);   // 'C'
    sub_1687(a1, 8LL, 64LL);
    sub_1896(a1, 2LL, 16LL);
    sub_1533(a1, 64LL, 79LL);   // 'O'
    sub_1687(a1, 8LL, 64LL);
    sub_1896(a1, 2LL, 16LL);
    sub_1533(a1, 64LL, 82LL);   // 'R'
    sub_1687(a1, 8LL, 64LL);
    sub_1896(a1, 2LL, 16LL);
    sub_1533(a1, 64LL, 82LL);   // 'R'
    sub_1687(a1, 8LL, 64LL);
    sub_1896(a1, 2LL, 16LL);
    sub_1533(a1, 64LL, 69LL);   // 'E'
    sub_1687(a1, 8LL, 64LL);
    sub_1896(a1, 2LL, 16LL);
    sub_1533(a1, 64LL, 67LL);   // 'C'
    sub_1687(a1, 8LL, 64LL);
    sub_1896(a1, 2LL, 16LL);
    sub_1533(a1, 64LL, 84LL);   // 'T'
    sub_1687(a1, 8LL, 64LL);
    sub_1896(a1, 2LL, 16LL);
    sub_1533(a1, 64LL, 33LL);   // '!'
    sub_1687(a1, 8LL, 64LL);
    sub_1896(a1, 2LL, 16LL);
    sub_1533(a1, 16LL, 1LL);
  }

  // Trailing newline write then SYS 0x1 (exit) — shared by both paths.
  sub_1533(a1, 64LL, 10LL);     // '\n'
  sub_1687(a1, 8LL, 64LL);
  sub_1896(a1, 2LL, 16LL);
  return sub_1896(a1, 16LL, 16LL);  // exit
}
```

```c title="/challenge/trust-the-yancode-hard :: sub_1568() :: Pseudocode" showLineNumbers
__int64 __fastcall sub_1568(__int64 a1, unsigned __int8 a2, unsigned __int8 a3)
{
  char v3; // bl
  char v4; // al

  // sub_1363 reads a register by its bitmask id; sub_1415 writes one. This
  // function reads two registers, adds them, and writes the result back to the
  // first — confirming sub_1568 is ADD reg1, reg2.
  v3 = sub_1363(a1, a2);                              // read register a2
  v4 = sub_1363(a1, a3);                              // read register a3
  return sub_1415(a1, a2, (unsigned __int8)(v3 + v4)); // write sum back to a2
}
```

### Helper Functions

We map helpers by cross-referencing argument patterns against the labeled easy trace. The second argument to every helper is a power-of-2 bitmask encoding the target register: `8 = b`, `16 = a`, `32 = c`, `64 = d`. `sub_1568` confirms the `ADD` mapping directly — it reads two registers via `sub_1363`, adds them, and writes back via `sub_1415`.

| Function | Yan85 Equivalent | Behavior |
|---|---|---|
| `sub_1533(mem, reg, val)` | `IMM reg = val` | Load immediate into register |
| `sub_1687(mem, reg1, reg2)` | `STM *reg1 = reg2` | Store register value into memory address held by reg1 |
| `sub_1568(mem, reg1, reg2)` | `ADD reg1, reg2` | reg1 = reg1 + reg2 |
| `sub_1896(mem, id, reg)` | `SYS id reg` | Syscall |

### Tracing the Logic

#### Step 1: Read Input

```c title="/challenge/trust-the-yancode-hard :: sub_1A97() :: Pseudocode" showLineNumbers
// IMM b=86 (buf address), IMM c=4 (count), IMM a=0 (stdin),
// SYS 0x8 a → read(stdin, mem[86], 4).
sub_1533(a1, 8LL, 86LL);    // IMM b = 86  (buf address)
sub_1533(a1, 32LL, 4LL);    // IMM c = 4   (count)
sub_1533(a1, 16LL, 0LL);    // IMM a = 0   (stdin)
sub_1896(a1, 8LL, 16LL);    // SYS 0x8 a   read(stdin, mem[86], 4)
```

The program reads **4 bytes** from stdin into memory at offset `86`.

#### Step 2: Build a Reference Array

Next, the program writes 4 hardcoded bytes into memory at offset `118`, incrementing the address pointer each time:

```c title="/challenge/trust-the-yancode-hard :: sub_1A97() :: Pseudocode" showLineNumbers
// IMM b=118 (dest pointer), IMM c=1 (step). Each iteration: load a byte into
// a via IMM, store it with STM *b=a, then advance b with ADD b c.
sub_1533(a1, 8LL, 118LL);   // IMM b = 118
sub_1533(a1, 32LL, 1LL);    // IMM c = 1

sub_1533(a1, 16LL, 124LL);  // IMM a = 0x7c → mem[118]
sub_1687(a1, 8LL, 16LL);    // STM *b = a
sub_1568(a1, 8LL, 32LL);    // ADD b c  →  b = 119

sub_1533(a1, 16LL, 227LL);  // IMM a = 0xe3 → mem[119]
sub_1687(a1, 8LL, 16LL);
sub_1568(a1, 8LL, 32LL);    // b = 120

sub_1533(a1, 16LL, 138LL);  // IMM a = 0x8a → mem[120]
sub_1687(a1, 8LL, 16LL);
sub_1568(a1, 8LL, 32LL);    // b = 121

sub_1533(a1, 16LL, 120LL);  // IMM a = 0x78 → mem[121]
sub_1687(a1, 8LL, 16LL);
```

The expected answer `\x7c\xe3\x8a\x78` is now at offsets `118–121`.

#### Step 3: Compare

```c title="/challenge/trust-the-yancode-hard :: sub_1A97() :: Pseudocode" showLineNumbers
// memcmp directly between the 4 reference bytes at mem[118] and our 4 input
// bytes at mem[86]. No transformation — the correct input is those bytes verbatim.
v2 = memcmp((const void *)(a1 + 118), (const void *)(a1 + 86), 4uLL) == 0;
```

A direct `memcmp` between the reference bytes at `118` and our input at `86`. There is no transformation or encoding — the correct input simply is those four bytes. If they match, the program prints `CORRECT! Your flag:`, opens `/flag`, and writes it to stdout. Otherwise it prints `INCORRECT!` and exits.

### Solution

```
hacker@reverse-engineering~trust-the-yancode-hard:~$ printf "\x7c\xe3\x8a\x78" | /challenge/trust-the-yancode-hard | grep "pwn.college"
pwn.college{U66Piapa9GpaWl9ssC5cuI2R9CK.0FN3IDL4ITM0EzW}
```

### Key Difference from Easy

The easy version used a live interpreter loop with a printed trace. The hard version **inlines all Yan85 operations as direct C function calls** with no trace output, forcing us to reverse the binary itself. The underlying logic is identical — the difficulty is purely in recovering the architecture from decompiled code rather than reading a trace.

&nbsp;

## Know the Yancode (Easy)

```
hacker@reverse-engineering~know-the-yancode-easy:~$ /challenge/know-the-yancode-easy
[+] Welcome to /challenge/know-the-yancode-easy!
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
```

This challenge builds on the Yan85 architecture from the previous challenges. The syscall IDs have changed, and two new instructions appear in the trace.

### Instruction Set

| Instruction | Behavior |
|---|---|
| `LDM <reg> = *<reg>` | Dereference the address in reg and load the value into reg |
| `CMP <reg1> <reg2>` | Compare two register values |

### Syscall Table

The syscall IDs are randomized per challenge instance. This time:

| ID | Name |
|---|---|
| `0x04` | `read` |
| `0x02` | `write` |
| `0x10` | `exit` |

### Tracing the Program

#### Step 1: Read Input

```
IMM b = 0x75    ; buf = 0x75
IMM c = 0x4     ; count = 4
IMM a = 0       ; fd = stdin
SYS 0x4 a       ; read(stdin, mem[0x75], 4)
```

The program reads **4 bytes** from stdin into memory at `0x75`.

#### Step 2: Build Reference Array

```
IMM b = 0x95
IMM c = 0x1
; write 0xdd → mem[0x95]
; write 0x3f → mem[0x96]
; write 0xc1 → mem[0x97]
; write 0x51 → mem[0x98]
```

The expected bytes `\xdd\x3f\xc1\x51` are hardcoded into memory at `0x95–0x98`.

#### Step 3: Compare Byte by Byte

Rather than a single `memcmp`, the comparison is done manually one byte at a time using `LDM` to dereference each address and `CMP` to compare:

```
IMM b = 0x95 ; LDM b = *b  → b = mem[0x95] = 0xdd
IMM a = 0x75 ; LDM a = *a  → a = mem[0x75] = input[0]
CMP a b      ; input[0] == 0xdd ?

IMM b = 0x96 ; LDM b = *b  → b = mem[0x96] = 0x3f
IMM a = 0x76 ; LDM a = *a  → a = mem[0x76] = input[1]
CMP a b      ; input[1] == 0x3f ?

; ... repeated for input[2] vs 0xc1, input[3] vs 0x51
```

There is no transformation — the correct input is exactly the reference bytes.

### Solution

```
hacker@reverse-engineering~know-the-yancode-easy:~$ printf "\xdd\x3f\xc1\x51" | /challenge/know-the-yancode-easy | grep "pwn.college"
pwn.college{stQcw4nk2SABvQVlC4r9NBGW_Jl.0VN3IDL4ITM0EzW}
```

&nbsp;

## Know the Yancode (Hard)

```
hacker@reverse-engineering~know-the-yancode-hard:~$ /challenge/know-the-yancode-hard
[+] Welcome to /challenge/know-the-yancode-hard!
[+] This challenge is an custom emulator. It emulates a completely custom
[+] architecture that we call "Yan85"! You'll have to understand the
[+] emulator to understand the architecture, and you'll have to understand
[+] the architecture to understand the code being emulated, and you will
[+] have to understand that code to get the flag. Good luck!
[+]
[+] This is an introductory Yan85 level, where we trigger Yan85 architecture
[+] operations directly. The parts of Yan85 that are used here is the emulated
[+] registers, memory, and system calls.
```

This is the hard version of Know the Yancode — no execution trace, and a new comparison mechanism using a flags register. Let's open it in a decompiler.

### Decompilation

```c title="/challenge/know-the-yancode-hard :: main() :: Pseudocode" showLineNumbers
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  char v4[256]; // [rsp+10h] [rbp-110h] BYREF
  int v5; // [rsp+110h] [rbp-10h]
  __int16 v6; // [rsp+114h] [rbp-Ch]
  char v7; // [rsp+116h] [rbp-Ah]
  _BYTE v8[9]; // [rsp+117h] [rbp-9h] BYREF
  *(_QWORD *)&v8[1] = __readfsqword(0x28u);
  printf("[+] Welcome to %s!\n", *a2);
  puts("[+] This challenge is an custom emulator. It emulates a completely custom");
  puts("[+] architecture that we call \"Yan85\"! You'll have to understand the");
  puts("[+] emulator to understand the architecture, and you'll have to understand");
  puts("[+] the architecture to understand the code being emulated, and you will");
  puts("[+] have to understand that code to get the flag. Good luck!");
  puts("[+]");
  puts("[+] This is an introductory Yan85 level, where we trigger Yan85 architecture");
  puts("[+] operations directly. The parts of Yan85 that are used here is the emulated");
  puts("[+] registers, memory, and system calls.");
  setvbuf(stdout, 0LL, 2, 1uLL);
  memset(v4, 0, sizeof(v4));
  v5 = 0;
  v6 = 0;
  v7 = 0;
  sub_1A77(v4, 0LL, v8);  // run the emulator with a 256-byte memory array
  return 0LL;
}
```

```c title="/challenge/know-the-yancode-hard :: sub_1A77() :: Pseudocode" showLineNumbers
__int64 __fastcall sub_1A77(__int64 a1)
{
  _BOOL4 v2; // [rsp+1Ch] [rbp-4h]

  // sub_1513 matches IMM (same power-of-2 register bitmask: 8=b, 16=a, 32=c,
  // 64=d). sub_1876 matches SYS. Register order here is d=buf, b=count, c=fd,
  // matching SYS 0x2 c → read(stdin, mem[97], 4).
  sub_1513(a1, 64LL, 97LL);
  sub_1513(a1, 8LL, 4LL);
  sub_1513(a1, 32LL, 0LL);
  sub_1876(a1, 2LL, 32LL);

  // sub_1667 matches STM; sub_1548 matches ADD. IMM d=129 (dest pointer),
  // IMM b=1 (step). Each iteration: IMM c=<val>, STM *d=c, ADD d b to advance.
  sub_1513(a1, 64LL, 129LL);
  sub_1513(a1, 8LL, 1LL);
  sub_1513(a1, 32LL, 68LL);    // 0x44
  sub_1667(a1, 64LL, 32LL);
  sub_1548(a1, 64LL, 8LL);
  sub_1513(a1, 32LL, 35LL);    // 0x23
  sub_1667(a1, 64LL, 32LL);
  sub_1548(a1, 64LL, 8LL);
  sub_1513(a1, 32LL, 220LL);   // 0xdc
  sub_1667(a1, 64LL, 32LL);
  sub_1548(a1, 64LL, 8LL);
  sub_1513(a1, 32LL, 239LL);   // 0xef
  sub_1667(a1, 64LL, 32LL);
  sub_1548(a1, 64LL, 8LL);

  // sub_16C6 matches LDM — dereferences the address in a register into itself.
  // sub_171D matches CMP — compares two registers and sets flags at mem[262].
  // Bit 3 of that flags byte is the equality flag; if set, the two values were
  // equal. v2 is initialized from the first comparison then ANDed with each
  // subsequent result — all 4 must match.
  sub_1513(a1, 64LL, 129LL);
  sub_16C6(a1, 64LL, 64LL);    // LDM d = *d  → d = mem[129] = 0x44
  sub_1513(a1, 32LL, 97LL);
  sub_16C6(a1, 32LL, 32LL);    // LDM c = *c  → c = mem[97]  = input[0]
  sub_171D(a1, 32LL, 64LL);    // CMP c, d
  v2 = (*(_BYTE *)(a1 + 262) & 8) != 0;  // v2 = (input[0] == 0x44)

  sub_1513(a1, 64LL, 130LL);
  sub_16C6(a1, 64LL, 64LL);    // d = mem[130] = 0x23
  sub_1513(a1, 32LL, 98LL);
  sub_16C6(a1, 32LL, 32LL);    // c = mem[98]  = input[1]
  sub_171D(a1, 32LL, 64LL);    // CMP c, d
  if ( (*(_BYTE *)(a1 + 262) & 8) == 0 )
    v2 = 0;                     // v2 &= (input[1] == 0x23)

  sub_1513(a1, 64LL, 131LL);
  sub_16C6(a1, 64LL, 64LL);    // d = mem[131] = 0xdc
  sub_1513(a1, 32LL, 99LL);
  sub_16C6(a1, 32LL, 32LL);    // c = mem[99]  = input[2]
  sub_171D(a1, 32LL, 64LL);    // CMP c, d
  if ( (*(_BYTE *)(a1 + 262) & 8) == 0 )
    v2 = 0;                     // v2 &= (input[2] == 0xdc)

  sub_1513(a1, 64LL, 132LL);
  sub_16C6(a1, 64LL, 64LL);    // d = mem[132] = 0xef
  sub_1513(a1, 32LL, 100LL);
  sub_16C6(a1, 32LL, 32LL);    // c = mem[100] = input[3]
  sub_171D(a1, 32LL, 64LL);    // CMP c, d
  if ( (*(_BYTE *)(a1 + 262) & 8) == 0 )
    v2 = 0;                     // v2 &= (input[3] == 0xef)

  sub_1513(a1, 32LL, 1LL);
  sub_1513(a1, 64LL, 0LL);
  sub_1513(a1, 8LL, 1LL);
  if ( v2 )
  {
    // CORRECT path: repeated IMM/STM/SYS write sequences printing
    // "CORRECT! Your flag:\n" one byte at a time.
    sub_1513(a1, 16LL, 67LL);   // 'C'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 16LL, 32LL);
    sub_1513(a1, 16LL, 79LL);   // 'O'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 16LL, 32LL);
    sub_1513(a1, 16LL, 82LL);   // 'R'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 16LL, 32LL);
    sub_1513(a1, 16LL, 82LL);   // 'R'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 16LL, 32LL);
    sub_1513(a1, 16LL, 69LL);   // 'E'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 16LL, 32LL);
    sub_1513(a1, 16LL, 67LL);   // 'C'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 16LL, 32LL);
    sub_1513(a1, 16LL, 84LL);   // 'T'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 16LL, 32LL);
    sub_1513(a1, 16LL, 33LL);   // '!'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 16LL, 32LL);
    sub_1513(a1, 16LL, 32LL);   // ' '
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 16LL, 32LL);
    sub_1513(a1, 16LL, 89LL);   // 'Y'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 16LL, 32LL);
    sub_1513(a1, 16LL, 111LL);  // 'o'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 16LL, 32LL);
    sub_1513(a1, 16LL, 117LL);  // 'u'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 16LL, 32LL);
    sub_1513(a1, 16LL, 114LL);  // 'r'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 16LL, 32LL);
    sub_1513(a1, 16LL, 32LL);   // ' '
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 16LL, 32LL);
    sub_1513(a1, 16LL, 102LL);  // 'f'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 16LL, 32LL);
    sub_1513(a1, 16LL, 108LL);  // 'l'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 16LL, 32LL);
    sub_1513(a1, 16LL, 97LL);   // 'a'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 16LL, 32LL);
    sub_1513(a1, 16LL, 103LL);  // 'g'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 16LL, 32LL);
    sub_1513(a1, 16LL, 58LL);   // ':'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 16LL, 32LL);
    sub_1513(a1, 16LL, 10LL);   // '\n'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 16LL, 32LL);

    // Build "/flag\0" at mem[0] with direct-addressed IMM d=<offset>, STM
    // *d=a writes. Then SYS 0x1 (open), SYS 0x2 (read), SYS 0x10 (write)
    // to read and print the flag file to stdout.
    sub_1513(a1, 16LL, 47LL);   // '/'
    sub_1513(a1, 64LL, 0LL);
    sub_1667(a1, 64LL, 16LL);
    sub_1513(a1, 16LL, 102LL);  // 'f'
    sub_1513(a1, 64LL, 1LL);
    sub_1667(a1, 64LL, 16LL);
    sub_1513(a1, 16LL, 108LL);  // 'l'
    sub_1513(a1, 64LL, 2LL);
    sub_1667(a1, 64LL, 16LL);
    sub_1513(a1, 16LL, 97LL);   // 'a'
    sub_1513(a1, 64LL, 3LL);
    sub_1667(a1, 64LL, 16LL);
    sub_1513(a1, 16LL, 103LL);  // 'g'
    sub_1513(a1, 64LL, 4LL);
    sub_1667(a1, 64LL, 16LL);
    sub_1513(a1, 16LL, 0LL);    // '\0'
    sub_1513(a1, 64LL, 5LL);
    sub_1667(a1, 64LL, 16LL);
    sub_1513(a1, 32LL, 0LL);
    sub_1513(a1, 64LL, 0LL);
    sub_1876(a1, 1LL, 32LL);    // open("/flag", 0)
    sub_1513(a1, 8LL, 100LL);
    sub_1876(a1, 2LL, 8LL);     // read(fd, mem[0], 100)
    sub_1513(a1, 32LL, 1LL);
    sub_1876(a1, 16LL, 8LL);    // write(stdout, mem[0], bytes_read)
    sub_1513(a1, 32LL, 0LL);
  }
  else
  {
    // INCORRECT path: same IMM/STM/SYS write pattern printing "INCORRECT!\n"
    // one character at a time before falling through to exit.
    sub_1513(a1, 16LL, 73LL);   // 'I'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 16LL, 32LL);
    sub_1513(a1, 16LL, 78LL);   // 'N'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 16LL, 32LL);
    sub_1513(a1, 16LL, 67LL);   // 'C'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 16LL, 32LL);
    sub_1513(a1, 16LL, 79LL);   // 'O'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 16LL, 32LL);
    sub_1513(a1, 16LL, 82LL);   // 'R'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 16LL, 32LL);
    sub_1513(a1, 16LL, 82LL);   // 'R'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 16LL, 32LL);
    sub_1513(a1, 16LL, 69LL);   // 'E'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 16LL, 32LL);
    sub_1513(a1, 16LL, 67LL);   // 'C'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 16LL, 32LL);
    sub_1513(a1, 16LL, 84LL);   // 'T'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 16LL, 32LL);
    sub_1513(a1, 16LL, 33LL);   // '!'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 16LL, 32LL);
    sub_1513(a1, 32LL, 1LL);
  }

  // Trailing newline write then SYS 0x4 (exit) — shared by both paths.
  sub_1513(a1, 16LL, 10LL);     // '\n'
  sub_1667(a1, 64LL, 16LL);
  sub_1876(a1, 16LL, 32LL);
  return sub_1876(a1, 4LL, 32LL);  // exit
}
```

### Helper Functions

We map helpers by cross-referencing argument patterns against the labeled easy trace. The power-of-2 register encoding carries over: `8 = b`, `16 = a`, `32 = c`, `64 = d`. Two new helpers appear compared to the Trust challenges — one for `LDM` and one for `CMP` — identified by their position mirroring the `LDM, LDM, CMP` pattern from the easy trace.

| Function | Yan85 Equivalent | Behavior |
|---|---|---|
| `sub_1513(mem, reg, val)` | `IMM reg = val` | Load immediate into register |
| `sub_1667(mem, reg1, reg2)` | `STM *reg1 = reg2` | Store reg2 into memory address held by reg1 |
| `sub_1548(mem, reg1, reg2)` | `ADD reg1, reg2` | reg1 = reg1 + reg2 |
| `sub_16C6(mem, reg1, reg2)` | `LDM reg1 = *reg2` | Dereference address in reg2 into reg1 |
| `sub_171D(mem, reg1, reg2)` | `CMP reg1, reg2` | Compare and set flags at `mem[262]` |
| `sub_1876(mem, id, reg)` | `SYS id reg` | Syscall |

The check `*(_BYTE *)(a1 + 262) & 8` reads **bit 3 of the flags register** — this is the equality flag set by `CMP`. If the two values are equal, bit 3 is set.

### Tracing the Logic

#### Step 1: Read Input

```c title="/challenge/know-the-yancode-hard :: sub_1A77() :: Pseudocode" showLineNumbers
// IMM d=97 (buf address), IMM b=4 (count), IMM c=0 (stdin),
// SYS 0x2 c → read(stdin, mem[97], 4).
sub_1513(a1, 64LL, 97LL);   // IMM d = 97  (buf address)
sub_1513(a1, 8LL, 4LL);     // IMM b = 4   (count)
sub_1513(a1, 32LL, 0LL);    // IMM c = 0   (stdin)
sub_1876(a1, 2LL, 32LL);    // SYS 0x2 c   read(stdin, mem[97], 4)
```

The program reads **4 bytes** from stdin into memory at offset `97`.

#### Step 2: Build Reference Array

The program writes 4 hardcoded expected bytes into memory at offsets `129–132`:

```c title="/challenge/know-the-yancode-hard :: sub_1A77() :: Pseudocode" showLineNumbers
// IMM d=129 (dest pointer), IMM b=1 (step). Each iteration: IMM c=<val>,
// STM *d=c, ADD d b to advance the pointer to the next slot.
sub_1513(a1, 64LL, 129LL);  // IMM d = 129
sub_1513(a1, 8LL, 1LL);     // IMM b = 1  (increment)

sub_1513(a1, 32LL, 68LL);   // IMM c = 0x44 → mem[129]
sub_1667(a1, 64LL, 32LL);   // STM *d = c
sub_1548(a1, 64LL, 8LL);    // ADD d b  → d = 130

sub_1513(a1, 32LL, 35LL);   // IMM c = 0x23 → mem[130]
sub_1667(a1, 64LL, 32LL);
sub_1548(a1, 64LL, 8LL);    // d = 131

sub_1513(a1, 32LL, 220LL);  // IMM c = 0xdc → mem[131]
sub_1667(a1, 64LL, 32LL);
sub_1548(a1, 64LL, 8LL);    // d = 132

sub_1513(a1, 32LL, 239LL);  // IMM c = 0xef → mem[132]
sub_1667(a1, 64LL, 32LL);
```

The expected bytes `\x44\x23\xdc\xef` are now at `mem[129–132]`.

#### Step 3: Compare Using LDM + CMP

Each byte is compared individually using `LDM` to dereference both sides and `CMP` to set the flags register:

```c title="/challenge/know-the-yancode-hard :: sub_1A77() :: Pseudocode" showLineNumbers
// LDM d=*d loads the reference byte; LDM c=*c loads the input byte. CMP sets
// bit 3 of mem[262] if equal. v2 is initialized from the first result and
// cleared if any subsequent comparison fails — all 4 bytes must match.
sub_1513(a1, 64LL, 129LL);              // IMM d = 129
sub_16C6(a1, 64LL, 64LL);              // LDM d = *d  → d = mem[129] = 0x44
sub_1513(a1, 32LL, 97LL);              // IMM c = 97
sub_16C6(a1, 32LL, 32LL);              // LDM c = *c  → c = mem[97] = input[0]
sub_171D(a1, 32LL, 64LL);              // CMP c, d
v2 = (*(_BYTE *)(a1 + 262) & 8) != 0; // v2 = (input[0] == 0x44)

sub_1513(a1, 64LL, 130LL);             // d = mem[130] = 0x23
sub_16C6(a1, 64LL, 64LL);
sub_1513(a1, 32LL, 98LL);              // c = mem[98] = input[1]
sub_16C6(a1, 32LL, 32LL);
sub_171D(a1, 32LL, 64LL);              // CMP c, d
if ( (*(_BYTE *)(a1 + 262) & 8) == 0 ) v2 = 0; // v2 &= (input[1] == 0x23)

// ... repeated for input[2] vs 0xdc, input[3] vs 0xef
```

`v2` is initialized from the first comparison and then ANDed with each subsequent result — all 4 bytes must match for `v2` to remain true.

### Solution

```
hacker@reverse-engineering~know-the-yancode-hard:~$ printf "\x44\x23\xdc\xef" | /challenge/know-the-yancode-hard | grep "pwn.college"
pwn.college{IjY7EpuKB8YVlqEUVrxL_DE6xu0.0lN3IDL4ITM0EzW}
```

### Key Differences from Easy

The easy version used a live trace and a simple `CMP` on register values. The hard version adds two layers of complexity: `LDM` is used to dereference both the reference address and the input address before comparing, and the equality flag at `mem[262]` bit 3 is checked after each `CMP` to build a running all-match boolean — the Yan85 equivalent of a multi-byte equality check without `memcmp`.

&nbsp;

## Master the Yancode (Easy)

```
hacker@reverse-engineering~master-the-yancode-easy:~$ /challenge/master-the-yancode-easy
[+] Welcome to /challenge/master-the-yancode-easy!
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
```

This challenge builds on the Yan85 architecture from the previous challenges. The key new concept is a **transformation step** — the reference array is mutated with per-byte additions before the comparison, so the correct input is not the raw hardcoded bytes but the result of applying those additions.

### Syscall Table

The syscall IDs are randomized per challenge instance. This time:

| ID | Name |
|---|---|
| `0x01` | `read` |
| `0x02` | `write` |
| `0x04` | `exit` |

### Tracing the Program

#### Step 1: Read Input

```
IMM b = 0x5a    ; buf = 0x5a
IMM c = 0x6     ; count = 6
IMM a = 0       ; fd = stdin
SYS 0x1 a       ; read(stdin, mem[0x5a], 6)
```

The program reads **6 bytes** from stdin into memory at `0x5a`.

#### Step 2: Build Reference Array

```
IMM b = 0x7a
IMM c = 0x1
; write 0x00 → mem[0x7a]
; write 0x77 → mem[0x7b]
; write 0x43 → mem[0x7c]
; write 0x2f → mem[0x7d]
; write 0x60 → mem[0x7e]
; write 0x81 → mem[0x7f]
```

Six hardcoded bytes are written into `mem[0x7a–0x7f]`.

#### Step 3: Transform the Reference Array

This is the new step compared to previous challenges. The program loops back over `mem[0x7a–0x7f]` and adds a different constant to each byte in place, with all arithmetic wrapping at 256:

```
IMM b = 0x7a
IMM c = 0x1
; LDM a = *b → a = mem[0x7a] = 0x00 ; IMM d = 0xf5 ; ADD a d ; STM *b = a → mem[0x7a] = 0xf5
; LDM a = *b → a = mem[0x7b] = 0x77 ; IMM d = 0xa5 ; ADD a d ; STM *b = a → mem[0x7b] = 0x1c
; LDM a = *b → a = mem[0x7c] = 0x43 ; IMM d = 0xd9 ; ADD a d ; STM *b = a → mem[0x7c] = 0x1c
; LDM a = *b → a = mem[0x7d] = 0x2f ; IMM d = 0x07 ; ADD a d ; STM *b = a → mem[0x7d] = 0x36
; LDM a = *b → a = mem[0x7e] = 0x60 ; IMM d = 0xff ; ADD a d ; STM *b = a → mem[0x7e] = 0x5f
; LDM a = *b → a = mem[0x7f] = 0x81 ; IMM d = 0x03 ; ADD a d ; STM *b = a → mem[0x7f] = 0x84
```

The final transformed reference array at `0x7a–0x7f`:

```
\xf5\x1c\x1c\x36\x5f\x84
```

#### Step 4: Compare Byte by Byte

The same `LDM` + `CMP` pattern from Know the Yancode compares each transformed reference byte against the corresponding input byte:

```
IMM b = 0x7a ; LDM b = *b  → b = mem[0x7a] = 0xf5
IMM a = 0x5a ; LDM a = *a  → a = mem[0x5a] = input[0]
CMP a b      ; input[0] == 0xf5 ?

IMM b = 0x7b ; LDM b = *b  → b = mem[0x7b] = 0x1c
IMM a = 0x5b ; LDM a = *a  → a = mem[0x5b] = input[1]
CMP a b      ; input[1] == 0x1c ?

; ... repeated for input[2] vs 0x1c, input[3] vs 0x36, input[4] vs 0x5f, input[5] vs 0x84
```

The transformation is applied to the reference, not our input, so there is nothing to invert — the correct input is simply the post-transformation bytes.

### Solution

```
hacker@reverse-engineering~master-the-yancode-easy:~$ printf "\xf5\x1c\x1c\x36\x5f\x84" | /challenge/master-the-yancode-easy | grep "pwn.college"
pwn.college{MeH5jO1lDM_xd6RTYUxhE1ORNy4.01N3IDL4ITM0EzW}
```

&nbsp;

## Master the Yancode (Hard)

```
hacker@reverse-engineering~master-the-yancode-hard:~$ /challenge/master-the-yancode-hard
[+] Welcome to /challenge/master-the-yancode-hard!
[+] This challenge is an custom emulator. It emulates a completely custom
[+] architecture that we call "Yan85"! You'll have to understand the
[+] emulator to understand the architecture, and you'll have to understand
[+] the architecture to understand the code being emulated, and you will
[+] have to understand that code to get the flag. Good luck!
[+]
[+] This is an introductory Yan85 level, where we trigger Yan85 architecture
[+] operations directly. The parts of Yan85 that are used here is the emulated
[+] registers, memory, and system calls.
```

This is the hard version of Master the Yancode — no execution trace, a shuffled register bitmask encoding, a shifted equality flag bit, and a 9-byte input with a per-byte ADD transformation on the reference array. Let's open it in a decompiler.

### Decompilation

```c title="/challenge/master-the-yancode-hard :: main() :: Pseudocode" showLineNumbers
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  char v4[256]; // [rsp+10h] [rbp-110h] BYREF
  int v5; // [rsp+110h] [rbp-10h]
  __int16 v6; // [rsp+114h] [rbp-Ch]
  char v7; // [rsp+116h] [rbp-Ah]
  _BYTE v8[9]; // [rsp+117h] [rbp-9h] BYREF
  *(_QWORD *)&v8[1] = __readfsqword(0x28u);
  printf("[+] Welcome to %s!\n", *a2);
  puts("[+] This challenge is an custom emulator. It emulates a completely custom");
  puts("[+] architecture that we call \"Yan85\"! You'll have to understand the");
  puts("[+] emulator to understand the architecture, and you'll have to understand");
  puts("[+] the architecture to understand the code being emulated, and you will");
  puts("[+] have to understand that code to get the flag. Good luck!");
  puts("[+]");
  puts("[+] This is an introductory Yan85 level, where we trigger Yan85 architecture");
  puts("[+] operations directly. The parts of Yan85 that are used here is the emulated");
  puts("[+] registers, memory, and system calls.");
  setvbuf(stdout, 0LL, 2, 1uLL);
  memset(v4, 0, sizeof(v4));
  v5 = 0;
  v6 = 0;
  v7 = 0;
  sub_1A77(v4, 0LL, v8);  // run the emulator with a 256-byte memory array
  return 0LL;
}
```

```c title="/challenge/master-the-yancode-hard :: sub_1A77() :: Pseudocode" showLineNumbers
__int64 __fastcall sub_1A77(__int64 a1)
{
  _BOOL4 v2; // [rsp+1Ch] [rbp-4h]

  // The register bitmask encoding has shuffled compared to previous challenges.
  // Cross-referencing the read syscall pattern (fd, buf, count) against known
  // argument positions: bitmask 64=d (buf), 1=b (count), 2=c (fd/return).
  // sub_1876 matches SYS; SYS 0x20 here is read.
  // IMM d=78 (buf), IMM b=9 (count), IMM c=0 (stdin), SYS 0x20 c → read(stdin, mem[78], 9).
  sub_1513(a1, 64LL, 78LL);
  sub_1513(a1, 1LL, 9LL);
  sub_1513(a1, 2LL, 0LL);
  sub_1876(a1, 32LL, 2LL);

  // sub_1667 matches STM; sub_1548 matches ADD. IMM d=110 (dest pointer),
  // IMM b=1 (step). Each iteration: IMM c=<val>, STM *d=c, ADD d b to advance.
  // This builds the raw reference array at mem[110..118]:
  // [0xb9, 0x04, 0x6f, 0x40, 0xcc, 0xaf, 0x0d, 0x27, 0x4e]
  sub_1513(a1, 64LL, 110LL);
  sub_1513(a1, 1LL, 1LL);
  sub_1513(a1, 2LL, 185LL);   // 0xb9
  sub_1667(a1, 64LL, 2LL);
  sub_1548(a1, 64LL, 1LL);
  sub_1513(a1, 2LL, 4LL);     // 0x04
  sub_1667(a1, 64LL, 2LL);
  sub_1548(a1, 64LL, 1LL);
  sub_1513(a1, 2LL, 111LL);   // 0x6f
  sub_1667(a1, 64LL, 2LL);
  sub_1548(a1, 64LL, 1LL);
  sub_1513(a1, 2LL, 64LL);    // 0x40
  sub_1667(a1, 64LL, 2LL);
  sub_1548(a1, 64LL, 1LL);
  sub_1513(a1, 2LL, 204LL);   // 0xcc
  sub_1667(a1, 64LL, 2LL);
  sub_1548(a1, 64LL, 1LL);
  sub_1513(a1, 2LL, 175LL);   // 0xaf
  sub_1667(a1, 64LL, 2LL);
  sub_1548(a1, 64LL, 1LL);
  sub_1513(a1, 2LL, 13LL);    // 0x0d
  sub_1667(a1, 64LL, 2LL);
  sub_1548(a1, 64LL, 1LL);
  sub_1513(a1, 2LL, 39LL);    // 0x27
  sub_1667(a1, 64LL, 2LL);
  sub_1548(a1, 64LL, 1LL);
  sub_1513(a1, 2LL, 78LL);    // 0x4e
  sub_1667(a1, 64LL, 2LL);
  sub_1548(a1, 64LL, 1LL);

  // sub_16C6 matches LDM. The pointer is reset to 110 and the program loops
  // over each byte, loading it with LDM c=*d, adding a per-byte constant via
  // IMM a=<key>, ADD c a, then writing back with STM *d=c and advancing d.
  // All arithmetic wraps at 256. The transformed values are:
  // mem[110]: (0xb9+0xc4)&0xff = 0x7d
  // mem[111]: (0x04+0x9a)&0xff = 0x9e
  // mem[112]: (0x6f+0x47)&0xff = 0xb6
  // mem[113]: (0x40+0x60)&0xff = 0xa0
  // mem[114]: (0xcc+0xa2)&0xff = 0x6e
  // mem[115]: (0xaf+0x4a)&0xff = 0xf9
  // mem[116]: (0x0d+0x93)&0xff = 0xa0
  // mem[117]: (0x27+0x4f)&0xff = 0x76
  // mem[118]: (0x4e+0xa2)&0xff = 0xf0
  sub_1513(a1, 64LL, 110LL);
  sub_1513(a1, 1LL, 1LL);
  sub_16C6(a1, 2LL, 64LL);    // LDM c = *d → c = mem[110] = 0xb9
  sub_1513(a1, 16LL, 196LL);  // IMM a = 0xc4
  sub_1548(a1, 2LL, 16LL);    // ADD c a → c = 0x7d
  sub_1667(a1, 64LL, 2LL);    // STM *d = c → mem[110] = 0x7d
  sub_1548(a1, 64LL, 1LL);    // d++
  sub_16C6(a1, 2LL, 64LL);    // c = mem[111] = 0x04
  sub_1513(a1, 16LL, 154LL);  // IMM a = 0x9a
  sub_1548(a1, 2LL, 16LL);    // ADD c a → c = 0x9e
  sub_1667(a1, 64LL, 2LL);    // STM *d = c → mem[111] = 0x9e
  sub_1548(a1, 64LL, 1LL);    // d++
  sub_16C6(a1, 2LL, 64LL);    // c = mem[112] = 0x6f
  sub_1513(a1, 16LL, 71LL);   // IMM a = 0x47
  sub_1548(a1, 2LL, 16LL);    // ADD c a → c = 0xb6
  sub_1667(a1, 64LL, 2LL);    // STM *d = c → mem[112] = 0xb6
  sub_1548(a1, 64LL, 1LL);    // d++
  sub_16C6(a1, 2LL, 64LL);    // c = mem[113] = 0x40
  sub_1513(a1, 16LL, 96LL);   // IMM a = 0x60
  sub_1548(a1, 2LL, 16LL);    // ADD c a → c = 0xa0
  sub_1667(a1, 64LL, 2LL);    // STM *d = c → mem[113] = 0xa0
  sub_1548(a1, 64LL, 1LL);    // d++
  sub_16C6(a1, 2LL, 64LL);    // c = mem[114] = 0xcc
  sub_1513(a1, 16LL, 162LL);  // IMM a = 0xa2
  sub_1548(a1, 2LL, 16LL);    // ADD c a → c = 0x6e
  sub_1667(a1, 64LL, 2LL);    // STM *d = c → mem[114] = 0x6e
  sub_1548(a1, 64LL, 1LL);    // d++
  sub_16C6(a1, 2LL, 64LL);    // c = mem[115] = 0xaf
  sub_1513(a1, 16LL, 74LL);   // IMM a = 0x4a
  sub_1548(a1, 2LL, 16LL);    // ADD c a → c = 0xf9
  sub_1667(a1, 64LL, 2LL);    // STM *d = c → mem[115] = 0xf9
  sub_1548(a1, 64LL, 1LL);    // d++
  sub_16C6(a1, 2LL, 64LL);    // c = mem[116] = 0x0d
  sub_1513(a1, 16LL, 147LL);  // IMM a = 0x93
  sub_1548(a1, 2LL, 16LL);    // ADD c a → c = 0xa0
  sub_1667(a1, 64LL, 2LL);    // STM *d = c → mem[116] = 0xa0
  sub_1548(a1, 64LL, 1LL);    // d++
  sub_16C6(a1, 2LL, 64LL);    // c = mem[117] = 0x27
  sub_1513(a1, 16LL, 79LL);   // IMM a = 0x4f
  sub_1548(a1, 2LL, 16LL);    // ADD c a → c = 0x76
  sub_1667(a1, 64LL, 2LL);    // STM *d = c → mem[117] = 0x76
  sub_1548(a1, 64LL, 1LL);    // d++
  sub_16C6(a1, 2LL, 64LL);    // c = mem[118] = 0x4e
  sub_1513(a1, 16LL, 162LL);  // IMM a = 0xa2
  sub_1548(a1, 2LL, 16LL);    // ADD c a → c = 0xf0
  sub_1667(a1, 64LL, 2LL);    // STM *d = c → mem[118] = 0xf0
  sub_1548(a1, 64LL, 1LL);    // d++

  // sub_171D matches CMP. The equality flag has shifted — this instance uses
  // bit 2 of mem[262] (& 4) instead of bit 3 (& 8) seen in previous challenges.
  // Each pair: LDM d=*ref_addr loads the transformed reference byte; LDM c=*input_addr
  // loads the input byte. CMP c,d sets the flag. v2 is initialized from the
  // first result and cleared if any subsequent comparison fails — all 9 bytes must match.
  sub_1513(a1, 64LL, 110LL);
  sub_16C6(a1, 64LL, 64LL);   // LDM d = *d → d = mem[110] = 0x7d
  sub_1513(a1, 2LL, 78LL);
  sub_16C6(a1, 2LL, 2LL);     // LDM c = *c → c = mem[78]  = input[0]
  sub_171D(a1, 2LL, 64LL);    // CMP c, d
  v2 = (*(_BYTE *)(a1 + 262) & 4) != 0;  // v2 = (input[0] == 0x7d)

  sub_1513(a1, 64LL, 111LL);
  sub_16C6(a1, 64LL, 64LL);   // d = mem[111] = 0x9e
  sub_1513(a1, 2LL, 79LL);
  sub_16C6(a1, 2LL, 2LL);     // c = mem[79]  = input[1]
  sub_171D(a1, 2LL, 64LL);    // CMP c, d
  if ( (*(_BYTE *)(a1 + 262) & 4) == 0 )
    v2 = 0;                    // v2 &= (input[1] == 0x9e)

  sub_1513(a1, 64LL, 112LL);
  sub_16C6(a1, 64LL, 64LL);   // d = mem[112] = 0xb6
  sub_1513(a1, 2LL, 80LL);
  sub_16C6(a1, 2LL, 2LL);     // c = mem[80]  = input[2]
  sub_171D(a1, 2LL, 64LL);
  if ( (*(_BYTE *)(a1 + 262) & 4) == 0 )
    v2 = 0;                    // v2 &= (input[2] == 0xb6)

  sub_1513(a1, 64LL, 113LL);
  sub_16C6(a1, 64LL, 64LL);   // d = mem[113] = 0xa0
  sub_1513(a1, 2LL, 81LL);
  sub_16C6(a1, 2LL, 2LL);     // c = mem[81]  = input[3]
  sub_171D(a1, 2LL, 64LL);
  if ( (*(_BYTE *)(a1 + 262) & 4) == 0 )
    v2 = 0;                    // v2 &= (input[3] == 0xa0)

  sub_1513(a1, 64LL, 114LL);
  sub_16C6(a1, 64LL, 64LL);   // d = mem[114] = 0x6e
  sub_1513(a1, 2LL, 82LL);
  sub_16C6(a1, 2LL, 2LL);     // c = mem[82]  = input[4]
  sub_171D(a1, 2LL, 64LL);
  if ( (*(_BYTE *)(a1 + 262) & 4) == 0 )
    v2 = 0;                    // v2 &= (input[4] == 0x6e)

  sub_1513(a1, 64LL, 115LL);
  sub_16C6(a1, 64LL, 64LL);   // d = mem[115] = 0xf9
  sub_1513(a1, 2LL, 83LL);
  sub_16C6(a1, 2LL, 2LL);     // c = mem[83]  = input[5]
  sub_171D(a1, 2LL, 64LL);
  if ( (*(_BYTE *)(a1 + 262) & 4) == 0 )
    v2 = 0;                    // v2 &= (input[5] == 0xf9)

  sub_1513(a1, 64LL, 116LL);
  sub_16C6(a1, 64LL, 64LL);   // d = mem[116] = 0xa0
  sub_1513(a1, 2LL, 84LL);
  sub_16C6(a1, 2LL, 2LL);     // c = mem[84]  = input[6]
  sub_171D(a1, 2LL, 64LL);
  if ( (*(_BYTE *)(a1 + 262) & 4) == 0 )
    v2 = 0;                    // v2 &= (input[6] == 0xa0)

  sub_1513(a1, 64LL, 117LL);
  sub_16C6(a1, 64LL, 64LL);   // d = mem[117] = 0x76
  sub_1513(a1, 2LL, 85LL);
  sub_16C6(a1, 2LL, 2LL);     // c = mem[85]  = input[7]
  sub_171D(a1, 2LL, 64LL);
  if ( (*(_BYTE *)(a1 + 262) & 4) == 0 )
    v2 = 0;                    // v2 &= (input[7] == 0x76)

  sub_1513(a1, 64LL, 118LL);
  sub_16C6(a1, 64LL, 64LL);   // d = mem[118] = 0xf0
  sub_1513(a1, 2LL, 86LL);
  sub_16C6(a1, 2LL, 2LL);     // c = mem[86]  = input[8]
  sub_171D(a1, 2LL, 64LL);
  if ( (*(_BYTE *)(a1 + 262) & 4) == 0 )
    v2 = 0;                    // v2 &= (input[8] == 0xf0)

  sub_1513(a1, 2LL, 1LL);
  sub_1513(a1, 64LL, 0LL);
  sub_1513(a1, 1LL, 1LL);
  if ( v2 )
  {
    // CORRECT path: repeated IMM/STM/SYS write sequences printing
    // "CORRECT! Your flag:\n" one byte at a time.
    sub_1513(a1, 16LL, 67LL);   // 'C'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 1LL, 2LL);
    sub_1513(a1, 16LL, 79LL);   // 'O'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 1LL, 2LL);
    sub_1513(a1, 16LL, 82LL);   // 'R'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 1LL, 2LL);
    sub_1513(a1, 16LL, 82LL);   // 'R'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 1LL, 2LL);
    sub_1513(a1, 16LL, 69LL);   // 'E'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 1LL, 2LL);
    sub_1513(a1, 16LL, 67LL);   // 'C'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 1LL, 2LL);
    sub_1513(a1, 16LL, 84LL);   // 'T'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 1LL, 2LL);
    sub_1513(a1, 16LL, 33LL);   // '!'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 1LL, 2LL);
    sub_1513(a1, 16LL, 32LL);   // ' '
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 1LL, 2LL);
    sub_1513(a1, 16LL, 89LL);   // 'Y'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 1LL, 2LL);
    sub_1513(a1, 16LL, 111LL);  // 'o'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 1LL, 2LL);
    sub_1513(a1, 16LL, 117LL);  // 'u'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 1LL, 2LL);
    sub_1513(a1, 16LL, 114LL);  // 'r'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 1LL, 2LL);
    sub_1513(a1, 16LL, 32LL);   // ' '
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 1LL, 2LL);
    sub_1513(a1, 16LL, 102LL);  // 'f'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 1LL, 2LL);
    sub_1513(a1, 16LL, 108LL);  // 'l'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 1LL, 2LL);
    sub_1513(a1, 16LL, 97LL);   // 'a'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 1LL, 2LL);
    sub_1513(a1, 16LL, 103LL);  // 'g'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 1LL, 2LL);
    sub_1513(a1, 16LL, 58LL);   // ':'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 1LL, 2LL);
    sub_1513(a1, 16LL, 10LL);   // '\n'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 1LL, 2LL);

    // Build "/flag\0" at mem[0] with direct-addressed IMM d=<offset>, STM *d=a
    // writes. Then SYS 0x2 (open), SYS 0x20 (read), SYS 0x1 (write) to read
    // and print the flag file to stdout.
    sub_1513(a1, 16LL, 47LL);   // '/'
    sub_1513(a1, 64LL, 0LL);
    sub_1667(a1, 64LL, 16LL);
    sub_1513(a1, 16LL, 102LL);  // 'f'
    sub_1513(a1, 64LL, 1LL);
    sub_1667(a1, 64LL, 16LL);
    sub_1513(a1, 16LL, 108LL);  // 'l'
    sub_1513(a1, 64LL, 2LL);
    sub_1667(a1, 64LL, 16LL);
    sub_1513(a1, 16LL, 97LL);   // 'a'
    sub_1513(a1, 64LL, 3LL);
    sub_1667(a1, 64LL, 16LL);
    sub_1513(a1, 16LL, 103LL);  // 'g'
    sub_1513(a1, 64LL, 4LL);
    sub_1667(a1, 64LL, 16LL);
    sub_1513(a1, 16LL, 0LL);    // '\0'
    sub_1513(a1, 64LL, 5LL);
    sub_1667(a1, 64LL, 16LL);
    sub_1513(a1, 2LL, 0LL);
    sub_1513(a1, 64LL, 0LL);
    sub_1876(a1, 2LL, 2LL);     // open("/flag", 0)
    sub_1513(a1, 1LL, 100LL);
    sub_1876(a1, 32LL, 1LL);    // read(fd, mem[0], 100)
    sub_1513(a1, 2LL, 1LL);
    sub_1876(a1, 1LL, 1LL);     // write(stdout, mem[0], bytes_read)
    sub_1513(a1, 2LL, 0LL);
  }
  else
  {
    // INCORRECT path: same IMM/STM/SYS write pattern printing "INCORRECT!\n"
    // one character at a time before falling through to exit.
    sub_1513(a1, 16LL, 73LL);   // 'I'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 1LL, 2LL);
    sub_1513(a1, 16LL, 78LL);   // 'N'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 1LL, 2LL);
    sub_1513(a1, 16LL, 67LL);   // 'C'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 1LL, 2LL);
    sub_1513(a1, 16LL, 79LL);   // 'O'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 1LL, 2LL);
    sub_1513(a1, 16LL, 82LL);   // 'R'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 1LL, 2LL);
    sub_1513(a1, 16LL, 82LL);   // 'R'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 1LL, 2LL);
    sub_1513(a1, 16LL, 69LL);   // 'E'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 1LL, 2LL);
    sub_1513(a1, 16LL, 67LL);   // 'C'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 1LL, 2LL);
    sub_1513(a1, 16LL, 84LL);   // 'T'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 1LL, 2LL);
    sub_1513(a1, 16LL, 33LL);   // '!'
    sub_1667(a1, 64LL, 16LL);
    sub_1876(a1, 1LL, 2LL);
    sub_1513(a1, 2LL, 1LL);
  }

  // Trailing newline write then SYS 0x4 (exit) — shared by both paths.
  sub_1513(a1, 16LL, 10LL);    // '\n'
  sub_1667(a1, 64LL, 16LL);
  sub_1876(a1, 1LL, 2LL);
  return sub_1876(a1, 4LL, 2LL);  // exit
}
```

### Helper Functions

The helper function addresses are new but the roles are the same as previous hard challenges. The register bitmask encoding has shuffled this instance — cross-referencing the `read` syscall at the top against the known argument order `(fd, buf, count)` gives us the new mapping:

| Bitmask | Register |
|---|---|
| `1` | `b` |
| `2` | `c` |
| `16` | `a` |
| `64` | `d` |

Two other differences from previous instances: the equality flag is now **bit 2** of `mem[262]` (`& 4`) instead of bit 3 (`& 8`), and the syscall IDs have shuffled again.

| Function | Yan85 Equivalent | Behavior |
|---|---|---|
| `sub_1513(mem, reg, val)` | `IMM reg = val` | Load immediate into register |
| `sub_1667(mem, reg1, reg2)` | `STM *reg1 = reg2` | Store reg2 into memory address held by reg1 |
| `sub_1548(mem, reg1, reg2)` | `ADD reg1, reg2` | reg1 = reg1 + reg2 |
| `sub_16C6(mem, reg1, reg2)` | `LDM reg1 = *reg2` | Dereference address in reg2 into reg1 |
| `sub_171D(mem, reg1, reg2)` | `CMP reg1, reg2` | Compare and set flags at `mem[262]` |
| `sub_1876(mem, id, reg)` | `SYS id reg` | Syscall |

### Syscall Table

| ID | Name |
|---|---|
| `0x20` | `read` |
| `0x01` | `write` |
| `0x02` | `open` |
| `0x04` | `exit` |

### Tracing the Logic

#### Step 1: Read Input

```c title="/challenge/master-the-yancode-hard :: sub_1A77() :: Pseudocode" showLineNumbers
// IMM d=78 (buf), IMM b=9 (count), IMM c=0 (stdin),
// SYS 0x20 c → read(stdin, mem[78], 9).
sub_1513(a1, 64LL, 78LL);   // IMM d = 78  (buf address)
sub_1513(a1, 1LL, 9LL);     // IMM b = 9   (count)
sub_1513(a1, 2LL, 0LL);     // IMM c = 0   (stdin)
sub_1876(a1, 32LL, 2LL);    // SYS 0x20 c  read(stdin, mem[78], 9)
```

The program reads **9 bytes** from stdin into memory at offset `78`.

#### Step 2: Build Reference Array

```c title="/challenge/master-the-yancode-hard :: sub_1A77() :: Pseudocode" showLineNumbers
// IMM d=110 (dest pointer), IMM b=1 (step). Each iteration: IMM c=<val>,
// STM *d=c, ADD d b to advance. Writes raw reference bytes into mem[110..118]:
// [0xb9, 0x04, 0x6f, 0x40, 0xcc, 0xaf, 0x0d, 0x27, 0x4e]
sub_1513(a1, 64LL, 110LL);  // IMM d = 110
sub_1513(a1, 1LL, 1LL);     // IMM b = 1
sub_1513(a1, 2LL, 185LL);   // IMM c = 0xb9 → mem[110]
sub_1667(a1, 64LL, 2LL);    // STM *d = c
sub_1548(a1, 64LL, 1LL);    // ADD d b → d = 111
sub_1513(a1, 2LL, 4LL);     // IMM c = 0x04 → mem[111]
sub_1667(a1, 64LL, 2LL);
sub_1548(a1, 64LL, 1LL);    // d = 112
// ... continues for 0x6f, 0x40, 0xcc, 0xaf, 0x0d, 0x27, 0x4e
```

#### Step 3: Transform the Reference Array

```c title="/challenge/master-the-yancode-hard :: sub_1A77() :: Pseudocode" showLineNumbers
// Pointer reset to 110. Each iteration: LDM c=*d loads the raw byte, IMM a=<key>,
// ADD c a adds the key (wrapping at 256), STM *d=c writes back, ADD d b advances.
// Final transformed values at mem[110..118]:
// (0xb9+0xc4)=0x7d, (0x04+0x9a)=0x9e, (0x6f+0x47)=0xb6, (0x40+0x60)=0xa0,
// (0xcc+0xa2)=0x6e, (0xaf+0x4a)=0xf9, (0x0d+0x93)=0xa0, (0x27+0x4f)=0x76,
// (0x4e+0xa2)=0xf0
sub_1513(a1, 64LL, 110LL);  // IMM d = 110 (reset pointer)
sub_1513(a1, 1LL, 1LL);     // IMM b = 1
sub_16C6(a1, 2LL, 64LL);    // LDM c = *d → c = 0xb9
sub_1513(a1, 16LL, 196LL);  // IMM a = 0xc4
sub_1548(a1, 2LL, 16LL);    // ADD c a → c = 0x7d
sub_1667(a1, 64LL, 2LL);    // STM *d = c → mem[110] = 0x7d
sub_1548(a1, 64LL, 1LL);    // d++
// ... repeated for remaining 8 bytes
```

#### Step 4: Compare Byte by Byte

```c title="/challenge/master-the-yancode-hard :: sub_1A77() :: Pseudocode" showLineNumbers
// LDM d=*ref_addr loads transformed reference; LDM c=*input_addr loads input.
// CMP sets bit 2 of mem[262] if equal. v2 initialized from first result,
// ANDed with each subsequent — all 9 bytes must match.
sub_1513(a1, 64LL, 110LL);
sub_16C6(a1, 64LL, 64LL);              // LDM d = *d → d = mem[110] = 0x7d
sub_1513(a1, 2LL, 78LL);
sub_16C6(a1, 2LL, 2LL);               // LDM c = *c → c = mem[78]  = input[0]
sub_171D(a1, 2LL, 64LL);              // CMP c, d
v2 = (*(_BYTE *)(a1 + 262) & 4) != 0; // v2 = (input[0] == 0x7d)
// ... repeated for input[1..8] vs 0x9e, 0xb6, 0xa0, 0x6e, 0xf9, 0xa0, 0x76, 0xf0
```

### Solution

```
hacker@reverse-engineering~master-the-yancode-hard:~$ printf "\x7d\x9e\xb6\xa0\x6e\xf9\xa0\x76\xf0" | /challenge/master-the-yancode-hard | grep "pwn.college"
pwn.college{4abBz0TawNAJTcnpLGW8GeVeSjK.0FO3IDL4ITM0EzW}
```

&nbsp;

