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
