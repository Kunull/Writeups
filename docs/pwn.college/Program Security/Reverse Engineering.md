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
# ---- snip ----

  v3 = BYTE2(buf);
  BYTE2(buf) = v5;
  LOBYTE(v5) = v3;

# ---- snip ----
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
