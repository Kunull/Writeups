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

### Decompilation

#### `main()`



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
  if ( !memcmp(&buf, str_Wylie, 5uLL) )
  {
    sub_12A9();
    exit(0);
  }
  puts("Wrong! No flag for you!");
  exit(1);
}
```