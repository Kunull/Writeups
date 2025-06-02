---
custom_edit_url: null
sidebar_position: 2
---

> Daddy told me about cool MD5 hash collision today.\
> I wanna do something like that too!
>
> ssh col@pwnable.kr -p2222 (pw:guest)

## File properties

Let's check the nature of our challenge file.

```
col@ubuntu:~$ file col
col: setgid ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=48d83f055c56d12dc4762db539bf8840e5b4f6cc, for GNU/Linux 3.2.0, not stripped
```

We can see that it is a little-endian 32-bit ELF executable.

## Source code

```c title="col.c"
#include <stdio.h>
#include <string.h>
unsigned long hashcode = 0x21DD09EC;
unsigned long check_password(const char* p){
    int* ip = (int*)p;
    int i;
    int res=0;
    for(i=0; i<5; i++){
        res += ip[i];
    }
    return res;
}

int main(int argc, char* argv[]){
    if(argc<2){
        printf("usage : %s [passcode]\n", argv[0]);
        return 0;
    }
    if(strlen(argv[1]) != 20){
        printf("passcode length should be 20 bytes\n");
        return 0;
    }

    if(hashcode == check_password( argv[1] )){
        setregid(getegid(), getegid());
        system("/bin/cat flag");
        return 0;
    }
    else
        printf("wrong passcode.\n");
    return 0;
}
```

The challenge expects users to enter a passcode of lenght 20 bytes.

The the passcode indirectly is compared to `hashcode` using the `check_password()` function.

### `check_password()`

```c
# --- snip ---

unsigned long check_password(const char* p){
    int* ip = (int*)p;

# --- snip ---
```

This function takes the `char` pointer `p` and casts it to an `int` pointer.
It then assigns this `int` pointer to `ip`.

Let's understand what this means.

#### Pointer casting

When the pointer p is initialized, it acts as `char` pointer and points to a character, which is 1 byte long.

```title="char pointer"
+------+------+------+------+     ... (total 20 bytes)
| 0x41 | 0x42 | 0x43 | 0x44 |     ... ('A', 'B', 'C', 'D', ...)
+------+------+------+------+
^^^^^^^^
|
char* p    
```

After casting `p` into an `int*`, it points to integer, which is 4 bytes long.

```title="int pointer"
+------+------+------+------+     ... (total 20 bytes)
| 0x41 | 0x42 | 0x43 | 0x44 |     ... ('A', 'B', 'C', 'D', ...)
+------+------+------+------+
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
|
(int*)p  
```

```title="int pointer"
+------------+------------+------------+     ...
| 0x44434241 | 0x48474645 | 0x4C4B4A49 |     ... (on little-endian systems)
+------------+------------+------------+
^^^^^^^^^^^^^^
|
(int*)p  
```

Next the `check_password()` function adds all the 5 integers now pointed to by the `ip` pointer.

```c
# --- snip ----

    int i;
    int res=0;
    for(i=0; i<5; i++){
        res += ip[i];
    }
    return res;

# --- snip ----
```

This sum has to be equal to the `hashcode` which is `0x21DD09EC` for us to get the flag.

Should be easy right?
We can just pass `\xEC\x09\xDD\x21` + `\x00`*16 and that will cause to sum to be equal to the `hashcode`.

```
Input:
0xEC09DD2100000000000000000000000000000000

+------------+------------+------------+------------+------------+    
| 0xEC09DD21 | 0x00000000 | 0x00000000 | 0x00000000 | 0x00000000 |
+------------+------------+------------+------------+------------+

   0xEC09DD21
 + 0x00000000
 + 0x00000000
 + 0x00000000
 + 0x00000000
--------------
   0xEC09DD21
```

Note that we are passing `\xEC\x09\xDD\x21` because the challenge is in little-endian, so we have to flip the bytes.

Let's try this solution.

```
col@ubuntu:~$ ./col "$(python3 -c 'import sys; sys.stdout.buffer.write(b"\xEC\x09\xDD\x21" + b"\x00"*16)')"
-bash: warning: command substitution: ignored null byte in input
passcode length should be 20 bytes
```

The program tells us that our input is not 20 bytes long, and that it ignored the null byte in our input.

This is because when we append `\x00` to our string, we essentially terminate it.
Therefore, our input length is registered as 4.

```
Actual Input:
0xEC09DD21
```

In order to get around this, we can use append 16 `\x01` bytes instead. However, we first have to modify our original input accordingly

```
Input:
0x????????01010101010101010101010101010101

+------------+------------+------------+------------+------------+    
| 0x???????? | 0x01010101 | 0x01010101 | 0x01010101 | 0x01010101 |
+------------+------------+------------+------------+------------+

   0x????????
 + 0x01010101
 + 0x01010101
 + 0x01010101
 + 0x01010101
--------------
   0xEC09DD21
```

Let's use Python to calculate our input.

```python
col@ubuntu:~$ python
Python 3.10.12 (main, Feb  4 2025, 14:57:36) [GCC 11.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> target = 0xEC09DD21
>>> value = 0x01010101
>>> x = target - (4 * value)
>>> print(f"Calculated value: 0x{x:08X}")
Calculated value: 0xE805D91D
```

Let's craft and send our final payload.

```
col@ubuntu:~$ ./col "$(python3 -c 'import sys; sys.stdout.buffer.write(b"\xE8\x05\xD9\x1D" + b"\x01"*16)')"
Two_hash_collision_Nicely
```
