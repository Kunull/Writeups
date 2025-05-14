---
custom_edit_url: null
---

## What's the password

```
hacker@data-dealings~whats-the-password:/$ /challenge/runme
Enter the password:
npknegwx              
Read 8 bytes.
Congrats! Here is your flag:
pwn.college{kQMMfnfgzYwYvTHUEbPNyVaGwSJ.QX5QjN0EDL4ITM0EzW}
```

&nbsp;

## ... and again!

```
hacker@data-dealings~-and-again:/$ /challenge/runme 
Enter the password:
fbharpsp
Read 8 bytes.
Congrats! Here is your flag:
pwn.college{E0dk8pfSQBwE13ZE790cjercb0t.QXwUjN0EDL4ITM0EzW}
```

&nbsp;

## Newline Troubles

In this level, we have to have to pass the input without using Newline, so we cannot use `Enter`.
There are a few ways of working around this.

### `CTRL` + `D`

```
hacker@data-dealings~newline-troubles:/$ /challenge/runme 
Enter the password:
bzvrlubuRead 8 bytes.
Congrats! Here is your flag:
pwn.college{83Yfzwc1-_dx46U81fdAkHxh-s4.QXxUjN0EDL4ITM0EzW}
```

### `echo`

```
hacker@data-dealings~newline-troubles:/$ echo -n "bzvrlubu" | /challenge/runme 
Enter the password:
Read 8 bytes.
Congrats! Here is your flag:
pwn.college{83Yfzwc1-_dx46U81fdAkHxh-s4.QXxUjN0EDL4ITM0EzW}
```

### File without newline

```
hacker@data-dealings~newline-troubles:/$ echo -n "bzvrlubu" > ~/no-newline
hacker@data-dealings~newline-troubles:/$ cat ~/no-newline | /challenge/runme 
Enter the password:
Read 8 bytes.
Congrats! Here is your flag:
pwn.college{83Yfzwc1-_dx46U81fdAkHxh-s4.QXxUjN0EDL4ITM0EzW}
```

&nbsp;

## Reasoning about files

```

```
