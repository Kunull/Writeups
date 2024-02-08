---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 1
---


## level 0 → level 1
> The password for the next level is stored in a file called **readme** located in the home directory. Use this password to log into bandit1 using SSH. Whenever you find a password for a level, use SSH (on port 2220) to log into that level and continue the game.

We can use `ls` to list the directories and files in our present directory.
```
bandit0@bandit:~$ ls
readme
```
In order to display the file contents, we can use `cat`.
```
bandit0@bandit:~$ cat readme
NH2SXQwcBdpmTEzi3bvBHMM9H66vVXjL
```

&nbsp;

## level 1 → level 2
> The password for the next level is stored in a file called **-** located in the home directory

If we just try to `cat` the file, we enter the interactive mode.
```
bandit1@bandit:~$ cat -

```
The key is to make sure that `cat` understands that `-` is a filename and not an indication of us wanting to enter interactive mode.

The way we can achieve this goal is by including the filename in single / double quotes.
```
bandit1@bandit:~$ cat "./-"
rRGizSaX8Mk1RTb1CNQoXTcYZWU6lgzi
```

&nbsp;

## level 2 → level 3
> The password for the next level is stored in a file called **spaces in this filename** located in the home directory

One way to solve this challenge is again by including the filename inside single / double quotes.
```
bandit2@bandit:~$ cat "spaces in this filename"
aBZ0W5EmUfAf7kHTQeOwd8bauFJ2lAiG
```
Another way is by inserting a backslash before every space.
```
bandit2@bandit:~$ cat spaces\ in\ this\ filename
aBZ0W5EmUfAf7kHTQeOwd8bauFJ2lAiG
```

&nbsp;

## level 3 → level 4
> The password for the next level is stored in a hidden file in the **inhere** directory.

If we `cd` into `inhere` and check for the files present in the directory, we are met with nothing.

Hidden files are generally used to store configurations or user settings.
`ls` has an option `a` which if provided, tells it to list all the files, even the hidden ones.
```
bandit3@bandit:~/inhere$ ls -a
.  ..  .hidden
```
There's our hidden file.
```
bandit3@bandit:~/inhere$ cat .hidden
2EW7BBsr6aMMoJ2HjW067dm8EgX26xNe
```

&nbsp;

## level 4 → level 5 
> The password for the next level is stored in the only human-readable file in the **inhere** directory. Tip: if your terminal is messed up, try the “reset” command.

Let's begin by finding a file that is readable using `find` command with the `readable` option.
```
bandit4@bandit:~/inhere$ find -type f -readable
./-file03
./-file06
./-file08
./-file07
./-file04
./-file00
./-file01
./-file02
./-file09
./-file05
```
All the files are readable.

Fortunately, `find` allows us to give other commands if we use the `exec` option.
The `exec` option itself takes as argument the command that we want to execute.
```
bandit4@bandit:~/inhere$ find -type f -readable -exec file {} + | grep ASCII
./-file07: ASCII text
./-file09: Non-ISO extended-ASCII text, with no line terminators
```
There's two files that have `ASCII` format. This greatly reduced our search-space.
```
bandit4@bandit:~/inhere$ cat "./-file07"
lrIWWI6bB37kxfiCQZqUdOIYfr6eEeqR
```

&nbsp;

## level 5 → level 6 
> The password for the next level is stored in a file somewhere under the **inhere** directory and has all of the following properties:
> - human-readable
> - 1033 bytes in size
> - not executable

We can provide the `size` option to specify the file size.
```
bandit5@bandit:~/inhere$ find -type f -size 1033c
./maybehere07/.file2: ASCII text, with very long lines (1000)
```
We are appending 1033 with c because that is the suffix for bytes as specified in the man page.
```
-size n[cwbkMG]
	`c'    for bytes
```
Let's read the file.
```
bandit5@bandit:~/inhere$ cat ./maybehere07/.file2
P4L4vucdmLnm8I7Vl7jG1ApGSfjYKqJU
```

&nbsp;

## level 6 → level 7 
> The password for the next level is stored **somewhere on the server** and has all of the following properties:
> - owned by user bandit7
> - owned by group bandit6
> - 33 bytes in size

The `user` option to specify the user that owns the file.
Similarly, the `group` option to specify the group that owns the file.
```
bandit6@bandit:~$ find / -type f -user bandit7 -group bandit6 -size 33c
find: ‘/var/log’: Permission denied
find: ‘/var/crash’: Permission denied
find: ‘/var/spool/rsyslog’: Permission denied
find: ‘/var/spool/bandit24’: Permission denied
find: ‘/var/spool/cron/crontabs’: Permission denied
find: ‘/var/tmp’: Permission denied
find: ‘/var/lib/polkit-1’: Permission denied
/var/lib/dpkg/info/bandit7.password
find: ‘/var/lib/chrony’: Permission denied
; -- snip --
```
As we can see a bunch of the results are files which we don't have permission to access, except one. You could try to find this file by just going through the results, but there is a better way.

We can clear out the results by only showing files that don't give Permission denied.
```
bandit6@bandit:~$ find / -type f -user bandit7 -group bandit6 -size 33c | grep -v "Permission denied"
```

```
bandit6@bandit:~$ cat /var/lib/dpkg/info/bandit7.password
z7WtoNQU2XfjmMtWA8u5rN4vzqu4v99S
```

&nbsp;

## level 7 → level 8 
> The password for the next level is stored in the file **data.txt** next to the word **millionth**

This level is pretty simple, we just have to pipe the `cat` result with `grep` and provide `millionth` as the pattern.
```
bandit7@bandit:~$ cat data.txt | grep "millionth"
millionth       TESKZC0XvTetK0S9xNwm25STk5iWrBvP
```

&nbsp;

## level 8 → level 9 
> The password for the next level is stored in the file **data.txt** and is the only line of text that occurs only once

We have to sort the file so that every repeating string is placed along with the duplicate strings. ( This step is necessary, if you directly try to use `uniq`, it  won't work. )

Next we pipe the output with the `uniq` command and provide the `u` option. ( `uniq` needs the duplicate strings to be next to each other. ) 
```
bandit8@bandit:~$ sort data.txt | uniq -u
EN632PlfYiZbn3PhVK3XOGSlNInNE00t
```

&nbsp;

## level 9 → level 10 
> The password for the next level is stored in the file **data.txt** in one of the few human-readable strings, preceded by several ‘=’ characters.

We can use `strings`, instead of cat in order to see the sequences of printable characters and pipe the result with grep.
```
bandit9@bandit:~$ strings data.txt | grep "="
4========== the#
========== password
========== is
========== G7w8LIi6J3kTb8A7j9LgrywtEUlyyp6s
```

&nbsp;

## level 10 → level 11 
> The password for the next level is stored in the file **data.txt**, which contains base64 encoded data

The `base64` command allows users to perform base64 operations.

If we provide the `d` option, it will decode the input.
```
bandit10@bandit:~$ base64 -d data.txt
The password is 6zPeziLdR2RKNdNYFNb6nVCKzphlXHBM
```

&nbsp;

## level 11 → level 12 
> The password for the next level is stored in the file **data.txt**, where all lowercase (a-z) and uppercase (A-Z) letters have been rotated by 13 positions

We can use the `tr` command to translate the string.
```
bandit11@bandit:~$ cat data.txt | tr 'A-Za-z' 'N-ZA-Mn-za-m'
The password is JVNBBFSmZwKKOP0XbFXOoW8chDz5yVRv
```
Here's how it works.
```
ABCDEFGHIJKLMNOPQRSTUVWXYZ    abcdefghijklmnopqrstuvwxyz
NOPQRSTUVWXYZABCDEFGHIJKLM    nopqrstuvwxyzabcdefghijklm
```
The characters are mapped to the character at offset 13.

&nbsp;

## level 12 → level 13
> The password for the next level is stored in the file **data.txt**, which is a hexdump of a file that has been repeatedly compressed. For this level it may be useful to create a directory under /tmp in which you can work using mkdir. For example: mkdir /tmp/myname123. Then copy the datafile using cp, and rename it using mv (read the manpages!)

Once we have set up our directory, we can cat out the file.
```
bandit12@bandit:/tmp/level12$ cat data.txt
00000000: 1f8b 0808 2773 4564 0203 6461 7461 322e  ....'sEd..data2.
00000010: 6269 6e00 0145 02ba fd42 5a68 3931 4159  bin..E...BZh91AY
00000020: 2653 597b 4f96 5f00 0018 ffff fd6f e7ed  &SY{O._......o..
00000030: bff7 bef7 9fdb d7ca ffbf edff 8ded dfd7  ................
00000040: bfe7 bbff bfdb fbff ffbf ff9f b001 3b56  ..............;V
00000050: 0400 0068 0064 3400 d341 a000 0680 0699  ...h.d4..A......
00000060: 0000 69a0 0000 1a00 1a0d 0034 0034 d3d4  ..i........4.4..
00000070: d1a3 d464 6834 6403 d469 b422 0d00 3400  ...dh4d..i."..4.
00000080: 1a68 068d 3403 4d06 8d00 0c80 00f5 0003  .h..4.M.........
00000090: 4031 3119 00d0 1a68 1a34 c86d 4640 00d0  @11....h.4.mF@..
000000a0: 0007 a80d 000d 00e9 a340 d034 0341 a000  .........@.4.A..
000000b0: 0699 07a9 881e a0d0 da80 6834 0c43 4068  ..........h4.C@h
000000c0: 6432 0340 0c80 6800 0346 8006 8000 d034  d2.@..h..F.....4
000000d0: 0001 f0e1 810e 1958 b7a4 92c7 640e 421a  .......X....d.B.
000000e0: a147 6142 a67e 3603 a756 3ba9 1b08 e034  .GaB.~6..V;....4
000000f0: 41fd 1247 661d b380 00b7 cd8c b23e b6b2  A..Gf........>..
00000100: 1947 e803 0be5 6077 a542 e9ea 7810 29f0  .G....`w.B..x.).
00000110: 429d e1d7 ad8b 0b78 056b e37c 06df 4917  B......x.k.|..I.
00000120: 9b46 f69d 4473 80b4 edc2 ee10 04e3 3e52  .F..Ds........>R
00000130: dd34 2244 08cb 5e64 9314 9521 505e e767  .4"D..^d...!P^.g
00000140: 9021 d029 85e7 9ce2 d1ce d44f 5ec5 f6d6  .!.).......O^...
00000150: d918 de31 f1f5 d149 4695 0937 d06b f046  ...1...IF..7.k.F
00000160: 789d 1bd0 ca69 11eb 2c9a 3290 3d9e 0511  x....i..,.2.=...
00000170: 6cad 205b edc8 c4b5 4691 379a 5978 58c3  l. [....F.7.YxX.
00000180: 4846 a4a0 3ba5 a89a a794 1f93 c588 8160  HF..;..........`
00000190: 016e 2504 2c74 643b 5046 4154 751c 33b1  .n%.,td;PFATu.3.
000001a0: c3e5 53d8 a959 5fdc 6c12 f2bd 02f3 2d83  ..S..Y_.l.....-.
000001b0: b965 3188 0d3c b097 4156 e950 9d49 64f6  .e1..<..AV.P.Id.
000001c0: da4a 2db5 a4ea 5365 27c0 1e79 8109 5f31  .J-...Se'..y.._1
000001d0: c184 46c9 74a5 f923 5ea1 6861 f058 226c  ..F.t..#^.ha.X"l
000001e0: 3df6 5d10 d11f d966 77c9 e488 448c 5a6f  =.]....fw...D.Zo
000001f0: 2c10 410b 4280 140a 0818 8afa 0cfa 8bf7  ,.A.B...........
00000200: ad34 3308 4077 6552 9849 378e 7d85 1fd8  .43.@weR.I7.}...
00000210: f287 1238 7639 11e2 f1e6 483b 7548 25e2  ...8v9....H;uH%.
00000220: 7de4 24ff 1a69 0b85 4b4c ebd0 1231 a512  }.$..i..KL...1..
00000230: f9fb 109c e7ea d932 98fd eb76 f4f8 fa29  .......2...v...)
00000240: 967c e152 9c69 c607 6207 eaef 2095 9441  .|.R.i..b... ..A
00000250: a64e 9ffc 5dc9 14e1 4241 ed3e 597c 9f2e  .N..]...BA.>Y|..
00000260: f0c8 4502 0000                           ..E...
```
As we can see the file contains `hexdump` which we need to convert back into `binary`

The `xxd` command is what creates a `hexdump` but if we specify the `r` option it will reverse the `hexdump` into `binary`.
```
bandit12@bandit:/tmp/level12$ xxd -r data.txt > data
``` 
We stored the output into a file.

Let's check the file-type using the `file` command.
```
bandit12@bandit:/tmp/level12$ file data
data: gzip compressed data, was "data2.bin", last modified: Sun Apr 23 18:04:23 2023, max compression, from Unix, original size modulo 2^32 581
```
We can see that the file is `gzip` compressed.

In order to decompress the file we have to rename the file so that it has `.gz` extension. This can be done using the `mv` command.
```
bandit12@bandit:/tmp/level12$ mv data data.gz
```
Now we can decompress the `data.gz` file using `gzip` along with it's `d` option.
```
bandit12@bandit:/tmp/level12$ gzip -d ./data.gz
bandit12@bandit:/tmp/level12$ ls
data  data.txt
```
Let's check the file-type of this new file.
```
bandit12@bandit:/tmp/level12$ file data
data: bzip2 compressed data, block size = 900k
```
This time it's `bzip2` compressed.

Let's rename it to `data.bz2`.
Now we can decompress it with the `bzip2` command and `d` option.
```
bandit12@bandit:/tmp/level12$ bzip2 -d data.bz2
bandit12@bandit:/tmp/level12$ ls
data  data.txt
```
Another file.
Let's check the file-type.
```
bandit12@bandit:/tmp/level12$ file data
data: gzip compressed data, was "data4.bin", last modified: Sun Apr 23 18:04:23 2023, max compression, from Unix, original size modulo 2^32 20480
```
Again `gzip` compressed.
We can decompress this by following the same steps as before and check the file-type.
```
bandit12@bandit:/tmp/level12$ file data
data: POSIX tar archive (GNU)
```
Alas! something different.
This time it's a tar archive.
```
bandit12@bandit:/tmp/level12$ tar -xvf data.tar
data5.bin
```
These file compressions are repeated quite a few times, so you can just follow the same steps and get the flag.

&nbsp;

## level 13 → level 14
> The password for the next level is stored in **/etc/bandit_pass/bandit14 and can only be read by user bandit14**. For this level, you don’t get the next password, but you get a private SSH key that can be used to log into the next level. **Note:** **localhost** is a hostname that refers to the machine you are working on

SSH is a service that allows us to connect to a remote system.

In order to use the key and not be prompted to enter a password, we have to use the `i` option.
```
bandit13@bandit:~$ ssh -i ./sshkey.private bandit14@localhost -p 2220
```

The passwords are stored in the `/etc/bandit_pass` directory. Since we are already in the bandit14 level, we should be able to cat the password.
```
bandit14@bandit:~$ cat /etc/bandit_pass/bandit14
fGrHPx402xGC7U7rXKDaxiWFTOiF0ENq
```

&nbsp;

## level 14 → level 15
> The password for the next level can be retrieved by submitting the password of the current level to **port 30000 on localhost**.

We can use Netcat or `nc` in linux to send messages to different hosts.
```
bandit14@bandit:~$ nc localhost 30000
fGrHPx402xGC7U7rXKDaxiWFTOiF0ENq
Correct!
jN2kgmIXJ6fShzhT2avhotn4Zcka6tnt
```

&nbsp;

## level 15 → level 16
> The password for the next level can be retrieved by submitting the password of the current level to **port 30001 on localhost** using SSL encryption.
   Helpful note: Getting “HEARTBEATING” and “Read R BLOCK”? Use -ign_eof and read the “CONNECTED COMMANDS” section in the manpage. Next to ‘R’ and ‘Q’, the ‘B’ command also works in this version of that command…

SSL encryption is a method to ensure a secure connection between client and server.

`openssl` is a tool that allows users to have SSL encryption over their messages.
```
bandit15@bandit:~$ openssl s_client -quiet localhost:30001
Can't use SSL_get_servername
depth=0 CN = localhost
verify error:num=18:self-signed certificate
verify return:1
depth=0 CN = localhost
verify error:num=10:certificate has expired
notAfter=Jun 22 01:40:29 2023 GMT
verify return:1
depth=0 CN = localhost
notAfter=Jun 22 01:40:29 2023 GMT
verify return:1
jN2kgmIXJ6fShzhT2avhotn4Zcka6tnt
Correct!
JQttfApK4SeyHwDlI9SXGR50qclOAil1
```
The `s_client` establishes a connection with a remote server. The `quiet` option is used to limit the data displayed on the terminal.

&nbsp;

## level 16 → level 17
> The credentials for the next level can be retrieved by submitting the password of the current level to **a port on localhost in the range 31000 to 32000**. First find out which of these ports have a server listening on them. Then find out which of those speak SSL and which don’t. There is only 1 server that will give the next credentials, the others will simply send back to you whatever you send to it.

We can use `nmap` in order to find the open ports on our localhost.
```
bandit16@bandit:~$ nmap localhost -p 31000-32000
Starting Nmap 7.80 ( https://nmap.org ) at 2023-06-22 17:18 UTC
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000099s latency).
Not shown: 996 closed ports
PORT      STATE SERVICE
31046/tcp open  unknown
31518/tcp open  unknown
31691/tcp open  unknown
31790/tcp open  unknown
31960/tcp open  unknown
```
- Let's conduct a more in-depth scan of these specific ports.
```
bandit16@bandit:~$ nmap localhost -p 31046,31518,31691,31790,31960 -sV -T5
Starting Nmap 7.80 ( https://nmap.org ) at 2023-06-22 17:19 UTC
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00062s latency).

PORT      STATE SERVICE     VERSION
31046/tcp open  echo
31518/tcp open  ssl/echo
31691/tcp open  echo
31790/tcp open  ssl/unknown
31960/tcp open  echo
```
The `sV` option enables version detection and the `T5` option specifies speed.
```
bandit16@bandit:~$ openssl s_client -quiet localhost:31790
Can't use SSL_get_servername
depth=0 CN = localhost
verify error:num=18:self-signed certificate
verify return:1
depth=0 CN = localhost
verify error:num=10:certificate has expired
notAfter=Jun 22 01:40:29 2023 GMT
verify return:1
depth=0 CN = localhost
notAfter=Jun 22 01:40:29 2023 GMT
verify return:1
JQttfApK4SeyHwDlI9SXGR50qclOAil1
Correct!
-----BEGIN RSA PRIVATE KEY-----

-----END RSA PRIVATE KEY-----
```
We get an RSA key this time. Save this RSA key in a file for the next level.
```
bandit16@bandit:/tmp/rsa$ chmod 600 bandit17.txt
```
We can now connect to `level17` using `ssh`.
```
bandit16@bandit:/tmp/rsa$ ssh -i bandit17.txt bandit17@localhost -p 2220
```

&nbsp;

## level 17 → level 18
> There are 2 files in the homedirectory: **passwords.old and passwords.new**. The password for the next level is in **passwords.new** and is the only line that has been changed between **passwords.old and passwords.new.
   NOTE: if you have solved this level and see ‘Byebye!’ when trying to log into bandit18, this is related to the next level, bandit19

This level is fairly simple, we just have to look at the changes made in the file using the `diff` command.
```
bandit17@bandit:~$ diff passwords.old passwords.new
42c42
< glZreTEH1V3cGKL6g4conYqZqaEj0mte
---
> hga5tuuCLF6fFzUpnagiMN8ssu9LFrdg
```
We can see that `glZreTEH1V3cGKL6g4conYqZqaEj0mte` has been replaced with `hga5tuuCLF6fFzUpnagiMN8ssu9LFrdg`.

&nbsp;

## level 18 → level 19
> The password for the next level is stored in a file **readme** in the homedirectory. Unfortunately, someone has modified **.bashrc** to log you out when you log in with SSH.

One thing about `ssh` is that it can run commands without being in the shell.

This allows us to pass commands appended to the `ssh` connection.
```
C>ssh bandit18@bandit.labs.overthewire.org -p 2220 "cat readme"
                         _                     _ _ _
                        | |__   __ _ _ __   __| (_) |_
                        | '_ \ / _` | '_ \ / _` | | __|
                        | |_) | (_| | | | | (_| | | |_
                        |_.__/ \__,_|_| |_|\__,_|_|\__|


                      This is an OverTheWire game server.
            More information on http://www.overthewire.org/wargames

bandit18@bandit.labs.overthewire.org's password:
awhqfNnAbc1naukrpqDYcF95h7HoMTrC
```

&nbsp;

## level 19 → level 20
> To gain access to the next level, you should use the setuid binary in the homedirectory. Execute it without arguments to find out how to use it. The password for this level can be found in the usual place (/etc/bandit_pass), after you have used the setuid binary.

```
bandit19@bandit:~$ ls -l
total 16
-rwsr-x--- 1 bandit20 bandit19 14876 Apr 23 18:04 bandit20-do
```
As we can see the file has the `setuid` bit set. And the file is owned by `bandit20`.
Setuid allows the user to run the file with the privileges of the person that owns the binary file. 

Let's see how this works in practical by first checking our id.
```
bandit19@bandit:~$ id
uid=11019(bandit19) gid=11019(bandit19) groups=11019(bandit19)
```
Now if we check id on running the binary file:
```
bandit19@bandit:~$ ./bandit20-do id
uid=11019(bandit19) gid=11019(bandit19) euid=11020(bandit20) groups=11019(bandit19)
```
We can see our `euid` (effective user id) is set to the id of `bandit20`.

This means we can run another command with the privileges of `bandit20`.
```
bandit19@bandit:~$ ./bandit20-do cat /etc/bandit_pass/bandit20
VxCazJaVykI6W36BkBU0mJTCM8rR95XT
```
And we have our password.

&nbsp;

# level 20 → level 21
>There is a setuid binary in the homedirectory that does the following: it makes a connection to localhost on the port you specify as a commandline argument. It then reads a line of text from the connection and compares it to the password in the previous level (bandit20). If the password is correct, it will transmit the password for the next level (bandit21).
>NOTE: Try connecting to your own network daemon to see if it works as you think

