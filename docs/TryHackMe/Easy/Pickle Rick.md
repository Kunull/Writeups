---
custom_edit_url: null
pagination_next: null
pagination_prev: null
---

## Task 1: Pickle Rick
### What is the first ingredient that Rick needs?
Let's perform a simple `nmap` scan to see which ports are open.
```
$ nmap -sC -sV 10.10.88.164
Starting Nmap 7.92 ( https://nmap.org ) at 2023-11-11 14:52 IST
Nmap scan report for 10.10.88.164
Host is up (0.13s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b0:56:f1:d5:f7:ee:f0:9f:0f:9f:07:88:c6:56:7a:29 (RSA)
|   256 ef:9b:c2:3f:b3:84:8d:22:5e:d2:b4:09:59:ba:be:15 (ECDSA)
|_  256 0d:2a:4f:24:a0:9f:3d:20:80:31:b8:51:42:29:a7:0f (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Rick is sup4r cool
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.91 seconds
```
There are two open ports:

| Port | Service |
| :-: | :-: |
| 22   | ssh     |
| 80   | http    |

Let's enter the IP address in the browser and see what comes up.

![2](https://github.com/Knign/Write-ups/assets/110326359/8aaa26f6-2805-47a9-a9e9-4f7d5f146ace)

Let's check the page source for more information.

![3](https://github.com/Knign/Write-ups/assets/110326359/be514f8f-df42-42f2-b747-5bb8b4a343cf)

So we have a username now: `R1ckRul3s`. However we don't know the password yet.

On most websites, the `robots.txt` file does the job of disallowing web crawlers from accessing particular pages. Let's see if we can find anything there.

![4](https://github.com/Knign/Write-ups/assets/110326359/1ab0843f-c6f0-441a-a2ee-dd96cddc3716)

Looks like `Wubbalubbadubdub` is the password.

But where should we enter these credentials?
In order to find the login page we will have to perform some directory brute-forcing. There are various tools available, but in this case let's use `gobuster`.
```
$ gobuster dir -u http://10.10.88.164 -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt -x php
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.88.164
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 291]
/login.php            (Status: 200) [Size: 882]
/assets               (Status: 301) [Size: 313] [--> http://10.10.88.164/assets/]
/portal.php           (Status: 302) [Size: 0] [--> /login.php]

<SNIP>
```
We can see a `/login.php` file. Let's go to the file in the browser.

![5](https://github.com/Knign/Write-ups/assets/110326359/b7853f1d-fbc0-4ecb-ad1c-d2bff3fb09e3)

Let's enter the credentials that we found before i.e. `R1ckRul3s` as username and `Wubbalubbadubdub` as the password.

![6](https://github.com/Knign/Write-ups/assets/110326359/47807896-3cb1-4374-922a-b55e7bb4378e)

We're in and we have a `Command Panel` to enter our commands.

We can use the `ls` command to list the files and subdirectories.

![7](https://github.com/Knign/Write-ups/assets/110326359/4e153ed7-49bd-498c-91d0-8ea6cd04720f)

The `Sup3rS3cretPickl3Ingred.txt` file seems interesting. Let's `cat` the contents of that file.

![8](https://github.com/Knign/Write-ups/assets/110326359/3fa9ddc0-5d16-489c-a440-726ff8a027b9)

Oh! So `cat` is disabled. We have to find another way to read the file.

We can `grep` all the contents of the file by using the `.` regular expression.
```
grep . Sup3rS3cretPickl3Ingred.txt
```

![9](https://github.com/Knign/Write-ups/assets/110326359/224248e8-51b4-4c9f-84e0-ce59a108cebd)

### Answer
```
mr. meeseek hair
```

&nbsp;

### What is the second ingredient in Rick’s potion?
We can check which user are present by using the following command:
```
cd /home ; ls
```

![10](https://github.com/Knign/Write-ups/assets/110326359/082c2c36-7474-427b-8af6-4b067f56973f)

Let's check what files `rick` has using the following command:
```
cd /home/rick ; ls
```

![11](https://github.com/Knign/Write-ups/assets/110326359/5f9aae7a-1551-49d2-8e58-b52001af6882)

Let's see what is in to the `second ingredients`.
```
grep . /home/rick/"second ingredients"
```

![12](https://github.com/Knign/Write-ups/assets/110326359/42962fdd-8d88-4e10-b720-a15542dd42bf)

### Answer
```
1 jerry tear
```

&nbsp;

### What is the last and final ingredient?
Let's look at the `/root` directory using the following command:
```
sudo ls /root
```

![13](https://github.com/Knign/Write-ups/assets/110326359/f0ca0ca7-10cb-4d6e-b473-825d342c0e58)

As always, we can use `grep` to read the contents of a file.
```
sudo grep . /root/3rd.txt
```

![14](https://github.com/Knign/Write-ups/assets/110326359/33d34bd6-679a-4193-b1e0-f473cb9fb191)

### Answer
```
fleeb juice
```
