---
custom_edit_url: null
sidebar_position: 4
---

## level 1

> In this challenge you will work with different UNIX permissions on the flag.\
> The flag file will be owned by you and have 400 permissions.
>
> Before:\
> -r-------- 1 root root 58 Jul  2 08:50 /flag\
> After:\
> -r-------- 1 hacker root 58 Jul  2 08:50 /flag

Let's verify the fact.

```
hacker@access-control~level1:/$ ls -la /flag 
-r-------- 1 hacker root 58 Jul  2 04:37 /flag
```

We can `cat` the flag.

```
hacker@access-control~level1:/$ cat /flag 
```

&nbsp;

## level 2

> In this challenge you will work with different UNIX permissions on the flag.\
> The flag file will be owned by root, group as you, and have 040 permissions.
>
> Before:\
> -r-------- 1 root root 58 Jul  2 08:51 /flag\
> After:\
> ----r----- 1 root hacker 58 Jul  2 08:51 /flag

We can check the file permissions.

```
hacker@access-control~level2:/$ ls -la /flag 
----r----- 1 root hacker 58 Jul  2 04:50 /flag
```

Let's check if our user is part of the `hacker` group. We can do this using the `groups` command.

```
hacker@access-control~level2:/$ groups
hacker
```

We are. This means we should be able to `cat` the flag.

```
hacker@access-control~level2:/$ cat /flag 
```

&nbsp;

## level 3

> In this challenge you will work with different UNIX permissions on the flag.\
> The flag file will be owned by you and have 000 permissions.
> 
> Before:\
> -r-------- 1 root root 58 Jul  2 05:17 /flag\
> After:\
> ---------- 1 hacker root 58 Jul  2 05:17 /flag


If we check the file permissions, we can see that we do not have any way to interact with the `/flag`.

```
hacker@access-control~level3:/$ ls -la /flag 
-r-------- 1 root root 58 Jul  2 05:17 /flag
```

We can use `chmod` to change the file permissions.

```
hacker@access-control~level3:/$ chmod 400 flag 
```

```
hacker@access-control~level3:/$ ls -la /flag 
-r-------- 1 hacker root 58 Jul  2 05:17 /flag
```

Now we can `cat` the flag.

```
hacker@access-control~level3:/$ cat /flag 
```

&nbsp;

## level 4

> In this challenge you will work understand how the SETUID bit for UNIX permissions works.\
> What if /bin/cat had the SETUID bit set?
>
> Before:\
> -rwxr-xr-x 1 root root 43416 Sep  5  2019 /bin/cat\
> After:\
> -rwsr-xr-x 1 root root 43416 Sep  5  2019 /bin/cat

Let's check the permissions of the `/flag` file.

```
hacker@access-control~level4:/$ ls -la /flag 
-r-------- 1 root root 58 Jul  2 08:55 /flag
```

Since the `/bin/cat` file has the SETUID bit enabled, it will be executed with the permission of the file owner.

```
hacker@access-control~level4:/$ ls -la /bin/cat
-rwsr-xr-x 1 root root 43416 Sep  5  2019 /bin/cat
```

Since the `/bin/cat` file is owned by `root`, the process created will have `root` privileges (`rws`).
We can simple `cat` the flag.

```
hacker@access-control~level4:/$ cat /flag 
```

&nbsp;

## level 5

> In this challenge you will work understand how the SETUID bit for UNIX permissions works.\
> What if /bin/cp had the SETUID bit set?\
> Hint: Look into how cp will deal with different permissions.\
> Another Hint: check the man page for cp, any options in there that might help?
> 
> Before:\
> -rwxr-xr-x 1 root root 153976 Sep  5  2019 /bin/cp\
> After:\
> -rwsr-xr-x 1 root root 153976 Sep  5  2019 /bin/cp

While using `cp` to copy files, if we specify the `--no-preserve` option, it doesn't preserve the specified attributes.

```
--no-preserve=ATTR_LIST
    don't preserve the specified attributes
```

These attributes could be:
  - `mode`
  - `timestamps`
  - `ownership`
  - `links`
  - `context`
  - `xattr`
  - `all`

Let's use the following command:

```
hacker@access-control~level5:/$ cp --no-preserve=all /flag /home/hacker/flag.backup
```

This will create a `flag.backup` file in our home directory without any of the original `/flag` file's attributes including permissions.

We can now check the permissions of the `/home/hacker/flag.backup` file.

```
hacker@access-control~level5:/$ ls -la /home/hacker/flag.backup 
-rw-r--r-- 1 root hacker 58 Jul  2 09:47 /home/hacker/flag.backup
```

As we can see, we can now read the file using `cat`.

```
hacker@access-control~level5:/$ cat /home/hacker/flag.backup 
```

&nbsp;

## level 6

> In this challenge you will work with different UNIX permissions on the flag.\
> The flag file is owned by root and a new group.\
> Hint: Search for how to join a group with a password. 
> 
> Before:\
> -r-------- 1 root root 58 Jul  2 09:54 /flag\
> After:\
> ----r----- 1 root group_nsgdhwri 58 Jul  2 09:54 /flag\
> The password for group_nsgdhwri is: toqhnmmv

Let's check the file permissions for `/flag`.

```
hacker@access-control~level6:/$ ls -la /flag 
----r----- 1 root group_nsgdhwri 58 Jul  2 09:54 /flag
```

We can see that the `group_nsgdhwri` group own the file and can read it.
We also know the password for `group_nsgdhwri` is `toqhnmmv`. 

In order to change add our current user to the `group_nsgdhwri` group, we can use the `newgrp` utility.

```
hacker@access-control~level6:/$ newgrp group_akgvhbnl
Password:
```

Let's check the groups that the `hacker` user is part of using the `groups` utility.

```
hacker@access-control~level6:/$ groups
group_akgvhbnl hacker
```

We can now `cat` the flag. 

```
hacker@access-control~level6:/$ cat /flag
```

&nbsp;

## level 7

> In this challenge you will work understand how UNIX permissions works with multiple users.\
> You'll also be given access to various user accounts, use su to switch between them.
> 
> Before:\
> -------r-- 1 hacker root 58 Jul  2 10:58 /flag\
> Created user user_iajvgicj with password ybvkgucm\
> After:\
> -------r-- 1 hacker root 58 Jul  2 10:58 /flag

Let's check the file permissions for `/flag`.

```
hacker@access-control~level7:/$ ls -la /flag 
-------r-- 1 hacker root 58 Jul  2 10:58 /flag
```

We can switch to the `user_iajvgicj` user with the `su` utility.

```
hacker@access-control~level7:/$ su user_iajvgicj
Password: 
user_iajvgicj@access-control~level7:/$ 
```

```
user_iajvgicj@access-control~level7:/$ ls -la /flag 
-------r-- 1 hacker root 58 Jul  2 11:25 /flag
```

Now, as the `user_iajvgicj` user, we can simply `cat` the flag.

```
user_iajvgicj@access-control~level7:/$ cat /flag 
```

&nbsp;

## level 8

> In this challenge you will work understand how UNIX permissions works with multiple users.\
> You'll also be given access to various user accounts, use su to switch between them.
> 
> Before:\
> -r-------- 1 root root 58 Jul  2 11:23 /flag\
> Created user user_culoxoyb with password kwwhmmst\
> After:\
> -r-------- 1 user_culoxoyb root 58 Jul  2 11:23 /flag

Let's check the file permissions for `/flag`.

```
hacker@access-control~level8:/$ ls -la /flag 
-r-------- 1 user_culoxoyb root 58 Jul  2 11:23 /flag
```

We can switch to the `user_culoxoyb` user with the `su` utility.

```
hacker@access-control~level8:/$ su user_culoxoyb
Password: 
user_culoxoyb@access-control~level8:/$ 
```

Now, as the `user_culoxoyb` user, we can simply `cat` the flag.

```
user_culoxoyb@access-control~level8:/$ cat /flag 
pwn.college{srqLcsfemTJ5f-fFeNdVJNRd9H0.dljM4MDL4ITM0EzW}
```

&nbsp;

## level 9

> In this challenge you will work understand how UNIX permissions works with multiple users.\
> You'll also be given access to various user accounts, use su to switch between them.
> 
> Before:\
> -r-------- 1 root root 58 Jul  2 11:28 /flag\
> Created user user_mnohngfr with password vykbymwf\
> After:\
> ----r----- 1 root user_mnohngfr 58 Jul  2 11:28 /flag

Let's check the file permissions for `/flag`.

```
hacker@access-control~level9:/$ ls -la /flag 
----r----- 1 root user_mnohngfr 58 Jul  2 11:31 /flag
```

We can switch to the `user_mnohngfr` user with the `su` utility.

```
hacker@access-control~level9:/$ su user_mnohngfr
Password: 
user_mnohngfr@access-control~level9:/$ 
```

Now, as the `user_culoxoyb` user, we can simply `cat` the flag.

```
user_mnohngfr@access-control~level9:/$ cat /flag 
```

&nbsp;

## level 10

> In this challenge you will work understand how UNIX permissions works with multiple users.\
> You'll also be given access to various user accounts, use su to switch between them.\
> Hint: How can you tell which user is in what group?
> 
> Before:\
> -r-------- 1 root root 58 Jul  2 11:37 /flag\
> Created user user_ggfbbiex with password odctcprl\
> Created user user_jwebpykm with password zsdcplow\
> Created user user_ykxdsqko with password lqdsivyj\
> Created user user_dsasvprd with password ipptudwj\
> Created user user_pmsujamy with password nxhanost\
> Created user user_hqzctllc with password ogmgthpf\
> Created user user_hvkmzrlv with password xthnccwu\
> Created user user_lkoglzrf with password ojfhpayx\
> Created user user_vjkvkhil with password nzjsptav\
> Created user user_zotbnzip with password rypahdlz\
> After:\
> ----r----- 1 root group_dbq 58 Jul  2 11:37 /flag

Let's check the file permissions for the `/flag` file.

```
hacker@access-control~level10:/$ ls -la /flag
----r----- 1 root group_dbq 58 Jul  2 11:37 /flag
```

As we can see, the file is owned by the `group_dbq` group. Out of all the users, we have to find the user that is part of this group.

We can `cat` the `/etc/group` file to obtain information about the groups and pipe it with `grep` to filter the output.

```
hacker@access-control~level10:/$ cat /etc/group | grep "group_dbq"
group_dbq:x:1001:user_ggfbbiex
```

Now that we know the `user_ggfbbiex` user is part of the `group_dbq` group, we can switch to that user using the `su` utility.

```
hacker@access-control~level10:/$ su user_ggfbbiex
Password: 
user_ggfbbiex@access-control~level10:/$
```

Now, we can `cat` the flag. 

```
user_ggfbbiex@access-control~level10:/$ cat /flag 
```

&nbsp;

## level 11

> In this challenge you will work understand how UNIX permissions for directories work with multiple users.\
> You'll be given access to various user accounts, use su to switch between them.
> 
> Created user user_nuwudvxt with password cbxpdvig\
> Created user user_iwbtimvf with password khxccqvf\
> A copy of the flag has been placed somewhere in /tmp:\
> total 40\
> drwxrwxrwt 1 root   root          4096 Jul  2 12:03 .\
> drwxr-xr-x 1 root   root          4096 Jul  2 12:00 ..\
> -rw-rw-r-- 1 root   root             4 Jun 22 07:00 .cc.txt\
> -rw-r--r-- 1 root   root            55 Jun 22 07:13 .crates.toml\
> -rw-r--r-- 1 root   root           453 Jun 22 07:13 .crates2.json\
> drwxr-xr-x 3 hacker hacker        4096 Jul  2 12:00 .dojo\
> drwxr-xr-x 2 root   root          4096 Jun 22 07:13 bin\
> drwxr-xr-x 1 root   root          4096 Jun 22 07:23 hsperfdata_root\
> drwx------ 1 mysql  mysql         4096 Jun 22 07:22 tmp.03myKcqN5v\
> dr-xr-x--x 2 root   user_nuwudvxt 4096 Jul  2 12:03 tmpsvtlxi6x\
> srwxr-xr-x 1 hacker hacker           0 Jul  2 12:03 vscode-git-c804107ea9.sock\
> srwxr-xr-x 1 hacker hacker           0 Jul  2 12:02 vscode-ipc-1753ea1a-1e62-4fc6-9282-01722892fe34.sock\
> srwxr-xr-x 1 hacker hacker           0 Jul  2 12:03 vscode-ipc-cb9cf3d0-b686-458f-b106-6283f8699456.sock

```
hacker@access-control~level11:/$ ls -la /flag 
-r-------- 1 root root 58 Jul  2 12:00 /flag
```

If we look closely at the `/tmp` directory listing, we can see that the `tmpsvtlxi6x` directory is owned by the `user_nuwudvxt` group. Users that are part of this group have `r-x` permissions.

We have been told that the password for the `user_nuwudvxt` user is `cbxpdvig`.
Let's switch to that user using the `su` utility.

```
hacker@access-control~level11:/$ su user_nuwudvxt
Password: 
user_nuwudvxt@access-control~level11:/$
```

Let's check if the user is part of the `user_nuwudvxt` group.

```
user_nuwudvxt@access-control~level11:/$ groups
user_nuwudvxt
```

Now, we can list out the contents of the `/tmp/tmpsvtlxi6x` directory.

```
user_nuwudvxt@access-control~level11:/$ ls -la /tmp/tmpsvtlxi6x
total 12
dr-xr-x--x 2 root user_nuwudvxt 4096 Jul  2 12:03 .
drwxrwxrwt 1 root root          4096 Jul  2 12:03 ..
-r--r----- 1 root user_iwbtimvf   58 Jul  2 12:03 tmpvn3bgul4
```

As we can see there is a file called `tmpvn3bgul4` which is owned by the `user_iwbtimvf` group.
Users that are part of this group have `r--` permissions.

We know that the password for the `user_iwbtimvf` user is `khxccqvf`.
Let's switch to that user using the `su` utility.

```
user_nuwudvxt@access-control~level11:/$ su user_iwbtimvf
Password: 
user_iwbtimvf@access-control~level11:/$
```

Let's check if the user is part of the `user_iwbtimvf` group.

```
user_iwbtimvf@access-control~level11:/$ groups
user_iwbtimvf
```

Since our current is part of the group that can read the flag, we can use the `cat` utility.

```
user_iwbtimvf@access-control~level11:/$ cat /tmp/tmpsvtlxi6x/tmpvn3bgul4
```

&nbsp;

## level 12

> In this challenge you will work understand how UNIX permissions for directories work with multiple users.\
> You'll be given access to various user accounts, use su to switch between them.
> 
> Created user user_bwzcfbrm with password cqblhvpg\
> Created user user_henkpdbb with password ocrukeou\
> Created user user_uclfhuvt with password nsoernsj\
> A copy of the flag has been placed somewhere in /tmp:\
> total 40\
> drwxrwxrwt 1 root   root          4096 Jul  2 12:54 .\
> drwxr-xr-x 1 root   root          4096 Jul  2 12:53 ..\
> -rw-rw-r-- 1 root   root             4 Jun 22 07:00 .cc.txt\
> -rw-r--r-- 1 root   root            55 Jun 22 07:13 .crates.toml\
> -rw-r--r-- 1 root   root           453 Jun 22 07:13 .crates2.json\
> drwxr-xr-x 3 hacker hacker        4096 Jul  2 12:53 .dojo\
> drwxr-xr-x 2 root   root          4096 Jun 22 07:13 bin\
> drwxr-xr-x 1 root   root          4096 Jun 22 07:23 hsperfdata_root\
> drwx------ 1 mysql  mysql         4096 Jun 22 07:22 tmp.03myKcqN5v\
> dr-xr-x--x 3 root   user_henkpdbb 4096 Jul  2 12:54 tmpls3r7t6a\
> srwxr-xr-x 1 hacker hacker           0 Jul  2 12:53 vscode-git-edc6e8baf6.sock\
> srwxr-xr-x 1 hacker hacker           0 Jul  2 12:53 vscode-ipc-5d4bf2fa-8287-4145-bb17-6c8a2f632545.sock\
> srwxr-xr-x 1 hacker hacker           0 Jul  2 12:53 vscode-ipc-75c4b866-4f5c-4759-b4e5-868b5e14c685.sock

If we look closely at the `/tmp` directory listing, we can see that the `tmpls3r7t6a` directory is owned by the `user_henkpdbb` group. Users that are part of this group have `r-x` permissions.

We have been told that the password for the `user_henkpdbb` user is `ocrukeou`.
Let's switch to that user using the `su` utility.

```
hacker@access-control~level12:/$ su user_henkpdbb
Password: 
user_henkpdbb@access-control~level12:/$ 
```

Let's check if the user is part of the `user_henkpdbb` group.

```
user_henkpdbb@access-control~level12:/$ groups
user_henkpdbb
```

We can now list the contents of the `/tmp/tmpls3r7t6a` directory.

```
user_henkpdbb@access-control~level12:/$ ls -la /tmp/tmpls3r7t6a
total 12
dr-xr-x--x 3 root user_henkpdbb 4096 Jul  2 12:54 .
drwxrwxrwt 1 root root          4096 Jul  2 12:54 ..
dr-xr-x--x 2 root user_bwzcfbrm 4096 Jul  2 12:54 tmpn95zewqc
```

As we can see there is a directory called `tmpn95zewqc` which is owned by the `user_bwzcfbrm` group.
Users that are part of this group have `r-x` permissions.

We know that the password for the `user_bwzcfbrm` user is `cqblhvpg`.
Let's switch to that user using the `su` utility.

```
user_henkpdbb@access-control~level12:/$ su user_bwzcfbrm
Password: 
user_bwzcfbrm@access-control~level12:/$ 
```

Let's check if the user is part of the `user_bwzcfbrm` group.

```
user_bwzcfbrm@access-control~level12:/$ groups
user_bwzcfbrm
```

We can now list the contents of the `/tmp/tmpls3r7t6a/tmpn95zewqc` directory.

```
user_bwzcfbrm@access-control~level12:/$ ls -la /tmp/tmpls3r7t6a/tmpn95zewqc
total 12
dr-xr-x--x 2 root user_bwzcfbrm 4096 Jul  2 12:54 .
dr-xr-x--x 3 root user_henkpdbb 4096 Jul  2 12:54 ..
-r--r----- 1 root user_uclfhuvt   58 Jul  2 12:54 tmpra2zhmig
```

As we can see there is a file called `tmpra2zhmig` which is owned by the `user_uclfhuvt` group.
Users that are part of this group have `r--` permissions.

We know that the password for the `user_uclfhuvt` user is `nsoernsj`.
Let's switch to that user using the `su` utility.

```
user_bwzcfbrm@access-control~level12:/$ su user_uclfhuvt
Password: 
user_uclfhuvt@access-control~level12:/$ 
```

Let's check if the user is part of the `user_bwzcfbrm` group.

```
user_uclfhuvt@access-control~level12:/$ groups
user_uclfhuvt
```

We can now `cat` the flag.

```
user_uclfhuvt@access-control~level12:/$ cat /tmp/tmpls3r7t6a/tmpn95zewqc/tmpra2zhmig
```

&nbsp;

## level 13

> In this challenge, your goal is to answer 1 questions correctly in 120 seconds about the following Mandatory Access Control (MAC) system:\
> 4 Levels (first is highest aka more sensitive):\
> TS\
> S\
> C\
> UC

A subject with level TS should be able to write to an object with level TS.
The answer is:

```
Q 1. Can a Subject with level TS write an Object with level TS?
yes
Correct!
```

&nbsp;

## level 14

> In this challenge, your goal is to answer 5 questions correctly in 120 seconds about the following Mandatory Access Control (MAC) system:\
> 4 Levels (first is highest aka more sensitive):\
> TS\
> S\
> C\
> UC

```
Q 1. Can a Subject with level S write an Object with level S?
yes
Correct!
Q 2. Can a Subject with level S read an Object with level TS?
no
Correct!
Q 3. Can a Subject with level C write an Object with level TS?
yes
Correct!
Q 4. Can a Subject with level TS read an Object with level S?
yes
Correct!
Q 5. Can a Subject with level S write an Object with level S?
yes
Correct!
```

&nbsp;

## level 15

> In this challenge, your goal is to answer 1 questions correctly in 120 seconds about the following Mandatory Access Control (MAC) system:\
> 4 Levels (first is highest aka more sensitive):\
> TS\
> S\
> C\
> UC\
> 4 Categories:\
> NUC\
> ACE\
> NATO\
> UFO

```
Q 1. Can a Subject with level S and categories {NUC, NATO} write an Object with level S and categories {NUC, ACE}?
no
Correct!
```

&nbsp;

## level 16

> In this challenge, your goal is to answer 5 questions correctly in 120 seconds about the following Mandatory Access Control (MAC) system:\
> 4 Levels (first is highest aka more sensitive):\
> TS\
> S\
> C\
> UC\
> 4 Categories:\
> ACE\
> UFO\
> NUC\
> NATO

```
Q 1. Can a Subject with level C and categories {UFO, NUC} write an Object with level C and categories {ACE, NUC}?
no
Correct!
Q 2. Can a Subject with level C and categories {NUC} read an Object with level UC and categories {ACE, UFO, NATO}?
no
Correct!
Q 3. Can a Subject with level UC and categories {UFO, NATO} write an Object with level C and categories {UFO, NUC}?
no
Correct!
Q 4. Can a Subject with level S and categories {ACE, NUC, NATO} read an Object with level S and categories {ACE}?
yes
Correct!
Q 5. Can a Subject with level TS and categories {ACE, NUC} read an Object with level TS and categories {ACE}?
yes
Correct!
```

&nbsp;

## level 17

> In this challenge you'll be answering many questions about the category-based Bell–LaPadula model of Mandatory Access Control.
>
> Hint: Use pwntools to interact with this process and answer the questions.
>
> In this challenge, your goal is to answer 20 questions correctly in 1 seconds about the following Mandatory Access Control (MAC) system:\
> 4 Levels (first is highest aka more sensitive):\
> TS\
> S\
> C\
> UC\
> 4 Categories:\
> NATO\
> NUC\
> UFO\
> ACE

```python title="access_control_17.py"
import subprocess
import re

process = subprocess.Popen(
    "/challenge/run", 
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,  # Capture stderr for additional debugging
    encoding="utf-8"
)

levels = {
    "TS": 4,  # Top Secret
    "S": 3,   # Secret
    "C": 2,   # Confidential
    "UC": 1,  # Unclassified
}

groups = {
    "NATO": 1,
    "UFO": 2,
    "NUC": 3,
    "ACE": 4,
}

flag_pattern = re.compile(r'pwn\.college\{.*?\}')

def parse_line(line):
    match = re.match(r'Q (\d+). Can a Subject with level ([A-Z]+) and categories \{([A-Z, ]*)\} (read|write) an Object with level ([A-Z]+) and categories \{([A-Z, ]*)\}\?', line)
    if match:
        print(line)
        question_number, subject_level, subject_groups_str, access_type, object_level, object_groups_str = match.groups()

        try:
            question_number = int(question_number)
            subject_level = levels[subject_level]
            subject_groups = set(groups[x] for x in subject_groups_str.split(", ") if x)
            object_level = levels[object_level]
            object_groups = set(groups[x] for x in object_groups_str.split(", ") if x)
        except KeyError as e:
            print(f"Error: Unknown level or category '{e.args[0]}'")
            return None, None, None, None, None

        return question_number, subject_level, subject_groups, access_type, object_level, object_groups

    return None, None, None, None, None

while True:
    line = process.stdout.readline()
    if not line:
        break

    # Print the line for debugging purposes
    # print(f"Received line: {line.strip()}")

    # Check for the flag
    match = flag_pattern.search(line)
    if match:
        print(match.group(0))
        break

    if not line.startswith("Q "):
        continue

    question_number, subject_level, subject_groups, access_type, object_level, object_groups = parse_line(line)

    if question_number is None:
        continue

    # Determine if the subject can read or write the object
    if access_type == "write":
        if subject_level <= object_level and subject_groups.issubset(object_groups):
            answer = "yes\n"
        else:
            answer = "no\n"
    elif access_type == "read":
        if subject_level >= object_level and object_groups.issubset(subject_groups):
            answer = "yes\n"
        else:
            answer = "no\n"

    # Write the answer back to the process
    print(f"Sending answer: {answer.strip()}")
    process.stdin.write(answer)
    process.stdin.flush()

# Ensure to close stdin to signal the process that input is done
process.stdin.close()
process.wait()
```

&nbsp;

## level 18

> In this challenge you'll be answering many more questions about the category-based Bell–LaPadula model of Mandatory Access Control.
>
> Hint: Use pwntools to interact with this process and answer the questions.
>
> In this challenge, your goal is to answer 64 questions correctly in 1 seconds about the following Mandatory Access Control (MAC) system:\
> 4 Levels (first is highest aka more sensitive):\
> TS\
> S\
> C\
> UC\
> 4 Categories:\
> NUC\
> NATO\
> UFO\
> ACE

Same script as [level 17](#level-17).

&nbsp;

## level 19

> Automate Answering 128 Mandatory Access Control questions with random levels and categories in one second

```py title="~/script.py" showLineNumbers
from pwn import *
import re
import time

context.log_level = 'error'  # Silence pwntools unless error occurs

p = process("/challenge/run")

# Wait until the MAC system prompt appears
p.recvuntil(b"Mandatory Access Control (MAC) system")

# --- Step 1: Parse 40 levels ---
levels = []
while len(levels) < 40:
    line = p.recvline(timeout=1).decode(errors="ignore").strip()
    if re.fullmatch(r'\w+', line):  # avoid blank or malformed lines
        levels.append(line)

# Sensitivity: highest (line 1) = 40 → lowest (line 40) = 1
level_map = {lvl: 40 - i for i, lvl in enumerate(levels)}

# --- Step 2: Parse 5 categories ---
categories = []
while len(categories) < 5:
    line = p.recvline(timeout=1).decode(errors="ignore").strip()
    if re.fullmatch(r'\w+', line):
        categories.append(line)

# --- Step 3: Prepare regex for question parsing ---
question_re = re.compile(
    r'Q \d+\. Can a Subject with level (\w+) and categories \{(.*?)\} '
    r'(read|write) an Object with level (\w+) and categories \{(.*?)\}\?'
)

# --- Step 4: Answer all 128 questions ---
start = time.time()
answered = 0

while answered < 128:
    try:
        line = p.recvline(timeout=1).decode(errors="ignore")
    except EOFError:
        break

    match = question_re.match(line)
    if not match:
        continue  # Ignore unrelated lines

    subj_lvl, subj_cats_str, access, obj_lvl, obj_cats_str = match.groups()

    try:
        subj_level = level_map[subj_lvl]
        obj_level = level_map[obj_lvl]
    except KeyError as e:
        print(f"[!] Unknown level: {e.args[0]}")
        continue

    subj_cats = set(subj_cats_str.split(", ")) if subj_cats_str else set()
    obj_cats = set(obj_cats_str.split(", ")) if obj_cats_str else set()

    if access == "read":
        allowed = subj_level >= obj_level and obj_cats.issubset(subj_cats)
    else:  # write
        allowed = subj_level <= obj_level and subj_cats.issubset(obj_cats)

    p.sendline(b"yes" if allowed else b"no")
    answered += 1

# --- Step 5: Capture and display the flag ---
try:
    out = p.recvall(timeout=2).decode(errors="ignore")
except EOFError:
    out = ""

flag = re.search(r'pwn\.college\{.*?\}', out)
if flag:
    print(flag.group(0))
else:
    print("[!] Flag not found.")

print(f"Answered {answered} questions in {time.time() - start:.3f} seconds")
```

```
hacker@access-control~level19:/$ /run/workspace/bin/python3 /home/hacker/script.py
pwn.college{kznjy32Xv0we3xgiiKO_HkMQIS0.dBDN4MDL4ITM0EzW}
Answered 128 questions in 0.083 seconds
```
