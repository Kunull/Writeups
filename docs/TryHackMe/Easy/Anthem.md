---
custom_edit_url: null
pagination_next: null
pagination_prev: null
---

## Task 1: Website Analysis

### What port is for the web server?
Let's scan the target using `nmap`.
```
$ nmap -sC -sV 10.10.5.238 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-12-07 19:48 IST
Nmap scan report for 10.10.5.238
Host is up (0.14s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=WIN-LU09299160F
| Not valid before: 2023-12-06T14:18:23
|_Not valid after:  2024-06-06T14:18:23
|_ssl-date: 2023-12-07T14:20:35+00:00; +2s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: WIN-LU09299160F
|   NetBIOS_Domain_Name: WIN-LU09299160F
|   NetBIOS_Computer_Name: WIN-LU09299160F
|   DNS_Domain_Name: WIN-LU09299160F
|   DNS_Computer_Name: WIN-LU09299160F
|   Product_Version: 10.0.17763
|_  System_Time: 2023-12-07T14:19:28+00:00
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1s, deviation: 0s, median: 1s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 103.08 seconds

```
There are two open ports:

| Port | Service |
| ---- | ------- |
| 80   | http    |
| 3389     |    ms-wbt-server     |

### Answer
```
80
```

&nbsp;

### What port is for remote desktop service?
`ms-wbt-server` is the remote desktop service that runs on port 3389.
### Answer
```
3389
```

&nbsp;

### What is a possible password in one of the pages web crawlers check for? 
The page that web crawlers check for is `robots.txt`. Let's see if that has something of importance.

![3](https://github.com/Knign/Write-ups/assets/110326359/85ce5eed-3d7e-4e7f-9ac2-0c87be8ba539)

The password is mentioned along with the disallowed pages.
### Answer
```
UmbracoIsTheBest!
```

&nbsp;

### What CMS is the website using?
We can find this answer on the `/robots.txt` page as well.

![4](https://github.com/Knign/Write-ups/assets/110326359/79089a15-5574-42e0-bade-7b44bcfa2eb7)

The `/umbraco/` page tells us that the CMS is Umbraco.
### Answer
```
Umbraco
```

&nbsp;

### What is the domain of the website?
Let's visit the webpage of the target machine.

![2](https://github.com/Knign/Write-ups/assets/110326359/3086b238-bedf-4f6e-8802-9902ce333355)

Nothing really important here. 
### Answer
```
anthem.com
```

&nbsp;

### What's the name of the Administrator
Let's check out the first blog post.

![5](https://github.com/Knign/Write-ups/assets/110326359/dbe1ef98-dcc9-465d-8313-5168ccb18a69)

We can see that there is a poem written about the admin. This poem is actually a real one written about Solomon Grundy.
### Answer
```
Solomon Grundy
```

&nbsp;

### Can we find find the email address of the administrator?
If we check out the second post, we can find the email format.

![6](https://github.com/Knign/Write-ups/assets/110326359/ad1e25bb-626c-4d42-85cb-94061f1005aa)

Now that we know the email of Jane Doe is `JD@anthem.com` we can guess Solomon Grundy's email address.
### Answer
```
SG@anthem.com
```

&nbsp;

## Task 2: Spot the Flags
### What is flag 1?
We can find the first flag in the source page of the second post.

![7](https://github.com/Knign/Write-ups/assets/110326359/e369849b-b8aa-410e-addd-02fd4aa2a812)

### Answer
```
THM{L0L_WH0_US3S_M3T4}
```

&nbsp;

### What is flag 2?
We can find the second flag in the source page of the main web page.

![8](https://github.com/Knign/Write-ups/assets/110326359/dc9968e2-eefc-479d-a13f-ece1e29de083)

### Answer
```
THM{G!T_G00D}
```

&nbsp;

### What is flag 3?
We can find the third flag on viewing Jane Doe's profile

![9](https://github.com/Knign/Write-ups/assets/110326359/2d2d861a-4508-4e7a-9222-38faa01b5cd7)

### Answer
```
THM{L0L_WH0_D15}
```

&nbsp;

### What is flag 4?
We can find the fourth flag on the source page of the first post.

![10](https://github.com/Knign/Write-ups/assets/110326359/79316d39-9faf-498c-b77d-6e3da17c4c25)

### Answer
```
THM{AN0TH3R_M3TA}
```

&nbsp;

## Task 3: Final stage
### Gain initial access to the machine, what is the contents of user.txt?
We know that there is a user `sg` and a password `UmbracoIsTheBest!`.

Using the credentials we can connect to the target through RDP.
```
$ xfreerdp /v:10.10.5.238 /u:sg /p:UmbracoIsTheBest! /cert:ignore +clipboard /dynamic-resolution
```

![11](https://github.com/Knign/Write-ups/assets/110326359/797a6f2b-b00a-4121-bef9-5f11bbccfacd)

### Answer
```
THM{N00T_NO0T}
```

&nbsp;

### Can we spot the admin password?
After changing the `View` to `Show hidden items` we can go to `C\backup`.

There is file there which we don't have the permissions to read.

![12](https://github.com/Knign/Write-ups/assets/110326359/87750212-b563-4100-bbe0-a1d220291dc9)

Let's see if we can change the permissions.

![13](https://github.com/Knign/Write-ups/assets/110326359/29cf5648-b5c3-414d-ac76-6e49917743dd)

After changing the permissions, we can read the file.

![14](https://github.com/Knign/Write-ups/assets/110326359/81721240-3102-4218-bbfc-478afc4b4d12)

### Answer
```
ChangeMeBaby1MoreTime
```

&nbsp;

### Escalate your privileges to root, what is the contents of root.txt?
Let's end the current RDP session and login again as `Administrator` with the password as `ChangeMeBaby1MoreTime`.
```
$ xfreerdp /v:10.10.5.238 /u:Administrator /p:ChangeMeBaby1MoreTime /cert:ignore +clipboard /dynamic-resolution
```

![15](https://github.com/Knign/Write-ups/assets/110326359/4215cb2c-2185-4d41-9095-bb5460615527)

### Answer
```
THM{Y0U_4R3_1337}
```
