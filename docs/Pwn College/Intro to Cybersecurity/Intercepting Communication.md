---
custom_edit_url: null
sidebar_position: 2
---

## Connect

In this challegne, we have to connect to `10.0.0.2` on port `31337`.

```
hacker@intercepting-communication~connect:/$ /challenge/run 
root@ip-10-0-0-1:/#
```

```
root@ip-10-0-0-1:/# nc 10.0.0.2 31337
pwn.college{wbLEvztIH-MlyXZbTzR3-bhhAwh.dlTNzMDL4ITM0EzW}
```

&nbsp;

## Send

This time we have to send a message containing `"Hello, World!""` to the remote host `10.0.0.2` on port `31337`.

```
root@ip-10-0-0-1:/# nc 10.0.0.2 31337
Hello, World!
pwn.college{0Hb11t9ijpcF9e3tDdE_3W2fDWk.QX1IDM2EDL4ITM0EzW}
```

&nbsp;

## Shutdown

We can use the `-N` option in `nc` so that it shuts down on `CTRL-D`.

```
hacker@intercepting-communication~shutdown:/$ /challenge/run 
root@ip-10-0-0-1:/# 
```

```
root@ip-10-0-0-1:/# nc -N 10.0.0.2 31337
pwn.college{M0ZqQvNQkxl9FGLlvmqyp4DYcoE.QX2IDM2EDL4ITM0EzW}
```

&nbsp;

## Listen

This time we have to listn for a connection on port `31337`.

```
hacker@intercepting-communication~listen:/$ /challenge/run 
root@ip-10-0-0-1:/#
```

```
root@ip-10-0-0-1:/# nc -l 31337
pwn.college{YEg8RQOuKAnFvEr1BPhIXGL7y1c.dBjNzMDL4ITM0EzW}
```

&nbsp

## Scan 1

In this challenge, we have to find the host which is up in our subnet, and then connect to it on port `31337`.

```
root@ip-10-0-0-1:/# for i in $(seq 1 255); do ping -c 1 -W 1 10.0.0.$i > /dev/null 2>&1 && echo "10.0.0.$i is up"; done; 
-bash: child setpgid (12 to 3746): Operation not permitted
10.0.0.1 is up
10.0.0.73 is up
root@ip-10-0-0-1:/# nc 10.0.0.73 31337
```

The `-c` option specifies the number of `ECHO_REQUEST` packets we send, and the `-W` option specifies the number of seconds we wait for a response before we timout and move on to the next host.

As we can see, the host `10.0.0.73` is up.

```
root@ip-10-0-0-1:/# nc 10.0.0.73 31337
pwn.college{w9cEDV2HoE3YNa5SUNShEMZAcfA.dFjNzMDL4ITM0EzW}
```

&nbsp;

## Scan 2

This time we have to scan the `/16` subnet using NMAP.

```
root@ip-10-0-0-1:/# nmap -p 31337 10.0.0.0/16 --open -T5 --min-hostgroup 256 --max-hostgroup 1024
Warning: You specified a highly aggressive --min-hostgroup.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-15 15:43 UTC
Nmap scan report for 10.0.220.241
Host is up (0.000055s latency).

PORT      STATE SERVICE
31337/tcp open  Elite
MAC Address: F6:1C:58:5C:33:86 (Unknown)

Nmap done: 65536 IP addresses (2 hosts up) scanned in 2663.68 seconds
```

The options used are as follows:
- `-p`: Scan only specified port
- `--open`: Show only hosts with ports
- `-T5`: Use the most aggressive timing (fastest scan)
- `--min-hostgroup`: Specify the minimum number of hosts to be scanned concurrently
- `--max-hostgroup`: Specify the maximum number of hosts to be scanned concurrently

```
root@ip-10-0-0-1:/# nc 10.0.220.241 31337
pwn.college{gpJ1hkttpIQi_Dr58v9ReQoWsFD.dJjNzMDL4ITM0EzW}
```

&nbsp;

## Monitor 1

For this challenge, we have to observe network traffic using Wireshark, and find the flag.

![image](https://github.com/user-attachments/assets/6ae68ef1-a095-4b66-972c-8cdc3ef42193)

```
pwn.college{w5xqRA9L9VqC5wgnj0y2NJf5Zd5.dNjNzMDL4ITM0EzW}
```

&nbsp;
