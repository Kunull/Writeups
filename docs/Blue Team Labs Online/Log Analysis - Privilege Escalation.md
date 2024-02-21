---
custom_edit_url: null
pagination_next: null
pagination_prev: null
---

## What user (other than ‘root’) is present on the server?
We can see the user move to a directory called `/home/daniel/`.

![1](https://github.com/Knign/Write-ups/assets/110326359/00f29ed8-d311-4368-a901-1edb63630ceb)

### Answer
```
daniel
```

&nbsp;

## What script did the attacker try to download to the server?
The attacker used the `wget` utility to download a Github script. 

![2](https://github.com/Knign/Write-ups/assets/110326359/1c912724-bb41-4e3f-b484-d4794770d217)

### Answer
```
linux-exploit-suggester.sh
```

&nbsp;

## What packet analyzer tool did the attacker try to use?
We can see the command `tcpdump` which is used for packet analysis on the command line.

![3](https://github.com/Knign/Write-ups/assets/110326359/9a3a0f68-e00d-4897-84b2-624eef3513d7)

### Answer
```
tcpdump
```

&nbsp;

## What file extension did the attacker use to bypass the file upload filter implemented by the developer?
The attacker tried to delete a file named `x.phtml`.

![4](https://github.com/Knign/Write-ups/assets/110326359/73a40386-280f-4003-9890-7c4d5cac8d85)

The PHTML files contain PHP code that is parsed by a PHP engine which allows the web server to generate dynamic HTML that is displayed in a web browser.
### Answer
```
.phtml
```

&nbsp;

## Based on the commands run by the attacker before removing the php shell, what misconfiguration was exploited in the ‘python’ binary to gain root-level access? 1- Reverse Shell ; 2- File Upload ; 3- File Write ; 4- SUID ; 5- Library load

We can see that the attacker tried to find binaries with the SUID bit set.

![5](https://github.com/Knign/Write-ups/assets/110326359/c75c5453-814b-47c3-888e-7a6a43df2581)

On executing a binary with the SUID bit set, the file executes with the effective permissions of the owner of the file instead of the person executing. This allows for temporary privilege escalation.

Then the attacker executes `sh`.

![6](https://github.com/Knign/Write-ups/assets/110326359/1eadcd52-21db-4424-96f4-7e425dec2093)

### Answer
```
4
```
