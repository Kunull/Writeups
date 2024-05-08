---
custom_edit_url: null
pagination_next: null
pagination_prev: null
---


## Q1. What is the name of the suspicious process?
Once we have downloaded the file, we can analyse it using `volatility`.
Let's begin by searching for malicious processes using the `windows.malfind` plugin.
```
$ volatility3/vol.py -f MemoryDump.mem windows.malfind
Volatility 3 Framework 2.7.0
Progress:  100.00		PDB scanning finished                                                                                             
PID	Process	Start VPN	End VPN	Tag	Protection	CommitCharge	PrivateMemory	File output	Notes	Hexdump	Disasm

5896	oneetx.exe	0x400000	0x437fff	VadS	PAGE_EXECUTE_READWRITE	56	1	Disabled	MZ header	
4d 5a 90 00 03 00 00 00	MZ......
04 00 00 00 ff ff 00 00	........
b8 00 00 00 00 00 00 00	........
40 00 00 00 00 00 00 00	@.......
00 00 00 00 00 00 00 00	........
00 00 00 00 00 00 00 00	........
00 00 00 00 00 00 00 00	........
00 00 00 00 00 01 00 00	........	
0x400000:	dec	ebp
0x400001:	pop	edx
0x400002:	nop	
0x400003:	add	byte ptr [ebx], al
0x400005:	add	byte ptr [eax], al
0x400007:	add	byte ptr [eax + eax], al
0x40000a:	add	byte ptr [eax], al
7540	smartscreen.ex	0x2505c140000	0x2505c15ffff	VadS	PAGE_EXECUTE_READWRITE	1	1	Disabled	N/A	
48 89 54 24 10 48 89 4c	H.T$.H.L
24 08 4c 89 44 24 18 4c	$.L.D$.L
89 4c 24 20 48 8b 41 28	.L$.H.A(
48 8b 48 08 48 8b 51 50	H.H.H.QP
48 83 e2 f8 48 8b ca 48	H...H..H
b8 60 00 14 5c 50 02 00	.`..\P..
00 48 2b c8 48 81 f9 70	.H+.H..p
0f 00 00 76 09 48 c7 c1	...v.H..	
0x2505c140000:	mov	qword ptr [rsp + 0x10], rdx
0x2505c140005:	mov	qword ptr [rsp + 8], rcx
0x2505c14000a:	mov	qword ptr [rsp + 0x18], r8
0x2505c14000f:	mov	qword ptr [rsp + 0x20], r9
0x2505c140014:	mov	rax, qword ptr [rcx + 0x28]
0x2505c140018:	mov	rcx, qword ptr [rax + 8]
0x2505c14001c:	mov	rdx, qword ptr [rcx + 0x50]
0x2505c140020:	and	rdx, 0xfffffffffffffff8
0x2505c140024:	mov	rcx, rdx
0x2505c140027:	movabs	rax, 0x2505c140060
0x2505c140031:	sub	rcx, rax
0x2505c140034:	cmp	rcx, 0xf70
0x2505c14003b:	jbe	0x2505c140046                              
```
There are two processes namely `oneetx.exe` and `smartscreen.ex`.

On some searching, we can find that `oneetx.exe` is a malicious process, related to Amadey dropper malware.
### Answer
```
oneetx.exe
```

&nbsp;


## Q2. What is the child process name of the suspicious process?
We can check the child process using the `pslist` plugin and then `grep` for 5896.
```
$ volatility3/vol.py -f MemoryDump.mem windows.pslist
Volatility 3 Framework 2.7.0
Progress:  100.00		PDB scanning finished                        
PID	PPID	ImageFileName	Offset(V)	Threads	Handles	SessionId	Wow64	CreateTime	ExitTime	File output

<--SNIP-->
5896	8844	oneetx.exe	0xad8189b41080	5	-	1	True	2023-05-21 22:30:56.000000 	N/A	Disabled
7732	5896	rundll32.exe	0xad818d1912c0	1	-	1	True	2023-05-21 22:31:53.000000 	N/A	Disabled
<--SNIP-->
```
We can see that the `rundll32.exe` process has the process id of `oneetx.exe` as it's `PPID`.

This tells us that `rundll32.exe` is the child process of `oneetx.exe`.

### Answer
```
rundll32.exe
```

&nbsp;


## Q3. What is the memory protection applied to the suspicious process memory region?
This already found this when we used the `malfind` plugin.
```
$ volatility3/vol.py -f MemoryDump.mem windows.malfind
Volatility 3 Framework 2.7.0
Progress:  100.00		PDB scanning finished                                                                                             
PID	Process	Start VPN	End VPN	Tag	Protection	CommitCharge	PrivateMemory	File output	Notes	Hexdump	Disasm

5896	oneetx.exe	0x400000	0x437fff	VadS	PAGE_EXECUTE_READWRITE	56	1	Disabled	MZ header	
4d 5a 90 00 03 00 00 00	MZ......
04 00 00 00 ff ff 00 00	........
b8 00 00 00 00 00 00 00	........
40 00 00 00 00 00 00 00	@.......
00 00 00 00 00 00 00 00	........
00 00 00 00 00 00 00 00	........
00 00 00 00 00 00 00 00	........
00 00 00 00 00 01 00 00	........	
0x400000:	dec	ebp
0x400001:	pop	edx
0x400002:	nop	
0x400003:	add	byte ptr [ebx], al
0x400005:	add	byte ptr [eax], al
0x400007:	add	byte ptr [eax + eax], al
0x40000a:	add	byte ptr [eax], al
7540	smartscreen.ex	0x2505c140000	0x2505c15ffff	VadS	PAGE_EXECUTE_READWRITE	1	1	Disabled	N/A	
48 89 54 24 10 48 89 4c	H.T$.H.L
24 08 4c 89 44 24 18 4c	$.L.D$.L
89 4c 24 20 48 8b 41 28	.L$.H.A(
48 8b 48 08 48 8b 51 50	H.H.H.QP
48 83 e2 f8 48 8b ca 48	H...H..H
b8 60 00 14 5c 50 02 00	.`..\P..
00 48 2b c8 48 81 f9 70	.H+.H..p
0f 00 00 76 09 48 c7 c1	...v.H..	
0x2505c140000:	mov	qword ptr [rsp + 0x10], rdx
0x2505c140005:	mov	qword ptr [rsp + 8], rcx
0x2505c14000a:	mov	qword ptr [rsp + 0x18], r8
0x2505c14000f:	mov	qword ptr [rsp + 0x20], r9
0x2505c140014:	mov	rax, qword ptr [rcx + 0x28]
0x2505c140018:	mov	rcx, qword ptr [rax + 8]
0x2505c14001c:	mov	rdx, qword ptr [rcx + 0x50]
0x2505c140020:	and	rdx, 0xfffffffffffffff8
0x2505c140024:	mov	rcx, rdx
0x2505c140027:	movabs	rax, 0x2505c140060
0x2505c140031:	sub	rcx, rax
0x2505c140034:	cmp	rcx, 0xf70
0x2505c14003b:	jbe	0x2505c140046         
```
### Answer
```
PAGE_EXECUTE_READWRITE
```

&nbsp;


## Q4. What is the name of the process responsible for the VPN connection?
Let's look at all the running processes.
```
$ volatility3/vol.py -f MemoryDump.mem windows.pstree
Volatility 3 Framework 2.7.0
Progress:  100.00		PDB scanning finished                        
PID	PPID	ImageFileName	Offset(V)	Threads	Handles	SessionId	Wow64	CreateTime	ExitTime	Audit	Cmd	Path

<--SNIP-->
*** 6724	3580	Outline.exe	0xad818e578080	0	-	1	True	2023-05-21 22:36:09.000000 	2023-05-21 23:01:24.000000 	\Device\HarddiskVolume3\Program Files (x86)\Outline\Outline.exe	-	-
**** 4224	6724	Outline.exe	0xad818e88b080	0	-	1	True	2023-05-21 22:36:23.000000 	2023-05-21 23:01:24.000000 	\Device\HarddiskVolume3\Program Files (x86)\Outline\Outline.exe	-	-
**** 4628	6724	tun2socks.exe	0xad818de82340	0	-	1	True	2023-05-21 22:40:10.000000 	2023-05-21 23:01:24.000000 	\Device\HarddiskVolume3\Program Files (x86)\Outline\resources\app.asar.unpacked\third_party\outline-go-tun2socks\win32\tun2socks.exe	-	-
<--SNIP-->
```
The `outline.exe` is responsible for making VPN connections.
### Answer
```
outline.exe
```

&nbsp;


## Q5. What is the attacker's IP address?
We can use `netscan` plugin to scan for network artifacts.
```
$ volatility3/vol.py -f MemoryDump.mem windows.netscan
Volatility 3 Framework 2.7.0
Progress:  100.00		PDB scanning finished                        
Offset	Proto	LocalAddr	LocalPort	ForeignAddr	ForeignPort	State	PID	Owner	Created

<--SNIP-->
0xad818de4aa20	TCPv4	10.0.85.2	55462	77.91.124.20	80	CLOSED	5896	oneetx.exe	2023-05-21 23:01:22.000000 
<--SNIP-->
0xad818e4a6900	UDPv4	0.0.0.0	0	*	0		5480	oneetx.exe	2023-05-21 22:39:47.000000 
0xad818e4a6900	UDPv6	::	0	*	0		5480	oneetx.exe	2023-05-21 22:39:47.000000 
0xad818e4a9650	UDPv4	0.0.0.0	0	*	0		5480	oneetx.exe	2023-05-21 22:39:47.000000 
<--SNIP-->
```
We can see that the `oneetx` process is making four network connections.

Out of the four, the TCP connection has a foreign address of `77.91.124.20`.

### Answer
```
77.91.124.20
```

&nbsp;


## Q6. Based on the previous artifacts. What is the name of the malware family?
If we search up the IP address that we found, we can get information including the name and delivery method.

![redline stealer](https://github.com/Knign/Write-ups/assets/110326359/d449b528-380c-4403-a6d0-138410cb8bd0)

### Answer
```
RedLine Stealer
```

&nbsp;


## Q7. What is the full URL of the PHP file that the attacker visited?
Let's dump all the strings into a text file.
```
$ strings MemoryDump.mem > strings.txt    
```

```
$ grep -Eo 'https?://[^[:space:]]+' strings.txt | grep -i "77.91.124.20"
http://77.91.124.20/
http://77.91.124.20/store/gamel
http://77.91.124.20/
http://77.91.124.20/DSC01491/
http://77.91.124.20/DSC01491/
http://77.91.124.20/store/games/index.php
http://77.91.124.20/store/games/index.php
http://77.91.124.20/store/games/index.php
```
### Answer
```
http://77.91.124.20/store/games/index.php
```

&nbsp;


## Q8. What is the full path of the malicious executable?
To get the full path, we can use the `filescan` plugin.
```
$ volatility3/vol.py -f MemoryDump.mem windows.filescan
Volatility 3 Framework 2.7.0
Progress:  100.00		PDB scanning finished                        
Offset	Name	Size

<--SNIP-->
0xad818d436c70  \Users\Tammam\AppData\Local\Temp\c3912af058\oneetx.exe	216
0xad818da36c30	\Users\Tammam\AppData\Local\Temp\c3912af058\oneetx.exe	216
0xad818ef1a0b0	\Users\Tammam\AppData\Local\Temp\c3912af058\oneetx.exe	216
<--SNIP-->
```
### Answer
```
C:\Users\Tammam\AppData\Local\Temp\c3912af058\oneetx.exe
```
