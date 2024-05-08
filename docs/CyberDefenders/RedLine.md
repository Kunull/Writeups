---
custom_edit_url: null
pagination_next: null
pagination_prev: null
---


## Q1. What is the name of the suspicious process?
Once we have downloaded the file, we can analyse it using `volatility`.

### Volatility 3
Let's begin by searching for malicious processes using the `windows.malfind` plugin in Volatility 3.
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

4	0	System	0xad8185883180	157	-	N/A	False	2023-05-21 22:27:10.000000 	N/A	-	-	-
* 1280	4	MemCompression	0xad8187835080	62	-	N/A	False	2023-05-21 22:27:49.000000 	N/A	MemCompression	-	-
* 108	4	Registry	0xad81858f2080	4	-	N/A	False	2023-05-21 22:26:54.000000 	N/A	Registry	-	-
* 332	4	smss.exe	0xad81860dc040	2	-	N/A	False	2023-05-21 22:27:10.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\smss.exe	-	-
452	444	csrss.exe	0xad81861cd080	12	-	0	False	2023-05-21 22:27:22.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\csrss.exe	-	-
528	520	csrss.exe	0xad8186f1b140	14	-	1	False	2023-05-21 22:27:25.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\csrss.exe		
552	444	wininit.exe	0xad8186f2b080	1	-	0	False	2023-05-21 22:27:25.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\wininit.exe	-	-
* 696	552	lsass.exe	0xad8186fc6080	10	-	0	False	2023-05-21 22:27:29.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\lsass.exe	C:\Windows\system32\lsass.exe	C:\Windows\system32\lsass.exe
* 676	552	services.exe	0xad8186f4d080	7	-	0	False	2023-05-21 22:27:29.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\services.exe	C:\Windows\system32\services.exe	C:\Windows\system32\services.exe
** 4228	676	SearchIndexer.	0xad818ce06240	15	-	0	False	2023-05-21 22:31:27.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\SearchIndexer.exe	C:\Windows\system32\SearchIndexer.exe /Embedding	C:\Windows\system32\SearchIndexer.exe
** 8708	676	svchost.exe	0xad818d431080	5	-	0	False	2023-05-21 22:57:33.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\svchost.exe	-	-
** 5136	676	SecurityHealth	0xad818d374280	7	-	0	False	2023-05-21 22:32:01.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\SecurityHealthService.exe	-	-
** 2200	676	VGAuthService.	0xad81896b3300	2	-	0	False	2023-05-21 22:28:19.000000 	N/A	\Device\HarddiskVolume3\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe	--
** 3608	676	svchost.exe	0xad818d07a080	3	-	0	False	2023-05-21 22:41:28.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\svchost.exe	-	-
** 2076	676	svchost.exe	0xad8187b94080	10	-	0	False	2023-05-21 22:28:19.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\svchost.exe	C:\Windows\System32\svchost.exe -k utcsvc -p	C:\Windows\System32\svchost.exe
** 1448	676	svchost.exe	0xad818796c2c0	30	-	0	False	2023-05-21 22:27:52.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\svchost.exe	C:\Windows\System32\svchost.exe -k NetworkService -p	C:\Windows\System32\svchost.exe
** 1064	676	svchost.exe	0xad8189d7c2c0	15	-	1	False	2023-05-21 22:30:09.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\svchost.exe	C:\Windows\system32\svchost.exe -k UnistackSvcGroup	C:\Windows\system32\svchost.exe
** 6696	676	svchost.exe	0xad818c532080	8	-	0	False	2023-05-21 22:34:07.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\svchost.exe	-	-
** 1196	676	svchost.exe	0xad81877972c0	34	-	0	False	2023-05-21 22:27:46.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\svchost.exe	C:\Windows\system32\svchost.exe -k LocalService -p	C:\Windows\system32\svchost.exe
** 1840	676	spoolsv.exe	0xad8187acb200	10	-	0	False	2023-05-21 22:28:03.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\spoolsv.exe	-	-
** 952	676	svchost.exe	0xad81876802c0	12	-	0	False	2023-05-21 22:27:36.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\svchost.exe	C:\Windows\system32\svchost.exe -k RPCSS -p	C:\Windows\system32\svchost.exe
** 824	676	svchost.exe	0xad818761d240	22	-	0	False	2023-05-21 22:27:32.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\svchost.exe	C:\Windows\system32\svchost.exe -k DcomLaunch -p	C:\Windows\system32\svchost.exe
*** 7312	824	ApplicationFra	0xad818e84f300	10	-	1	False	2023-05-21 22:35:44.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\ApplicationFrameHost.exe	C:\Windows\system32\ApplicationFrameHost.exe -Embedding	C:\Windows\system32\ApplicationFrameHost.exe
*** 4116	824	RuntimeBroker.	0xad818cd93300	3	-	1	False	2023-05-21 22:31:24.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\RuntimeBroker.exe	-	-
*** 5656	824	RuntimeBroker.	0xad81876e8080	0	-	1	False	2023-05-21 21:58:19.000000 	2023-05-21 22:02:01.000000 	\Device\HarddiskVolume3\Windows\System32\RuntimeBroker.exe--
*** 2332	824	TiWorker.exe	0xad818e780080	4	-	0	False	2023-05-21 22:58:13.000000 	N/A	\Device\HarddiskVolume3\Windows\WinSxS\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_10.0.19041.1940_none_7dd80d767cb5c7b0\TiWorker.exe	-	-
*** 7336	824	RuntimeBroker.	0xad818e8bb080	2	-	1	False	2023-05-21 22:11:39.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\RuntimeBroker.exe	-	-
*** 5808	824	HxTsr.exe	0xad818de5d080	0	-	1	False	2023-05-21 21:59:58.000000 	2023-05-21 22:07:45.000000 	\Device\HarddiskVolume3\Program Files\WindowsApps\microsoft.windowscommunicationsapps_16005.11629.20316.0_x64__8wekyb3d8bbwe\HxTsr.exe	-	-
*** 7160	824	SearchApp.exe	0xad818ccc4080	57	-	1	False	2023-05-21 22:39:13.000000 	N/A	\Device\HarddiskVolume3\Windows\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy\SearchApp.exe	-	-
*** 6076	824	ShellExperienc	0xad818eb18080	14	-	1	False	2023-05-21 22:11:36.000000 	N/A	\Device\HarddiskVolume3\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe	-	-
*** 5704	824	RuntimeBroker.	0xad8185962080	5	-	1	False	2023-05-21 22:32:44.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\RuntimeBroker.exe	C:\Windows\System32\RuntimeBroker.exe -Embedding	C:\Windows\System32\RuntimeBroker.exe
*** 8264	824	RuntimeBroker.	0xad818eec8080	4	-	1	False	2023-05-21 22:40:33.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\RuntimeBroker.exe	-	-
*** 3160	824	StartMenuExper	0xad818cad3240	14	-	1	False	2023-05-21 22:31:21.000000 	N/A	\Device\HarddiskVolume3\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe	"C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe" -ServerName:App.AppXywbrabmsek0gm3tkwpr5kwzbs55tkqay.mca	C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe
*** 4448	824	RuntimeBroker.	0xad818c09a080	9	-	1	False	2023-05-21 22:31:33.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\RuntimeBroker.exe	C:\Windows\System32\RuntimeBroker.exe -Embedding	C:\Windows\System32\RuntimeBroker.exe
*** 1764	824	dllhost.exe	0xad818d176080	7	-	1	False	2023-05-21 22:32:48.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\dllhost.exe		
*** 3944	824	WmiPrvSE.exe	0xad818c054080	13	-	0	False	2023-05-21 22:30:44.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\wbem\WmiPrvSE.exe	C:\Windows\system32\wbem\wmiprvse.exe	C:\Windows\system32\wbem\wmiprvse.exe
*** 6644	824	SkypeApp.exe	0xad818d3ac080	49	-	1	False	2023-05-21 22:41:52.000000 	N/A	\Device\HarddiskVolume3\Program Files\WindowsApps\Microsoft.SkypeApp_14.53.77.0_x64__kzf8qxf38zg5c\SkypeApp.exe	-	-
*** 372	824	SkypeBackgroun	0xad8186f49080	3	-	1	False	2023-05-21 22:10:00.000000 	N/A	\Device\HarddiskVolume3\Program Files\WindowsApps\Microsoft.SkypeApp_14.53.77.0_x64__kzf8qxf38zg5c\SkypeBackgroundHost.exe	-	-
*** 7540	824	smartscreen.ex	0xad818e893080	14	-	1	False	2023-05-21 23:02:26.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\smartscreen.exe	C:\Windows\System32\smartscreen.exe -Embedding	C:\Windows\System32\smartscreen.exe
*** 8952	824	TextInputHost.	0xad818e6db080	10	-	1	False	2023-05-21 21:59:11.000000 	N/A	\Device\HarddiskVolume3\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\TextInputHost.exe	"C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\TextInputHost.exe" -ServerName:InputApp.AppXjd5de1g66v206tj52m9d0dtpppx4cgpn.mca	C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\TextInputHost.exe
*** 1916	824	SearchApp.exe	0xad818d099080	24	-	1	False	2023-05-21 22:33:05.000000 	N/A	\Device\HarddiskVolume3\Windows\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy\SearchApp.exe	-	-
** 6200	676	SgrmBroker.exe	0xad818d09f080	7	-	0	False	2023-05-21 22:33:42.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\SgrmBroker.exe	-	-
** 3004	676	svchost.exe	0xad818c4212c0	7	-	0	False	2023-05-21 22:30:55.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\svchost.exe	C:\Windows\system32\svchost.exe -k LocalServiceAndNoImpersonation -p	C:\Windows\system32\svchost.exe
** 448	676	svchost.exe	0xad8187721240	54	-	0	False	2023-05-21 22:27:41.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\svchost.exe	C:\Windows\system32\svchost.exe -k netsvcs -p	C:\Windows\system32\svchost.exe
*** 1600	448	taskhostw.exe	0xad8189d07300	10	-	1	False	2023-05-21 22:30:09.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\taskhostw.exe	-	-
*** 6048	448	taskhostw.exe	0xad818dc5d080	5	-	1	False	2023-05-21 22:40:20.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\taskhostw.exe	-	-
*** 3876	448	taskhostw.exe	0xad8189b30080	8	-	1	False	2023-05-21 22:08:02.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\taskhostw.exe	-	-
*** 5480	448	oneetx.exe	0xad818d3d6080	6	-	1	True	2023-05-21 23:03:00.000000 	N/A	\Device\HarddiskVolume3\Users\Tammam\AppData\Local\Temp\c3912af058\oneetx.exe	-	-
*** 1392	448	sihost.exe	0xad8189e94280	11	-	1	False	2023-05-21 22:30:08.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\sihost.exe	sihost.exe	C:\Windows\system32\sihost.exe
** 832	676	msdtc.exe	0xad8185861280	9	-	0	False	2023-05-21 22:29:25.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\msdtc.exe	-	-
** 6596	676	TrustedInstall	0xad818dc88080	4	-	0	False	2023-05-21 22:58:13.000000 	N/A	\Device\HarddiskVolume3\Windows\servicing\TrustedInstaller.exe	-	-
** 5964	676	svchost.exe	0xad818ef86080	5	-	0	False	2023-05-21 22:27:56.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\svchost.exe	-	-
** 1232	676	svchost.exe	0xad8186f4a2c0	7	-	0	False	2023-05-21 22:29:39.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\svchost.exe	-	-
** 3028	676	dllhost.exe	0xad8185907080	12	-	0	False	2023-05-21 22:29:20.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\dllhost.exe	C:\Windows\system32\dllhost.exe /Processid:{02D4B3F1-FD88-11D1-960D-00805FC79235}	C:\Windows\system32\dllhost.exe
** 1496	676	svchost.exe	0xad81879752c0	12	-	0	False	2023-05-21 22:27:52.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\svchost.exe	C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p	C:\Windows\System32\svchost.exe
*** 6324	1496	audiodg.exe	0xad818df2e080	4	-	0	False	2023-05-21 22:42:56.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\audiodg.exe	-	-
** 1116	676	svchost.exe	0xad818c426080	6	-	1	False	2023-05-21 22:31:00.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\svchost.exe	C:\Windows\system32\svchost.exe -k ClipboardSvcGroup -p	C:\Windows\system32\svchost.exe
** 7772	676	svchost.exe	0xad818e88e140	3	-	0	False	2023-05-21 22:36:03.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\svchost.exe	-	-
** 1376	676	svchost.exe	0xad81878020c0	15	-	0	False	2023-05-21 22:27:49.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\svchost.exe	C:\Windows\system32\svchost.exe -k LocalServiceNoNetwork -p	C:\Windows\system32\svchost.exe
** 2144	676	vmtoolsd.exe	0xad81896ab080	11	-	0	False	2023-05-21 22:28:19.000000 	N/A	\Device\HarddiskVolume3\Program Files\VMware\VMware Tools\vmtoolsd.exe	"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"	C:\Program Files\VMware\VMware Tools\vmtoolsd.exe
** 1120	676	MsMpEng.exe	0xad818945c080	12	-	0	False	2023-05-21 22:10:01.000000 	N/A	\Device\HarddiskVolume3\ProgramData\Microsoft\Windows Defender\Platform\4.18.2304.8-0\MsMpEng.exe		
** 1892	676	svchost.exe	0xad8187b34080	14	-	0	False	2023-05-21 22:28:05.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\svchost.exe	C:\Windows\system32\svchost.exe -k LocalServiceNoNetworkFirewall -p	C:\Windows\system32\svchost.exe
** 5476	676	svchost.exe	0xad818e752080	9	-	0	False	2023-05-21 22:58:08.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\svchost.exe	C:\Windows\System32\svchost.exe -k NetworkService -p	C:\Windows\System32\svchost.exe
** 2024	676	svchost.exe	0xad8187b65240	7	-	0	False	2023-05-21 22:28:11.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\svchost.exe	-	-
** 2152	676	vm3dservice.ex	0xad81896ae240	2	-	0	False	2023-05-21 22:28:19.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\vm3dservice.exe	-	-
*** 2404	2152	vm3dservice.ex	0xad8186619200	2	-	1	False	2023-05-21 22:28:32.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\vm3dservice.exe	-	-
** 1644	676	svchost.exe	0xad8187a112c0	6	-	0	False	2023-05-21 22:27:58.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\svchost.exe	-	-
** 752	676	svchost.exe	0xad8187758280	21	-	0	False	2023-05-21 22:27:43.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\svchost.exe	C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p	C:\Windows\System32\svchost.exe
*** 3204	752	ctfmon.exe	0xad8189c8b280	12	-	1	False	2023-05-21 22:30:11.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\ctfmon.exe	"ctfmon.exe"	C:\Windows\system32\ctfmon.exe
** 1012	676	svchost.exe	0xad818774c080	19	-	0	False	2023-05-21 22:27:43.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\svchost.exe	C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p	C:\Windows\System32\svchost.exe
** 1652	676	svchost.exe	0xad8187a2d2c0	10	-	0	False	2023-05-21 22:27:58.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\svchost.exe	C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p	C:\Windows\system32\svchost.exe
** 4340	676	VSSVC.exe	0xad818e888080	3	-	0	False	2023-05-21 23:01:06.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\VSSVC.exe	C:\Windows\system32\vssvc.exe	C:\Windows\system32\vssvc.exe
** 2044	676	svchost.exe	0xad8189b27080	28	-	0	False	2023-05-21 22:49:29.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\svchost.exe	C:\Windows\system32\svchost.exe -k wsappx -p	C:\Windows\system32\svchost.exe
* 852	552	fontdrvhost.ex	0xad818761b0c0	5	-	0	False	2023-05-21 22:27:33.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\fontdrvhost.exe	-	-
588	520	winlogon.exe	0xad8186f450c0	5	-	1	False	2023-05-21 22:27:25.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\winlogon.exe	-	-
* 1016	588	dwm.exe	0xad81876e4340	15	-	1	False	2023-05-21 22:27:38.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\dwm.exe	"dwm.exe"	C:\Windows\system32\dwm.exe
* 3556	588	userinit.exe	0xad818c02f340	0	-	1	False	2023-05-21 22:30:28.000000 	2023-05-21 22:30:43.000000 	\Device\HarddiskVolume3\Windows\System32\userinit.exe	-	-
** 3580	3556	explorer.exe	0xad818c047340	76	-	1	False	2023-05-21 22:30:28.000000 	N/A	\Device\HarddiskVolume3\Windows\explorer.exe	C:\Windows\Explorer.EXE	C:\Windows\Explorer.EXE
*** 6724	3580	Outline.exe	0xad818e578080	0	-	1	True	2023-05-21 22:36:09.000000 	2023-05-21 23:01:24.000000 	\Device\HarddiskVolume3\Program Files (x86)\Outline\Outline.exe	-	-
**** 4224	6724	Outline.exe	0xad818e88b080	0	-	1	True	2023-05-21 22:36:23.000000 	2023-05-21 23:01:24.000000 	\Device\HarddiskVolume3\Program Files (x86)\Outline\Outline.exe	-	-
**** 4628	6724	tun2socks.exe	0xad818de82340	0	-	1	True	2023-05-21 22:40:10.000000 	2023-05-21 23:01:24.000000 	\Device\HarddiskVolume3\Program Files (x86)\Outline\resources\app.asar.unpacked\third_party\outline-go-tun2socks\win32\tun2socks.exe	-	-
*** 5636	3580	notepad.exe	0xad818db45080	1	-	1	False	2023-05-21 22:46:50.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\notepad.exe	-	-
*** 464	3580	SecurityHealth	0xad818979d080	3	-	1	False	2023-05-21 22:31:59.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\SecurityHealthSystray.exe	-	-
*** 5328	3580	msedge.exe	0xad818d0980c0	54	-	1	False	2023-05-21 22:32:02.000000 	N/A	\Device\HarddiskVolume3\Program Files (x86)\Microsoft\Edge\Application\msedge.exe	"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --no-startup-window --win-session-start /prefetch:5	C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
**** 4544	5328	msedge.exe	0xad818d75b080	14	-	1	False	2023-05-21 22:32:39.000000 	N/A	\Device\HarddiskVolume3\Program Files (x86)\Microsoft\Edge\Application\msedge.exe	--
**** 8896	5328	msedge.exe	0xad8187a39080	18	-	1	False	2023-05-21 22:28:21.000000 	N/A	\Device\HarddiskVolume3\Program Files (x86)\Microsoft\Edge\Application\msedge.exe	--
**** 5156	5328	msedge.exe	0xad818c553080	14	-	1	False	2023-05-21 22:28:22.000000 	N/A	\Device\HarddiskVolume3\Program Files (x86)\Microsoft\Edge\Application\msedge.exe	--
**** 7964	5328	msedge.exe	0xad818dee5080	19	-	1	False	2023-05-21 22:22:09.000000 	N/A	\Device\HarddiskVolume3\Program Files (x86)\Microsoft\Edge\Application\msedge.exe	--
**** 4396	5328	msedge.exe	0xad818d515080	7	-	1	False	2023-05-21 22:32:19.000000 	N/A	\Device\HarddiskVolume3\Program Files (x86)\Microsoft\Edge\Application\msedge.exe	--
**** 6544	5328	msedge.exe	0xad818c0ea080	18	-	1	False	2023-05-21 22:22:35.000000 	N/A	\Device\HarddiskVolume3\Program Files (x86)\Microsoft\Edge\Application\msedge.exe	--
**** 2388	5328	msedge.exe	0xad818e54c340	18	-	1	False	2023-05-21 22:05:35.000000 	N/A	\Device\HarddiskVolume3\Program Files (x86)\Microsoft\Edge\Application\msedge.exe	--
**** 6292	5328	msedge.exe	0xad818d7a1080	20	-	1	False	2023-05-21 22:06:15.000000 	N/A	\Device\HarddiskVolume3\Program Files (x86)\Microsoft\Edge\Application\msedge.exe	--
**** 1144	5328	msedge.exe	0xad818d75f080	18	-	1	False	2023-05-21 22:32:38.000000 	N/A	\Device\HarddiskVolume3\Program Files (x86)\Microsoft\Edge\Application\msedge.exe	--
**** 5340	5328	msedge.exe	0xad818d7b3080	10	-	1	False	2023-05-21 22:32:39.000000 	N/A	\Device\HarddiskVolume3\Program Files (x86)\Microsoft\Edge\Application\msedge.exe	--
*** 3252	3580	vmtoolsd.exe	0xad8189796300	8	-	1	False	2023-05-21 22:31:59.000000 	N/A	\Device\HarddiskVolume3\Program Files\VMware\VMware Tools\vmtoolsd.exe	"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe" -n vmusr	C:\Program Files\VMware\VMware Tools\vmtoolsd.exe
*** 2228	3580	FTK Imager.exe	0xad818d143080	10	-	1	False	2023-05-21 22:43:56.000000 	N/A	\Device\HarddiskVolume3\Program Files\AccessData\FTK Imager\FTK Imager.exe	-	-
*** 8920	3580	FTK Imager.exe	0xad818ef81080	20	-	1	False	2023-05-21 23:02:28.000000 	N/A	\Device\HarddiskVolume3\Program Files\AccessData\FTK Imager\FTK Imager.exe	"C:\Program Files\AccessData\FTK Imager\FTK Imager.exe" 	C:\Program Files\AccessData\FTK Imager\FTK Imager.exe
* 860	588	fontdrvhost.ex	0xad818761f140	5	-	1	False	2023-05-21 22:27:33.000000 	N/A	\Device\HarddiskVolume3\Windows\System32\fontdrvhost.exe	-	-
5896	8844	oneetx.exe	0xad8189b41080	5	-	1	True	2023-05-21 22:30:56.000000 	N/A	\Device\HarddiskVolume3\Users\Tammam\AppData\Local\Temp\c3912af058\oneetx.exe	-	-
* 7732	5896	rundll32.exe	0xad818d1912c0	1	-	1	True	2023-05-21 22:31:53.000000 	N/A	\Device\HarddiskVolume3\Windows\SysWOW64\rundll32.exe	-	-
```
The `outline.exe` is responsible for making VPN connections. It has the `PPID` of 6724.
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
0xad818d436c70.0\Users\Tammam\AppData\Local\Temp\c3912af058\oneetx.exe	216
0xad818da36c30	\Users\Tammam\AppData\Local\Temp\c3912af058\oneetx.exe	216
0xad818ef1a0b0	\Users\Tammam\AppData\Local\Temp\c3912af058\oneetx.exe	216
<--SNIP-->
```
### Answer
```
C:\Users\Tammam\AppData\Local\Temp\c3912af058\oneetx.exe
```
