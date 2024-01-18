---
custom_edit_url: null
pagination_next: null
pagination_prev: null
---


## Q1. Which volatility profile would be best for this machine?
- We can find the correct profile using the `kdbgscan` plugin.
```
$ volatility_2.5.linux.standalone/volatility_2.5_linux_x64 -f CYBERDEF-567078-20230213-171333.raw kdbgscan 
Volatility Foundation Volatility Framework 2.5
**************************************************
Instantiating KDBG using: Kernel AS WinXPSP2x86 (5.1.0 32bit)
Offset (V)                    : 0x8054cde0
Offset (P)                    : 0x54cde0
KDBG owner tag check          : True
Profile suggestion (KDBGHeader): WinXPSP3x86
Version64                     : 0x8054cdb8 (Major: 15, Minor: 2600)
Service Pack (CmNtCSDVersion) : 3
Build string (NtBuildLab)     : 2600.xpsp.080413-2111
PsActiveProcessHead           : 0x80561358 (25 processes)
PsLoadedModuleList            : 0x8055b1c0 (104 modules)
KernelBase                    : 0x804d7000 (Matches MZ: True)
Major (OptionalHeader)        : 5
Minor (OptionalHeader)        : 1
KPCR                          : 0xffdff000 (CPU 0)

**************************************************
Instantiating KDBG using: Kernel AS WinXPSP2x86 (5.1.0 32bit)
Offset (V)                    : 0x8054cde0
Offset (P)                    : 0x54cde0
KDBG owner tag check          : True
Profile suggestion (KDBGHeader): WinXPSP2x86
Version64                     : 0x8054cdb8 (Major: 15, Minor: 2600)
Service Pack (CmNtCSDVersion) : 3
Build string (NtBuildLab)     : 2600.xpsp.080413-2111
PsActiveProcessHead           : 0x80561358 (25 processes)
PsLoadedModuleList            : 0x8055b1c0 (104 modules)
KernelBase                    : 0x804d7000 (Matches MZ: True)
Major (OptionalHeader)        : 5
Minor (OptionalHeader)        : 1
KPCR                          : 0xffdff000 (CPU 0)
```

&nbsp;

## Q2. How many processes were running when the image was acquired?
- The `pslist` plugin lists out the processes of a system.
```
$ $ volatility3-2.4.1/vol.py -f CYBERDEF-567078-20230213-171333.raw windows.pslist 
Volatility 3 Framework 2.4.1
Progress:  100.00               PDB scanning finished                        
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime        File output

4       0       System  0x89c037f8      55      245     N/A     False   N/A     N/A     Disabled
368     4       smss.exe        0x89965020      3       19      N/A     False   2023-02-14 04:54:15.000000      N/A     Disabled
592     368     csrss.exe       0x89a98da0      11      321     0       False   2023-02-14 04:54:15.000000      N/A     Disabled
616     368     winlogon.exe    0x89a88da0      18      508     0       False   2023-02-14 04:54:15.000000      N/A     Disabled
660     616     services.exe    0x89938998      15      240     0       False   2023-02-14 04:54:15.000000      N/A     Disabled
672     616     lsass.exe       0x89aa0020      21      335     0       False   2023-02-14 04:54:15.000000      N/A     Disabled
832     660     VBoxService.exe 0x89aaa3d8      9       115     0       False   2023-02-14 04:54:15.000000      N/A     Disabled
880     660     svchost.exe     0x89aab590      21      295     0       False   2023-02-13 17:54:16.000000      N/A     Disabled
968     660     svchost.exe     0x89a9f6f8      10      244     0       False   2023-02-13 17:54:17.000000      N/A     Disabled
1060    660     svchost.exe     0x89730da0      51      1072    0       False   2023-02-13 17:54:17.000000      N/A     Disabled
1108    660     svchost.exe     0x897289a8      5       78      0       False   2023-02-13 17:54:17.000000      N/A     Disabled
1156    660     svchost.exe     0x899adda0      13      192     0       False   2023-02-13 17:54:17.000000      N/A     Disabled
1484    1440    explorer.exe    0x89733938      14      489     0       False   2023-02-13 17:54:18.000000      N/A     Disabled
1608    660     spoolsv.exe     0x897075d0      10      106     0       False   2023-02-13 17:54:18.000000      N/A     Disabled
480     1060    wscntfy.exe     0x89694388      1       28      0       False   2023-02-13 17:54:30.000000      N/A     Disabled
540     660     alg.exe 0x8969d2a0      5       102     0       False   2023-02-13 17:54:30.000000      N/A     Disabled
376     1484    VBoxTray.exe    0x89982da0      13      125     0       False   2023-02-13 17:54:30.000000      N/A     Disabled
636     1484    msmsgs.exe      0x8994a020      2       157     0       False   2023-02-13 17:54:30.000000      N/A     Disabled
1880    1484    taskmgr.exe     0x89a0b2f0      0       -       0       False   2023-02-13 18:25:15.000000      2023-02-13 18:26:21.000000      Disabled
964     1484    rootkit.exe     0x899dd740      0       -       0       False   2023-02-13 18:25:26.000000      2023-02-13 18:25:26.000000      Disabled
1960    964     cmd.exe 0x89a18da0      0       -       0       False   2023-02-13 18:25:26.000000      2023-02-13 18:25:26.000000      Disabled
528     1484    notepad.exe     0x896c5020      0       -       0       False   2023-02-13 18:26:55.000000      2023-02-13 18:27:46.000000      Disabled
1432    1484    notepad.exe     0x89a0d180      0       -       0       False   2023-02-13 18:28:25.000000      2023-02-13 18:28:40.000000      Disabled
1444    1484    notepad.exe     0x899e6da0      0       -       0       False   2023-02-13 18:28:42.000000      2023-02-13 18:28:47.000000      Disabled
276     1484    DumpIt.exe      0x89a0fda0      1       25      0       False   2023-02-13 18:29:08.000000      N/A     Disabled
```
- There are total 25 processes. 
- 6 of the processes have 0 threads. This means that these 6 processes have been terminated.
- So, the total number of running processes is 19.

&nbsp;

## Q3. What is the process ID of cmd.exe?
- We can `grep` the list of processes for `cmd.exe`.
```
$ volatility3-2.4.1/vol.py -f CYBERDEF-567078-20230213-171333.raw windows.pslist | grep -i "cmd.exe"
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime        File output

1960ress964100.0cmd.exe 0x89a18da0      0       -       0       False   2023-02-13 18:25:26.000000      2023-02-13 18:25:26.000000      Disabled

```

&nbsp;

## Q4. What is the name of the most suspicious process?
```
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime        File output

964     1484    rootkit.exe     0x899dd740      0       -       0       False   2023-02-13 18:25:26.000000      2023-02-13 18:25:26.000000      Disabled
1960    964     cmd.exe 0x89a18da0      0       -       0       False   2023-02-13 18:25:26.000000      2023-02-13 18:25:26.000000      Disabled
```
- We can find this suspicious process `rootkit.exe` because of it's name and also because it's child process is `cmd.exe`.



## Q5. Which process shows the highest likelihood of code injection?
- Let's look for malicious processes using the `malfind` plugin.
```
$ volatility3-2.4.1/vol.py -f CYBERDEF-567078-20230213-171333.raw windows.malfind                                              
Volatility 3 Framework 2.4.1
Progress:  100.00               PDB scanning finished                        
PID     Process Start VPN       End VPN Tag     Protection      CommitCharge    PrivateMemory   File output     Hexdump Disasm

--snip--;
880     svchost.exe     0x980000        0x988fff        VadS    PAGE_EXECUTE_READWRITE  9       1       pid.880.vad.0x980000-0x988fff.dmp
4d 5a 90 00 03 00 00 00 MZ......
04 00 00 00 ff ff 00 00 ........
b8 00 00 00 00 00 00 00 ........
40 00 00 00 00 00 00 00 @.......
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 f8 00 00 00 ........        4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 f8 00 00 00                          
```
- We can use dump the output into a file.
```
$ volatility3-2.4.1/vol.py -f CYBERDEF-567078-20230213-171333.raw -o malfinddump/ windows.malfind --pid 880 --dump
```
- The `md5sum` command gives us the MD5 hash of the file.
```
$ md5sum pid.880.vad.0x980000-0x988fff.dmp 
20020a9d850bd496954d8c21dfa614be  pid.880.vad.0x980000-0x988fff.dmp
```
- Let's search this hash in Virustotal.
![[virus total.png]]
- We can see that the process is vulnerable to DLL injection.

&nbsp;

## Q6. There is an odd file referenced in the recent process. Provide the full path of that file.
- The `handles` plugin gives us the open handles in a process including the files.
```
$ volatility_2.5.linux.standalone/volatility_2.5_linux_x64 -f CYBERDEF-567078-20230213-171333.raw --profile=WinXPSP2x86 -p 880 handles -t file
Volatility Foundation Volatility Framework 2.5
Offset(V)     Pid     Handle     Access Type             Details
---------- ------ ---------- ---------- ---------------- -------
0x89a28890    880        0xc   0x100020 File             \Device\HarddiskVolume1\WINDOWS\system32
0x89a1a6f8    880       0x50   0x100001 File             \Device\KsecDD
0x89937358    880       0x68   0x100020 File             \Device\HarddiskVolume1\WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.5512_x-ww_35d4ce83
0x899d0250    880       0xbc   0x12019f File             \Device\NamedPipe\net\NtControlPipe2
0x89a17a50    880      0x100   0x100000 File             \Device\Dfs
0x89732cb8    880      0x158   0x12019f File             \Device\NamedPipe\lsarpc
0x8969fee0    880      0x274   0x12019f File             \Device\Termdd
0x89ab3478    880      0x294   0x12019f File             \Device\Termdd
0x89ab3978    880      0x29c   0x12019f File             \Device\Termdd
0x896bcd18    880      0x2b8   0x12019f File             \Device\NamedPipe\Ctx_WinStation_API_service
0x8997a248    880      0x2bc   0x12019f File             \Device\NamedPipe\Ctx_WinStation_API_service
0x899a24b0    880      0x304   0x12019f File             \Device\Termdd
0x89a00f90    880      0x33c   0x12019f File             \Device\{9DD6AFA1-8646-4720-836B-EDCB1085864A}
0x89af0cf0    880      0x340   0x12019f File             \Device\HarddiskVolume1\WINDOWS\system32\drivers\str.sys
0x89993f90    880      0x3d8   0x100020 File             \Device\HarddiskVolume1\WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.5512_x-ww_35d4ce83
0x89958b78    880      0x3e4   0x12019f File             \Device\HarddiskVolume1\WINDOWS\system32\config\systemprofile\Local Settings\Temporary Internet Files\Content.IE5\index.dat
0x899fe2e0    880      0x3f8   0x12019f File             \Device\HarddiskVolume1\WINDOWS\system32\config\systemprofile\Cookies\index.dat
0x89a492e8    880      0x400   0x12019f File             \Device\HarddiskVolume1\WINDOWS\system32\config\systemprofile\Local Settings\History\History.IE5\index.dat
0x896811d8    880      0x424   0x100020 File             \Device\HarddiskVolume1\WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.5512_x-ww_35d4ce83
0x89bbc028    880      0x488   0x100020 File             \Device\HarddiskVolume1\WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.5512_x-ww_35d4ce83
0x89999980    880      0x4a8   0x1200a0 File             \Device\NetBT_Tcpip_{B35F0A5F-EBC3-4B5D-800D-7C1B64B30F14}
```
- We can also check the `strings` in the file that we saved earlier.
```
$ strings ./pid.880.vad.0x980000-0x988fff.dmp 

--snip--;
C:\WINDOWS\system32\drivers\str.sys
--snip--;
```

&nbsp;

## Q7. What is the name of the injected dll file loaded from the recent process?
- The `ldrmodules` plugin can be used to list the loaded modules (DLLs) in a process, and it can also be used to detect unlinked/hidden DLLs.
```
$ volatility3-2.4.1/vol.py -f CYBERDEF-567078-20230213-171333.raw windows.ldrmodules --pid 880
Volatility 3 Framework 2.4.1
Progress:  100.00               PDB scanning finished                        
Pid     Process Base    InLoad  InInit  InMem   MappedPath

880     svchost.exe     0x6f880000      True    True    True    \WINDOWS\AppPatch\AcGenral.dll
880     svchost.exe     0x1000000       True    False   True    \WINDOWS\system32\svchost.exe
880     svchost.exe     0x670000        True    True    True    \WINDOWS\system32\xpsp2res.dll
880     svchost.exe     0x9a0000        False   False   False   \WINDOWS\system32\msxml3r.dll
--snip--;
```
- We can see 3 DLL lists: InLoad, InInit, and InMem which indicate whether a module has been loaded into memory, initialized, or is currently in the process memory.
- The `msxml3r.dll` is not linked to any of the three ldr modules. That makes it the most suspicious.

&nbsp;

## Q8. What is the base address of the injected dll?
- We have already found the answer in a previous question when we used `malfind` plugin
```
$  volatility3-2.4.1/vol.py -f CYBERDEF-567078-20230213-171333.raw windows.malfind --pid 880 
Volatility 3 Framework 2.4.1
Progress:  100.00               PDB scanning finished                        
PID     Process Start VPN       End VPN Tag     Protection      CommitCharge    PrivateMemory   File output     Hexdump Disasm

880     svchost.exe     0x980000        0x988fff        VadS    PAGE_EXECUTE_READWRITE  9       1       Disabled
4d 5a 90 00 03 00 00 00 MZ......
04 00 00 00 ff ff 00 00 ........
b8 00 00 00 00 00 00 00 ........
40 00 00 00 00 00 00 00 @.......
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 00 00 00 00 ........
00 00 00 00 f8 00 00 00 ........        4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 f8 00 00 00
                                      
```
