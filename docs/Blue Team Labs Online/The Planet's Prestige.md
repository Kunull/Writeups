---
custom_edit_url: null
---

## What is the email service used by the malicious actor?
To find the email service used by the malicious actor we need to check the `Received` field after opening the email in a text-editor.

![1](https://github.com/Knign/Write-ups/assets/110326359/357f8954-840e-4cb5-b649-b152b3b70472)

### Answer
```
emkei.cz
```

&nbsp;

## What is the Reply-To email address?
If we open the file using Thunderbird, we can find the `Reply-To` email address.

![2](https://github.com/Knign/Write-ups/assets/110326359/1a48e22c-12e7-49e1-ad91-bcb41aa7806e)

### Answer
```
negeja3921@pashter.com
```

&nbsp;

## What is the filetype of the received attachment which helped to continue the investigation?
Let's open the PDF file attached to the email.

![3](https://github.com/Knign/Write-ups/assets/110326359/e91adc52-a32a-4956-adcb-178fb43f9aef)

So the file isn't opening. Maybe it is not really a PDF.

Using the `file` utility we can check the actual format of the file.
```
$ file PuzzleToCoCanDa.pdf 
PuzzleToCoCanDa.pdf: Zip archive data, at least v2.0 to extract
```
### Answer
```
zip
```

&nbsp;

## What is the name of the malicious actor?
Now that we know it is a ZIP file, we can rename it to `PuzzleToCoCanDa.zip` and then unzip it.
```
$ unzip PuzzleToCoCanDa.pdf
Archive:  PuzzleToCoCanDa.pdf
  inflating: PuzzleToCoCanDa/DaughtersCrown  
  inflating: PuzzleToCoCanDa/GoodJobMajor  
  inflating: PuzzleToCoCanDa/Money.xlsx  
```
We can see that the ZIP file contains a file called `GoodJobMajor`.

If we use the `exiftool` utility on that file to check the metadata we can find the name of the malicious actor.
```
$ exiftool GoodJobMajor 
ExifTool Version Number         : 12.42
File Name                       : GoodJobMajor
Directory                       : .
File Size                       : 28 kB
File Modification Date/Time     : 2021:01:26 11:14:22-05:00
File Access Date/Time           : 2023:09:28 11:06:29-04:00
File Inode Change Date/Time     : 2023:09:28 10:51:42-04:00
File Permissions                : -rw-rw-r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.5
Linearized                      : No
Author                          : Pestero Negeja
Producer                        : Skia/PDF m90
Page Count                      : 1
```
### Answer
```
Pestero Negeja
```

&nbsp;

## What is the location of the attacker in this Universe?
On opening the `Money.xlsx` file, we can see that there are two sheets: `Sheet1` and `Sheet3`.

![4](https://github.com/Knign/Write-ups/assets/110326359/36ec910a-7090-4fb6-a144-a2e81d9ee384)

Let's covert both the sheets to text files so that we can view the content better.

If we open the `Sheet3.txt` file we can see some text that appears to be encrypted.

![5](https://github.com/Knign/Write-ups/assets/110326359/6c6c1423-6aa6-471a-b626-54ae65103c29)

The `==` at the end indicates that the encryption is Base64.

We can use Cyberchef to decrypt the text.

![6](https://github.com/Knign/Write-ups/assets/110326359/1f7e67c0-f510-49a2-b9f4-6339ddb62cdf)

### Answer
```
The Martian Colony, Beside Interplanetary Spaceport
```

&nbsp;

## What could be the probable C&C domain to control the attacker’s autonomous bots?
The attacker's name is `Pestero Negeja` and the reply-to email is `negeja3921@pashter.com` so we can guess the C&C domain used by the attacker.
### Answer
```
pashter.com
```
