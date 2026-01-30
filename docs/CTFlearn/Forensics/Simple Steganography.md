---
custom_edit_url: null
---

> Think the flag is somewhere in there. Would you help me find it? hint-" Steghide Might be Helpfull"
> [Minions1.jpeg](https://ctflearn.com/challenge/download/894) 

Let's use the `strings` utility to extract the strings in the image file.
```
$ strings 894 | head
JFIF
0Photoshop 3.0
8BIM
myadmin
!1#%)+...
383-7(-.+
&/-/-//-++------------------------+---.-----/------
$3br
%&'()*456789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz
```
The `steghide` utility allows users to extract data from image and audio files.
```
$ steghide extract -sf 894
Enter passphrase:
wrote extracted data to "raw.txt".
```
We can now use the `cat` command to view the contents of the extracted file.
```
$ cat raw.txt
AEMAVABGAGwAZQBhAHIAbgB7AHQAaABpAHMAXwBpAHMAXwBmAHUAbgB9
```
That looks like it is encrypted using Base64. Let's decode it using Cyberchef.

<figure style={{ textAlign: 'center' }}>
![1](https://github.com/Knign/Write-ups/assets/110326359/1f557e3b-8688-4f55-947b-5c5843035c21)
</figure>

## Flag
```
CTFlearn{This_is_fun}
```
