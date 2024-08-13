---
custom_edit_url: null
---

## What is the response message obtained from the PCAP file?
Let's open the `insider.pcap` file using Wireshark.

![1](https://github.com/Knign/Write-ups/assets/110326359/1f6114b1-6bf0-4caa-b641-5dcf3f5f00c5)

Let's follow the TCP stream via `Follow > TCP Stream`.

![2](https://github.com/Knign/Write-ups/assets/110326359/36b2d84d-71b8-4d67-9a4e-daf50432f229)

### Answer
```
use your own password
```

&nbsp;

## What is the password of the ZIP file?
The answer to the previous question told us to use our own password.

If we look at the TCP stream we can see a string sent by us that might be a password.

![3](https://github.com/Knign/Write-ups/assets/110326359/6d63468f-4f58-4fcc-af6a-69582eca3b05)

The string has two `==` signs at the end. This is an indication that the string has been encrypted using Base64.

Let's use Cyberchef to decode it.

![4](https://github.com/Knign/Write-ups/assets/110326359/6cfc7113-0281-430e-84ff-6c4b5e935baa)

### Answer
```
redforever
```

&nbsp;

## Will more passwords be required?
We can now unzip `file.zip` using the `redforever` password.
```
$ unzip file.zip 
Archive:  file.zip
[file.zip] ssdog1.jpeg password: 
  inflating: ssdog1.jpeg             
  inflating: README.txt              
```
As there are no more Zip files, we can safely say that no more password will be required.
### Answer
```
No
```

&nbsp;

## What is the name of a widely-used tool that can be used to obtain file information?
The `exiftool` utility can be used to obtain file information such as the metadata.
### Answer
```
Exiftool
```

&nbsp;

## What is the name and value of the interesting information obtained from the image file metadata?
Let's look at the file metadata using the `exiftool` utility as mentioned previously.
```
$ exiftool ssdog1.jpeg 
ExifTool Version Number         : 12.42
File Name                       : ssdog1.jpeg
Directory                       : .
File Size                       : 84 kB
File Modification Date/Time     : 2021:09:26 16:07:52-04:00
File Access Date/Time           : 2021:09:26 16:07:57-04:00
File Inode Change Date/Time     : 2023:09:17 11:04:50-04:00
File Permissions                : -rw-rw-r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : None
X Resolution                    : 1
Y Resolution                    : 1
XMP Toolkit                     : Image::ExifTool 11.88
Technique                       : Steganography
Technique Command               : steghide
Image Width                     : 1080
Image Height                    : 1018
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:4:4 (1 1)
Image Size                      : 1080x1018
Megapixels                      : 1.1
```
All the information is pretty standard for an image except for the `Technique : Steganography` field. Steganography is used to hide information in other information most notably images.
### Answer
```
Technique : Steganography
```

&nbsp;

## Based on the answer from the previous question, what tool needs to be used to retrieve the information hidden in the file?
The `steghide` tool needs to be used retrieve the hidden information.
```
Technique                       : Steganography
Technique Command               : steghide
```
### Answer
```
StegHide
```

&nbsp;

## Enter the ID retrieved.
Let's use the `steghide` utility to retrieve the ID.
```
$ steghide extract -sf ssdog1.jpeg 
Enter passphrase: 
wrote extracted data to "idInsider.txt".
```
The `sf` flag is used to specify the name of the stego file.
```
$ cat idInsider.txt 
0726ba878ea47de571777a
```
### Answer
```
0726ba878ea47de571777a
```

&nbsp;

## What is the profile name of the attacker?
Let's look at our own user profile.

![5](https://github.com/Knign/Write-ups/assets/110326359/a53a9675-944f-4e01-b3f8-439dba2b6ed5)

If we look at the user profile, we can see that the user IDs are included in the URI.
```
https://blueteamlabs.online/home/user/26e1135472d925e971ea68
```
What if we replace this ID with the one we retrieved: `0726ba878ea47de571777a`.

![6](https://github.com/Knign/Write-ups/assets/110326359/c25b16d1-b2c3-4c2a-8799-acc49fc8b2ef)

We have our attacker.
### Answer
```
bluetiger
```
