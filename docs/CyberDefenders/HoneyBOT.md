---
custom_edit_url: null
pagination_next: null
pagination_prev: null
---


## Q1. What is the attacker's IP address?

We can see that the `Source address` field of the first packet is `98.114.205.102`.

![HoneyBOT 1](https://github.com/Kunull/Write-ups/assets/110326359/45b1d818-c1c2-4522-81ce-28beb01b79cb)

### Answer
```
98.114.205.102
```

&nbsp;

## Q2. What is the target's IP address?

The target's IP address is included in the `Destination address` field.

![HoneyBOT 2](https://github.com/Kunull/Write-ups/assets/110326359/37a2aea0-8f46-4996-afb9-53c08fb9df74)

### Answer
```
192.150.11.111
```

&nbsp;

## Q3. Provide the country code for the attacker's IP address (a.k.a geo-location).

We can obtain more information about the attacker's IP address using [IPinfo](https://ipinfo.io/).

![HoneyBOT 3](https://github.com/Kunull/Write-ups/assets/110326359/1db84fda-8ae5-4718-8539-a8af510475d7)

### Answer
```
US
```

&nbsp;

## Q4. How many TCP sessions are present in the captured traffic?

We can find TCP sessions by selecting the `Statistics > Conversations` option.

![HoneyBOT 4](https://github.com/Kunull/Write-ups/assets/110326359/9faaaf85-f5a5-4941-ac7e-0b764558c92f)

We can see that there are 5 TCP sessions present.

### Answer
```
5
```

&nbsp;

## Q5. How long did it take to perform the attack (in seconds)?

Let us set the time display format to `Seconds since beginning of capture`.

![HoneyBOT 5](https://github.com/Kunull/Write-ups/assets/110326359/58b518f3-9ae3-44b3-982f-53028207df9c)

We can see that the last packet arrives around 16 seconds after the first packet. So it took 16 seconds to perform the attack.

### Answer
```
16
```

&nbsp;

## Q7. Provide the CVE number of the exploited vulnerability.

Using the following filter we can filter out SMB packets.

```
smb
```

On observing the packets, we can see a few `DSSETUP` packets. These are used to obtain information about a remote hosts Active Directory.

![HoneyBOT 7](https://github.com/Kunull/Write-ups/assets/110326359/63b919a6-942e-4867-a1d1-2ed893f60fe6)

The `Operation` field is set to `DsRoleUpgradeDownlevelServer`.

A quick google search gives us the CVE number of the exploited vulnerability.

![HoneyBOT 7 2](https://github.com/Kunull/Write-ups/assets/110326359/99840eb2-bfb2-4665-a05d-4afa7e0eafd5)

It exploits a buffer overflow which in turn allows the attacker to perform [ACE](https://en.wikipedia.org/wiki/Arbitrary\_code\_execution) in order to create long debug entries.

### Answer
```
CVE-2003-0533
```

&nbsp;

## Q8. Which protocol was used to carry over the exploit?

As we saw in the previous question, the protocol used was SMB.

### Answer
```
SMB
```

&nbsp;

## Q9. Which protocol did the attacker use to download additional malicious files to the target system?

Let us follow the stream through `Analyze > Follow > TCP Stream`.

On checking the 3rd TCP stream we can see the steps performed by the attacker.

![HoneyBOT 9](https://github.com/Kunull/Write-ups/assets/110326359/7be1886a-c4cf-4118-94ef-a14208d5f458)

These steps resemble that of a [FTP login sequence](https://www.ibm.com/docs/en/zos/2.2.0?topic=ftp-logging-in).

![HoneyBOT 9 2](https://github.com/Kunull/Write-ups/assets/110326359/4d766303-d34e-4141-91da-e47beccc2e3a)

Alternatively, in TCP stream 2 we can see the command executed by the attacker.

![HoneyBOT 9 3](https://github.com/Kunull/Write-ups/assets/110326359/fe188222-3a69-4a19-abc5-7512103ed7d6)

The attacker ran the `ftp` command using the script file `o` and disabled auto-login using the `n` flag.

### Answer
```
ftp
```

&nbsp;

## Q10. What is the name of the downloaded malware?

Again in TCP stream 3 we can see that the attacker retrieved the copy of the `ssms.exe` file.

![HoneyBOT 10](https://github.com/Kunull/Write-ups/assets/110326359/7fae2c5c-4f04-486a-a652-422535268570)

In TCP stream 2 we can see that the attacker executed the `ssms.exe` file.

![HoneyBOT 10 2](https://github.com/Kunull/Write-ups/assets/110326359/6d0c3494-e23c-4425-8dcc-6c3b442e7a75)

### Answer
```
ssms.exe
```

&nbsp;

## Q11. The attacker's server was listening on a specific port. Provide the port number.

In the 2nd TCP stream, we can see port `8884` specified in the `echo` command.

![HoneyBOT 11](https://github.com/Kunull/Write-ups/assets/110326359/252630b6-7718-4c2c-ae54-c333e0cf8ab8)

The result of this command is redirected into the script file `o` used during FTP login.

### Answer
```
8884
```

&nbsp;

## Q12. When was the involved malware first submitted to VirusTotal for analysis? Format: YYYY-MM-DD

TCP stream 4 contains the file sent from the attacker to the victim.

![HoneyBOT 12](https://github.com/Kunull/Write-ups/assets/110326359/db7d9dff-85e7-4b56-ba96-4fc6b3c1c2dc)

We can download this file in the raw format via `Save as... > Raw`.

Using the `md5sum` command we can find the hash of the saved file.

```
$ md5sum malware 
14a09a48ad23fe0ea5a180bee8cb750a  malware
```

We can now search up this file hash using [VirusTotal](https://www.virustotal.com/gui/home/upload).&#x20;

![HoneyBOT 12 2](https://github.com/Kunull/Write-ups/assets/110326359/28c38979-cd67-4478-a61f-c4d6f1dbf850)

### Answer
```
2007-06-27
```

&nbsp;

## Q13. What is the key used to encode the shellcode?
