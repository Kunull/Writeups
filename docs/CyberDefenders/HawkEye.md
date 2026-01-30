---
custom_edit_url: null
---


## Q1. How many packets does the capture have?
In order to find the number of packets we have to go to the `Statistics > Capture File Properties` section.

<figure style={{ textAlign: 'center' }}>
![hawkeye 1](https://github.com/Knign/Write-ups/assets/110326359/b0634e3d-ecc0-4cd8-987b-fd6d33ede5af)
</figure>

### Answer
```
2019-04-10 20:37:07 UTC
```

&nbsp;


## Q2. At what time was the first packet captured?
We have to set the format to UTC in the `View > Time Display Format` section.

<figure style={{ textAlign: 'center' }}>
![hawkeye 2](https://github.com/Knign/Write-ups/assets/110326359/55d47d6d-f587-427f-b633-7310c864ef05)
</figure>

Alternatively, we can also find the answer in the `Capture File Properties` section.

<figure style={{ textAlign: 'center' }}>
![hawkeye 2 2](https://github.com/Knign/Write-ups/assets/110326359/a64919a0-9eba-4483-962b-f418a8279433)
</figure>

### Answer
```
2019-04-10 20:37:07 UTC
```

&nbsp;


## Q3. What is the duration of the capture?
Again this answer can be found in the `Capture File Properties` section.

<figure style={{ textAlign: 'center' }}>
![hawkeye 3](https://github.com/Knign/Write-ups/assets/110326359/d2a46911-5c68-4537-93cf-cf9b8fb98339)
</figure>

### Answer
```
01:03:41
```

&nbsp;


## Q4. What is the most active computer at the link level?
If we go to the `Statistics > Endpoints` section, we can see information about all the devices in the packet transfer.

<figure style={{ textAlign: 'center' }}>
![hawkeye 4](https://github.com/Knign/Write-ups/assets/110326359/e4ab540d-c026-428a-bc5a-339b871b966b)
</figure>

### Answer
```
00:08:02:1c:47:ae
```

&nbsp;


## Q5. Manufacturer of the NIC of the most active system at the link level?
We can use A-Packets, in order to find the answer easily.

Open the `Ethernet` section of the file.

<figure style={{ textAlign: 'center' }}>
![hawkeye 6](https://github.com/Knign/Write-ups/assets/110326359/fd3a1217-2b81-415f-81c4-e7d536446dc0)
</figure>

Alternatively, we can also use Wireshark to find the NIC manufacturer.

Put the following filter on in order to filter for relevant traffic.
```
eth.addr==00:08:02:1c:47:ae
```
On applying the filter, we can see the following packet.

<figure style={{ textAlign: 'center' }}>
![hawkeye 5 3](https://github.com/Knign/Write-ups/assets/110326359/6848ff74-c952-4138-948f-914095f6454d)
</figure>

The source address is `00:08:02:1c:47:ae`. Let's search this MAC address on DNSChecker.

<figure style={{ textAlign: 'center' }}>
![hawkeye 5 2](https://github.com/Knign/Write-ups/assets/110326359/bdc01c7a-4d52-430c-bfa7-d378f99fd89b)
</figure>

Same answer as the one we got from A-Packets.

### Answer
```
Hewlett-Packard
```

&nbsp;


## Q6. Where is the headquarter of the company that manufactured the NIC of the most active computer at the link level?
A quick Google search tells us where the headquarters are located.

<figure style={{ textAlign: 'center' }}>
![hawkeye 6 1](https://github.com/Knign/Write-ups/assets/110326359/2bde953e-f478-4599-8c07-2fb1e00df134)
</figure>

### Answer
```
Palo Alto
```

&nbsp;


## Q7. The organization works with private addressing and netmask /24. How many computers in the organization are involved in the capture?
The `/24` subnet mask denotes that the first 24 bytes are part of the network and the last 8 bytes are part of the host.

This means that every host within the `10.4.10.x/24` subnetis part of the organization![[hawkeye 7.png]]

We can see that the first 3 devices are part of the same subnet thus the same organization. Note that the broadcast address is not counted.

### Answer
```
3
```

&nbsp;


## Q8. What is the name of the most active computer at the network level?
Since we already know the MAC address of the most active host, we can set a filter for that address and `dhcp` to find the host name.
```
eth.addr==00:08:02:1c:47:ae && dhcp
```

Let's look at the `Host Name` option.

<figure style={{ textAlign: 'center' }}>
![hawkeye 8](https://github.com/Knign/Write-ups/assets/110326359/5a21a9b8-c4bd-4de2-ac76-f494cf2bd727)
</figure>

### Answer
```
BEIJING-5CD1-PC
```

&nbsp;


## Q9. What is the IP of the organization's DNS server?
In the `DNS` section of A-Packets, we can see the IP of the organization.

<figure style={{ textAlign: 'center' }}>
![hawkeye 9](https://github.com/Knign/Write-ups/assets/110326359/06ceca92-cc9e-4dab-ac6f-e5233d799390)
</figure>

We can also filter for `dns` packets in Wireshark.

<figure style={{ textAlign: 'center' }}>
![hawkeye 9 2](https://github.com/Knign/Write-ups/assets/110326359/9d9f8108-f499-459e-8ded-2caed94dbef0)
</figure>

### Answer
```
10.4.10.4
```

&nbsp;


## Q10. What domain is the victim asking about in packet 204?
Let's analyze the 204th packet.

<figure style={{ textAlign: 'center' }}>
![hawkeye 10](https://github.com/Knign/Write-ups/assets/110326359/5e1789f6-52b5-4bbc-8545-97b57483a138)
</figure>

### Answer
```
proforma-invoices.com
```

&nbsp;


## Q11. What is the IP of the domain in the previous question?
Let's look through the `Connections` section in A-Packets.

<figure style={{ textAlign: 'center' }}>
![hawkeye 11](https://github.com/Knign/Write-ups/assets/110326359/04bbcd4e-2de9-4f29-9fc7-1bad5ac4cd63)
</figure>

In order to find the answer in Wireshark, we have to set the following filter:
```
frame contains proforma-invoices.com
```
Look in the destination IP address field.

<figure style={{ textAlign: 'center' }}>
![hawkeye 11 2](https://github.com/Knign/Write-ups/assets/110326359/f6fdaef8-ded4-4d08-8edb-b5ef1275d048)
</figure>

### Answer
```
217.182.138.150
```

&nbsp;


## Q12. Indicate the country to which the IP in the previous section belongs.
We can use the `IP Lookup` tool in DNSChecker.

<figure style={{ textAlign: 'center' }}>
![hawkeye 12](https://github.com/Knign/Write-ups/assets/110326359/4fd889ca-c6d6-497e-afa3-c17240385153)
</figure>

### Answer
```
France
```

&nbsp;

## Q13. What operating system does the victim's computer run?
Let's filter the http requests using the following filter:
```
eth.addr==00:08:02:1c:47:ae && http.request
```
Go to `Follow > TCP Stream` in order to see the entire message.

<figure style={{ textAlign: 'center' }}>
![hawkeye 13](https://github.com/Knign/Write-ups/assets/110326359/681808f5-32ef-4765-b317-1e7ea7445eec)
</figure>

We can also find the OS in the `HTTP` section of A-Packets.

<figure style={{ textAlign: 'center' }}>
![hawkeye 13 2](https://github.com/Knign/Write-ups/assets/110326359/183691ca-9d56-41f6-9321-7caf8a5fadd3)
</figure>

### Answer
```
Windows NT 6.1
```

&nbsp;


## Q14. What is the name of the malicious file downloaded by the accountant?
In the `HTTP Headers` section of A-Packets, we can find the file that is being downloaded.

<figure style={{ textAlign: 'center' }}>
![hawkeye 14](https://github.com/Knign/Write-ups/assets/110326359/3c9d4cad-1f63-4275-b5c3-e7fa6eab096f)
</figure>

Alternatively, in Wireshark we can filter for `GET` request using the following filter:
```
http.request.method == GET
```
Only the 210th packet is accessing a file.

<figure style={{ textAlign: 'center' }}>
![hawkeye 14 2](https://github.com/Knign/Write-ups/assets/110326359/dbe1fbd5-fb87-4dd2-82a4-251eefff8370)
</figure>

### Answer
```
tkraw_Protected99.exe
```

&nbsp;


## Q15. What is the md5 hash of the downloaded file?
Let's extract the file via `File > Export Objects > HTTP`.

We can now use `md5sum` command in order to obtain the file hash.
```
$ md5sum tkraw_Protected99.exe 
71826ba081e303866ce2a2534491a2f7  tkraw_Protected99.exe
```
We can also upload the file to VirusTotal in order to find the file hash.

<figure style={{ textAlign: 'center' }}>
![hawkeye 15](https://github.com/Knign/Write-ups/assets/110326359/a2a17c1c-cdf8-4bc3-addc-7ff9ef415404)
</figure>

### Answer
```
71826ba081e303866ce2a2534491a2f7
```

&nbsp;

## Q16. What software runs the webserver that hosts the malware?
In Wireshark, we can again follow the TCP Stream in order to find the server.

<figure style={{ textAlign: 'center' }}>
![hawkeye 17](https://github.com/Knign/Write-ups/assets/110326359/2232a43d-823d-4c9f-85f4-d0e0d4d185f5)
</figure>

### Answer
```
173.66.146.112
```

&nbsp;

## Q17. What is the public IP of the victim's computer?
Let's filter for all HTTP requests:
```
http.request
```
If we follow TCP Stream, we can find the public IP.

<figure style={{ textAlign: 'center' }}>
![hawkeye 18](https://github.com/Knign/Write-ups/assets/110326359/bae4d808-1ffc-4863-8ac6-fb16a4a665db)
</figure>

### Answer
```
United States
```

&nbsp;

## Q18. In which country is the email server to which the stolen information is sent?
We can use the `IP Lookup` tool in DNSChecker.

<figure style={{ textAlign: 'center' }}>
![hawkeye 19](https://github.com/Knign/Write-ups/assets/110326359/23feafbf-b454-4b1b-8f19-2811e9be3745)
</figure>

### Answer
```
Exim 4.91
```

&nbsp;

## Q19. Analyzing the first extraction of information. What software runs the email server to which the stolen data is sent?
Put on the following filter:
```
ip.addr == 10.4.10.132 && smtp.req
```
We can follow the TCP stream.

<figure style={{ textAlign: 'center' }}>
![hawkeye 20](https://github.com/Knign/Write-ups/assets/110326359/ae598f37-c5f4-49c0-ae18-861679de15a4)
</figure>

### Answer
```
sales.del@macwinlogistics.in
```

&nbsp;

## Q20. To which email account is the stolen information sent?
Further down in the TCP stream we can see the email that the information is sent to.

<figure style={{ textAlign: 'center' }}>
![hawkeye 21 1](https://github.com/Knign/Write-ups/assets/110326359/52de53ae-21d8-41ba-8b98-a563064c11e1)
</figure>

### Answer
```
Sales@23
```

&nbsp;

## Q21. What is the password used by the malware to send the email?
We will use the same filter as before:
```
ip.addr == 10.4.10.132 && smtp.req
```
We can see a password. However, it seems to be base64 encoded.

<figure style={{ textAlign: 'center' }}>
![hawkeye 22 2](https://github.com/Knign/Write-ups/assets/110326359/9d34af8b-fbb0-4a1c-8fcf-65248f5da44d)
</figure>

Let's use CyberChef to decode the password.

<figure style={{ textAlign: 'center' }}>
![hawkeye 22](https://github.com/Knign/Write-ups/assets/110326359/5e2bf519-352b-408d-8b64-4c5bcffe85fb)
</figure>

### Answer
```
Reborn v9
```

&nbsp;

## Q22. Which malware variant exfiltrated the data?
If we follow the same TCP stream, we can see a huge blob of data.

<figure style={{ textAlign: 'center' }}>
![hawkeye 23 2](https://github.com/Knign/Write-ups/assets/110326359/a1958e88-a118-411f-a968-4d6884538d1c)
</figure>

This has been base64 encoded. We have to again use CyberChef to decode it.

<figure style={{ textAlign: 'center' }}>
![hawkeye 23](https://github.com/Knign/Write-ups/assets/110326359/8e55bcc2-5f41-40f3-80e4-62e024f017d0)
</figure>

### Answer
```
roman.mcguire:P@ssw0rd$
```

&nbsp;


## Q23. What are the bankofamerica access credentials? (username:password)
This information is available in the output for the previous question.

<figure style={{ textAlign: 'center' }}>
![hawkeye 24](https://github.com/Knign/Write-ups/assets/110326359/8f5f5fce-90d2-4adf-b6f8-aee288951c17)
</figure>

### Answer
```
```

&nbsp;


## Q24. Every how many minutes does the collected data get exfiltrated?
If we look at the SMTP packets, we can see that the email is sent every 10 minutes.

<figure style={{ textAlign: 'center' }}>
![hawkeye 25](https://github.com/Knign/Write-ups/assets/110326359/40f753a3-26cc-4db5-a7d6-a5bc7dccb7f9)
</figure>

### Answer
```
10
```
