---
custom_edit_url: null
---


## Q1. What is the FTP password?
We can set the filter such that it filters out FTP packets.
```
ftp
```
Following the TCP stream via `Follow > TCP Stream`, we can see the password.

<figure style={{ textAlign: 'center' }}>
![packetmaze 1](https://github.com/Knign/Write-ups/assets/110326359/6a8f6ff6-1a33-48ee-8d04-8d91171cbf0d)
</figure>

### Answer
```
AfricaCTF2021
```

&nbsp;


## Q2. What is the IPv6 address of the DNS server used by 192.168.1.26? (####::####:####:####:####)
We can filter the DNS packets using the following filter:
```
dns
```
On analyzing the packet, we can see the source MAC address.

<figure style={{ textAlign: 'center' }}>
![packetmaze 2](https://github.com/Knign/Write-ups/assets/110326359/a5512a90-60b6-49bb-84af-f79ebf08d208)
</figure>

We can create a second filter as follows:
```
eth.src == c8:09:a8:57:47:93 && ipv6 && dns
```
Let's look at the first packet.

<figure style={{ textAlign: 'center' }}>
![packetmaze 2 2](https://github.com/Knign/Write-ups/assets/110326359/b84e2aa7-f71e-4a36-8473-f7fb6a44ccdb)
</figure>

We can see the IPv6 address of the DNS server in the `Destination Address` field.

### Answer
```
fe80::c80b:adff:feaa:1db7
```

&nbsp;


## Q3. What domain is the user looking up in packet 15174?
Let's filter out the relevant packet.
```
frame.number == 15174
```
The domain is specified in the `Queries` filed of the DNS message.

<figure style={{ textAlign: 'center' }}>
![packetmaze 3](https://github.com/Knign/Write-ups/assets/110326359/fc7113b8-be23-4932-989b-ceebe3576984)
</figure>

### Answer
```
www.7-zip.org
```

&nbsp;

## Q4. How many UDP packets were sent from 192.168.1.26 to 24.39.217.246?
We can filter the relevant packets using the following filter:
```
ip.src == 192.168.1.26 && ip.dst == 24.39.217.246 && udp
```

<figure style={{ textAlign: 'center' }}>
![packetmaze 4](https://github.com/Knign/Write-ups/assets/110326359/a98e416a-6e20-427f-9928-89b5e5719f46)
</figure>

We can see that there are 10 packets that fit the description.

### Answer
```
10
```

&nbsp;

## Q5. What is the MAC address of the system being investigated in the PCAP?”
We already found the answer to this while researching for a previous question.

<figure style={{ textAlign: 'center' }}>
![packetmaze 2](https://github.com/Knign/Write-ups/assets/110326359/e2f9eb54-feb6-4007-a498-2548d9597513)
</figure>

### Answer
```
c8:09:a8:57:47:93
```

&nbsp;

## Q6. What was the camera model name used to take picture 20210429_152157.jpg ?
Since the image is a file, we can filter out for FTP-Data.
```
ftp-data
```

<figure style={{ textAlign: 'center' }}>
![packetmaze 6](https://github.com/Knign/Write-ups/assets/110326359/1160632f-ff86-4a16-912e-83910c89bdf1)
</figure>

We can see the file being moved. On following the TCP stream we can see the contents of the file.

<figure style={{ textAlign: 'center' }}>
![packetmaze 6 2](https://github.com/Knign/Write-ups/assets/110326359/440354a4-db9d-4ffa-84a9-5e09d20da587)
</figure>

There's the camera model name. However there is a better way to do this.

Let's save the image in `Raw` format.

<figure style={{ textAlign: 'center' }}>
![packetmaze 6 3](https://github.com/Knign/Write-ups/assets/110326359/048cb4cd-f98a-4014-b336-db27d18d844e)
</figure>

Using `exiftool` we can view the metadata of the image.
```
$ exiftool 20210429_152157.jpg 
--snip--;
Camera Model Name               : LM-Q725K
--snip--;
```

### Answer
```
LM-Q725K
```

&nbsp;

## Q7. What is the server certificate public key that was used in TLS session: da4a0000342e4b73459d7360b4bea971cc303ac18d29b99067e46d16cc07f4ff?
We can filter the packet based on the session ID the we have been provided with.
```
tls.handshake.session_id == da:4a:00:00:34:2e:4b:73:45:9d:73:60:b4:be:a9:71:cc:30:3a:c1:8d:29:b9:90:67:e4:6d:16:cc:07:f4:ff
```
In the `Server key Exchange` field we can find the `Pubkey`.

<figure style={{ textAlign: 'center' }}>
![packetmaze 7](https://github.com/Knign/Write-ups/assets/110326359/a82d0e22-ee0a-4dbc-a170-a137ccbae19e)
</figure>

### Answer
```
04edcc123af7b13e90ce101a31c2f996f471a7c8f48a1b81d765085f548059a550f3f4f62ca1f0e8f74d727053074a37bceb2cbdc7ce2a8994dcd76dd6834eefc5438c3b6da929321f3a1366bd14c877cc83e5d0731b7f80a6b80916efd4a23a4d
```

&nbsp;

## Q8. What is the first TLS 1.3 client random that was used to establish a connection with protonmail.com?
We have to first set a filter.
```
frame contains protonmail.com && tls
```
Let's look at the first packet. In the `Random` field we can find the answer to our question.

<figure style={{ textAlign: 'center' }}>
![packetmaze 8](https://github.com/Knign/Write-ups/assets/110326359/1799c8b6-7b10-4691-bdc7-a78f95d7e721)
</figure>

### Answer
```
24e92513b97a0348f733d16996929a79be21b0b1400cd7e2862a732ce7775b70
```

&nbsp;

## Q9. What country is the MAC address of the FTP server registered in? (two words, one space in between)
On filtering for `ftp` traffic, we can find the source MAC address.

<figure style={{ textAlign: 'center' }}>
![packetmaze 9 3](https://github.com/Knign/Write-ups/assets/110326359/c757841e-332c-459a-8a79-8fbfdc5abc13)
</figure>

We can then search this MAC address on DNSChecker.

<figure style={{ textAlign: 'center' }}>
![packetmaze 9 2](https://github.com/Knign/Write-ups/assets/110326359/9fb04682-90ce-4746-8820-55aad688553e)
</figure>

Alternatively, we can also use macaddress.io.

<figure style={{ textAlign: 'center' }}>
![packetmaze 9](https://github.com/Knign/Write-ups/assets/110326359/2d7626b5-a438-4b1d-a572-b65c7a460889)
</figure>

### Answer
```
United States
```

&nbsp;

## Q10. What time was a non-standard folder created on the FTP server on the 20th of April? (hh:mm)
We need to first filter for FTP-Data.
```
ftp-data
```
On following the TCP stream, we can see a list of folders.

<figure style={{ textAlign: 'center' }}>
![packetmaze 10](https://github.com/Knign/Write-ups/assets/110326359/f9146d1e-2b09-4564-b033-f7971f78c0ab)
</figure>

Out of all the folders in the list the `ftp` folder is the non-standard one.

### Answer
```
17:53
```

&nbsp;

## Q11. What domain was the user connected to in packet 27300?
We have to first set a filter.
```
frame.number == 27300
```
We can see the destination address of the packet.

<figure style={{ textAlign: 'center' }}>
![packetmaze 11](https://github.com/Knign/Write-ups/assets/110326359/1aa0083d-d78b-4f62-809f-6b450ce817aa)
</figure>

Now let's go to `Statistics > Resolved Addresses` in order to see if this IP address has been resolved or not.

<figure style={{ textAlign: 'center' }}>
![packetmaze 11 2](https://github.com/Knign/Write-ups/assets/110326359/72061898-2f02-496e-a8bf-af7d6efdc870)
</figure>

### Answer
```
dfir.science
```
