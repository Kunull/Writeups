

> Q1. What is the FTP password?
- We can set the filter such that it filters out FTP packets.
```
ftp
```
- Following the TCP stream via `Follow > TCP Stream`, we can see the password.
![[packetmaze 1.png]]


> Q2. What is the IPv6 address of the DNS server used by 192.168.1.26? 
>        (####::####:####:####:####)
- We can filter the DNS packets using the following filter:
```
dns
```
- On analyzing the packet, we can see the source MAC address.
![[packetmaze 2.png]]
- We can create a second filter as follows:
```
eth.src == c8:09:a8:57:47:93 && ipv6 && dns
```
- Let's look at the first packet.
![[packetmaze 2.2.png]]
- We can see the IPv6 address of the DNS server in the `Destination Address` field.





> Q3. What domain is the user looking up in packet 15174?
- Let's filter out the relevant packet.
```
frame.number == 15174
```
- The domain is specified in the `Queries` filed of the DNS message.
![[packetmaze 3.png]]




> Q4. How many UDP packets were sent from 192.168.1.26 to 24.39.217.246?
- We can filter the relevant packets using the following filter:
```
ip.src == 192.168.1.26 && ip.dst == 24.39.217.246 && udp
```
![[packetmaze 4.png]]
- We can see that there are 10 packets that fit the description.






> Q5. What is the MAC address of the system being investigated in the PCAP?”
- We already found the answer to this while researching for a previous question.
![[packetmaze 2.png]]




> Q6. What was the camera model name used to take picture 20210429_152157.jpg ?
- Since the image is a file, we can filter out for FTP-Data.
```
ftp-data
```
![[packetmaze 6.png]]
- We can see the file being moved. On following the TCP stream we can see the contents of the file.
![[packetmaze 6.2.png]]
- There's the camera model name. However there is a better way to do this.
- Let's save the image in `Raw` format.
![[packetmaze 6.3.png]]
- Using `exiftool` we can view the metadata of the image.
```
$ exiftool 20210429_152157.jpg 
--snip--;
Camera Model Name               : LM-Q725K
--snip--;
```



> Q7. What is the server certificate public key that was used in TLS session:
>        da4a0000342e4b73459d7360b4bea971cc303ac18d29b99067e46d16cc07f4ff?
- We can filter the packet based on the session ID the we have been provided with.
```
tls.handshake.session_id == da:4a:00:00:34:2e:4b:73:45:9d:73:60:b4:be:a9:71:cc:30:3a:c1:8d:29:b9:90:67:e4:6d:16:cc:07:f4:ff
```
- In the `Server key Exchange` field we can find the `Pubkey`.![[packetmaze 7.png]]




> Q8. What is the first TLS 1.3 client random that was used to establish a connection with protonmail.com?
- We have to first set a filter.
```
frame contains protonmail.com && tls
```
- Let's look at the first packet. In the `Random` field we can find the answer to our question.
![[packetmaze 8.png]]





> Q9. What country is the MAC address of the FTP server registered in? (two words, one space in between)
- On filtering for `ftp` traffic, we can find the source MAC address.
![[packetmaze 9.3.png]]
- We can then search this MAC address on DNSChecker.
![[packetmaze 9.2.png]]
- Alternatively, we can also use macaddress.io.
![[packetmaze 9.png]]





> Q10. What time was a non-standard folder created on the FTP server on the 20th of April? (hh:mm)
- We need to first filter for FTP-Data.
```
ftp-data
```
- On following the TCP stream, we can see a list of folders.
![[packetmaze 10.png]]
- Out of all the folders in the list the `ftp` folder is the non-standard one.




> Q11. What domain was the user connected to in packet 27300?
- We have to first set a filter.
```
frame.number == 27300
```
- We can see the destination address of the packet.
![[packetmaze 11.png]]
 - Now let's go to `Statistics > Resolved Addresses` in order to see if this IP address has been resolved or not.
![[packetmaze 11.2.png]]
