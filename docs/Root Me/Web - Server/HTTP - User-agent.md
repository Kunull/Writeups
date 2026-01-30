---
custom_edit_url: null
sidebar_position: 4
---

<figure style={{ textAlign: 'center' }}>
![1](https://github.com/Knign/Write-ups/assets/110326359/b3d342fb-b41b-4ad9-a2d3-55e2e01fbc7a)
</figure>

Let's intercept the request using Burpsuite so that we can modify it.

<figure style={{ textAlign: 'center' }}>
![2](https://github.com/Knign/Write-ups/assets/110326359/58d37567-7542-4db1-aeb6-785e518d747c)
</figure>

We can now send the request to `Repeater`.

<figure style={{ textAlign: 'center' }}>
![3](https://github.com/Knign/Write-ups/assets/110326359/712ba327-d3d9-4323-8b4d-19b2abdba880)
</figure>

## User-Agent
The **User-Agent** [request header](https://developer.mozilla.org/en-US/docs/Glossary/Request_header) is a characteristic string that lets servers and network peers identify the application, browser used to make the request.

We have to modify it to `admin`.

## HTTP Request
```
GET /web-serveur/ch2/ HTTP/1.1
Host: challenge01.root-me.org
User-Agent: admin
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
DNT: 1
Connection: close
Cookie: _ga_SRYSKX09J7=GS1.1.1697381490.9.1.1697381491.0.0.0; _ga=GA1.1.1863804672.1697290591
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
```
Finally, we have to send the request to the server.

<figure style={{ textAlign: 'center' }}>
![4](https://github.com/Knign/Write-ups/assets/110326359/b5e05e4e-bda8-407b-976f-e01c6085c716)
</figure>

## Flag
```
rr$Li9%L34qd1AAe27
```
