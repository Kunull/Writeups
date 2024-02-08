---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 10
---

![1](https://github.com/Knign/Write-ups/assets/110326359/cf7d1f93-5c3c-4a1e-99d9-df3cd36acf9f)

Maybe the clue lie in the response headers. 

In order to check the response headers we have to intercept the request using Burpsuite.

![2](https://github.com/Knign/Write-ups/assets/110326359/9c19cc3a-66bd-40e8-88d1-8bd3985d47ea)

Let's forward the request to the `Repeater`.

![3](https://github.com/Knign/Write-ups/assets/110326359/de8e5b8e-c91d-4f70-8038-470d977a9118)

The response has a header called `Header-RootMe-Admin`. We can include this header in our next request.

## HTTP Request
```
GET /web-serveur/ch5/ HTTP/1.1
Host: challenge01.root-me.org
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Header-RootMe-Admin: none
DNT: 1
Connection: close
Cookie: _ga_SRYSKX09J7=GS1.1.1697389021.11.1.1697389201.0.0.0; _ga=GA1.1.1863804672.1697290591
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
```
Finally, we have to send this request to the server.

![4](https://github.com/Knign/Write-ups/assets/110326359/41cdaf93-3927-4352-b23c-6f3b5a729c67)

## Flag
```
HeadersMayBeUseful
```
