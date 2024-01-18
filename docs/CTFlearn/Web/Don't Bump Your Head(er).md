---
custom_edit_url: null
pagination_next: null
pagination_prev: null
---

> Try to bypass my security measure on this site! http://165.227.106.113/header.php

![1](https://github.com/Knign/Write-ups/assets/110326359/ecd02f95-ab41-4a3a-9972-08926b96078c)

- Before we do anything else let's check the source code.

![2](https://github.com/Knign/Write-ups/assets/110326359/6bce9304-1b8c-4f33-8f15-8e2079bdb39f)

```
Sup3rS3cr3tAg3nt
```
## Burpsuite
- Let's open Burpsuite and turn on the `Proxy`.
- Then we can visit the website again so that it shows up in the `Proxy > HTTP History`.

![3](https://github.com/Knign/Write-ups/assets/110326359/4e6a4862-c78f-4692-ab7f-6e56f6953d80)

- Let's send the HHTP request to the Repeater by `Left click > Send to Repeater`.

![4](https://github.com/Knign/Write-ups/assets/110326359/3526c0ea-ac2e-40a4-a3b9-5e8fe4bf932c)

- Now we have to change the `User-Agent` to `Sup3rS3cr3tAg3nt`.

![5](https://github.com/Knign/Write-ups/assets/110326359/93ba7f74-364b-4b08-b909-40e758cae7d6)

- The website expects us to visit from `awesomesauce.com`.
- We can use the `Referer` HTTP header to help the server identify referring page.
## HTTP Request
```
GET /header.php HTTP/1.1
Host: 165.227.106.113
User-Agent: Sup3rS3cr3tAg3nt
Referer: awesomesauce.com
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
```
- We can now send the request and check the `Response` tab.

![6](https://github.com/Knign/Write-ups/assets/110326359/b6fd12ee-fcf5-4f9e-97f8-7e6360bdacdc)

## Flag
```
CTFlearn{did_this_m3ss_with_y0ur_h34d}
```
