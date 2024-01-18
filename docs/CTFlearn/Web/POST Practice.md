---
custom_edit_url: null
pagination_next: null
pagination_prev: null
---

> This website requires authentication, via POST. However, it seems as if someone has defaced our site. Maybe there is still some way to authenticate? 
> http://165.227.106.113/post.php


- Before we do anything else let's check the source code.

![1 5](https://github.com/Knign/Write-ups/assets/110326359/a6ac0e5d-58b2-4801-9311-315b53247c11)

```
username: admin
password: 71urlkufpsdnlkadsf
```
## Burpsuite
- Let's open Burpsuite and turn on the `Proxy`.
- Then we can visit the website again so that it shows up in the `Proxy > HTTP History`.

![2](https://github.com/Knign/Write-ups/assets/110326359/af5debe2-5282-4637-a5ca-43e00dbd33a8)

- Let's send the HHTP request to the Repeater by `Left click > Send to Repeater`.

![3](https://github.com/Knign/Write-ups/assets/110326359/db0fee9f-2d65-4f0b-9d04-6e41a54ddf42)

- Now we have to add the username and password as the content to this request and change the method to POST. 
- The HTTP request must look like this when we are done:
```
POST /post.php HTTP/1.1
Host: 165.227.106.113
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
Cache-Control: max-age=0
Content-Type: application/x-www-form-urlencoded
Content-Length: 42

username=admin&password=71urlkufpsdnlkadsf
```
- We can now send the request and check the `Response` tab.

![4](https://github.com/Knign/Write-ups/assets/110326359/26fe62d6-9abc-4fad-88a1-619e1dc0609a)

## Flag
```
CTFlearn{p0st_d4t4_4ll_d4y}
```
