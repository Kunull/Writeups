---
custom_edit_url: null
sidebar_position: 13
---

<figure style={{ textAlign: 'center' }}>
![1](https://github.com/Knign/Write-ups/assets/110326359/622c0af4-c293-404c-8509-e8c3c8199a5b)
</figure>

We can login as the admin using the following credentials:

| Username | Password |
| -------- | -------- |
| administrator         | admin         |

<figure style={{ textAlign: 'center' }}>
![2](https://github.com/Knign/Write-ups/assets/110326359/74d770e5-552c-47db-9b88-30e9fab023a5)
</figure>

Let's go to the admin panel and upgrade the `carlos` user.

<figure style={{ textAlign: 'center' }}>
![3](https://github.com/Knign/Write-ups/assets/110326359/47852fb2-7724-451f-a43d-d5a63a9e8e69)
</figure>

Since we are proxying the traffic through Burp Suite, we can go to the `Proxy > HTTP History` tab to view the request.

<figure style={{ textAlign: 'center' }}>
![4](https://github.com/Knign/Write-ups/assets/110326359/75509ebc-441e-45ec-9b11-edebf6b1984e)
</figure>

Notice that the request contains the `Refered` header set to the following:

```
https://0ab4000404f019d8885f257200e0002f.web-security-academy.net/admin
```

That tells the server that the request is coming from the `/admin` page which can only be accessed by the administrator.

Let's forward this request to the `Repeater` for further modification.

Next, let's logout and login using the following credentials:


| Username | Password |
| -------- | -------- |
| wiener         | peter         |

<figure style={{ textAlign: 'center' }}>
![5](https://github.com/Knign/Write-ups/assets/110326359/3a55dc06-8719-4a59-9d68-c1fc8ee19860)
</figure>

We now have to replace the session cookie in the `Repeater` tab with the `wiener` user's session cookie and set the `username` parameter to the following:

```
wiener
```

<figure style={{ textAlign: 'center' }}>
![6](https://github.com/Knign/Write-ups/assets/110326359/35bb9edb-77f3-4bc9-9dd2-750b5c78963d)
</figure>

Since we included the `Referer` header, the server upgraded our user.

Let's check in the browser.

<figure style={{ textAlign: 'center' }}>
![7](https://github.com/Knign/Write-ups/assets/110326359/19636a58-9691-4fef-a18c-9fd5deb045f4)
</figure>

We have solved the lab.

<figure style={{ textAlign: 'center' }}>
![8](https://github.com/Knign/Write-ups/assets/110326359/6cc72237-4f42-41a5-bf99-28c59e79d3a4)
</figure>
