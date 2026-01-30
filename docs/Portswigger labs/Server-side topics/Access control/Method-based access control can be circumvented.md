---
custom_edit_url: null
sidebar_position: 11
---

<figure style={{ textAlign: 'center' }}>
![1](https://github.com/Knign/Write-ups/assets/110326359/73ad1e49-c6ab-4d85-b04f-211dc275b154)
</figure>

Let's login as the admin using the following credentials:

| Username | Password |
| -------- | -------- |
| administrator         | admin         |

<figure style={{ textAlign: 'center' }}>
![2](https://github.com/Knign/Write-ups/assets/110326359/1bf1d705-0b91-4f8a-be99-d3ba18aabc4c)
</figure>

We can now upgrade the `carlos` user to admin.

<figure style={{ textAlign: 'center' }}>
![3](https://github.com/Knign/Write-ups/assets/110326359/c8272181-c074-4cbd-a8c8-c99a7e9093ff)
</figure>

Since we are proxying the traffic through Burp Suite, we will be able to view this request in the `Proxy > HTTP History` tab.

<figure style={{ textAlign: 'center' }}>
![4](https://github.com/Knign/Write-ups/assets/110326359/54384e46-02d0-4402-be31-f6f68a2620af)
</figure>

Let's forward this request to the `Repeater` for further modification.

Next, let's log out and log back in using the following credentials:

| Username | Password |
| -------- | -------- |
| wiener         | peter         |

<figure style={{ textAlign: 'center' }}>
![5](https://github.com/Knign/Write-ups/assets/110326359/e58f99ef-9fba-4101-be3f-5d8704d6bf20)
</figure>

We can go to the `Proxy > HTTP History` tab to get the session cookie.

<figure style={{ textAlign: 'center' }}>
![6](https://github.com/Knign/Write-ups/assets/110326359/11de2d78-cdec-4a12-8894-22609761e8da)
</figure>

Now, let's go back to the `Repeater` tab and change the request method.

<figure style={{ textAlign: 'center' }}>
![7](https://github.com/Knign/Write-ups/assets/110326359/7a5562b0-e467-4cc4-8ab4-52b4af27c5e3)
</figure>

Next, we have to replace the session cookie with the one from the `wiener` user's request.

We also have to set the `username` parameter to the following:

```
wiener
```

<figure style={{ textAlign: 'center' }}>
![8](https://github.com/Knign/Write-ups/assets/110326359/50edf04e-c15b-4bc5-8f0b-9ef667a0b362)
</figure>

Let's go and check the browser.

<figure style={{ textAlign: 'center' }}>
![9](https://github.com/Knign/Write-ups/assets/110326359/d4e8cee7-dfc2-4818-8995-6569eab9f7c1)
</figure>

We have solved the lab.

<figure style={{ textAlign: 'center' }}>
![10](https://github.com/Knign/Write-ups/assets/110326359/64f69236-a934-4cf1-a7c9-d900a951a2c6)
</figure>
