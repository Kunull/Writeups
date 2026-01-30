---
custom_edit_url: null
sidebar_position: 6
---

<figure style={{ textAlign: 'center' }}>
![1](https://github.com/Knign/Write-ups/assets/110326359/8f05eb79-a60b-4d6d-a786-ad7f4fdaf0a8)
</figure>

We can login using the following credentials:

| Username | Password |
| -------- | -------- |
| wiener         | peter         |

<figure style={{ textAlign: 'center' }}>
![2](https://github.com/Knign/Write-ups/assets/110326359/fadc6a94-3a50-40a2-9a9a-c500f9bfdfd3)
</figure>

Since we are proxying the traffic through Burp Suite, we can go to `Proxy > HTTP History` in order to view the request.

<figure style={{ textAlign: 'center' }}>
![3](https://github.com/Knign/Write-ups/assets/110326359/bb82c2c6-3b8e-40f4-b628-47e3e78b123a)
</figure>

As we can see, the request contains an `id` parameter. In order to access the `carlos` user's API key we will first need to find his GUID.

First let's forward this request to the `Repeater` for later modification.

Let's now look for some post written by the `carlos` user.

<figure style={{ textAlign: 'center' }}>
![4](https://github.com/Knign/Write-ups/assets/110326359/f180f68a-afaa-4e1a-bf4b-b8aca02a9905)
</figure>

We can now view the user's profile.

<figure style={{ textAlign: 'center' }}>
![5](https://github.com/Knign/Write-ups/assets/110326359/3e765dac-39ae-42b3-ab01-16a9a19046f3)
</figure>

Let's read this request in the `Proxy > HTTP History` tab.

<figure style={{ textAlign: 'center' }}>
![6](https://github.com/Knign/Write-ups/assets/110326359/15cd78d8-3ca5-470c-8f9f-8ff6eddebef9)
</figure>

Now that we have the GUID, we can go to the `Repeater`  and set the `id` parameter to the `carlos` user's GUID and send the request.

<figure style={{ textAlign: 'center' }}>
![7](https://github.com/Knign/Write-ups/assets/110326359/e00e37dc-37d3-4757-98e0-79892536d6de)
</figure>

Let's submit the API key.

<figure style={{ textAlign: 'center' }}>
![8](https://github.com/Knign/Write-ups/assets/110326359/6b6dfce6-7c08-415c-a50b-da811af3a3ef)
</figure>

We have solved the lab.

<figure style={{ textAlign: 'center' }}>
![9](https://github.com/Knign/Write-ups/assets/110326359/70d6c7d8-001b-45a7-a791-bb27e1d8658a)
</figure>
