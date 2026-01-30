---
custom_edit_url: null
sidebar_position: 3
---

<figure style={{ textAlign: 'center' }}>
![1](https://github.com/Knign/Write-ups/assets/110326359/23eb100b-2052-4a9c-9aa5-c2d7134f3eb4)
</figure>

Let's clink on `My account`.

<figure style={{ textAlign: 'center' }}>
![2](https://github.com/Knign/Write-ups/assets/110326359/549a053d-f0df-4f03-8717-f3d9f25b1045)
</figure>

Clink on `Forgot password?`. Then enter the `wiener` username.

<figure style={{ textAlign: 'center' }}>
![3](https://github.com/Knign/Write-ups/assets/110326359/e6ee2b62-c5e8-47a4-b630-cd7f6d39a628)
</figure>

Next, we have to click on `Email client` in order to check our emails.

<figure style={{ textAlign: 'center' }}>
![5](https://github.com/Knign/Write-ups/assets/110326359/75d73923-e7de-4c97-aff8-300a09594f20)
</figure>

Let's click on the link provided to us.

<figure style={{ textAlign: 'center' }}>
![6](https://github.com/Knign/Write-ups/assets/110326359/bf27dd7b-8eb9-4b7e-b7f0-f8c51237ecf6)
</figure>

We can enter any password.

Since we are proxying the traffic through Burp Suite, we can view this request in the `Proxy > HTTP History` tab.

<figure style={{ textAlign: 'center' }}>
![7](https://github.com/Knign/Write-ups/assets/110326359/ea08fe9f-e184-4f00-a7a0-8587bfd71b8d)
</figure>

We can forward this request to the `Repeater` so that we can modify it.

Once in the `Repeater` tab, let's remove the `temp-forgot-password-token` parameter from the URI as well as the POST data field and send the request to the server.

<figure style={{ textAlign: 'center' }}>
![8](https://github.com/Knign/Write-ups/assets/110326359/b55fa44c-df9a-482b-8d58-3debc8b67cf7)
</figure>

We can see that our password has been changed even though we did not include the token, This means that the server sets the token but does not validate it.

Let's set the `username` field to the following and resend the request:
```
carlos
```

<figure style={{ textAlign: 'center' }}>
![9](https://github.com/Knign/Write-ups/assets/110326359/c80449c9-7ebc-470f-9776-f453fef2dc2c)
</figure>

Now we can login using the following credentials:

| Username | Password |
| -------- | -------- |
| carlos         | password         |

<figure style={{ textAlign: 'center' }}>
![10](https://github.com/Knign/Write-ups/assets/110326359/c0b94f97-5de4-4190-aec7-45ef9e626e3a)
</figure>

<figure style={{ textAlign: 'center' }}>
![11](https://github.com/Knign/Write-ups/assets/110326359/22750b4f-cb15-4f5b-96f6-84b06e680039)
</figure>

We have solved the lab.

<figure style={{ textAlign: 'center' }}>
![12](https://github.com/Knign/Write-ups/assets/110326359/eb0ddeb9-f929-4cda-93a6-7ef1efe65f8e)
</figure>
