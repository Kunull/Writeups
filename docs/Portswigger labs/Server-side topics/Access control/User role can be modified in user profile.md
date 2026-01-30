---
custom_edit_url: null
sidebar_position: 4
---

<figure style={{ textAlign: 'center' }}>
![1](https://github.com/Knign/Write-ups/assets/110326359/59eb992c-ae98-4c86-afa1-55cba4d7a2ce)
</figure>

Let's login using the following credentials:

| Username | Password |
| -------- | -------- |
| wiener         | peter         |

Once logged in, we can change our email address.

<figure style={{ textAlign: 'center' }}>
![2](https://github.com/Knign/Write-ups/assets/110326359/263d9811-e16a-417d-afd1-4e28b38199ad)
</figure>

Since we are proxying the traffic through Burp Suite, we can view the request by going to `Proxy > HTTP History`.

<figure style={{ textAlign: 'center' }}>
![3](https://github.com/Knign/Write-ups/assets/110326359/1ea56211-0c9e-4083-bd93-4615a2b09565)
</figure>

We can see that the response contains the following key:value pair:

```
"roleid":1
```

Let's forward this request to the `Repeater` and include the key:value pair in the body of the request.

<figure style={{ textAlign: 'center' }}>
![4](https://github.com/Knign/Write-ups/assets/110326359/b7314e2d-d7d8-4327-be5a-ac4fbe04c230)
</figure>

Now we can access tot admin panel using our browser.

<figure style={{ textAlign: 'center' }}>
![5](https://github.com/Knign/Write-ups/assets/110326359/56c7171e-853a-4508-ac96-715e936607ee)
</figure>

Let's delete the `carlos` user.

<figure style={{ textAlign: 'center' }}>
![6](https://github.com/Knign/Write-ups/assets/110326359/9522da0b-fcbb-4c02-b073-04ff42526478)
</figure>

We have solved the lab.

<figure style={{ textAlign: 'center' }}>
![7](https://github.com/Knign/Write-ups/assets/110326359/22251415-4e32-43df-af60-d10ad1e4fb3c)
</figure>
