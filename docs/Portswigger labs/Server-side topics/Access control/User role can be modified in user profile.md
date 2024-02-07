---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 4
---

![1](https://github.com/Knign/Write-ups/assets/110326359/59eb992c-ae98-4c86-afa1-55cba4d7a2ce)

Let's login using the following credentials:

| Username | Password |
| -------- | -------- |
| wiener         | peter         |

Once logged in, we can change our email address.

![2](https://github.com/Knign/Write-ups/assets/110326359/263d9811-e16a-417d-afd1-4e28b38199ad)

Since we are proxying the traffic through Burp Suite, we can view the request by going to `Proxy > HTTP History`.

![3](https://github.com/Knign/Write-ups/assets/110326359/1ea56211-0c9e-4083-bd93-4615a2b09565)

We can see that the response contains the following key:value pair:

```
"roleid":1
```

Let's forward this request to the `Repeater` and include the key:value pair in the body of the request.

![4](https://github.com/Knign/Write-ups/assets/110326359/b7314e2d-d7d8-4327-be5a-ac4fbe04c230)

Now we can access tot admin panel using our browser.

![5](https://github.com/Knign/Write-ups/assets/110326359/56c7171e-853a-4508-ac96-715e936607ee)

Let's delete the `carlos` user.

![6](https://github.com/Knign/Write-ups/assets/110326359/9522da0b-fcbb-4c02-b073-04ff42526478)

We have solved the lab.

![7](https://github.com/Knign/Write-ups/assets/110326359/22251415-4e32-43df-af60-d10ad1e4fb3c)
