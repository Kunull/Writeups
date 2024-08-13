---
custom_edit_url: null
sidebar_position: 4
---

![1](https://github.com/Knign/Write-ups/assets/110326359/87133e37-52bb-4e19-8afe-3028ea16302c)

Let's login using the following credentials:

| Username | Password |
| -------- | -------- |
| wiener         | peter         |

Once we have logged in, we can try to access the `/admin` page.

![3](https://github.com/Knign/Write-ups/assets/110326359/51cd3e80-52a4-4da9-bf30-28aff17b9e83)

As we can see the admin panel is only accessible to local users.

Since we are proxying the request through Burp Suite, we will be able to see the request in the `Proxy > HTTP History` tab.

![4](https://github.com/Knign/Write-ups/assets/110326359/c0b361a5-24af-419c-ba58-d099fe8f3aee)

Let's forward this request to the `Repeater` for further modification.

Once in the `Repeater`, let's modify the method to TRACE and send the request.

![5](https://github.com/Knign/Write-ups/assets/110326359/1224223e-2926-4801-b7ed-6d8b7ad06d36)

In the response, the returns contains the `X-Custom-IP-Authorization` header which is set to our IP address.

Let's go into the `Proxy settings` tab.

![6](https://github.com/Knign/Write-ups/assets/110326359/ac0b8e05-adf5-4fcc-8449-a73b0ade6c80)

Next we have to scroll down to `Match and Replace` and click `Add`.

Inside the `Replace` field, paste the following:

```
X-Custom-IP-Authorization: 127.0.0.1
```

![7](https://github.com/Knign/Write-ups/assets/110326359/01ff0856-ee48-4caa-bad4-f5b2f0d693e8)

This header will now be added to every request that we send.
Therefore, we will be treated as local users and will have access to the admin panel.

![8](https://github.com/Knign/Write-ups/assets/110326359/0dfbce45-725a-4655-a81b-93d409f53c38)

Let's go inside and delete the `carlos` user.

![10](https://github.com/Knign/Write-ups/assets/110326359/e9c50e18-7eef-452c-bfda-2c8c3ce84859)

We have solved the lab.

![11](https://github.com/Knign/Write-ups/assets/110326359/f1fb703a-c008-406e-9260-2a7d7283096f)
