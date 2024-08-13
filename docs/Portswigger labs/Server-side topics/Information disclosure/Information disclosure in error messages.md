---
custom_edit_url: null
sidebar_position: 1
---

![1](https://github.com/Knign/Write-ups/assets/110326359/2f516894-c9fc-43c3-97ed-d0c1a5d5de5a)

Let's click on the first product and view it.

![2](https://github.com/Knign/Write-ups/assets/110326359/49aac59c-1bd9-446e-b969-af44a8614c04)

Since we are proxying the traffic through Burp Suite, we can view this request in the `Proxy > HTTP History`.

![3](https://github.com/Knign/Write-ups/assets/110326359/24cb5dbe-1ad2-463c-8c9c-8b64ba90ea4a)

Let's forward this request to the `Repeater` for further modification.

Once in the `Repeater`, we have to set the `productId` parameter to a not-integer value as follows and send the request to the server:

```
"string"
```

![4](https://github.com/Knign/Write-ups/assets/110326359/2121fdb7-9536-48dd-b67b-637c3d1d8926)

```
2 2.3.31
```

As we can see, the server discloses the Apache version in the response.

We can not submit this as the answer.

![6](https://github.com/Knign/Write-ups/assets/110326359/00d35c98-915b-403f-afce-097bf373ccce)

We have solved the lab.

![7](https://github.com/Knign/Write-ups/assets/110326359/3bcb7403-f3ce-4d20-a3e8-79485661d57c)
