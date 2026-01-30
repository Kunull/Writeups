---
custom_edit_url: null
sidebar_position: 1
---

<figure style={{ textAlign: 'center' }}>
![1](https://github.com/Knign/Write-ups/assets/110326359/2f516894-c9fc-43c3-97ed-d0c1a5d5de5a)
</figure>

Let's click on the first product and view it.

<figure style={{ textAlign: 'center' }}>
![2](https://github.com/Knign/Write-ups/assets/110326359/49aac59c-1bd9-446e-b969-af44a8614c04)
</figure>

Since we are proxying the traffic through Burp Suite, we can view this request in the `Proxy > HTTP History`.

<figure style={{ textAlign: 'center' }}>
![3](https://github.com/Knign/Write-ups/assets/110326359/24cb5dbe-1ad2-463c-8c9c-8b64ba90ea4a)
</figure>

Let's forward this request to the `Repeater` for further modification.

Once in the `Repeater`, we have to set the `productId` parameter to a not-integer value as follows and send the request to the server:

```
"string"
```

<figure style={{ textAlign: 'center' }}>
![4](https://github.com/Knign/Write-ups/assets/110326359/2121fdb7-9536-48dd-b67b-637c3d1d8926)
</figure>

```
2 2.3.31
```

As we can see, the server discloses the Apache version in the response.

We can not submit this as the answer.

<figure style={{ textAlign: 'center' }}>
![6](https://github.com/Knign/Write-ups/assets/110326359/00d35c98-915b-403f-afce-097bf373ccce)
</figure>

We have solved the lab.

<figure style={{ textAlign: 'center' }}>
![7](https://github.com/Knign/Write-ups/assets/110326359/3bcb7403-f3ce-4d20-a3e8-79485661d57c)
</figure>
