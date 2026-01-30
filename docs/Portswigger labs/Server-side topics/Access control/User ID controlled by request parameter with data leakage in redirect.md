---
custom_edit_url: null
sidebar_position: 7
---

<figure style={{ textAlign: 'center' }}>
![1](https://github.com/Knign/Write-ups/assets/110326359/c90ad9ba-1f1e-4c24-a661-c36e266f48d8)
</figure>

Let's login using the following credentials:

| Username | Password |
| -------- | -------- |
| wiener         | peter         |

<figure style={{ textAlign: 'center' }}>
![2](https://github.com/Knign/Write-ups/assets/110326359/756e2e41-3e4f-4419-b17f-11c059cf41dc)
</figure>

Since we are proxying the traffic through Burp Suite, we will be able to view the request in `Proxy > HTTP History`.

<figure style={{ textAlign: 'center' }}>
![3](https://github.com/Knign/Write-ups/assets/110326359/3b96d298-d23a-4c0e-80ed-5ae526b2e868)
</figure>

We can see that the URI contains the `id` parameter set to `wiener`.

Let's forward it to the `Repeater` for further modification.

Once in the `Repeater`, we can set the `id` parameter to the following and send the request:

```
carlos
```

<figure style={{ textAlign: 'center' }}>
![4](https://github.com/Knign/Write-ups/assets/110326359/6c679ef5-9af3-4d26-8741-a2c10042592f)
</figure>

As we can see the response contains a 302 code. Which means that this is a redirection response.

We can follow the redirection however it is not necessary since we have the API key. Let's submit the key.

<figure style={{ textAlign: 'center' }}>
![6](https://github.com/Knign/Write-ups/assets/110326359/38472e47-52e6-44bc-af63-b1708475aaa1)
</figure>

We have solved the lab.

<figure style={{ textAlign: 'center' }}>
![7](https://github.com/Knign/Write-ups/assets/110326359/a66bfa60-42bd-4873-a38f-e11ed5857811)
</figure>
