---
custom_edit_url: null
sidebar_position: 5
---

<figure style={{ textAlign: 'center' }}>
![1](https://github.com/Knign/Write-ups/assets/110326359/4cee44a3-fea8-47bb-bd05-35b14df757bd)
</figure>

Let's login using the following credentials:

| Username | Password |
| -------- | -------- |
| wiener         | peter         |

<figure style={{ textAlign: 'center' }}>
![2](https://github.com/Knign/Write-ups/assets/110326359/9df3f8bf-fffd-4dd9-a297-b864d1c22901)
</figure>

Since we are proxying the traffic through Burp Suite, we can view this request by going to `Porxy > HTTP History`.

<figure style={{ textAlign: 'center' }}>
![3](https://github.com/Knign/Write-ups/assets/110326359/2f0697b3-6d55-44c0-8aac-dc8185df0ee4)
</figure>

We can see that the request contains a parameter called `ìd` which is set to `wiener`.

Let's forward the request to the `Repeater` and set the `id` parameter to the following:
```
carlos
```

<figure style={{ textAlign: 'center' }}>
![4](https://github.com/Knign/Write-ups/assets/110326359/628e1eb7-cb17-4052-8c47-689a397e9652)
</figure>

We can now submit this API key through the browser.

<figure style={{ textAlign: 'center' }}>
![6](https://github.com/Knign/Write-ups/assets/110326359/2046f6ed-7334-4a3e-b8a6-a2b98227982d)
</figure>

We have solved the lab.

<figure style={{ textAlign: 'center' }}>
![7](https://github.com/Knign/Write-ups/assets/110326359/c11cf67f-a16c-433a-9f2d-e3ea5fec4b55)
</figure>
