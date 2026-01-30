---
custom_edit_url: null
sidebar_position: 1
---

<figure style={{ textAlign: 'center' }}>
![1](https://github.com/Knign/Write-ups/assets/110326359/3c3e49fb-22ad-4cc0-bf8c-398261f221f0)
</figure>

We can click on the `My account` button and login using the following credentials:

| Username | Password |
| ---- | ---- |
| wiener | peter |

<figure style={{ textAlign: 'center' }}>
![2](https://github.com/Knign/Write-ups/assets/110326359/3142caf9-b5eb-4368-bdbf-982bc569d398)
</figure>

We can now go back to the web store and click on the "Lightweight l33t leather jacket".

<figure style={{ textAlign: 'center' }}>
![3](https://github.com/Knign/Write-ups/assets/110326359/572f81bf-840f-40f5-8284-4ecb86c99bf6)
</figure>

Let's add the product to the cart.

<figure style={{ textAlign: 'center' }}>
![4](https://github.com/Knign/Write-ups/assets/110326359/d2b144dd-f470-4187-af35-97d0846ebecf)
</figure>

We can place the order but it won't go through because we don't have enough credits.

Since we are proxying the traffic Burp Suite, we can view this request through the `Proxy > HTTP History` tab.

<figure style={{ textAlign: 'center' }}>
![5](https://github.com/Knign/Write-ups/assets/110326359/237c85ce-7064-411e-a113-8c82ca8e98ce)
</figure>

Let's forward the request to the `Repeater` for further modifications.

Once in the `Repeater`, we can set the `price` parameter to the following:

```
9
```

Let's send the request.

<figure style={{ textAlign: 'center' }}>
![6](https://github.com/Knign/Write-ups/assets/110326359/c34a55e4-cb5e-4cf6-8eb0-3c4a9a887c92)
</figure>

If we check our cart through the browser, we can see that the price of the product has been set to the modified `price` parameter's value.

The quantity has also been updated.

<figure style={{ textAlign: 'center' }}>
![7](https://github.com/Knign/Write-ups/assets/110326359/d95e9d78-6dd6-4b51-9484-a9dde19cd796)
</figure>

Since the total price is less than our credits, we can now place the order.

<figure style={{ textAlign: 'center' }}>
![8](https://github.com/Knign/Write-ups/assets/110326359/a95ac7e7-4f51-4699-b3a9-d43e9dd43b84)
</figure>

We have solved the lab.

<figure style={{ textAlign: 'center' }}>
![9](https://github.com/Knign/Write-ups/assets/110326359/2e5c0f61-f790-464b-a7f3-88d021dc3171)
</figure>
