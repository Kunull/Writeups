---
custom_edit_url: null
sidebar_position: 2
---

<figure style={{ textAlign: 'center' }}>
![1](https://github.com/Knign/Write-ups/assets/110326359/6582164d-5517-4f7f-8949-4a33754bc2d1)
</figure>

Let's submit the feedback for one of these products.

<figure style={{ textAlign: 'center' }}>
![3](https://github.com/Knign/Write-ups/assets/110326359/8c10e41a-9068-47d7-b155-a7b9675b292a)
</figure>

We can now proxy the traffic through Burpsuite.

<figure style={{ textAlign: 'center' }}>
![4](https://github.com/Knign/Write-ups/assets/110326359/44952b37-331f-4116-b66b-b674dd8eb300)
</figure>

Let's forward this request to the `Repeater` so that we can modify it.

Once in the `Repeater` we can set the `email` parameter to the following and send the request:
```
x%40gmail.com||ping+-c+10+127.0.0.1||
```

<figure style={{ textAlign: 'center' }}>
![5](https://github.com/Knign/Write-ups/assets/110326359/f44fa8d0-d595-4774-a95c-311baa0292d0)
</figure>

The response takes 10 seconds to return.

We have solved the lab

<figure style={{ textAlign: 'center' }}>
![6](https://github.com/Knign/Write-ups/assets/110326359/f854e08f-1d98-4051-95e5-1639b11d3b2c)
</figure>
