---
custom_edit_url: null
sidebar_position: 2
---

<figure style={{ textAlign: 'center' }}>
![1](https://github.com/Knign/Write-ups/assets/110326359/6752b464-8aac-4292-87b4-7b09cbd9c8d2)
</figure>

Let's check out the stock.

<figure style={{ textAlign: 'center' }}>
![2](https://github.com/Knign/Write-ups/assets/110326359/c96daa13-cd0a-4e89-a9e4-3bb8e1f76e5f)
</figure>

We can intercept the request using Burpsuite and send it to the `Intruder`.

<figure style={{ textAlign: 'center' }}>
![3](https://github.com/Knign/Write-ups/assets/110326359/2006971d-fc18-43b7-9247-91d65e62ad26)
</figure>

After setting the `stockAPI` field to the following, we can select the payloads.

```
http://192.168.0.X:8080/admin
```

For the payload, the type is `Numbers` from 1-255.

<figure style={{ textAlign: 'center' }}>
![4](https://github.com/Knign/Write-ups/assets/110326359/dd6f7017-5757-49a1-bffa-8b1c7a1bedef)
</figure>

Let's start the attack.

After some time we can see the only request that returned a `200` response code.

<figure style={{ textAlign: 'center' }}>
![5](https://github.com/Knign/Write-ups/assets/110326359/96cd041e-02d5-47c6-915b-97d5bf2f33be)
</figure>

Finally, we have to send the request to the `Repeater` and set the `stockAPI` field to the following:

```
http://192.168.0.159:8080/admin/delete?username=carlos
```

<figure style={{ textAlign: 'center' }}>
![6](https://github.com/Knign/Write-ups/assets/110326359/27899971-2ce1-48df-9043-205dc24b9e90)
</figure>

We have solved the lab

<figure style={{ textAlign: 'center' }}>
![7](https://github.com/Knign/Write-ups/assets/110326359/da96333f-005f-4a80-8092-0c12ce9cfe4b)
</figure>
