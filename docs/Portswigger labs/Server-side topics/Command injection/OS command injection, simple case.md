---
custom_edit_url: null
sidebar_position: 1
---

<figure style={{ textAlign: 'center' }}>
![1](https://github.com/Knign/Write-ups/assets/110326359/805ad217-9677-4017-885c-15bae0d9e89f)
</figure>

Let's check the first product's stock.

<figure style={{ textAlign: 'center' }}>
![2](https://github.com/Knign/Write-ups/assets/110326359/056a57c4-c753-4aa9-a681-d70653d3acfe)
</figure>

We can intercept this request using the Burp Suite `Proxy` and forward it to the `Repeater` to modify it.

<figure style={{ textAlign: 'center' }}>
![3](https://github.com/Knign/Write-ups/assets/110326359/6a71c09e-682f-4b49-8785-07c60ea1ea85)
</figure>

Now let's set the `storeID` parameter to the following and send the request:

```
1|whoami
```

<figure style={{ textAlign: 'center' }}>
![4](https://github.com/Knign/Write-ups/assets/110326359/929c8a86-85b3-4624-88a2-0f00457fbdb6)
</figure>

We have solved the lab.

<figure style={{ textAlign: 'center' }}>
![5](https://github.com/Knign/Write-ups/assets/110326359/12a547c8-7eb2-48cf-b80f-6649740e9df4)
</figure>
