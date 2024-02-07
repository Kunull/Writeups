---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 2
---

![1](https://github.com/Knign/Write-ups/assets/110326359/c9847993-cda2-4e2a-8dc6-c5124ca94db6)

Let's check out the stock.

![2](https://github.com/Knign/Write-ups/assets/110326359/cca3aa69-8b90-40bc-9b88-a663cc3850eb)

We can intercept the request using Burpsuite and send it to the `Intruder`.

![3](https://github.com/Knign/Write-ups/assets/110326359/4ef49911-269f-4ba1-945f-e8a84b93c2d5)

After setting the `stockAPI` field to the following, we can select the payloads.

```
http://192.168.0.X:8080/admin
```

For the payload, the type is `Numbers` from 1-255.

![4](https://github.com/Knign/Write-ups/assets/110326359/2f8f3e23-730c-4a1e-a589-6df4fb705e83)

Let's start the attack.

After some time we can see the only request that returned a `200` response code.

![5](https://github.com/Knign/Write-ups/assets/110326359/e65c7f56-3a68-4c2a-8a5a-e56ed15903bc)

Finally, we have to send the request to the `Repeater` and set the `stockAPI` field to the following:

```
http://192.168.0.159:8080/admin/delete?username=carlos
```

![6](https://github.com/Knign/Write-ups/assets/110326359/6219558d-c5a3-49d0-9fac-c99225fd6fd7)

We have solved the lab

![7](https://github.com/Knign/Write-ups/assets/110326359/7cec6823-24a0-4a20-9b24-e664e15f4abb)
