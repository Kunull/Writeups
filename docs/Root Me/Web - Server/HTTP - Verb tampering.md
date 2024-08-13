---
custom_edit_url: null
sidebar_position: 13
---

> Bypass the security establishment.

![1](https://github.com/Knign/Write-ups/assets/110326359/d6920634-5762-430b-9aae-3bb324d9235d)

On visiting the site, we are prompted to enter the user and password.

Let's intercept this request in Burpsuite.

![2](https://github.com/Knign/Write-ups/assets/110326359/bfcf7b08-f953-4866-a686-9bba1c42ff8d)

We can now forward the request to the `Intruder`.

![3](https://github.com/Knign/Write-ups/assets/110326359/f5694b20-9b09-4c19-8764-49fa4bed6b3e)

After we have selected the request method, we can set the payload.

For the payload, we are using all the request methods.

![4](https://github.com/Knign/Write-ups/assets/110326359/93652d81-67b1-4fbc-8244-e16dfb00d205)

Let's send this payload and check the response.

![5](https://github.com/Knign/Write-ups/assets/110326359/3be645e2-76d6-46b1-8b73-0ca47ce2f5f0)

## Flag
```
a23e$dme96d3saez$$prap
```

