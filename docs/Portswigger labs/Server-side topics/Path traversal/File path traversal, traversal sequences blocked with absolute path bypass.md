---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 2
---

![1](https://github.com/Knign/Write-ups/assets/110326359/4a2e90f0-7a53-4dbd-bcca-72086a111b8c)

Let's check out the image URI.

![2](https://github.com/Knign/Write-ups/assets/110326359/2fd12fab-b643-47bc-b946-c442fffc8fb3)

We can intercept the request for this image in BurpSuite using the `Proxy`.

![3](https://github.com/Knign/Write-ups/assets/110326359/d34278ef-0766-4681-94a0-a02863a1e9f6)

Let's forward the request to the `Repeater` so the we can modify it.

Once in the `Repeater`, set the `filename` parameter to the following and forward the request: 

```
../../../etc/passwd
```

![4](https://github.com/Knign/Write-ups/assets/110326359/3e3fec65-452d-49ae-a452-d730d70970e7)

The server tells us that there is no such file. This is because the path in out URI is relative and is being stripped.

We can bypass this by using an absolute path as follows:

```
/etc/passwd
```

![5](https://github.com/Knign/Write-ups/assets/110326359/ae2f5644-34dc-4b4f-bb4d-75b2003fffb4)

We have successfully solved the lab.

![6](https://github.com/Knign/Write-ups/assets/110326359/35f6aa2f-1867-4ccc-adff-9e40b2ed6508)
