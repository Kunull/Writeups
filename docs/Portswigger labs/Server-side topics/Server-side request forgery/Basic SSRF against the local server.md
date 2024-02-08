---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 1
---

![1](https://github.com/Knign/Write-ups/assets/110326359/74ca74bc-f88f-498a-9703-06248e393e36)

Let's click on `View details`.

![2](https://github.com/Knign/Write-ups/assets/110326359/f334ce2f-62d3-4b0b-b500-2edf5b77eb57)

If we click on `Check stock`, the application returns us the available units.

We can now intercept this request in Burpsuite.

![4](https://github.com/Knign/Write-ups/assets/110326359/9e689b9f-eab6-4fed-8950-a10a34d5b30b)

Let's send it to the `Repeater` so that we can modify and forward the request.

We can set the `stockApi` field to the following, so that the server return the content to us:

```
http://localhost/admin
```

![5](https://github.com/Knign/Write-ups/assets/110326359/14ee34d8-2b63-4c69-a274-5af0b3ce6cc2)

Let's send the request.

![6](https://github.com/Knign/Write-ups/assets/110326359/695ab6ab-c243-4112-b50f-774763c7c432)

The application returned the content of `/admin`.

We can now set the `setAPI` field to he following:

```
http://localhost/admin/delete?username=carlos
```

This will cause the application to delete the `carlos` user on our behalf.

![7](https://github.com/Knign/Write-ups/assets/110326359/0498252a-b94b-4e65-b9de-6d0399bb2015)

We have solved the lab.

![8](https://github.com/Knign/Write-ups/assets/110326359/79818a39-6100-4956-9d3e-e4c06fe02115)
