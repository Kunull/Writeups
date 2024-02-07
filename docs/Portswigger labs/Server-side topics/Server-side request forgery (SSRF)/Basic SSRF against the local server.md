---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 1
---

![1](https://github.com/Knign/Write-ups/assets/110326359/95a09378-4583-420e-8f5a-5332c4106e8d)

Let's click on `View details`.

![2](https://github.com/Knign/Write-ups/assets/110326359/97ceb956-69cb-4e67-9af9-26811190d9bb)

If we click on `Check stock`, the application returns us the available units.

We can now intercept this request in Burpsuite.

![4](https://github.com/Knign/Write-ups/assets/110326359/bf414abf-0cfc-4ad4-bc78-14ca18776b44)

Let's send it to the `Repeater` so that we can modify and forward the request.

We can set the `stockApi` field to the following, so that the server return the content to us:

```
http://localhost/admin
```

![5](https://github.com/Knign/Write-ups/assets/110326359/bdb755f6-35d1-4550-be25-8af42216438d)

Let's send the request.

![6](https://github.com/Knign/Write-ups/assets/110326359/37d5c6c3-d65c-4aaf-b606-6fe3b6f3089c)

The application returned the content of `/admin`.

We can now set the `setAPI` field to he following:

```
http://localhost/admin/delete?username=carlos
```

This will cause the application to delete the `carlos` user on our behalf.

![7](https://github.com/Knign/Write-ups/assets/110326359/dd7be37f-a0c9-4c4a-9292-d73c83cfa403)

We have solved the lab.

![8](https://github.com/Knign/Write-ups/assets/110326359/7a9a3bbc-aafc-43c5-8158-4cf182e9d1cd)
