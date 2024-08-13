---
custom_edit_url: null
sidebar_position: 8
---

![1](https://github.com/Knign/Write-ups/assets/110326359/d9a86644-3866-44f5-aa32-a75f91c4e2de)

Let's login using the following credentials:

| Username | Password |
| -------- | -------- |
| wiener         | peter         |

![2](https://github.com/Knign/Write-ups/assets/110326359/da501295-1ff2-4596-aa6e-55eff421a79b)

We can see that the password is included in the input field for resetting the password. However this password is hidden.

Let's view this in the `Proxy > HTTP History` tab.

![3](https://github.com/Knign/Write-ups/assets/110326359/eccfa5d3-dea8-44b1-b621-95928759a9de)

We can clearly see the value of the password. We can view the administrator's password in a similar manner.

Let's forward the request to the `Repeater` and set the `id` parameter to the following:
```
administrator
```

![4](https://github.com/Knign/Write-ups/assets/110326359/6f1be6fe-1ddf-4d4e-baf8-d8b4221c8e6a)

Now we can login as the administrator using the following credentials:

| Username      | Password             |
| ------------- | -------------------- |
| administrator | eg9yjeq3lztdlfb0bnay |

![5](https://github.com/Knign/Write-ups/assets/110326359/1d6c49a8-1a56-4472-8195-3db270586736)

We have access to the admin panel.

![6](https://github.com/Knign/Write-ups/assets/110326359/34d7b1db-2eaf-41a5-960d-c871d240d039)

Let's delete the `carlos` user.

![7](https://github.com/Knign/Write-ups/assets/110326359/11cf5665-fbe5-4f57-b493-595dd5329416)

We have solved the lab.

![8](https://github.com/Knign/Write-ups/assets/110326359/776bbf16-3cf9-41bf-8f92-d49a4d64b613)
