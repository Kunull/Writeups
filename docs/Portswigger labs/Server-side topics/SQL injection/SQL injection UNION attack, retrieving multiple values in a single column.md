---
custom_edit_url: null
sidebar_position: 10
---

<figure style={{ textAlign: 'center' }}>
![1](https://github.com/Knign/Write-ups/assets/110326359/32298c1f-08fc-45aa-9772-36e4d2635e30)
</figure>

Let's filter for `Accessories`.

<figure style={{ textAlign: 'center' }}>
![2](https://github.com/Knign/Write-ups/assets/110326359/6f54e509-b9f2-434d-9764-35f2e9f6586f)
</figure>

Since we are proxying the traffic through Burp Suite, we can go to the `Proxy > HTTP History` tab to view this request.

<figure style={{ textAlign: 'center' }}>
![3](https://github.com/Knign/Write-ups/assets/110326359/6ec58a00-8557-4fc7-80e0-10bbbb9fb2b8)
</figure>

Let's forward this request to the `Repeater` for further modification.

Once in the `Repeater`, let's set the `category` parameter to the following:

```
' UNION SELECT NULL--
```

<figure style={{ textAlign: 'center' }}>
![4](https://github.com/Knign/Write-ups/assets/110326359/23dd6f87-8045-4d2e-9a55-b7ce062a926f)
</figure>

Since the application returns an error, we know that the number of columns in the current query is more than 1.

Let's set the `category` parameter to the following:

```
' UNION SELECT NULL,NULL--
```

<figure style={{ textAlign: 'center' }}>
![5](https://github.com/Knign/Write-ups/assets/110326359/a1355107-c973-4f65-bd6e-adc302c3ea4b)
</figure>

Now that we know the current query has two columns, we can retrieve the usernames and password from the `username` and `password` columns respectively.

```
' UNION SELECT NULL,username||':'||password FROM users--
```

The `||` characters are used to concatenate strings together. So we are essentially dumping the username and password in the same column in the following format:

```
username:password
```

<figure style={{ textAlign: 'center' }}>
![6](https://github.com/Knign/Write-ups/assets/110326359/3bd733d5-44e8-4003-8470-880c6b3149ea)
</figure>

We can now login as the admin using the following credentials:

| Username | Password |
| -------- | -------- |
| administrator         | fq4yq6966ve3gff4iz65         |

<figure style={{ textAlign: 'center' }}>
![7](https://github.com/Knign/Write-ups/assets/110326359/ba4067df-4a1d-4ad5-b00d-7375511f4cc4)
</figure>

We have solved the lab.

<figure style={{ textAlign: 'center' }}>
![8](https://github.com/Knign/Write-ups/assets/110326359/3a7114a4-c067-4abb-b98b-02dcd30811fc)
</figure>
