---
custom_edit_url: null
sidebar_position: 10
---

<figure style={{ textAlign: 'center' }}>
![1](https://github.com/Knign/Write-ups/assets/110326359/e0540b7e-9462-456a-99e8-5622d79641a5)
</figure>

Let's try to access the admin panel.

<figure style={{ textAlign: 'center' }}>
![2](https://github.com/Knign/Write-ups/assets/110326359/2d2f38f5-58d4-4f7c-ba5b-6e151a881eb2)
</figure>

Since we are proxying the traffic through Burp Suite, we can go to `Proxy > HTTP History` to view the request.

<figure style={{ textAlign: 'center' }}>
![3](https://github.com/Knign/Write-ups/assets/110326359/5628a920-3f70-4ade-82e0-1bb54d6fad08)
</figure>

Let's forward the request to the `Repeater` for further modification.

Once inside the `Repeater`, set the request URI to:

```
/
```

and add the following request header:

```
X-Original-URL: /admin
```

This header overrides the URI present in the original request.

<figure style={{ textAlign: 'center' }}>
![4](https://github.com/Knign/Write-ups/assets/110326359/35975875-177d-4c44-8756-2147ca4f7e7c)
</figure>

In order to delete the `carlos` user, we have to set the original URL to:

```
/?username=carlos
```

And then we have to modify the header to the following:

```
X-Original-Url: /admin/delete
```

<figure style={{ textAlign: 'center' }}>
![5](https://github.com/Knign/Write-ups/assets/110326359/75927c67-e4db-43d5-a580-c1ccf60ff5a4)
</figure>

Let's go and check the panel through the browser.

<figure style={{ textAlign: 'center' }}>
![6](https://github.com/Knign/Write-ups/assets/110326359/2286c2e5-03e8-4f32-be81-fd8b30ed4f93)
</figure>

We have solved the lab.

<figure style={{ textAlign: 'center' }}>
![7](https://github.com/Knign/Write-ups/assets/110326359/503994f5-ee74-49e2-a878-6c7d34fd62c2)
</figure>
