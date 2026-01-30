---
custom_edit_url: null
sidebar_position: 5
---

<figure style={{ textAlign: 'center' }}>
![1](https://github.com/Knign/Write-ups/assets/110326359/752dd029-73b8-4399-868b-f2e79e69b06f)
</figure>

Let's access the image through the browser.

<figure style={{ textAlign: 'center' }}>
![2](https://github.com/Knign/Write-ups/assets/110326359/1a63df00-8fb4-4d29-a6c5-f72ff150e665)
</figure>

We can now intercept this request in Burp Suite using the `Proxy`.

<figure style={{ textAlign: 'center' }}>
![3](https://github.com/Knign/Write-ups/assets/110326359/b8816468-445d-4baa-ad22-154e691e7439)
</figure>

Now, we can forward the request to the `Repeater` to makes changes in it.

Let's change the `filename` parameter to the following and forward the request:

```
/etc/passwd
```

<figure style={{ textAlign: 'center' }}>
![4](https://github.com/Knign/Write-ups/assets/110326359/97df9e17-2c21-47d8-9e8e-31eb5a78d28d)
</figure>

The server requires the user-supplied filename to start with `/var/www/images`.

```
/var/www/images/../../../etc/passwd
```

<figure style={{ textAlign: 'center' }}>
![5](https://github.com/Knign/Write-ups/assets/110326359/6337fc29-7bc6-4175-b528-debdd8894e52)
</figure>

We have successfully solved the lab.

<figure style={{ textAlign: 'center' }}>
![6](https://github.com/Knign/Write-ups/assets/110326359/904fbac2-6793-438a-a605-ddb54ae76c53)
</figure>
