---
custom_edit_url: null
sidebar_position: 2
---

<figure style={{ textAlign: 'center' }}>
![1](https://github.com/Knign/Write-ups/assets/110326359/ab697bbf-6958-4496-a82c-cdb268ebfe6a)
</figure>

If we go to `Target > Site map`,we can see a request for `/cgi-bin/phpinfo.php`. Let's forward that request to the `Repeater` and send it.

When the response is returned to us, we can search for the following string:

```
SECRET_KEY
```

<figure style={{ textAlign: 'center' }}>
![3](https://github.com/Knign/Write-ups/assets/110326359/d09588d7-0c97-46ab-bb50-66256e53abb6)
</figure>

As we can see, the secret is revealed by the server in the response.

We can now submit the secret key as the answer:

```
08py31h0x95q3hfiieipk0q5i3xch7d9
```

<figure style={{ textAlign: 'center' }}>
![4](https://github.com/Knign/Write-ups/assets/110326359/837ccb27-7765-419b-af61-d96c6b5ffc62)
</figure>

We have solved the lab.

<figure style={{ textAlign: 'center' }}>
![5](https://github.com/Knign/Write-ups/assets/110326359/476eee6a-847f-4482-a8b1-8082f8331461)
</figure>
