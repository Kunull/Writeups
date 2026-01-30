---
custom_edit_url: null
sidebar_position: 7
---

<figure style={{ textAlign: 'center' }}>
![1](https://github.com/Knign/Write-ups/assets/110326359/82d4b6bd-9f05-4940-b826-8823147599ff)
</figure>

Let's insert the following payload in the search field:

```
test_payload
```

We can now open `Left CLick > Inspect` to open the developer tools and search our payload.

<figure style={{ textAlign: 'center' }}>
![2](https://github.com/Knign/Write-ups/assets/110326359/a3a0a02c-7c06-43b9-8ff9-d7f1a4fd829e)
</figure>

We can see that our `test_payload` has been inserted into the `value` attribute of the `<input>` tag.

In order to generate an alert, we need to first escape the `value` attribute and than add an `onmouseover` event attribute.

```html
test_payload" onmouseover="alert(1)
```

The alert will be displayed only when we hover over the input field with our mouse.

<figure style={{ textAlign: 'center' }}>
![3](https://github.com/Knign/Write-ups/assets/110326359/2ead0fce-bfb9-45ab-8461-3f6fbb7600cd)
</figure>

We have solved the lab.

<figure style={{ textAlign: 'center' }}>
![4](https://github.com/Knign/Write-ups/assets/110326359/2e733b01-1aab-4a51-abb2-90bfe56d728a)
</figure>
