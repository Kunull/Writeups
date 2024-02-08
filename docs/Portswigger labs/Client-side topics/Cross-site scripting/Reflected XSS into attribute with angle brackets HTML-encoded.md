---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 7
---

![1](https://github.com/Knign/Write-ups/assets/110326359/82d4b6bd-9f05-4940-b826-8823147599ff)

Let's insert the following payload in the search field:

```
test_payload
```

We can now open `Left CLick > Inspect` to open the developer tools and search our payload.

![2](https://github.com/Knign/Write-ups/assets/110326359/a3a0a02c-7c06-43b9-8ff9-d7f1a4fd829e)

We can see that our `test_payload` has been inserted into the `value` attribute of the `<input>` tag.

In order to generate an alert, we need to first escape the `value` attribute and than add an `onmouseover` event attribute.

```
test_payload" onmouseover="alert(1)
```

The alert will be displayed only when we hover over the input field with our mouse.

![3](https://github.com/Knign/Write-ups/assets/110326359/2ead0fce-bfb9-45ab-8461-3f6fbb7600cd)

We have solved the lab.

![4](https://github.com/Knign/Write-ups/assets/110326359/2e733b01-1aab-4a51-abb2-90bfe56d728a)
