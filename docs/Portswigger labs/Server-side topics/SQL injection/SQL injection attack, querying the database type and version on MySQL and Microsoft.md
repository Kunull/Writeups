---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 4
---

![1](https://github.com/Knign/Write-ups/assets/110326359/f602dcc7-1cac-4b24-a854-086fc0622c1f)

Let's filter for `Accessories`.

![2](https://github.com/Knign/Write-ups/assets/110326359/2d8e28eb-f98a-44f5-8e54-1a8919ce96c1)

Since we are proxying the traffic through Burp Suite, we can go to the `Proxy > HTTP History` tab to view this request.

![3](https://github.com/Knign/Write-ups/assets/110326359/c6fd5345-81c6-4e5c-b8f5-dd530373637a)

Let's forward the request to the `Repeater` for further modification.
Once in the `Repeater`, let's set the `category` parameter to the following:

```
' UNION SELECT 'test','test'#
```

![4](https://github.com/Knign/Write-ups/assets/110326359/12a51a54-c1c3-4e3b-93ed-397e0b196951)

Now that we know there are two columns, we can set the `category` parameter to the following:

```
' UNION SELECT `@@version`, NULL#
```

![5](https://github.com/Knign/Write-ups/assets/110326359/e1a8d76a-cf77-4839-8d0e-9766fea15854)

We have solved the lab.

![6](https://github.com/Knign/Write-ups/assets/110326359/aaca7ecd-2bde-4b36-b494-5effef27a9fd)
