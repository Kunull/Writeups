---
custom_edit_url: null
sidebar_position: 4
---

![1](https://github.com/Knign/Write-ups/assets/110326359/a15f69c4-fe97-408d-85c7-836af5c912d7)

Let's filter for `Accessories`.

![2](https://github.com/Knign/Write-ups/assets/110326359/b0569b5c-de60-46b6-a9ca-df7fe40a3157)

Since we are proxying the traffic through Burp Suite, we can go to the `Proxy > HTTP History` tab to view this request.

![3](https://github.com/Knign/Write-ups/assets/110326359/17041208-f6cc-4a66-a79d-81a92e984eab)

Let's forward the request to the `Repeater` for further modification.

Once in the `Repeater`, let's set the `category` parameter to the following:

```
' UNION SELECT 'test','test'#
```

![4](https://github.com/Knign/Write-ups/assets/110326359/4c86f757-f741-45f3-9faa-f499ecfab559)

Now that we know there are two columns, we can set the `category` parameter to the following:

```
' UNION SELECT `@@version`, NULL#
```

![5](https://github.com/Knign/Write-ups/assets/110326359/6a90675f-20d0-490e-bdca-77cb837dbf35)

We have solved the lab.

![6](https://github.com/Knign/Write-ups/assets/110326359/22988b07-a3e4-4669-98b7-46da46c38ba4)
