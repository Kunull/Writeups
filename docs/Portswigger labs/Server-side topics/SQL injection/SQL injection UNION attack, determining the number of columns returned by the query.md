---
custom_edit_url: null
sidebar_position: 7
---

![1](https://github.com/Knign/Write-ups/assets/110326359/d592006a-83e0-411f-906e-6a762e212e9a)

Let's filter for `Accessories`.

![2](https://github.com/Knign/Write-ups/assets/110326359/13598bd5-d6fc-49b0-9422-919473744f98)

Since we are proxying the traffic through Burp Suite, we can go to the `Proxy > HTTP History` tab to view this request.

![3](https://github.com/Knign/Write-ups/assets/110326359/f779f557-23c5-4607-b60c-2029c5145938)

Let's forward this request to the `Repeater` for further modification.

Once in the `Repeater`, let's set the `category` parameter to the following:

```
UNION SELECT NULL--
```

![4](https://github.com/Knign/Write-ups/assets/110326359/de4d8128-7e00-4883-9b9e-f3fac3b37fa2)

Since the application returns an error, we know that the number of columns in the current query is more than 1.

Let's try for two columns:

```
UNION SELECT NULL,NULL--
```

![5](https://github.com/Knign/Write-ups/assets/110326359/9d3bab31-30e3-49f0-8e13-4f5c86d9d822)

The application again returns an error.

Let's try for three columns:

```
UNION SELECT NULL,NULL,NULL--
```

![6](https://github.com/Knign/Write-ups/assets/110326359/5a2a34fa-8adb-4b06-8f75-e03d32e7fbbd)

The application no longer throws an error which means that there are 3 columns in the current query.

We have solved the lab.

![7](https://github.com/Knign/Write-ups/assets/110326359/b07a8689-ee83-40a6-af4d-a4e7affa8e47)
