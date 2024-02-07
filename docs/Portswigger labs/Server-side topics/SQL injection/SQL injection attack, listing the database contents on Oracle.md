---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 7
---

![1](https://github.com/Knign/Write-ups/assets/110326359/c62c1005-0fff-45f0-bab4-39346cd7a589)

Let's filter for `Accessories`.

![2](https://github.com/Knign/Write-ups/assets/110326359/1b8e60ca-1d08-4d69-9206-4165c6a46216)

Since we are proxying the traffic through Burp Suite, we can go to the `Proxy > HTTP History` tab to view this request.

![3](https://github.com/Knign/Write-ups/assets/110326359/a4127f3f-bfa2-48b3-aee8-5b96cfdf82e9)

Let's forward this request to the `Repeater` for further modification.

Once in the `Repeater`, let's set the `category` parameter to the following:

```
UNION SELECT NULL--
```

![4](https://github.com/Knign/Write-ups/assets/110326359/d7a8eaae-31b6-4435-8571-244f93e46f55)

Since the application returns an error, we know that the number of columns in the current query is more than 1.

Let's try for two columns:

```
UNION SELECT NULL,NULL--
```
![5](https://github.com/Knign/Write-ups/assets/110326359/2acbca6b-25e3-4d45-86e1-4cc99344d510)


The application again returns an error.

Let's try for three columns:

```
UNION SELECT NULL,NULL,NULL--
```

![6](https://github.com/Knign/Write-ups/assets/110326359/408e6005-3849-4d62-84f2-17461566dcff)

The application no longer throws an error which means that there are 3 columns in the current query.

We have solved the lab.

![7](https://github.com/Knign/Write-ups/assets/110326359/19d96ef4-04ab-450d-b2d0-fb39d7b1f8a3)
