---
custom_edit_url: null
sidebar_position: 8
---

![1](https://github.com/Knign/Write-ups/assets/110326359/80696683-3bfa-46e5-a932-2d45c93b039a)

Let's filter for `Accessories`.

![2](https://github.com/Knign/Write-ups/assets/110326359/c603b253-f818-42d7-89fa-93325b34d80d)

Since we are proxying the traffic through Burp Suite, we can go to the `Proxy > HTTP History` tab to view this request.

![3](https://github.com/Knign/Write-ups/assets/110326359/8b7c32bb-1ea4-4a42-a6d3-ddc6c4d094fe)

Let's forward this request to the `Repeater` for further modification.

Once in the `Repeater`, let's set the `category` parameter to the following:

```
UNION SELECT NULL--
```

![4](https://github.com/Knign/Write-ups/assets/110326359/83237477-d147-4c6b-98c1-36a3f85f4790)

Since the application returns an error, we know that the number of columns in the current query is more than 1.

Let's try for two columns:

```
UNION SELECT NULL,NULL--
```

![5](https://github.com/Knign/Write-ups/assets/110326359/8bc5e66f-7f05-479b-85d9-ff22c082eb82)

The application again returns an error.

Let's try for three columns:

```
UNION SELECT NULL,NULL,NULL--
```

![6](https://github.com/Knign/Write-ups/assets/110326359/d235e8fc-7181-44e6-b6d5-9984b3f12c4d)

The application no longer throws an error which means that there are 3 columns in the current query.

Now let's change one column to a string instead of `NULL` and observe the behaviour.

```
UNION SELECT 'test',NULL,NULL--
```

![7](https://github.com/Knign/Write-ups/assets/110326359/dc1f9f67-3109-44d7-b92e-b634252adda5)

That tells us that the first column is not compatible with string data.

Let's move on to the next column.

```
UNION SELECT NULL,'test',NULL--
```

![8](https://github.com/Knign/Write-ups/assets/110326359/8208db0f-1c96-4b4c-87ea-e96c7ae46abc)

We can see that the second column is compatible with string data.

Now all we have to do is replace `test` with the string that we have to make the database retrieve.

![9](https://github.com/Knign/Write-ups/assets/110326359/3dcbc060-5b92-4720-aded-86be08646b48)

We have solved the lab.

![10](https://github.com/Knign/Write-ups/assets/110326359/3d862de6-a1b0-4a63-895d-9196052b0b44)
