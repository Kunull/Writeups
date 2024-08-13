---
custom_edit_url: null
sidebar_position: 6
---

![1](https://github.com/Knign/Write-ups/assets/110326359/91bf71e2-b7d8-493d-9032-cdbcd20f6b73)

Let's access the image through the browser.

![2](https://github.com/Knign/Write-ups/assets/110326359/17fee3bd-3f39-40cc-970b-a119e82e9af9)

We can now intercept this request in Burp Suite using the `Proxy`.

![3](https://github.com/Knign/Write-ups/assets/110326359/7f7db76c-a4a5-4692-b933-bdcfec73fb37)

Now, we can forward the request to the `Repeater` to makes changes in it.

Let's change the `filename` parameter to the following and forward the request:

```
../../../etc/passwd
```

![4](https://github.com/Knign/Write-ups/assets/110326359/2d01fd8f-518b-409b-9eac-2c253c59c68d)

The server expects a `.png` file extension.

We can use `%00` characters before the extension so that our string gets terminated before the extension

```
../../../etc/passwd%00.png
```

![5](https://github.com/Knign/Write-ups/assets/110326359/237ac5fa-4deb-44ee-beac-8800e32e3d9a)

We have successfully solved the lab.

![6](https://github.com/Knign/Write-ups/assets/110326359/daa305b0-d143-4fd9-907b-75206eef591d)
