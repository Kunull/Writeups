---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 4
---

![1](https://github.com/Knign/Write-ups/assets/110326359/6beaef35-f74e-4828-9ea0-2921bbda93a8)

Let's access the image through the browser.

![2](https://github.com/Knign/Write-ups/assets/110326359/f6231e23-ae3e-4b2d-b461-f77fbf7a0d4f)

We can now intercept this request in BurpSuite using the `Proxy`.

![3](https://github.com/Knign/Write-ups/assets/110326359/9db5f853-3dcb-4e85-a5b0-e759f6195041)

Now, we can forward the request to the `Repeater` to makes changes in it.

Let's change the `filename` parameter to the following and forward the request:

```
../../../etc/passwd
```

![4](https://github.com/Knign/Write-ups/assets/110326359/a6ad719f-122e-4539-abb6-5e0253b129c7)

The server tells us that the file does not exist. This is because the `../` characters are being stripped from our parameter.

| Original parameter | Stripped parameter |
| ------------------ | ------------------ |
| ../../../etc/passwd                   | etc/passwd                   |

We can bypass this by URI encoding the `../../../` character sequence.
This way when the server tries to match the pattern, it won't find it because it has been encoded.

![5](https://github.com/Knign/Write-ups/assets/110326359/bc164bf0-55c2-43a6-a2ef-c6c7ec28cec2)

Now we can set the `filename` parameter to the following:
```
%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66etc/passwd
```

![6](https://github.com/Knign/Write-ups/assets/110326359/c451c242-d729-43bf-ba7f-4fc3b3f50323)

We have successfully solved the lab.

![7](https://github.com/Knign/Write-ups/assets/110326359/a2e67a6d-2c07-4538-a58e-968166b7cb36)
