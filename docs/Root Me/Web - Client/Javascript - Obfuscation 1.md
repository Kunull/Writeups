---
custom_edit_url: null
sidebar_position: 5
---

<figure style={{ textAlign: 'center' }}>
![1](https://github.com/Knign/Write-ups/assets/110326359/ef0cfad0-a588-4a80-8621-720a28f0f080)
</figure>

Let's check the source code with `CTRL + U`.

<figure style={{ textAlign: 'center' }}>
![2](https://github.com/Knign/Write-ups/assets/110326359/e3017369-d094-4892-af25-32203395287a)
</figure>

The password is Hex-encoded.

We can decode it using the `decodeURI` function.

<figure style={{ textAlign: 'center' }}>
![3](https://github.com/Knign/Write-ups/assets/110326359/36692902-8fe0-46d4-8de0-2ecc97fab3b8)
</figure>

```
> decodeURI("%63%70%61%73%62%69%65%6e%64%75%72%70%61%73%73%77%6f%72%64")
<- 'cpasbiendurpassword'
```
Let's try the decoded password.

<figure style={{ textAlign: 'center' }}>
![4](https://github.com/Knign/Write-ups/assets/110326359/6d28db62-2b6a-4d34-a2be-4b084935a9e6)
</figure>

## Password
```
cpasbiendurpassword
```
