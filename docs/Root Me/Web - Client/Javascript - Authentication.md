---
custom_edit_url: null
sidebar_position: 2
---

![1](https://github.com/Knign/Write-ups/assets/110326359/7e4b2f66-5145-44ab-b922-b35974f6e749)

The form asks us to input the username and password.

Let's check the source code by going to `More tools > Developer tools > Elements`.

![2](https://github.com/Knign/Write-ups/assets/110326359/6e7bfa3d-65ba-483d-bded-862ef19ab292)

We can see that the `<input>` elements have the names `pseudo` and `password`.

If we go to the `Sources` tab we can see the files and resources that are being accessed.

![3](https://github.com/Knign/Write-ups/assets/110326359/58ea15f1-dd41-4332-beff-13133f3e503f)

Let's check the `login.js` file.

![4](https://github.com/Knign/Write-ups/assets/110326359/4d91d94e-c728-450f-8d6c-234d21e93684)

So the script has a conditional statement that allows login if the username is `4dm1n` and the password is `sh.org`.

![5](https://github.com/Knign/Write-ups/assets/110326359/3ec747e4-dd12-45cd-8381-fd825bfd1966)

## Password
```
sh.org
```
