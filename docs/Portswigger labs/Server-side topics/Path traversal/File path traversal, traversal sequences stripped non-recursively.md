---
custom_edit_url: null
sidebar_position: 3
---

![1](https://github.com/Knign/Write-ups/assets/110326359/ad51b139-9c18-4b50-a210-18c963ec15f8)

Let's access the image through the browser.

![2](https://github.com/Knign/Write-ups/assets/110326359/630298b9-2416-4361-9a2f-7b010b43f309)

We can intercept this request in Burpsuite using the `Proxy`.

![3](https://github.com/Knign/Write-ups/assets/110326359/7e1ca6aa-5c85-4558-8503-6ad53cf4622a)

Now, we can sent this intercepted request to the `Repeater` to modify it.

Once in the `Repeater`, we can set the `filename` parameter to the following:

```
../../../etc/passwd
```

![4](https://github.com/Knign/Write-ups/assets/110326359/53a0198b-f87c-4f14-ba7b-8757ab89d064)

The server tells us that the file does not exist. This is because the `../` characters are being stripped from our parameter.

| Original Parameter | Stripped parameter |
| ---- | ---- |
| ../../../etc/passwd | etc/passwd |

The problem is, the server does not strip the parameters recursively

We can exploit it by setting the `filename` parameter to the following:
```
....//....//....//etc/passwd
```

Now, when the `../` characters are stripped it still leaves a set of `../` characters.

| Original parameter | Stripped parameter |
| ------------------ | ------------------ |
| ....//....//....//etc/passwd                   | ../../../etc/passwd                   |

![5](https://github.com/Knign/Write-ups/assets/110326359/90b7b892-98bc-430f-97b8-876760695462)

We have successfully solved the lab.

![6](https://github.com/Knign/Write-ups/assets/110326359/e4587b5b-0b1d-488d-8aec-c35c49e076fa)
