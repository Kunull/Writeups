---
custom_edit_url: null
sidebar_position: 9
---

<figure style={{ textAlign: 'center' }}>
![1](https://github.com/Kunull/Write-ups/assets/110326359/89576bc1-11c5-4959-adcc-c786983dfc02)
</figure>

The website prompts us to enter a password.

Let's check the source code.

<figure style={{ textAlign: 'center' }}>
![2](https://github.com/Kunull/Write-ups/assets/110326359/847fe11c-54f5-43eb-9ab3-c76ce36a36a8)
</figure>

The password is string is obfuscated to hexadecimal.

We can use the `String.fromCharCode()` function in `Developer tools > Console` to convert the hexadecimal character into string.

<figure style={{ textAlign: 'center' }}>
![3](https://github.com/Kunull/Write-ups/assets/110326359/25e01b1d-3694-4695-b7ed-98549e033494)
</figure>

## Password

```
786OsErtk12
```
