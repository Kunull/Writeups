---
title: XSS (Stored)
custom_edit_url: null
pagination_next: null
pagination_prev: null
---

> ### Objective
> Redirect everyone to a web page of your choosing.

## Security Level: Low
> Low level will not check the requested input, before including it to be used in the output text.
> Spoiler: Either name or message field: <script>alert("XSS");</script>.

![1](https://github.com/Knign/Write-ups/assets/110326359/94c4d860-7718-4ef2-837a-d03508c1bc02)

We can provide any random string as the input.

![2](https://github.com/Knign/Write-ups/assets/110326359/3aa2426c-9bc5-48e5-9e85-98f8924408f3)

As we can see, our input has been stored on the server.

Let's provide the following input in order to obtain the cookie.

```
<script>alert()</script>
```

![3](https://github.com/Knign/Write-ups/assets/110326359/0d4ba394-6fef-4ccb-9f35-c5e8808be7c1)

Anytime a user visits this page and their browser enders our message, they will get this alert.
