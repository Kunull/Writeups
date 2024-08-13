---
title: HTML Injection - Reflected (URL)
custom_edit_url: null
---

## low

![1](https://github.com/Knign/Write-ups/assets/110326359/c3530907-5c72-418d-802d-f8e2a9621f54)

The application prints our current URL on the page.

Let's turn on the intercept in Burpsuite and reload the page.

![2](https://github.com/Knign/Write-ups/assets/110326359/1c152d44-c43a-4d1b-88ab-cfb97ee656cf)

We can change the `Host:` field to any value we want.

```
Host: getHacked
```

Let's turn off the intercept so that the request reaches to the server.

![3](https://github.com/Knign/Write-ups/assets/110326359/1c07dac4-c3ca-48f2-8cab-c3fb78c7b73a)

We have successfully performed HTML injection.
