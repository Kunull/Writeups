---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 5
---


Let's login using the following credentials:


| Username | Password |
| -------- | -------- |
| wiener         | peter         |


![[2 140.png]]

Since we are proxying the traffic through Burp Suite, we can view this request by going to `Porxy > HTTP History`.

![[3 121.png]]

We can see that the request contains a parameter called `ìd` which is set to `wiener`.
Let's forward the request to the `Repeater` and set the `id` parameter to the following:
```
carlos
```

![[4 103.png]]

We can now submit this API key through the browser.

![[6 72.png]]

We have solved the lab.

![[7 53.png]]
