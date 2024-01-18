---
custom_edit_url: null
pagination_next: null
pagination_prev: null
---

> Here! http://web.ctflearn.com/web7/ I forget how we were doing those calculations, but something tells me it was pretty insecure.
- We can start by performing some basic calculation like `1+1`.

![1](https://github.com/Knign/Write-ups/assets/110326359/04de04e1-b74e-488e-8d74-7e0b060d5fe4)

- Let's check the Burpsuite `Proxy > HTTP History`.

![2](https://github.com/Knign/Write-ups/assets/110326359/23811ced-0c4b-4f91-91ee-9c8d349bac01)

- Now let's send this request to the `Repeater`.

![3](https://github.com/Knign/Write-ups/assets/110326359/93d6dec1-0bf7-427e-80a7-930e300ec28a)

- At the bottom of the request we can see the expression that we inputted.
- We can replace the expression with `;ls` and send the request.

![4](https://github.com/Knign/Write-ups/assets/110326359/b343bad8-1f5e-4a2c-88cc-04893f58d6e3)

## Flag
```
CTFlearn{watch_0ut_f0r_th3_m0ng00s3}
```
