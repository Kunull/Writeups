---
custom_edit_url: null
sidebar_position: 4
---

![1](https://github.com/Knign/Write-ups/assets/110326359/2f0a8e5d-9e1b-4515-a221-75d64bacbf6c)

We have to login using the following credentials:

| Username | Password |
| -------- | -------- |
| wiener         | peter         |

At the top of the page, we an see the following code:

```
NEWCUST5
```

If we scroll to the bottom, there is a newsletter that we can sign up for.

![2](https://github.com/Knign/Write-ups/assets/110326359/2b13ab36-f492-4114-b223-990abb4c8357)

Once we signup for the newsletter, we get another code:

![3](https://github.com/Knign/Write-ups/assets/110326359/e88bc028-4925-4619-a96d-90a894e19880)

```
SIGNUP30
```

Now, all we have to do is add the "Lightweight l33t leather jacket" and apply the coupons in an alternating manner.

![5](https://github.com/Knign/Write-ups/assets/110326359/3cdeda41-84b3-4f94-baac-0e21b29b48d8)

This works because the server checks if the coupon is not applied right after itself but does not check if it is applied after another coupon.

![6](https://github.com/Knign/Write-ups/assets/110326359/50b768c4-8dd1-4b98-aedf-44cfcacab103)

We have solved the lab.

![7](https://github.com/Knign/Write-ups/assets/110326359/1bb9f49e-ac21-43cf-9e0c-1e4279d40007)
