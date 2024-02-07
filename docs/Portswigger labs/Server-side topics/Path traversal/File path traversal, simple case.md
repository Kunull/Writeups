---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 1
---

![1](https://github.com/Knign/Write-ups/assets/110326359/30d8fa06-a95e-4961-b4e4-a62d4ca40f25)

Let's access the image.

![2](https://github.com/Knign/Write-ups/assets/110326359/e0f4381b-6832-4c1b-9ad8-dae5b3abcd96)

We can now intercept this request in BurpSuite using the `Proxy`.

![3](https://github.com/Knign/Write-ups/assets/110326359/717182a0-be53-4955-a324-9334945813e3)

Now, we can forward the request to the `Repeater` to makes changes in it.

Let's change the `filename` parameter to the following and forward the request:

```
../../../etc/passwd
```

![4](https://github.com/Knign/Write-ups/assets/110326359/0b7d4c2b-471c-401a-b6d4-f1aa85b59dd5)

We have solved the lab.

![5](https://github.com/Knign/Write-ups/assets/110326359/165ae011-cbe2-468e-814b-39dcc6831cdb)
