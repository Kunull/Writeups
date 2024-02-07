---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 12
---

![1](https://github.com/Knign/Write-ups/assets/110326359/63a557cc-8b92-400a-8fb0-a3ffdf58f38d)

Let's login as the admin using the following credentials:

| Username | Password |
| -------- | -------- |
| administrator         | admin         |

![2](https://github.com/Knign/Write-ups/assets/110326359/ac5ba8bd-527b-4146-8a28-04c597ab6373)

Let's now promote the `carlos` user to admin.

![3](https://github.com/Knign/Write-ups/assets/110326359/400129c5-787c-4171-8aee-261900c89368)

Since we are proxying the traffic through Burp Suite, we can view this request in the `Proxy > HTTP History` tab.

![4](https://github.com/Knign/Write-ups/assets/110326359/3e5dcad0-0140-4929-a3c8-40eac62d86c7)

Let's forward this request to the `Repeater` for further modification.

Next, let's login using the following credentials:

| Username | Password |
| -------- | -------- |
| wiener         | peter         |

![5](https://github.com/Knign/Write-ups/assets/110326359/9d158eb8-855a-4cf5-9343-a13bc5c33169)

Let's view the session cookie in the `Proxy > HTTP History` tab.

![6](https://github.com/Knign/Write-ups/assets/110326359/fdde1663-7040-4856-81bf-74552e6d065f)

We now have to replace the session cookie in the `Repeater` tab with the `wiener` user's session cookie.

We also have to the set the `username` parameter to the following:

```
wiener
```

![7](https://github.com/Knign/Write-ups/assets/110326359/993b2ecd-dc1a-45be-abee-c4d9be5ab11b)

Let's go check in the browser.

![8](https://github.com/Knign/Write-ups/assets/110326359/af196686-84f4-44ae-a85d-03d75467c6d9)

We have solved the lab.

![9](https://github.com/Knign/Write-ups/assets/110326359/45766aa7-cbb2-4442-8c55-b669ee0be93e)
