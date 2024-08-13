---
custom_edit_url: null
sidebar_position: 3
---

![1](https://github.com/Knign/Write-ups/assets/110326359/939ed246-1da4-4e3d-a736-5cac0294ae6f)

We can login using the following credentials:

| Username | Password |
| -------- | -------- |
| wiener         | peter         |

![2](https://github.com/Knign/Write-ups/assets/110326359/6b81b1ae-e7cc-410c-978c-ec313dc7f9de)

Since we are proxying the traffic through Burp Suite, we can see this request in the `Proxy > HTTP History` tab.

![3](https://github.com/Knign/Write-ups/assets/110326359/f27ed8d5-414b-4d13-8c8a-cfcc6aadfb43)

As we can see, the response sets an `Admin` cookie to `false`.
In the next request, we can see that the cookie is used in the header.

![4](https://github.com/Knign/Write-ups/assets/110326359/94bd4bc1-a6ba-4129-aa70-4d0ded525b6a)

Let's go into the browser `Developer Tools > Storage` and set the `Admin` cookie to `true`.

![8](https://github.com/Knign/Write-ups/assets/110326359/a2ee8a3e-294b-4686-bb13-5e213c4cd2fe)

We can now refresh the page.

![6](https://github.com/Knign/Write-ups/assets/110326359/38a98643-0895-4ba8-adad-ee3330e184ab)

We now have access to the admin panel.

![7](https://github.com/Knign/Write-ups/assets/110326359/214c05a0-9a0c-4ded-a019-0b6f3fd0d88a)

Let's delete the `carlos` user.

![9](https://github.com/Knign/Write-ups/assets/110326359/0812617e-3ae9-4e86-90eb-745ac08e2196)

We have solved the lab.

![10](https://github.com/Knign/Write-ups/assets/110326359/e294be8d-2529-4125-a598-334303cb837d)
