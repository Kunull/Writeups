---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 3
---

![1](https://github.com/Knign/Write-ups/assets/110326359/2ff99054-16c1-4b06-8192-73c584374a00)

We can go to the `Target > Site Map` tab in Burp Suite in order to see the domain.

![2](https://github.com/Knign/Write-ups/assets/110326359/ab398cbe-a4f9-452e-ac99-926382ddcd99)

Let's left click on the domain present and then `Engagement tools > Discover content`.

![3](https://github.com/Knign/Write-ups/assets/110326359/392c4ff8-692c-4302-a8fe-443f620a3f22)

That would tell us that there is a directory called `/admin`. Alternatively, we can also directory fuzzing tools.

Let's visit the `/admin` page through the browser.

![4](https://github.com/Knign/Write-ups/assets/110326359/a2382754-07e6-4fb3-aa15-1d92e8e9f43e)

As we can see, the admin page is only accessible to "DontWannaCry" users.

Let's `Register` our user using our assigned email address.

![5](https://github.com/Knign/Write-ups/assets/110326359/2d57782c-5260-45cc-9310-a8f1a5f92105)

Next, we can go to the `Email client` and click our registration email.

![6](https://github.com/Knign/Write-ups/assets/110326359/59b78a17-ab63-403a-9cb8-eaa2eeac7a3e)

Then, we can login to our created account through the `My account` tab.

![7](https://github.com/Knign/Write-ups/assets/110326359/3de6f1e8-627c-4048-a31d-46b622f74a9b)

Once inside, we get the option to change our email.

Let's set it the following:

```
attacker@dontwannacry.com
```

![8](https://github.com/Knign/Write-ups/assets/110326359/f3c989eb-bb0c-43a1-b81b-9f9b9ee64fd0)

Once we update our email, the admin panel becomes accessible to us.

![9](https://github.com/Knign/Write-ups/assets/110326359/02df5cd2-db15-4ccb-bc39-a44a4123a569)

Let's go inside the admin panel.

![10](https://github.com/Knign/Write-ups/assets/110326359/0b3ce9d1-cf9e-4b24-87cc-329de48a0605)

We have to delete the `carlos` user.

![11](https://github.com/Knign/Write-ups/assets/110326359/0c4739c4-e6c8-49af-b24a-faa0de674b03)

We have solved the lab.

![12](https://github.com/Knign/Write-ups/assets/110326359/0f95c73a-e643-4462-b783-569c1179df25)
