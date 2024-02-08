---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 8
---

![1](https://github.com/Knign/Write-ups/assets/110326359/bc1fb9f4-2309-446a-b9f1-1bcffc21e459)

Let's go and comment the following under the post.

![2](https://github.com/Knign/Write-ups/assets/110326359/1bc0db51-abdc-46ab-beeb-bf0ad82c3598)

We can now open `Left CLick > Inspect` to open the developer tools and search our `website.com` payload.

![3](https://github.com/Knign/Write-ups/assets/110326359/eef7345a-4a56-49cd-bd0c-b60da8e228c5)

As we can see, it is being inserted in the `href` attribute of the `<a>` tag.

In order to solve the lab, we have to use the following payload in the `Website` input field:

```
javascript:alert("1");
```

![4](https://github.com/Knign/Write-ups/assets/110326359/1c355984-d197-45bf-bb8d-a3479fd24c85)

Let's verify if the payload has been inserted properly.

![5](https://github.com/Knign/Write-ups/assets/110326359/bfb7c306-f212-4d33-84d8-cdf755cff225)

Now, if we click on the `<a>` tag link, the Javascript will be executed, generating an alert.

![6](https://github.com/Knign/Write-ups/assets/110326359/788ed762-5205-4abb-bebf-0b795e68155b)

We have solved the lab.

![7](https://github.com/Knign/Write-ups/assets/110326359/9e4e5d19-9a68-4af4-991e-508560dd7f08)
