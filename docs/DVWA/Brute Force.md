---
custom_edit_url: null
---

> ### Objective
> Your goal is to get the administrator’s password by brute forcing. Bonus points for getting the other four user passwords!

## Security Level: Low

<figure style={{ textAlign: 'center' }}>
![1](https://github.com/Knign/Write-ups/assets/110326359/f3afd939-4fe6-470a-8c1a-fabf63b7c68f)
</figure>

The application provides us with two input fields in order to enter the username and the password.

Let's enter `admin` as both.

<figure style={{ textAlign: 'center' }}>
![2](https://github.com/Knign/Write-ups/assets/110326359/8e55f01a-6236-406c-82d5-6804cbaa52bc)
</figure>

Let's intercept the request in Burpsuite.

<figure style={{ textAlign: 'center' }}>
![3](https://github.com/Knign/Write-ups/assets/110326359/3a63a009-a4a5-4c4b-b6bf-2040c8c960aa)
</figure>

We can now forward this request to the `Intruder` to automate the attack.

<figure style={{ textAlign: 'center' }}>
![4](https://github.com/Knign/Write-ups/assets/110326359/f7ed0799-6640-4e58-90cf-7f2f26232a4f)
</figure>

After adding a field to the password, we can move on to setting up the substitution payload.

<figure style={{ textAlign: 'center' }}>
![5](https://github.com/Knign/Write-ups/assets/110326359/130c0faa-8d09-4223-813f-820456aceb72)
</figure>

For the payload type we want a simple list, more specifically the `darkweb2017-top100.txt` passwords lists from the `seclists` collection.

Before we start the attack there is something important that we have to do.
In the `Options` tab, we can set the string to grep for.

We can set it to the following:
```
Username and/or password incorrect.
```

<figure style={{ textAlign: 'center' }}>
![6](https://github.com/Knign/Write-ups/assets/110326359/5390e66a-fb3f-4b48-8615-553331d106de)
</figure>

Let's start the attack.

<figure style={{ textAlign: 'center' }}>
![7](https://github.com/Knign/Write-ups/assets/110326359/3a407c73-45c8-4bc0-a973-61d0451d3d2e)
</figure>

We can immediately see that the response for `password` did not include the string.

Let's take a closer look at the response.

<figure style={{ textAlign: 'center' }}>
![8](https://github.com/Knign/Write-ups/assets/110326359/c1378c6e-94e7-42cd-996d-02ebea714710)
</figure>

We can see that it greets us with a welcome message. This means that the password is `password`.
