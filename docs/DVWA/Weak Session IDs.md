---
custom_edit_url: null
---

> ### Objective
> This module uses four different ways to set the dvwaSession cookie value, the objective of each level is to work out how the ID is generated and then infer the IDs of other system users.

## Security Level: Low
> The cookie value should be very obviously predictable.

<figure style={{ textAlign: 'center' }}>
![1](https://github.com/Knign/Write-ups/assets/110326359/b3162260-4398-415b-a2a0-1468e8ac0936)
</figure>

Let's inspect the page and check for the cookies.

<figure style={{ textAlign: 'center' }}>
![2](https://github.com/Knign/Write-ups/assets/110326359/a5d88a78-c87b-4eea-b68d-fcdc3a908e8b)
</figure>

As we can see, the `dvwaSession` cookie is set to 1. Let's click on the `Generate` button and check what happens.

<figure style={{ textAlign: 'center' }}>
![3](https://github.com/Knign/Write-ups/assets/110326359/9cb3a7c9-2fe2-41e3-815e-7b8a5effaa89)
</figure>

The `dvwaSession` cookie is now set to 1.  Now we know that the application increments the cookie every time the user clicks on the `Generate` button.

We could also check the provided source code to be sure.

<figure style={{ textAlign: 'center' }}>
![4](https://github.com/Knign/Write-ups/assets/110326359/2b0763a6-5df4-4a30-a1a8-b74a2f075d15)
</figure>

&nbsp;

## Security Level: Medium
> The value looks a little more random than on low but if you collect a few you should start to see a pattern.

In this level the value of the `dvwaSession` cookie increments by 1 the first we click the button and then by 2.

This process is repeated as many times as the user clicks the button.
