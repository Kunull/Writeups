---
title: HTML Injection - Reflected (GET)
custom_edit_url: null
---


## low

![1](https://github.com/Knign/Write-ups/assets/110326359/33af387c-2969-4635-9aee-5657a227942d)

We are prompted to enter the first and last name.

Let's give it some random name and see what happens.

![2](https://github.com/Knign/Write-ups/assets/110326359/4cd74667-4027-4f04-96d5-a718f912a1f0)

Looks like our input is reflected back on the screen.

### HTML injection
HTML injection is a type of injection when the user is able to enter arbitrary html code in a web page.

This allows the us the modify the contents of the page.

Let's input the following HTML tag:
```
First name: 
<h1>john</h1>

Last name: 
<h2>doe</h2>
```

![3](https://github.com/Knign/Write-ups/assets/110326359/99ec84b6-b937-44f0-b5d3-cb5c592e5161)

We can use this vulnerability to obtain important information such as the Cookie.

&nbsp;

## medium
Let's try inserting the same input as before.
```
First name: 
<h1>john</h1>

Last name: 
<h2>doe</h2>
```

![4](https://github.com/Knign/Write-ups/assets/110326359/09395e51-146c-491b-b5de-1c7af1c55dcb)

This time the input is not treated as HTML code. 

We can intercept the request in Burpsuite to check how out input is being treated.

![5](https://github.com/Knign/Write-ups/assets/110326359/77db24e2-c582-4604-ac0e-6a350ce38f1d)

As we can see our input HTML characters are URL encoded. We can also check this out in the `Decoder`.

![6](https://github.com/Knign/Write-ups/assets/110326359/e4b7c57d-db49-44d6-ab3e-477d14e4ab44)

We can bypass the security filter using double URL encoding as suggested in this OWASP document.

### Double URL encoding

![7](https://github.com/Knign/Write-ups/assets/110326359/47ba146f-95d0-424a-ae87-736febf3c769)

```
%25%33%63%25%36%38%25%33%31%25%33%65%25%36%61%25%36%66%25%36%38%25%36%65%25%33%63%25%32%66%25%36%38%25%33%31%25%33%65
```
Let's forward the request to the `Repeater` so that we can make modifications. 

We can now provide the double encoded string as the input.

![8](https://github.com/Knign/Write-ups/assets/110326359/1c95ee65-323a-4189-8e4e-a09f45a8e43e)

As we can see the name is now threated as an `h1` element. This means we have successfully performed URL injection.
