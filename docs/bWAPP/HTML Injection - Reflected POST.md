---
title: HTML Injection - Reflected (POST)
custom_edit_url: null
pagination_next: null
pagination_prev: null
---

## low

![1](https://github.com/Knign/Write-ups/assets/110326359/d8ec7c41-822b-4685-82bd-95baae99bd00)

We are provided with two input fields to input the first and last name.

Let's provide the input and intercept the request in Burpsuite.

![2](https://github.com/Knign/Write-ups/assets/110326359/1aa76804-81fc-4f96-9f60-8e6e7e661e32)

We can see that the request method is POST. 

Let's input the following HTML tag:

```
First name: 
<h1>john</h1>

Last name: 
<h2>doe</h2>
```

![3](https://github.com/Knign/Write-ups/assets/110326359/b0068bb7-b06c-4e79-8375-3c4dc0c3741f)

&nbsp;

## medium
Let's intercept the request using Burpsuite.

![4](https://github.com/Knign/Write-ups/assets/110326359/c06834be-1007-4c57-9a58-06036664a0de)

As we can see, our input HTML characters have been URL encoded.

Let's forward the request to the `Repeater` encode the entire input including the name to check if that evades the security filter.
```
firstname=%3c%68%31%3e%6a%6f%68%6e%3c%2f%68%31%3e&lastname=%3c%68%32%3e%64%6f%65%3c%2f%68%32%3e&form=submit
```

![6](https://github.com/Knign/Write-ups/assets/110326359/4f0964b1-e120-4f57-bcb5-b9afbb670726)

We have successfully exploited the HTML injection vulnerability.
