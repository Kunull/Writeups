---
custom_edit_url: null
sidebar_position: 6
---

![1](https://github.com/Knign/Write-ups/assets/110326359/4d237aab-f71e-44cf-b9e2-456f62c23444)

The page is empty. Let's inspect the source code of the page.

![2](https://github.com/Knign/Write-ups/assets/110326359/9a79f214-0238-4257-be90-050459531f19)

Looks like password has been encoded multiple times. We can use the `decodeURI` and function to decode it.

![3](https://github.com/Knign/Write-ups/assets/110326359/bf518109-cffe-4392-8fb6-251e6b5b7e3d)

```js
> decodeURI("unescape%28%22String.fromCharCode%2528104%252C68%252C117%252C102%252C106%252C100%252C107%252C105%252C49%252C53%252C54%2529%22%29")
<- 'unescape("String.fromCharCode%28104%2C68%2C117%2C102%2C106%2C100%2C107%2C105%2C49%2C53%2C54%29")'
> decodeURIComponent("String.fromCharCode%28104%2C68%2C117%2C102%2C106%2C100%2C107%2C105%2C49%2C53%2C54%29")
<- 'String.fromCharCode(104,68,117,102,106,100,107,105,49,53,54)'
> String.fromCharCode(104,68,117,102,106,100,107,105,49,53,54)
<- 'hDufjdki156'
```
## Password
```
hDufjdki156
```
