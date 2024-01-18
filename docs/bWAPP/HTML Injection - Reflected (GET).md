# low
![[1 53.png]]
- We are prompted to enter the first and last name.
- Let's give it some random name and see what happens.
![[2 49.png]]
- Looks like our input is reflected back on the screen.
## HTML injection
- HTML injection is a type of injection when the user is able to enter arbitrary html code in a web page.
- This allows the us the modify the contents of the page.
- Let's input the following HTML tag:
```
First name: 
<h1>john</h1>

Last name: 
<h2>doe</h2>
```
![[3 41.png]]
- We can use this vulnerability to obtain important information such as the Cookie.

# medium
- Let's try inserting the same input as before.
```
First name: 
<h1>john</h1>

Last name: 
<h2>doe</h2>
```
![[4 27.png]]
- This time the input is not treated as HTML code. 
- We can intercept the request in Burpsuite to check how out input is being treated.
![[5 16.png]]
- As we can see our input HTML characters are URL encoded. We can also check this out in the `Decoder`.
![[6 8.png]]
- We can bypass the security filter using double URL encoding as suggested in this OWASP document.
## Double URL encoding
![[7 4.png]]
```
%25%33%63%25%36%38%25%33%31%25%33%65%25%36%61%25%36%66%25%36%38%25%36%65%25%33%63%25%32%66%25%36%38%25%33%31%25%33%65
```
- Let's forward the request to the `Repeater` so that we can make modifications. 
- We can now provide the double encoded string as the input.
![[8 1.png]]
- As we can see the name is now threated as an `h1` element. This means we have successfully performed URL injection.
