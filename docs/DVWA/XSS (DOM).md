---
custom_edit_url: null
pagination_next: null
pagination_prev: null
---

> ### Objective
> Run your own JavaScript in another user's browser, use this to steal the cookie of a logged in user.

## Security Level: Low
> Low level will not check the requested input, before including it to be used in the output text.
> Spoiler: /vulnerabilities/xss_d/?default=English<script>alert(1)</script>.
- Let's select the first option i.e. `English` and click `Submit`.

![1](https://github.com/Knign/Write-ups/assets/110326359/959ff393-694b-422d-aa1a-50c41213ce94)

- If we look at the URL, we can see that our input has been set as a URL parameter.
- DOM-based XSS vulnerabilities usually arise when JavaScript takes data from an attacker-controllable source, such as the URL, and passes it to a sink that supports dynamic code execution.
- Let's change the URL to the following:
```
10.0.4.5/DVWA/vulnerabilities/xss_d/?default=<script>alert();</script>
```

![2](https://github.com/Knign/Write-ups/assets/110326359/040fb1b1-eedc-4899-a79d-97d420e098f5)

&nbsp;


## Security Level: Medium
> The developer has tried to add a simple pattern matching to remove any references to "<script" to disable any JavaScript. Find a way to run JavaScript without using the script tags.
> Spoiler: You must first break out of the select block then you can add an image with an onerror event:  
> /vulnerabilities/xss_d/?default=English>/option></select><img src='x' onerror='alert(1)'>.
- Let's check the source code.

![3](https://github.com/Knign/Write-ups/assets/110326359/ac7216de-a267-4126-9ff7-c0c38fa67bee)

- So our input is being stripped of `<script` tags.
- Let's inspect the code in the web page as well.

![4](https://github.com/Knign/Write-ups/assets/110326359/a0fe7593-ebce-4bb2-a364-379469ccfce9)

- We can see that we first need to escape the `<select>` tag that we are in.
- Once we have done that we can use the `img onerror` attribute to trigger an alert.
```
10.0.4.5/DVWA/vulnerabilities/xss_d/?default=</select><img src=1 onerror=alert(document.cookie)>
```

![5](https://github.com/Knign/Write-ups/assets/110326359/a57d294d-0d1d-4841-a41a-e93a08410b5b)

&nbsp;


## Security Level: High
> The developer is now white listing only the allowed languages, you must find a way to run your code without it going to the server.
> Spoiler: The fragment section of a URL (anything after the # symbol) does not get sent to the server and so cannot be blocked. The bad JavaScript being used to render the page reads the content from it when creating the page.  
> /vulnerabilities/xss_d/?default=English#<script>alert(1)</script>.
- Let's check the source code first.

![6](https://github.com/Knign/Write-ups/assets/110326359/602f9853-2478-423b-a9f6-1f0d31c5710e)

- In this case we can use the `#` character so that our URI is fragmented and it satisfies the checks.
```
10.0.4.5/DVWA/vulnerabilities/xss_d/#?default=<script>alert(document.cookie);</script>
```

![7](https://github.com/Knign/Write-ups/assets/110326359/1d08e85f-3bcb-4a4a-bf9a-2eede0611040)
