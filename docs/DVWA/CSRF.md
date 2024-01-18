---
custom_edit_url: null
pagination_next: null
pagination_prev: null
---

> ### Objective
> Your task is to make the current user change their own password, without them knowing about their actions, using a CSRF attack.

## Security Level: Low
> There are no measures in place to protect against this attack. This means a link can be crafted to achieve a certain action (in this case, change the current users password). Then with some basic social engineering, have the target click the link (or just visit a certain page), to trigger the action.
> Spoiler: ?password_new=password&password_conf=password&Change=Change.

![1](https://github.com/Knign/Write-ups/assets/110326359/d7b1127f-9597-49da-8a4f-dd3ae451e916)

- Let's click on the `Test Credentials` button and enter `password` as the password.

![2](https://github.com/Knign/Write-ups/assets/110326359/e3584a4e-cb81-4f00-9914-0509bd698514)

- We can now set the password to any other value let's say `password123` and intercept the request using Burpsuite.

![4](https://github.com/Knign/Write-ups/assets/110326359/88510d71-659c-46fc-ae08-a7cbe9b3bfd6)

- As we can see, the passwords are being used in the URI. 
- We can now use this send this URI to a victim to have their password changed..
```
http://10.0.4.5/DVWA/vulnerabilities/csrf/?password_new=password123&password_conf=password123&Change=Change
```

&nbsp;


## Security Level: Medium
> For the medium level challenge, there is a check to see where the last requested page came from. The developer believes if it matches the current domain, it must of come from the web application so it can be trusted.
> It may be required to link in multiple vulnerabilities to exploit this vector, such as reflective XSS.

- Let's intercept the request in Burpsuite again.

![5](https://github.com/Knign/Write-ups/assets/110326359/f74d4d01-ecff-46b6-a81d-af9a870cb4b0)

- We can see, that the `Referer` header has the same domain as the one we are on i.e. `DVWA/vulnerabilities/csrf/`.
- As the hint suggests, we are going to need to use the reflected XSS vulnerability to exploit this level.
- 
