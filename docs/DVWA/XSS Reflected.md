---
title: XSS (Reflected)
custom_edit_url: null
pagination_next: null
pagination_prev: null
---

> ### Objective
> One way or another, steal the cookie of a logged in user.

## Security Level: Low
> Low level will not check the requested input, before including it to be used in the output text.
> Spoiler: ?name=<script>alert("XSS");</script>.

![1](https://github.com/Knign/Write-ups/assets/110326359/c6094b05-b87e-4d7d-8d86-954f821cc0e3)

- Let's prove `john` as the input.

![2](https://github.com/Knign/Write-ups/assets/110326359/f475a13e-d6d4-4aea-9ace-adc9060563e7)

- We can see that our input is being reflected back to us.
- Let's provide the following input:
```
<script>alert(document.cookie)</script>
```

![3](https://github.com/Knign/Write-ups/assets/110326359/9aa1b48d-d04c-4ab3-9b75-0c25e3be756a)

&nbsp;


## Security Level: Medium
<!---
> The developer has tried to add a simple pattern matching to remove any references to "</script>", to disable any JavaScript.
-->
> Spoiler: Its cAse sENSiTiVE.
- Let's check out the source code.

![4](https://github.com/Knign/Write-ups/assets/110326359/ee8421db-c404-45f4-b97a-6b178df5f83f)

- The `<script>` tag is being replaced with empty space using the  `str_replace` function.
- The problem with this function is that it is case sensitive i.e. it will not replace a `<SCRIPT>` tag.
- This allows us to craft our payload as follows:
```
<SCRIPT>alert(document.cookie)</SCRIPT>
```

![5](https://github.com/Knign/Write-ups/assets/110326359/73e0fac2-7ebd-4e23-a399-8e999d578179)

&nbsp;


## Security Level: High
<!---
> The developer now believes they can disable all JavaScript by removing the pattern "<s*c*r*i*p*t>".
-->
> Spoiler: HTML events.
- In this level the `<script` pattern itself is removed.
- Let's check the source code to see how this has been implemented.

![6](https://github.com/Knign/Write-ups/assets/110326359/5f930149-5533-4579-b18c-769f6e09ad4d)

- The developer has used the `preg_replace` function.
- However, we can still use HTML events in order to trigger the alert.
- For our payload we can use the `<img onerror>` attribute as follows:
```
<img src=1 onerror=alert(document.cookie)>
```

![7](https://github.com/Knign/Write-ups/assets/110326359/89e4a99f-334b-473e-b54e-e982983286c3)
