---
custom_edit_url: null
pagination_next: null
pagination_prev: null
---

> ### Objective
> Remotely, find out the user of the web service on the OS, as well as the machines hostname via RCE.
## Security Level: Low
> This allows for direct input into one of many PHP functions that will execute commands on the OS. It is possible to escape out of the designed command and executed unintentional actions.
> This can be done by adding on to the request, "once the command has executed successfully, run this command".
> Spoiler: To add a command "&&". Example: 127.0.0.1 && dir.

![1](https://github.com/Knign/Write-ups/assets/110326359/6274dc2d-aa0d-418d-8f07-b556a9d0215d)

- Let's enter `127.0.0.1` as the IP address.

![2](https://github.com/Knign/Write-ups/assets/110326359/d60d766c-af4b-450e-8b00-77993275a5fa)

- So the application takes the user input and uses that in a `ping` command.
- We can chain multiple commands together using the `&&` operator.
```
127.0.0.1 && cat /etc/passwd
```

![3](https://github.com/Knign/Write-ups/assets/110326359/3f3762ba-7fec-4d5b-9fb4-721a97449299)

&nbsp;


## Security Level: Medium
> The developer has read up on some of the issues with command injection, and placed in various pattern patching to filter the input. However, this isn't enough.
> Various other system syntaxes can be used to break out of the desired command.
> Spoiler: e.g. background the ping command.
- We can check the source code for each level at the bottom of the page.

![4](https://github.com/Knign/Write-ups/assets/110326359/4e68805a-66f3-456d-987e-528ef9aa62c0)

- As we can see, our input characters `&&` are being substituted with empty space.
- Let's try using the pipe `|` operator.

![5](https://github.com/Knign/Write-ups/assets/110326359/35fbc180-d1f0-4885-94f2-66c86e3803ed)

&nbsp;


## Security Level: High
> In the high level, the developer goes back to the drawing board and puts in even more pattern to match. But even this isn't enough.
> The developer has either made a slight typo with the filters and believes a certain PHP command will save them from this mistake.
> Spoiler: [trim()](https://secure.php.net/manual/en/function.trim.php)			removes all leading & trailing spaces, right?.
- Let's check what typo the developer has made.

![6](https://github.com/Knign/Write-ups/assets/110326359/87fcec55-b767-4132-90fd-f8678a4c3940)

- As we can see, in the third case, the characters `| ` are being replaced with empty space.
- We can provide the same input as above just with a slight modification:
```
127.0.0.1 |cat /etc/passwd
```

![7](https://github.com/Knign/Write-ups/assets/110326359/5da830c9-dfe8-43c0-918d-e59548876ce4)
