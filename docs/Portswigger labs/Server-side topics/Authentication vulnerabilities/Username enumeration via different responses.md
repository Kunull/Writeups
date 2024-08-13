---
custom_edit_url: null
sidebar_position: 1
---

![1](https://github.com/Knign/Write-ups/assets/110326359/c5820cdb-77e1-4730-889a-a1e36f4e81dd)

We can click on `My Account` in order to login.

![2](https://github.com/Knign/Write-ups/assets/110326359/4c423eff-7c8a-4010-b44c-242500353927)

We can view the `Proxy > HTTP History` in Burp Suite to view this request.

![3](https://github.com/Knign/Write-ups/assets/110326359/5e4f3cae-f57a-4355-b984-46e324628de2)

Let's forward it to the `Intruder` and add a payload field to the `username` parameter.

![4](https://github.com/Knign/Write-ups/assets/110326359/1a8be363-41aa-4079-87cf-49e4f6b53c93)

Next we can go to the `Payloads` tab and set the `Payload type` to `Simple list`. Once that is done, we can paste the usernames provided to us here in the `Payloads settings` section.

![5](https://github.com/Knign/Write-ups/assets/110326359/bc3328a4-4926-4e97-bbb3-feccd144f4e0)

Let's start the attack.

![6](https://github.com/Knign/Write-ups/assets/110326359/17c5b5c7-4f90-4d1b-a206-99d5b0fae462)

We can observe that the request with `username` set to `analyzer` returned a different response than the others.

This is because this username was correct whereas the others weren't.

Now we can craft another attack by setting the `username` parameter to `carlos` and adding a payload field to the `password` parameter.

![7](https://github.com/Knign/Write-ups/assets/110326359/b2f3ebe9-b2c0-427e-b4db-a5ce8b6aeb9b)

In the `Payloads` tab we will again be using a `Simple list`.

Let's paste the passwords provided to use here in the `Paeyloads section`.

![8](https://github.com/Knign/Write-ups/assets/110326359/436c8b3d-1dd7-4043-9a86-d1a10302ac82)

We are now set to start the attack.

![9](https://github.com/Knign/Write-ups/assets/110326359/eb057ba5-a5c1-41f8-85cb-eb42f125888b)

As we can see, the request with the `password` set to `1234567890` gives a `302` response.

Now that we know what the username and password are, let's login.

| Username | Password |
| -------- | -------- |
| analyzer         | 1234567890         |

![10](https://github.com/Knign/Write-ups/assets/110326359/743731d9-dc83-4104-bfe8-8fe98147bc7a)

We have solved the lab.

![11](https://github.com/Knign/Write-ups/assets/110326359/2eafd40c-d6e1-4d45-af27-65de6173f547)
