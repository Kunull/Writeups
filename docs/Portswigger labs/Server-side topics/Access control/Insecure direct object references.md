---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 9
---

![1](https://github.com/Knign/Write-ups/assets/110326359/f46e9246-1f1f-4d05-83cc-0fa63e820988)

Let's start the live chat.

![2](https://github.com/Knign/Write-ups/assets/110326359/e05e75e5-df3f-45cd-975e-7d9953ae2430)

We can now download this chat by clicking on the `View transcript` button.

Since we are proxying the traffic through Burp Suite, we will be able to see the request in the `Proxy > HTTP History`.

![2 2](https://github.com/Knign/Write-ups/assets/110326359/04747615-3a7b-49bf-ab4b-0ade89704084)

We are being redirected, let's view the next request.

![3](https://github.com/Knign/Write-ups/assets/110326359/b2e9ea41-f703-4ac0-a9d6-a2e533dfe018)

As we can see, our entire chat log is saved.

Let's forward this request to the `Repeater` for further modification.

Once in the `Repeater`, change the GET URI to the following:

```
/download-tanscript/2.txt
```

![4](https://github.com/Knign/Write-ups/assets/110326359/ce57f78b-e6be-4663-aabe-b1973cd43183)

This causes the application to give the transcripts of another user's chat.

We can now try to login to the `carlos` user's account using the following credentials:

| Username | Password             |
| -------- | -------------------- |
| carlos   | z7yiqtqjuttawu19dlxw |

![5](https://github.com/Knign/Write-ups/assets/110326359/0bb527ab-fbcd-4c12-9b43-14e43d3505eb)

We have solved the lab.

![6](https://github.com/Knign/Write-ups/assets/110326359/f9daeb89-c05b-4f0b-b377-02c71c4d68bf)
