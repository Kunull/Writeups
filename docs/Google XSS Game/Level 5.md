---
title:  Level 5 - Breaking protocol
edit_url: null
---

![1](https://github.com/user-attachments/assets/ca8fd8e8-273c-43ac-800e-1484cbcfc8f8?raw=1)

## Hints

> 1. The title of this level is a hint.

> 2. It is useful look at the source of the signup frame and see how the URL parameter is used.

> 3. If you want to make clicking a link execute Javascript (without using the `onclick` handler), how can you do it?

> 4. If you're really stuck, take a look at this [IETF draft](http://tools.ietf.org/html/draft-hoehrmann-javascript-scheme-00)


## Exploitation

Open the frame in a different tab using the following URI:
https://xss-game.appspot.com/level5/frame/

![4](https://github.com/user-attachments/assets/f4037355-827e-41ca-8caf-fefa6c8901cb?raw=1)

Click on the `Sign up` link.

![2](https://github.com/user-attachments/assets/e3e6f000-56f4-4c61-93c3-9f1aa2576f61?raw=1)

### Payload

Change the `next` parameter to the following:

```
?next=javascript:alert(1);
```

Click on the `Next` button.

![3](https://github.com/user-attachments/assets/fa283492-a378-4440-83ee-5f4a02d952b1?raw=1)
