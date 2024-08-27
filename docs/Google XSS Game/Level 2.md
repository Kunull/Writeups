---
title: Level 2 - Persistence is key
custom_edit_url: null
---

![1](https://github.com/user-attachments/assets/d5c7465c-6558-4d47-80c0-4212865fe3a6)

## Hints

> 1. Note that the "welcome" post contains HTML, which indicates that the template doesn't escape the contents of status messages.

> 2. Entering a `<script>` tag on this level will not work. Try an element with a JavaScript attribute instead.

> 3. This level is sponsored by the letters _i_, _m_ and _g_ and the attribute `onerror`.

## Exploitation

### Payload

Since we cannot use `<script>` tags, we have to craft a basic payload using `<img>` tags.

```html
<img src=1 onerror=alert(1)>
```

![2](https://github.com/user-attachments/assets/0eb0fce5-786f-4eec-9b2f-4b9492aafa28)
