---
title: Level 1 - Hello, world of XSS
custom_edit_url: null
---

<figure style={{ textAlign: 'center' }}>
![1](https://github.com/user-attachments/assets/e4599026-d77c-4ab9-8a58-109f243305c6?raw=1)
</figure>

## Hints

> 1. To see the source of the application you can right-click on the frame and choose _View Frame Source_ from the context menu or use your browser's developer tools to inspect network traffic.

> 2. What happens when you enter a presentational tag such as `<h1>`?

> 3. Alright, one last hint: `<script> ... alert ...`

## Exploitation

### Payload

The payload required to solve this level will be pretty simple.

```html
<script>alert(1)</script>
```

<figure style={{ textAlign: 'center' }}>
![2](https://github.com/user-attachments/assets/1d6daca7-6eb9-4997-ba10-84a9ba89c626?raw=1)
</figure>
