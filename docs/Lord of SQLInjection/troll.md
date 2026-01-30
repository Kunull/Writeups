---
custom_edit_url: null
sidebar_position: 8
---

<figure style={{ textAlign: 'center' }}>
![1](https://github.com/Kunull/Write-ups/assets/110326359/fc58b667-606c-4fe8-87ab-d10342b5a1a4)
</figure>

We are provided with the SQL query:

```sql
SELECT id FROM prob_troll WHERE id='{$_GET[id]}'
```

This level blocks the `admin` word from the payload.
However, SQL is not case sensitive. Therefore we can use `ADMIN` instead of `admin`.

If we provide the following URI parameter:

```
?id=ADMIN
```

The resultant query becomes:

```sql
SELECT id FROM prob_troll WHERE id='ADMIN'
```

<figure style={{ textAlign: 'center' }}>
![2](https://github.com/Kunull/Write-ups/assets/110326359/b726e13f-6c99-4ae8-b43f-83971c9caec3)
</figure>
