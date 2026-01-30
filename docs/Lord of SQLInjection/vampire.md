---
custom_edit_url: null
sidebar_position: 9
---

<figure style={{ textAlign: 'center' }}>
![1](https://github.com/Kunull/Write-ups/assets/110326359/ac165bb9-b70d-4723-b941-ab315029c976)
</figure>

We are provided with the SQL query:

```sql
SELECT id FROM prob_vampire WHERE id='{$_GET[pw]}'
```

This level uses the `str_replace()` function to replace `admin` with ` `. 


However this function is not recursive which means when we provide the following URI parameter:

```
?id=adadminmin
```

The application replaces `admin`, and our URI parameter becomes:

```
?id=admin
```

The resultant query then becomes:

```sql
SELECT id FROM prob_vampire WHERE id='admin'
```

<figure style={{ textAlign: 'center' }}>
![2](https://github.com/Kunull/Write-ups/assets/110326359/f8d863b8-07ab-4d01-b24a-93901a8906c5)
</figure>
